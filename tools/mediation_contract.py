"""Deterministic checks for specific public documentation invariants.

These rules recognize known high-risk assertions and a bounded set of scoped,
negated and historical forms. They are not a natural-language truth validator
and cannot prove that arbitrary English contains no misleading claims. Review
new wording against the implementation, then add explicit regression examples.

The closed claim-unit heuristic carries an explicit Guard subject to leading
"it" clauses only within one sentence. Any other clause resets that subject;
this deliberately does not attempt general English coreference resolution.
"""
import re


MEDIATION_STATEMENT = (
    "Guard enforces actions that pass through its wrapped tool boundary. Actions "
    "that reach the same capability through another function, tool, process, "
    "credential, or API path are outside that enforcement guarantee."
)
GUIDE = "docs/architecture/REPOSITORY_WORKSPACE.md"
QUICKSTART = "docs/getting-started/README.md"
PACKAGED_DOCS = ("README.md", "SECURITY.md", GUIDE, QUICKSTART)
THREAT_CLASSES = (
    "Direct function or API bypass", "Alternate tools and plugins",
    "Subprocess and shell execution", "Filesystem access outside the repository adapter",
    "Credential reuse or theft", "Privileged operator or administrator bypass",
    "In-process tampering", "Independent concurrent writers",
    "Post-callback substitution detection", "Unsupported operating systems and mutation types",
    "Decision replay versus physical mutation",
)
# Match affirmative verbs, not just sensitive nouns. Direct "is not" / "does
# not" forms therefore do not match. Only the action rule accepts an attached
# mediation qualifier: a qualifier cannot make sandbox or rollback claims true.
CLAIM_RULES = (
    ("all-actions", r"\b(?:guard|waveframe)\s+(?:controls|protects|governs)\s+(?:all|every)\s+(?:agent\s+)?(?:mediated\s+)?actions?\b"),
    ("whole-resource", r"\b(?:guard|waveframe)\s+(?:controls|protects|governs)\s+(?:the\s+|your\s+)?(?:entire|whole)\s+(?:repository|host|machine|agent|organization)\b"),
    ("global-state", r"\b(?:(?:a\s+)?connected\s+runtime\s+means\s+(?:the\s+)?)?(?:repository|host|machine|agent|organization)\s+is\s+(?:globally|fully)\s+(?:protected|controlled|governed)\b"),
    ("no-bypass", r"\b(?:guard|waveframe)\s+guarantees\s+(?:that\s+)?bypass\s+cannot\s+occur\b"),
    ("impossible-bypass", r"\bbypass\s+is\s+impossible\b"),
    ("isolation", r"\bguard\s+is\s+(?:a\s+)?(?:filesystem\s+sandbox|tamper[- ]resistant)\b"),
    ("strong-mediation", r"\bguard\s+(?:provides|guarantees)\s+(?:tamper[- ]resistant|always[- ]invoked)\s+mediation\b"),
    ("exhaustive-evidence", r"\bdecision\s+evidence\s+proves\s+(?:that\s+)?no\s+alternate\s+path\s+was\s+used\b"),
    ("physical-replay", r"\breplay\s+reproduces\s+(?:the\s+)?physical\s+mutation\b"),
    ("rollback", r"\bdetection\s+after\s+a\s+callback\s+rolls\s+back\s+already[- ]written\s+bytes\b"),
    ("exclusive-path", r"\bonly\s+the\s+guarded\s+callable\s+can\s+reach\b"),
)

# Sentence, paragraph, table-cell and Markdown item boundaries end subject
# carry. Coordinated clauses retain only a named Guard subject or leading "it".
# Unknown/non-pronoun clauses clear it, without guessing their subject grammar.
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|(?<=[.!?][\"'])\s+|\|\s*")
GUARD_SUBJECT = re.compile(r"\b(?:waveframe\s+guard(?:\s+sdk)?|guard\s+sdk|guard|waveframe)\b", re.IGNORECASE)
ASSERTION_START = (
    r"(?:it\b|guard\b|waveframe\b|(?:a\s+)?connected\s+runtime\b|"
    r"(?:the\s+|a\s+)?(?:repository|host|machine|agent|organization)\b|"
    r"decision\s+evidence\b|replay\b|detection\s+after\b|bypass\b|only\s+the\s+guarded\b)"
)
CLAUSE_BREAK = re.compile(
    r";\s*|\s*[\u2014\u2013]\s*|,?\s+(?:but|and|while|however|yet|nevertheless)\s+|"
    r",\s*(?=" + ASSERTION_START + r")",
    re.IGNORECASE,
)
NEGATED_INTRO = re.compile(
    r"\b(?:(?:do\s+not|must\s+not|never)\s+claim|"
    r"does\s+not\s+(?:establish|guarantee|mean|imply|prove))"
    r"(?:\s+that)?\s*[:\"']?\s*(?:(?:the|a|an)\b\s*)?$",
    re.IGNORECASE,
)
# Quotes alone are not exemptions. These explicit historical attributions must
# immediately introduce a quotation; its closing quote bounds the exemption.
HISTORICAL_INTRO = re.compile(
    r'(?:\bhistorical\s+wording\s*\(no\s+longer\s+accurate\)\s*:\s*|'
    r'\bpreviously,?\s+(?:the\s+)?(?:readme|documentation|docs)\s+(?:claimed|stated)\s*)"$',
    re.IGNORECASE,
)
ACTION_SCOPE = re.compile(
    r"^\s+(?:that\s+(?:pass|passes|flow|flows)\s+through\s+(?:its|the|this)\s+"
    r"(?:installed\s+)?wrapped\s+(?:tool\s+)?boundary\b|"
    r"(?:on|through|within)\s+(?:the|its|this)\s+wrapped\s+callable\s+path\b)",
    re.IGNORECASE,
)


def normalized(text):
    text = text.translate(str.maketrans({"\u201c": '"', "\u201d": '"', "\u2019": "'", "\u2011": "-"}))
    text = re.sub(r"\[([^\]]+)\]\([^\n)]*\)", r"\1", text)
    text = text.replace("`", "").replace("*", "").replace("__", "")
    text = re.sub(r"(?<!\w)_(\S(?:.*?\S)?)_(?!\w)", r"\1", text, flags=re.DOTALL)
    return " ".join(text.split())


def claim_clauses(text):
    # Preserve structural breaks before whitespace/Markdown normalization.
    text = re.sub(r"(?m)^\s*(?:>\s*)*(?:#{1,6}\s+|[-+*]\s+|\d+[.)]\s+)", "\n\n", text)
    text = re.sub(r"(?m)^\s*>\s?", "", text)
    for paragraph in re.split(r"\n\s*\n", text):
        for sentence in SENTENCE_BREAK.split(normalized(paragraph)):
            guard_active = False
            for clause in filter(None, CLAUSE_BREAK.split(sentence)):
                clause = clause.strip()
                # Canonicalize only the finite supported names, retaining the
                # warning/quotation prefix for assertion-local checks below.
                subject = GUARD_SUBJECT.search(clause)
                named_guard = subject is not None and (
                    subject.start() == 0
                    or NEGATED_INTRO.search(clause[:subject.start()].rstrip())
                )
                if named_guard:
                    guard_active = True
                    clause = clause[:subject.start()] + "Guard" + clause[subject.end():]
                elif re.match(r"^it\b", clause, re.IGNORECASE):
                    if guard_active:
                        clause = re.sub(r"^it\b", "Guard", clause, count=1, flags=re.IGNORECASE)
                else:
                    guard_active = False
                yield clause


def _qualified_or_disclaimed(clause, match, rule):
    prefix = clause[:match.start()].rstrip()
    if NEGATED_INTRO.search(prefix):
        return True
    if HISTORICAL_INTRO.search(prefix) and '"' in clause[match.end():]:
        return True
    if rule == "all-actions":
        return bool(re.search(r"\bmediated\s+actions?\b", match.group(), re.IGNORECASE)
                    or ACTION_SCOPE.match(clause[match.end():]))
    return False


def validate_claims(text, label):
    for clause in claim_clauses(text):
        for rule, pattern in CLAIM_RULES:
            for match in re.finditer(pattern, clause, re.IGNORECASE):
                if not _qualified_or_disclaimed(clause, match, rule):
                    raise AssertionError(f"{label}: prohibited global-control or bypass claim ({rule})")


def validate_mediation_document(text, label):
    validate_claims(text, label)
    text = normalized(text)
    if label != "SECURITY.md":
        assert MEDIATION_STATEMENT in text, f"{label}: missing mediated-action statement"
    if label == GUIDE:
        for phrase in (*THREAT_CLASSES, "Least-privilege deployment", "Operator verification",
                       "specific Guard integration is reporting", "dedicated least-privileged service identity",
                       "Separate agent identity from operator/admin identity",
                       "Monitor for use of alternate paths", "separate, stronger assurance class",
                       "Expose only Guard-wrapped mutation tools to the agent",
                       "raw repository/cloud/service credentials", "Remove or restrict alternate shell",
                       "scope its credentials and filesystem permissions to that capability",
                       "Run one expected-allowed mediated action", "Run one expected-blocked mediated action",
                       "Detection after a callback does not roll back already-written bytes",
                       "Decision evidence does not prove that no alternate path was used",
                       "Verify the blocked callback was not invoked",
                       "Independently confirm the agent lacks a usable alternate mutation path",
                       "target_binding.adapter_version", "authority_basis.contract_id",
                       "execution_request.action", "execution_request.target", "mutation_status"):
            assert phrase in text, f"{label}: missing boundary guidance: {phrase}"
