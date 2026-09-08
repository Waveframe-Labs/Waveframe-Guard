"""Shared source/distribution checks for the public mediation claims."""
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
FORBIDDEN_CLAIMS = (
    r"(?:guard|waveframe)\s+(?:controls|protects|governs)\s+(?:all|every)\s+(?:agent\s+)?actions?",
    r"(?:repository|host|machine|organization)\s+is\s+(?:globally|fully)\s+(?:protected|controlled)",
    r"bypass\s+is\s+impossible",
    r"guard\s+is\s+(?:a\s+)?(?:filesystem\s+sandbox|tamper[- ]resistant)",
    r"guard\s+(?:provides|guarantees)\s+(?:tamper[- ]resistant|always[- ]invoked)\s+mediation",
    r"decision\s+evidence\s+proves\s+(?:that\s+)?no\s+alternate\s+path\s+was\s+used",
    r"replay\s+reproduces\s+(?:the\s+)?physical\s+mutation",
    r"detection\s+after\s+a\s+callback\s+rolls\s+back\s+already[- ]written\s+bytes",
    r"only\s+the\s+guarded\s+callable\s+can\s+reach",
)


def normalized(text):
    return " ".join(text.replace("`", "").replace("**", "").split())


def validate_claims(text, label):
    text = normalized(text)
    for pattern in FORBIDDEN_CLAIMS:
        if re.search(pattern, text, re.IGNORECASE):
            raise AssertionError(f"{label}: prohibited global-control or bypass claim")


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
