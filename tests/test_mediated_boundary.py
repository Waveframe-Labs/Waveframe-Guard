"""Regressions for known public-documentation claims, not arbitrary English truth.

Explicit positive/negative examples define the deterministic contract. Passing
these checks never substitutes for reviewing new claims against implementation.
"""
import ast
import io
from pathlib import Path
import subprocess
import tarfile
import zipfile

import pytest

from tools.mediation_contract import (
    GUIDE, MEDIATION_STATEMENT, PACKAGED_DOCS, THREAT_CLASSES,
    normalized, validate_claims, validate_mediation_document,
)
from tools.acceptance import package_acceptance
from test_licensing import archive_files


ROOT = Path(__file__).resolve().parents[1]

ACCEPT_CLAIMS = (
    "Guard controls all actions that pass through its wrapped tool boundary.",
    "Do not claim that Guard is a filesystem sandbox.",
    "Guard is not a filesystem sandbox.",
    "Guard does not guarantee that bypass cannot occur.",
    MEDIATION_STATEMENT,
)
REJECT_CLAIMS = (
    "Guard controls all agent actions.",
    "Guard protects the entire repository, including direct filesystem writes.",
    "Guard guarantees that bypass cannot occur.",
    "Guard is a filesystem sandbox.",
    "Guard provides tamper-resistant mediation.",
    "A connected runtime means the repository is globally protected.",
    "Decision evidence proves no alternate path was used.",
    "Replay reproduces the physical mutation.",
    "Detection after a callback rolls back already-written bytes.",
)


COORDINATED_REJECT_CLAIMS = (
    "Guard is not a filesystem sandbox, but it controls all agent actions.",
    "Guard controls mediated actions, and it protects the entire repository.",
    "Do not claim bypass is impossible; Guard guarantees bypass cannot occur.",
)
COORDINATED_ACCEPT_CLAIMS = (
    "Guard controls all actions that pass through its wrapped tool boundary.",
    "Guard is not a filesystem sandbox.",
    "Guard is not a filesystem sandbox, and it controls all actions that pass through its wrapped tool boundary.",
    "Guard controls mediated actions, and it does not protect the entire repository.",
    "Guard evaluates mediated actions, and it records their outcomes.",
)


@pytest.mark.parametrize("claim", COORDINATED_REJECT_CLAIMS)
def test_coordinated_unsafe_claims_fail(claim):
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(claim, "coordinated REJECT example")


@pytest.mark.parametrize("claim", COORDINATED_ACCEPT_CLAIMS)
def test_coordinated_accurate_claims_pass(claim):
    validate_claims(claim, "coordinated ACCEPT example")


@pytest.mark.parametrize("document", PACKAGED_DOCS)
@pytest.mark.parametrize("claim", COORDINATED_REJECT_CLAIMS[:2])
def test_canonical_document_cannot_hide_coordinated_list_claim(document, claim):
    text = (ROOT / document).read_text(encoding="utf-8")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_mediation_document(text + "\n\n- " + claim, document)


@pytest.mark.parametrize("subject", ["Guard", "Waveframe Guard", "Guard SDK"])
@pytest.mark.parametrize("separator", [", but ", ", and ", "; ", " \u2014 "])
@pytest.mark.parametrize("formatting", ["plain", "list", "emphasis", "inline-code", "wrapped"])
def test_subject_carry_and_clause_local_limits(subject, separator, formatting):
    def render(text):
        return {
            "plain": text, "list": "- " + text, "emphasis": "**" + text + "**",
            "inline-code": "`" + text + "`", "wrapped": text.replace(" ", "\n  "),
        }[formatting]

    # The first clause supplies a subject, never its negation or qualifier.
    for first, second in (
        ("is not a filesystem sandbox", "controls all agent actions"),
        ("controls mediated actions", "protects the entire repository"),
        ("controls all actions that pass through its wrapped tool boundary", "is a filesystem sandbox"),
    ):
        with pytest.raises(AssertionError, match="prohibited"):
            validate_claims(render(subject + " " + first + separator + "it " + second + "."), "local limits")
    for claim in COORDINATED_ACCEPT_CLAIMS[2:]:
        claim = claim.replace("Guard", subject).replace(", and ", separator)
        validate_claims(render(claim), "local accurate predicate")


@pytest.mark.parametrize("separator", [", but ", ", and ", "; ", " \u2014 "])
@pytest.mark.parametrize("other", ["the sandbox", "Acme", "another tool", "the operator"])
def test_different_subject_ends_guard_carry(separator, other):
    text = "Guard evaluates mediated actions" + separator + other + " handles isolation" + separator + "it protects the entire repository."
    validate_claims(text, "different subject")
    # A fresh explicit Guard subject starts a fresh carry, even after a reset.
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(text + " Guard records decisions" + separator + "it controls all agent actions.", "fresh Guard subject")


@pytest.mark.parametrize("boundary", [". ", "! ", "? ", ".\n\n", "\n\n", "\n- ", "\n## ", " | "])
def test_guard_pronoun_is_not_inferred_across_sentence_or_structural_boundaries(boundary):
    # Out-of-scope unbound pronouns are deliberately not resolved by this
    # closed documentation heuristic. This is not an English truth validator.
    validate_claims("Guard evaluates mediated actions" + boundary + "It protects the entire repository.", "no cross-boundary inference")


def test_carry_is_not_activated_by_an_object_named_guard():
    validate_claims("The sandbox contains Guard, and it protects the entire repository.", "Guard object")


@pytest.mark.parametrize("claim", ACCEPT_CLAIMS)
def test_required_accurate_claims_pass(claim):
    validate_claims(claim, "required ACCEPT example")


@pytest.mark.parametrize("claim", REJECT_CLAIMS)
def test_required_overclaims_fail(claim):
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(claim, "required REJECT example")


@pytest.mark.parametrize("claim", (
    "Guard controls all mediated actions.",
    "Guard controls all actions that pass through the wrapped boundary.",
    "Guard controls all actions on the wrapped callable path.",
    "Must not claim that Guard is a filesystem sandbox.",
    "Never claim: Guard provides tamper-resistant mediation.",
    "A connected runtime does not establish that the repository is globally protected.",
    "Guard does not guarantee that bypass is impossible.",
    'Historical wording (no longer accurate): "Guard is a filesystem sandbox."',
    'Previously, the README claimed "Guard controls all agent actions."',
))
def test_known_scoped_negated_and_historical_forms_pass(claim):
    validate_claims(claim, "accurate scope or attributed historical wording")


@pytest.mark.parametrize("claim", REJECT_CLAIMS)
@pytest.mark.parametrize("warning", ["Do not claim that ", "Must not claim that ", "Never claim: "])
def test_explicit_warning_applies_to_the_known_assertion_only(claim, warning):
    validate_claims(warning + claim, "explicit warning")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(warning + claim + " " + claim, "warning followed by assertion")


def test_historical_quote_does_not_exempt_current_claim():
    history = 'Historical wording (no longer accurate): "Guard is a filesystem sandbox."'
    validate_claims(history, "historical quotation")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(history + " Guard is a filesystem sandbox.", "history followed by current claim")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims('"Guard is a filesystem sandbox."', "unattributed quoted claim")


@pytest.mark.parametrize("document", PACKAGED_DOCS)
@pytest.mark.parametrize("claim", REJECT_CLAIMS)
def test_safe_document_does_not_exempt_appended_contradiction(document, claim):
    text = (ROOT / document).read_text(encoding="utf-8")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_mediation_document(text + "\n\n" + claim, document)


@pytest.mark.parametrize("document", PACKAGED_DOCS)
def test_valid_document_with_scoped_and_negated_warnings_passes(document):
    text = (ROOT / document).read_text(encoding="utf-8")
    validate_mediation_document(text + "\n\n" + "\n".join(ACCEPT_CLAIMS), document)


@pytest.mark.parametrize("separator", [". ", "; ", ", but ", ", and ", "\n\n", "\n- ", "\n## "])
def test_negation_does_not_exempt_an_independent_assertion(separator):
    text = "Do not claim that Guard is a filesystem sandbox" + separator + "Guard controls all agent actions."
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(text, "independent assertions")


def test_later_qualifier_does_not_excuse_earlier_global_claim():
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(REJECT_CLAIMS[0] + " " + ACCEPT_CLAIMS[0], "global then scoped")
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(ACCEPT_CLAIMS[0] + " But " + REJECT_CLAIMS[0], "scoped then global")


@pytest.mark.parametrize("claim", REJECT_CLAIMS)
@pytest.mark.parametrize("formatting", ["emphasis", "inline-code", "wrapped", "heading", "list", "blockquote", "links", "normalized", "underscore"])
def test_markdown_formatting_does_not_hide_affirmative_claim(claim, formatting):
    # A blockquote or inline quote alone is not a historical/disclaimed assertion.
    formats = {
        "emphasis": "**" + claim + "**", "inline-code": "`" + claim + "`",
        "wrapped": claim.replace(" ", "\n"), "heading": "### " + claim,
        "list": "1. " + claim, "blockquote": "> " + claim,
        "links": "[" + claim + "](https://example.com)",
        "normalized": "__" + claim.upper().replace(" ", "\u00a0") + "__",
        "underscore": "_" + claim.replace(" ", "\n") + "_",
    }
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(formats[formatting], "formatted assertion")


@pytest.mark.parametrize("claim", ACCEPT_CLAIMS)
@pytest.mark.parametrize("marker", ["**", "_", "__", "`"])
def test_formatting_preserves_relevant_qualifier_and_negation(claim, marker):
    validate_claims("- " + marker + claim.replace(" ", "\n  ") + marker, "wrapped scoped list item")


@pytest.mark.parametrize("document", PACKAGED_DOCS)
def test_installed_documentation_checks_use_the_same_claim_contract(tmp_path, document):
    for name in PACKAGED_DOCS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / name).read_text(encoding="utf-8")
        path.write_text(text + "\n\n" + "\n".join(ACCEPT_CLAIMS), encoding="utf-8")
    # This is the exact independent-interpreter check used by clean installation.
    exec(package_acceptance.DOCUMENTATION_VALIDATION_SCRIPT, {"documentation": tmp_path})
    with (tmp_path / document).open("a", encoding="utf-8") as output:
        output.write("\n\n" + REJECT_CLAIMS[1])
    with pytest.raises(AssertionError, match="prohibited"):
        exec(package_acceptance.DOCUMENTATION_VALIDATION_SCRIPT, {"documentation": tmp_path})


def test_customer_documents_retain_mediation_contract():
    for name in PACKAGED_DOCS:
        validate_mediation_document((ROOT / name).read_text(encoding="utf-8"), name)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for name in filter(None, tracked):
        if name.endswith(".md"):
            validate_claims((ROOT / name).read_text(encoding="utf-8"), name)


def test_canonical_quickstart_names_actual_callback_and_mutation():
    path = ROOT / "waveframe_guard/quickstarts/external_agent.py"
    module = ast.parse(path.read_text(encoding="utf-8"))
    documentation = normalized(ast.get_docstring(module))
    assert MEDIATION_STATEMENT in documentation
    for phrase in ("run_quickstart wraps allocate_budget with @guard.tool",
                   "immediately before invoking allocate_budget", "mutations.append(mutation)",
                   "not the entire machine or repository globally", "Threat model and operator verification"):
        assert phrase in documentation
    run = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "run_quickstart")
    callback = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "allocate_budget")
    assert any(ast.unparse(d.func) == "guard.tool" for d in callback.decorator_list if isinstance(d, ast.Call))
    assert any(isinstance(n, ast.Call) and ast.unparse(n.func) == "mutations.append" for n in ast.walk(callback))
    readme = normalized((ROOT / "README.md").read_text(encoding="utf-8"))
    assert "your_existing_allocate_budget" in readme and "guarded_allocate" in readme
    assert "immediately before invoking" in readme
    entrypoint = ast.parse((ROOT / "examples/external_agent_quickstart.py").read_text(encoding="utf-8"))
    assert MEDIATION_STATEMENT in normalized(ast.get_docstring(entrypoint))


@pytest.mark.parametrize("claim", [
    "Guard controls all agent actions.", "The repository is globally protected.",
    "The host is fully controlled.", "Bypass is impossible.",
    "Guard is a filesystem sandbox.", "Guard is tamper-resistant.",
    "Guard provides always-invoked mediation.", "Guard guarantees tamper-resistant mediation.",
    "Decision evidence proves no alternate path was used.", "Replay reproduces the physical mutation.",
    "Detection after a callback rolls back already-written bytes.",
    "Only the guarded callable can reach publish_release.",
])
def test_prohibited_claims_are_rejected(claim):
    with pytest.raises(AssertionError, match="prohibited"):
        validate_claims(claim, "customer copy")


@pytest.mark.parametrize("name", ["README.md", "docs/getting-started/README.md", GUIDE])
def test_alternate_path_statement_cannot_be_removed(name):
    text = normalized((ROOT / name).read_text(encoding="utf-8"))
    with pytest.raises(AssertionError, match="mediated-action"):
        validate_mediation_document(text.replace(MEDIATION_STATEMENT, ""), name)


@pytest.mark.parametrize("topic", THREAT_CLASSES)
def test_each_bypass_class_is_required(topic):
    text = (ROOT / GUIDE).read_text(encoding="utf-8")
    with pytest.raises(AssertionError, match="boundary guidance"):
        validate_mediation_document(text.replace(topic, ""), GUIDE)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("failure", ["missing", "weakened", "appended"])
@pytest.mark.parametrize("document", PACKAGED_DOCS)
def test_packaged_boundary_documentation_cannot_disappear(tmp_path, kind, failure, document):
    files, _ = archive_files(kind)
    prefix = "waveframe_guard-0.17.0.data/data/share/doc/waveframe-guard/" if kind == "wheel" else ""
    if failure == "missing":
        del files[prefix + document]
    elif failure == "weakened":
        files[prefix + document] = b"Guard controls all agent actions."
    else:
        files[prefix + document] += b"\n\nGuard protects the entire repository, including direct filesystem writes."
    if kind == "wheel":
        path = tmp_path / "test.whl"
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        inspect = package_acceptance._inspect_wheel
    else:
        path = tmp_path / "test.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo("waveframe_guard-0.17.0/" + name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        inspect = package_acceptance._inspect_sdist
    with pytest.raises(AssertionError, match="documentation|prohibited|required public files"):
        inspect(path, "0.17.0")
