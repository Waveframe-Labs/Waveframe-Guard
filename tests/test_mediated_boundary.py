"""Customer claims and installed documentation must describe actual mediation."""
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


@pytest.mark.parametrize("name", ["README.md", "docs/getting-started/README.md"])
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
@pytest.mark.parametrize("failure", ["missing", "weakened"])
@pytest.mark.parametrize("document", PACKAGED_DOCS)
def test_packaged_boundary_documentation_cannot_disappear(tmp_path, kind, failure, document):
    files, _ = archive_files(kind)
    prefix = "waveframe_guard-0.17.0.data/data/share/doc/waveframe-guard/" if kind == "wheel" else ""
    if failure == "missing":
        del files[prefix + document]
    else:
        files[prefix + document] = b"Guard controls all agent actions."
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
