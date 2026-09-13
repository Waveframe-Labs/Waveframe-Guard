"""Reject archive, installed-resource and origin substitutions at the gate."""
import hashlib
import json
from pathlib import Path
import sys
import types
import zipfile

import pytest

from tools import package_provenance as provenance


@pytest.fixture
def installation(tmp_path, monkeypatch):
    site = tmp_path / "site"
    wheel = tmp_path / "candidate.whl"
    members = {"compiler/__init__.py": b"# compiler\n",
               "compiler/schemas/policy.json": b'{"type":"object"}'}
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
            target = site / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    digest = provenance.sha256(wheel)
    direct = {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": digest}}}
    dist = types.SimpleNamespace(version="0.5.0", locate_file=lambda entry: site / entry,
                                 read_text=lambda name: json.dumps(direct) if direct else None)
    compiler = types.ModuleType("compiler")
    compiler.__file__ = str(site / "compiler/__init__.py")
    compiler.compile_action_policy = lambda: None
    monkeypatch.setitem(sys.modules, "compiler", compiler)
    # The real suite may already have imported Compiler submodules.
    for name in list(sys.modules):
        if name.startswith("compiler."):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(provenance.metadata, "distribution", lambda name: dist)
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    return site, wheel, digest, direct


def check(installation, report=None):
    _, wheel, digest, _ = installation
    return provenance.installed_archive("cricore-contract-compiler", "0.5.0", ["compiler"],
                                        {"wheel": str(wheel), "sha256": digest}, report)


@pytest.mark.parametrize("form", ["hashes", "hash", "both", "report-only"])
def test_verified_archive_origin_forms(installation, tmp_path, form):
    _, _, digest, direct = installation
    report = None
    if form in ("hash", "both"):
        direct["archive_info"]["hash"] = "sha256=" + digest
        if form == "hash":
            direct["archive_info"].pop("hashes")
    if form == "report-only":
        report = tmp_path / "install.json"
        report.write_text(json.dumps({"install": [{"metadata": {
            "name": "cricore-contract-compiler", "version": "0.5.0"},
            "download_info": direct}]}))
        direct.clear()
    result = check(installation, report)
    assert "compiler/schemas/policy.json" in result["installed_sha256"]


@pytest.mark.parametrize("tamper", ["archive", "module", "resource", "extra", "import",
                                     "url", "digest", "contradictory", "report"])
def test_provenance_rejects_substitution(installation, tmp_path, tamper):
    site, wheel, digest, direct = installation
    report = None
    if tamper == "archive":
        wheel.write_bytes(wheel.read_bytes() + b"changed")
    elif tamper in ("module", "resource", "extra"):
        relative = {"module": "__init__.py", "resource": "schemas/policy.json", "extra": "unrecorded.py"}[tamper]
        (site / "compiler" / relative).write_bytes(b"changed")
    elif tamper == "import":
        sys.modules["compiler"].__file__ = str(tmp_path / "contamination/compiler/__init__.py")
    elif tamper == "url":
        direct["url"] = (tmp_path / "arbitrary.whl").as_uri()
    elif tamper == "digest":
        direct["archive_info"]["hashes"]["sha256"] = "0" * 64
    elif tamper == "contradictory":
        direct["archive_info"]["hash"] = "sha256=" + "0" * 64
    elif tamper == "report":
        report = tmp_path / "install.json"
        report.write_text(json.dumps({"install": [{"metadata": {
            "name": "cricore-contract-compiler", "version": "0.5.0"},
            "download_info": {"url": wheel.as_uri(), "archive_info": {
                "hashes": {"sha256": "0" * 64}}}}]}))
    with pytest.raises(AssertionError):
        check(installation, report)


def test_archive_requires_explicit_source_binding(installation, tmp_path, monkeypatch):
    _, wheel, digest, direct = installation
    monkeypatch.delenv("LEDGER_ARCHIVE_EXPECTATIONS", raising=False)
    with pytest.raises(AssertionError):
        provenance.compiler_provenance()
    expectation = tmp_path / "expected.json"
    expectation.write_text(json.dumps({"distributions": {"cricore-contract-compiler": {
        "wheel": str(wheel), "sha256": digest, "source_commit": "0" * 40,
        "build_origin": {"url": provenance.COMPILER_URL, "vcs_info": {
            "vcs": "git", "commit_id": "0" * 40, "requested_revision": "0" * 40}}}}}))
    with pytest.raises(AssertionError):
        provenance.compiler_provenance(expectation)


def test_exact_git_provenance_rejects_wrong_commit():
    with pytest.raises(AssertionError):
        provenance.verify_git({"url": provenance.COMPILER_URL, "vcs_info": {
            "vcs": "git", "commit_id": "0" * 40, "requested_revision": provenance.CANDIDATE}})


def test_relocated_documentation_bytes_are_required(installation, tmp_path):
    site, wheel, _, direct = installation
    member = "candidate-0.5.0.data/data/share/doc/candidate/README.md"
    installed = tmp_path / "share/doc/candidate/README.md"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"retained documentation")
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(member, installed.read_bytes())
    digest = provenance.sha256(wheel)
    direct["archive_info"]["hashes"]["sha256"] = digest
    updated = site, wheel, digest, direct
    assert member in check(updated)["installed_sha256"]
    installed.write_bytes(b"tampered documentation")
    with pytest.raises(AssertionError, match="installed bytes differ"):
        check(updated)
