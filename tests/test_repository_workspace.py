from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from waveframe_guard import Guard, RepositoryBoundaryError, RepositoryTarget
from guard.sdk import GuardExecutionBlocked


def authority(*, allow=False):
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "arbitrary-id", "contract_version": "1.0.0",
        "contract_hash": "sha256:test", "authority_requirements": {},
        "approval_requirements": {}, "artifact_requirements": {},
        "stage_requirements": {}, "invariants": {},
        "target_requirements": {
            "allow": [{"match": "prefix", "value": "safe/"}] if allow else [],
            "deny": [{"match": "prefix", "value": "crypto/"}],
        },
    }


def request(path):
    return {"schema_version": "normalized_execution_request.v1", "request_id": "repo-1",
            "action": "modify", "target": path, "arguments": {}, "artifacts": []}


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "safe").mkdir()
    (root / "safe/file.txt").write_bytes(b"before")
    (root / "crypto").mkdir()
    (root / "crypto/key.txt").write_bytes(b"secret")
    return root


@pytest.fixture(params=[False, True], ids=["deny-only", "allow-list"])
def guard(repository, tmp_path, request):
    instance = Guard.local(repository_root=repository, workspace=tmp_path / "evidence",
                           contract=authority(allow=request.param))
    yield instance
    instance.close()


@pytest.mark.parametrize("path", [
    "", None, 3, b"safe/file.txt", Path("safe/file.txt"),
    "/safe/file.txt", "C:/safe/file.txt", "C:safe/file.txt", "C:\\safe\\file.txt",
    "//server/share/file", "\\\\server\\share\\file", "\\\\?\\C:\\safe\\file.txt",
    "\\\\.\\GLOBALROOT\\file", "\\safe\\file.txt", "safe\\file.txt",
    "safe/../crypto/key.txt", "./safe/file.txt", "safe/./file.txt", "../file.txt",
    "safe//file.txt", "safe/", "safe///../crypto/key.txt", "safe/./../file.txt",
    "safe/fi\x00le.txt", "safe/file.txt:stream", "safe/file.txt.", "safe/file.txt ",
    "safe/NUL", "safe/CON.txt", "safe/COM1", "safe/fi\nle", "safe/\ud800", "safe/é",
])
def test_noncanonical_paths_precede_authority_and_never_mutate(guard, repository, path, monkeypatch):
    boundary = guard.boundary_for()
    calls = []
    monkeypatch.setattr(boundary, "_evaluate", lambda *a, **k: pytest.fail("authority evaluated"))
    with pytest.raises(RepositoryBoundaryError):
        boundary.execute_repository(lambda target: calls.append(target), execution_request=request(path))
    assert calls == []
    assert (repository / "safe/file.txt").read_bytes() == b"before"
    assert guard.store.history() == []


def test_canonical_allow_deny_and_nonexistent_parent_chain(guard):
    boundary = guard.boundary_for()
    assert boundary.evaluate(request("safe/file.txt"), save=False)["status"] == "admissible"
    assert boundary.evaluate(request("safe/new/child.txt"), save=False)["status"] == "admissible"
    assert boundary.evaluate(request("crypto/key.txt"), save=False)["status"] == "blocked"
    calls = []
    blocked = boundary.execute_repository(lambda target: calls.append(target),
                                         execution_request=request("crypto/key.txt"), raise_on_block=False)
    assert not blocked["executed"] and not calls


def test_missing_workspace_and_generic_callback_fail_closed(tmp_path, guard):
    unbound = Guard.local(workspace=tmp_path / "unbound", contract=authority())
    with pytest.raises(RepositoryBoundaryError, match="repository_root"):
        unbound.boundary_for().evaluate(request("safe/file.txt"), save=False)
    calls = []
    with pytest.raises(RepositoryBoundaryError, match="generic"):
        guard.boundary_for().execute(lambda: calls.append(True), execution_request=request("safe/file.txt"))
    assert calls == []


def test_literal_targets_are_never_reinterpreted(tmp_path):
    literal = Guard.local(workspace=tmp_path, contract=authority(), target_domain="literal")
    value = "safe/../crypto/key.txt"
    assert literal.boundary_for().execute(lambda: value, execution_request=request(value))["value"] == value


def test_case_behavior_matches_filesystem(guard, repository):
    case_sensitive = not (repository / "SAFE").exists()
    if case_sensitive:
        (repository / "CRYPTO").mkdir()
        (repository / "CRYPTO/key.txt").write_bytes(b"distinct")
        expected = "blocked" if guard.resolve_authority("arbitrary-id@1.0.0")["target_requirements"]["allow"] else "admissible"
        assert guard.boundary_for().evaluate(request("CRYPTO/key.txt"), save=False)["status"] == expected
    else:
        for path in ("CRYPTO/key.txt", "crypto/KEY.txt", "SAFE/file.txt", "safe/FILE.txt"):
            with pytest.raises(RepositoryBoundaryError):
                guard.boundary_for().evaluate(request(path), save=False)


def test_case_alias_of_deny_with_different_disk_spelling(repository, tmp_path):
    if not (repository / "SAFE").exists():
        pytest.skip("case-insensitive filesystem required")
    (repository / "crypto").rename(repository / "intermediate")
    (repository / "intermediate").rename(repository / "CRYPTO")
    instance = Guard.local(repository_root=repository, workspace=tmp_path / "evidence", contract=authority())
    try:
        with pytest.raises(RepositoryBoundaryError, match="denied path"):
            instance.boundary_for().evaluate(request("CRYPTO/key.txt"), save=False)
    finally:
        instance.close()


@pytest.mark.parametrize("missing", [False, True])
def test_symlink_parent_escape(guard, repository, tmp_path, missing):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_bytes(b"outside")
    link = repository / "safe/link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink privilege unavailable; Windows junction tested separately")
    calls = []
    with pytest.raises(RepositoryBoundaryError):
        guard.boundary_for().execute_repository(lambda target: calls.append(target),
            execution_request=request("safe/link/new.txt" if missing else "safe/link/file.txt"))
    assert not calls
    assert (outside / "file.txt").read_bytes() == b"outside"
    assert not (outside / "new.txt").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse test")
def test_junction_parent_escape(guard, repository, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = repository / "safe/junction"
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(RepositoryBoundaryError):
            guard.boundary_for().evaluate(request("safe/junction/new.txt"), save=False)
    finally:
        link.rmdir()  # Remove only the junction, never its external target.
    assert outside.is_dir()


def test_hardlink_alias_rejected(guard, repository):
    os.link(repository / "crypto/key.txt", repository / "safe/alias.txt")
    with pytest.raises(RepositoryBoundaryError):
        guard.boundary_for().evaluate(request("safe/alias.txt"), save=False)


def test_workspace_root_substitution(guard, repository):
    moved = repository.with_name("moved")
    if os.name == "nt":
        with pytest.raises(OSError):
            repository.rename(moved)
    else:
        repository.rename(moved)
        repository.mkdir()
        with pytest.raises(RepositoryBoundaryError, match="substituted"):
            guard.boundary_for().evaluate(request("safe/file.txt"), save=False)


def test_nonexistent_mutation_is_explicitly_unsupported(guard, repository):
    calls = []
    with pytest.raises(RepositoryBoundaryError, match="unsupported"):
        guard.boundary_for().execute_repository(lambda target: calls.append(target),
                                               execution_request=request("safe/new.txt"))
    assert not calls and not (repository / "safe/new.txt").exists()


def test_adapter_uses_bound_target_once_and_expires_it(guard, repository):
    calls = []
    @guard.repository_tool(target="path", return_result=True)
    def write(path, content):
        assert isinstance(path, RepositoryTarget)
        with pytest.raises(TypeError):
            Path(path)  # The adapter cannot accidentally reopen a string path.
        calls.append(path)
        return path.write_bytes(content)

    if os.name != "nt":
        with pytest.raises(RepositoryBoundaryError, match="unsupported on POSIX"):
            write("safe/file.txt", b"after")
        assert not calls and (repository / "safe/file.txt").read_bytes() == b"before"
        return
    result = write("safe/file.txt", b"after")
    assert result["executed"] and result["value"] == 5 and len(calls) == 1
    assert (repository / "safe/file.txt").read_bytes() == b"after"
    with pytest.raises(RepositoryBoundaryError, match="not active"):
        calls[0].write_bytes(b"late")
    record, = guard.store.history()
    assert record["inputs"]["execution_request"]["target"] == "safe/file.txt"
    assert str(repository) not in json.dumps(record)
    assert "after" not in json.dumps(record)


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace locks")
def test_authorization_and_callback_cannot_replace_target(guard, repository, monkeypatch):
    boundary = guard.boundary_for()
    original = boundary._evaluate
    attempts = []

    def attempt_substitution(*args, **kwargs):
        result = original(*args, **kwargs)
        with pytest.raises(OSError):
            (repository / "safe/file.txt").rename(repository / "safe/other.txt")
        with pytest.raises(OSError):
            (repository / "safe").rename(repository / "moved-safe")
        attempts.append(True)
        return result

    monkeypatch.setattr(boundary, "_evaluate", attempt_substitution)
    original_request = request("safe/file.txt")
    def mutate(target):
        original_request["target"] = "crypto/key.txt"
        return target.write_bytes(b"bound")
    result = boundary.execute_repository(mutate, execution_request=original_request)
    assert result["executed"] and attempts
    assert (repository / "safe/file.txt").read_bytes() == b"bound"
    assert (repository / "crypto/key.txt").read_bytes() == b"secret"


def test_closed_workspace_fails_closed(guard):
    guard.close()
    with pytest.raises(RepositoryBoundaryError, match="closed"):
        guard.boundary_for().evaluate(request("safe/file.txt"), save=False)


@pytest.mark.skipif(os.name != "nt", reason="NTFS case-sensitive directory feature")
def test_windows_case_sensitive_workspace_where_supported(tmp_path):
    root = tmp_path / "case-sensitive"
    root.mkdir()
    enabled = subprocess.run(["fsutil", "file", "setCaseSensitiveInfo", str(root), "enable"], capture_output=True)
    if enabled.returncode:
        pytest.skip("Windows case-sensitive directory feature/privilege unavailable")
    (root / "crypto").mkdir()
    (root / "CRYPTO").mkdir()
    (root / "CRYPTO/key.txt").write_bytes(b"distinct")
    instance = Guard.local(repository_root=root, workspace=tmp_path / "evidence", contract=authority())
    try:
        assert instance.boundary_for().evaluate(request("CRYPTO/key.txt"), save=False)["status"] == "admissible"
        assert instance.boundary_for().evaluate(request("crypto/key.txt"), save=False)["status"] == "blocked"
    finally:
        instance.close()


def test_leaf_symlink_escape(guard, repository, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    try:
        (repository / "safe/link.txt").symlink_to(outside)
    except OSError:
        pytest.skip("file symlink privilege unavailable")
    with pytest.raises(RepositoryBoundaryError):
        guard.boundary_for().evaluate(request("safe/link.txt"), save=False)
    assert outside.read_bytes() == b"outside"


def test_repository_rules_cannot_introduce_unsupported_aliases(repository, tmp_path):
    contract = authority()
    contract["target_requirements"]["deny"] = [{"match": "prefix", "value": "K/"}]
    instance = Guard.local(repository_root=repository, workspace=tmp_path / "evidence", contract=contract)
    try:
        with pytest.raises(RepositoryBoundaryError):
            instance.boundary_for().evaluate(request("safe/file.txt"), save=False)
    finally:
        instance.close()
