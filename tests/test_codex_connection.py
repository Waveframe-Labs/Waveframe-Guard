"""Focused translation/evidence checks; real CLI/OS proof lives beside the example."""
import importlib.util
import json
from pathlib import Path

import pytest
from waveframe_guard.authority.exceptions import AuthorityVerificationError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codex_writer", ROOT / "examples/codex_connection/writer.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def writer(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "generated").mkdir()
    (repo / "README.md").write_bytes(b"before\n")
    value = MODULE.Writer(repo, tmp_path / "evidence", ROOT / "tests/fixtures/action_policy_release_v4/mixed")
    yield value, repo
    value.close()


def test_released_capabilities_and_saved_evidence(writer):
    instance, repo = writer
    for action, path in (("create", "generated/new.md"), ("modify", "README.md")):
        result = instance.write(dict(action=action, path=path, content="after\n"))
        assert result["outcome"] == "executed"
        assert (repo / path).read_bytes() == b"after\n"
        assert instance.guards[action].store.load_execution_attestation(result["run_id"]) == result["execution_attestation"]
    status = instance.status()
    assert status["policies"]["modify"]["authority"] == "repository-mixed@3.0.0"
    assert status["policies"]["create"]["actor_identity"]["role"] == "repository-maintainer"
    assert status["policies"]["modify"]["actor_identity"]["role"] == "security-reviewer"


def test_denial_and_collision_are_different_and_zero_write(writer):
    instance, repo = writer
    request = dict(action="create", path="generated/new.md", content="first")
    assert instance.write(request)["outcome"] == "executed"
    request["content"] = "replacement"
    collision = instance.write(request)
    assert collision["outcome"] == "failed"
    # Preserve the released SDK's conservative callback-failure semantics.
    assert collision["mutation_status"] == "unknown"
    assert collision["execution_attestation"]["repository_operation"]["created"] is False
    assert collision["execution_attestation"]["repository_operation"]["bytes_written"] == 0
    assert (repo / "generated/new.md").read_bytes() == b"first"
    for action, path in (("modify", "generated/new.md"), ("create", "README.md"), ("create", "blocked.md")):
        result = instance.write(dict(action=action, path=path, content="denied"))
        assert result["outcome"] == "blocked"
        assert result["mutation_status"] == "not_performed"
        assert result["execution_attestation"]["callback_invoked"] is False
    assert (repo / "README.md").read_bytes() == b"before\n"
    assert not (repo / "blocked.md").exists()


@pytest.mark.parametrize("change", [{"role": "admin"}, {"authority": "other@1"}, {"root": "C:/"},
                                     {"action": "delete"}, {"content": 1}, {"content": "x" * 65537}])
def test_request_cannot_select_trust_or_unreleased_operations(writer, change):
    instance, repo = writer
    result = instance.write({"action": "create", "path": "generated/new.md", "content": "x", **change})
    assert result["outcome"] == "invalid_request"
    assert not (repo / "generated/new.md").exists()


def test_unknown_failure_never_retries_or_claims_rollback(writer, monkeypatch):
    instance, repo = writer
    calls = []
    def uncertain(*args, **kwargs):
        calls.append(1)
        raise OSError("lost result")
    boundary = instance.guards["create"].boundary_for()
    monkeypatch.setattr(boundary, "execute_repository", uncertain)
    monkeypatch.setattr(instance.guards["create"], "boundary_for", lambda: boundary)
    result = instance.write(dict(action="create", path="generated/new.md", content="x"))
    assert calls == [1]
    assert result["mutation_status"] == "unknown"
    assert result["automatic_retry"] is False


def test_invalid_publication_cannot_report_connected(tmp_path):
    publication = tmp_path / "publication"
    publication.mkdir()
    fixture = ROOT / "tests/fixtures/action_policy_release_v4/mixed"
    for name in ("authority-bundle.json", "publication-receipt.json"):
        data = json.loads((fixture / name).read_text())
        if name == "authority-bundle.json":
            data["compiled_authority_contract"]["action_requirements"]["create"]["required_role"] = "attacker"
        (publication / name).write_text(json.dumps(data))
    with pytest.raises(AuthorityVerificationError):
        MODULE.Writer(tmp_path, tmp_path / "evidence", publication)
