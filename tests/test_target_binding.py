import copy
import json
from dataclasses import FrozenInstanceError, replace, dataclass

import pytest

from guard.sdk import Guard, RepositoryBoundaryError
from guard.runtime.identity import stable_hash
from guard.sdk.local_persistence import _artifact_replay_failure_reasons
from test_repository_workspace import authority, request, repository


@pytest.fixture
def bound(repository, tmp_path):
    instance = Guard.local(repository_root=repository, workspace=tmp_path / "evidence", contract=authority(),
                           evaluation_time_source=lambda: "2026-09-07T00:00:00Z")
    yield instance
    instance.close()


def test_binding_is_frozen_and_per_workspace_activation(bound, repository, tmp_path):
    boundary = bound.boundary_for()
    binding = boundary.target_binding
    with pytest.raises(FrozenInstanceError):
        binding.target_domain = "literal"
    assert binding == bound.boundary_for().target_binding
    other = Guard.local(repository_root=repository, workspace=tmp_path / "other", contract=authority())
    try:
        assert binding.workspace_binding_id != other.boundary_for().target_binding.workspace_binding_id
    finally:
        other.close()
    assert str(repository) not in json.dumps(binding.evidence())


@pytest.mark.parametrize("field", ["target_binding", "target_binding_hash", "target_domain", "repository_root",
                                   "workspace_binding_id", "adapter_version", "assurance_class"])
@pytest.mark.parametrize("nested", [False, True])
def test_request_cannot_supply_binding(bound, field, nested, monkeypatch):
    payload = request("safe/file.txt")
    payload.update({"arguments": {field: "literal"}} if nested else {field: "literal"})
    monkeypatch.setattr("guard.sdk.execution.evaluate_runtime", lambda **k: pytest.fail("authority evaluated"))
    with pytest.raises(RepositoryBoundaryError, match="caller-supplied target binding"):
        bound.boundary_for().evaluate(payload)
    assert bound.store.history() == []


def test_context_cannot_supply_binding(bound):
    with pytest.raises(RepositoryBoundaryError, match="caller-supplied target binding"):
        bound.boundary_for().evaluate(request("safe/file.txt"), execution_context={"target_binding": {}})


@pytest.mark.parametrize("substitution", ["domain", "workspace", "binding", "authority"])
def test_boundary_cannot_be_reinterpreted(bound, substitution):
    boundary = bound.boundary_for()
    if substitution == "domain":
        boundary._target_domain = "literal"
    elif substitution == "workspace":
        boundary._repository_workspace = None
    elif substitution == "binding":
        boundary._target_binding = replace(boundary.target_binding, target_domain="literal")
    else:
        boundary.compiled_authority.pop("target_requirements")
    with pytest.raises(RepositoryBoundaryError, match="changed|substituted"):
        boundary.evaluate(request("safe/file.txt"))


def test_guard_configuration_cannot_silently_change_domain(bound):
    bound._target_domain = "literal"
    with pytest.raises(RepositoryBoundaryError, match="configuration changed"):
        bound.boundary_for()


def test_v1_reuse_has_distinct_domain_proof_and_receipt_identity(bound, tmp_path):
    literal = Guard.local(workspace=tmp_path / "literal", contract=authority(), target_domain="literal",
                          evaluation_time_source=bound.evaluation_time_source)
    repo_result = bound.boundary_for().evaluate(request("safe/file.txt"))
    literal_result = literal.boundary_for().evaluate(request("safe/file.txt"))
    assert repo_result["status"] == literal_result["status"] == "admissible"
    assert repo_result["target_binding"]["target_domain"] == "repository_path"
    assert literal_result["target_binding"]["target_domain"] == "literal"
    assert literal_result["target_binding"]["workspace_binding_id"] is None
    assert repo_result["target_binding_hash"] != literal_result["target_binding_hash"]
    assert repo_result["run_id"] != literal_result["run_id"]
    for runtime, result in [(bound, repo_result), (literal, literal_result)]:
        record = runtime.store.load_run(result["run_id"])
        digest = result["target_binding_hash"]
        assert digest == stable_hash(record["inputs"]["target_binding"])
        assert record["receipt"]["input_hashes"]["target_binding_hash"] == digest
        assert "target_binding_hash" in record["artifact_manifest"]["lineage_continuity_fields"]
        assert record["inputs"]["runtime_evidence"]["execution_context"]["target_binding"] == result["target_binding"]
    repo_result["target_binding"]["target_domain"] = "literal"
    assert bound.boundary_for().evaluate(request("safe/file.txt"), save=False)["target_binding"]["target_domain"] == "repository_path"


@pytest.mark.parametrize("location", ["inputs", "evaluation", "context"])
def test_binding_substitution_breaks_replay_integrity(bound, location):
    result = bound.boundary_for().evaluate(request("safe/file.txt"))
    record = copy.deepcopy(bound.store.load_run(result["run_id"]))
    if location == "context":
        record["inputs"]["runtime_evidence"]["execution_context"]["target_binding"]["workspace_binding_id"] = "other"
    else:
        record[location]["target_binding"]["target_domain"] = "literal"
    assert any("binding" in item["field"] for item in _artifact_replay_failure_reasons(record))


def test_replay_reproduces_recorded_logic_without_workspace(bound, repository):
    result = bound.boundary_for().evaluate(request("safe/file.txt"))
    bound.close()
    repository.rename(repository.with_name("historical-workspace-gone"))
    replay = bound.store.replay(result["run_id"])
    assert replay["matches"]
    assert replay["replay_scope"] == "logical_decision_only"
    assert replay["filesystem_state_recreated"] is False
    assert replay["binding_assurance"] == "recorded_not_revalidated"
    assert replay["target_binding_hash"] == result["target_binding_hash"]
    assert not repository.exists()


def test_cloud_preservation_proof_has_binding_without_absolute_root(bound, repository):
    @dataclass
    class Result:
        ok: bool = False
    class Capture:
        def preserve(self, package):
            self.package = package
            return Result()
    capture = Capture()
    bound.cloud_preservation_client = capture
    result = bound.boundary_for().evaluate(request("safe/file.txt"))
    package = capture.package
    assert str(repository) not in json.dumps(package)
    assert repository.as_posix() not in json.dumps(package)
    saved = package["saved_evaluation"]
    assert saved["inputs"]["target_binding"] == result["target_binding"]
    assert package["receipt"]["input_hashes"]["target_binding_hash"] == result["target_binding_hash"]
    assert package["replay_result"]["filesystem_state_recreated"] is False
