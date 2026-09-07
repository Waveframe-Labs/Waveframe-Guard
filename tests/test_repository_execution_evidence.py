"""Privacy admission and authority-version-neutral execution proof regressions."""
import copy
import json
import os
import traceback
from dataclasses import dataclass

import pytest

from guard.runtime.identity import stable_hash
from guard.sdk import Guard, GuardExecutionBlocked, RepositoryBoundaryError
from guard.sdk.local_persistence import validate_execution_attestation, GuardArtifactError
from guard.sdk.repository_evidence import validate_repository_attestation
from test_repository_workspace import authority, request


@pytest.fixture(scope="module", params=[1, 2, 3], ids=["v1", "v2", "v3"])
def publication_basis(request):
    if request.param == 1:
        return 1, None
    if request.param == 2:
        from test_ledger_v2_authority_runtime import _publication
        return 2, _publication()
    from test_ledger_v3_authority_runtime import _publication, _has_ledger_v3
    if not _has_ledger_v3():
        pytest.skip("Ledger 0.8 v3 APIs unavailable on minimum dependency matrix")
    return 3, _publication("multi")


@pytest.fixture
def runtime(publication_basis, tmp_path):
    version, publication = publication_basis
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_bytes(b"before")
    options = {}
    if version == 1:
        contract = authority()
        contract["target_requirements"]["deny"].append({"match": "prefix", "value": "deployment/"})
        options["contract"] = contract
    else:
        if version == 2:
            from test_ledger_v2_authority_runtime import _write_publication as write
        else:
            from test_ledger_v3_authority_runtime import _write_artifacts as write
        options.update(authority="repository-authority@1.0.0",
                       authority_resolver=write(tmp_path / "publication", publication))
    instance = Guard.local(repository_root=root, workspace=tmp_path / "evidence",
                           actor_identity={"id": "agent", "type": "agent", "role": "repository-maintainer"},
                           **options)
    yield instance, root, version
    instance.close()


@dataclass
class PreservationResult:
    ok: bool = False


class Capture:
    def __init__(self):
        self.packages = []

    def preserve(self, package):
        self.packages.append(copy.deepcopy(package))
        return PreservationResult()


@pytest.mark.parametrize("method", ["evaluate", "execute_repository"])
@pytest.mark.parametrize("injection", ["text", "bytes", "workspace", "nested", "artifact_path",
                                       "artifact_content", "extra", "binding", "provider",
                                       "action_path", "id_path", "bad_schema", "missing"])
def test_closed_request_rejects_before_every_side_effect(runtime, monkeypatch, method, injection):
    guard, root, _ = runtime
    secret = "PRIVATE-CONTENT-DO-NOT-PRESERVE"
    payload = request("README.md")
    if injection in {"text", "bytes", "workspace", "nested"}:
        value = {"text": secret, "bytes": secret.encode(), "workspace": str(root),
                 "nested": {"provider": {"target_binding": {"repository_root": str(root), "content": secret}}}}[injection]
        payload["arguments"] = {"content" if injection != "workspace" else "workspace": value}
    elif injection.startswith("artifact"):
        payload["artifacts"] = [{"path": str(root)} if injection == "artifact_path" else {"content": secret}]
    elif injection in {"extra", "binding", "provider"}:
        payload[{"extra": "metadata", "binding": "target_binding", "provider": "runtime_facts"}[injection]] = {
            "workspace": str(root), "content": secret}
    elif injection == "action_path":
        payload["action"] = str(root)
    elif injection == "id_path":
        payload["request_id"] = str(root)
    elif injection == "bad_schema":
        payload["schema_version"] = {"root": str(root), "content": secret}
    else:
        payload.pop("artifacts")
    capture = Capture()
    guard.cloud_preservation_client = capture
    boundary = guard.boundary_for()
    calls = []
    monkeypatch.setattr("guard.sdk.execution.evaluate_runtime", lambda **kw: pytest.fail("authority evaluated"))
    monkeypatch.setattr(guard._repository_workspace, "bind", lambda *a, **kw: pytest.fail("filesystem handle acquired"))
    with pytest.raises(RepositoryBoundaryError) as error:
        if method == "evaluate":
            boundary.evaluate(payload, save=True)
        else:
            boundary.execute_repository(lambda target: calls.append(target), execution_request=payload, save=True)
    diagnostic = "".join(traceback.format_exception(error.value)) + json.dumps(vars(error.value), default=str)
    assert secret not in diagnostic and str(root) not in diagnostic and root.as_posix() not in diagnostic
    assert calls == [] and capture.packages == [] and guard.store.history() == []
    assert not list(guard.store.root.rglob("*"))
    assert (root / "README.md").read_bytes() == b"before"


@pytest.mark.parametrize("mode", ["success", "blocked", "unsupported", "callback_error", "post_callback", "post_callback_native"])
def test_repository_execution_states_persist_and_reload(runtime, mode):
    guard, root, version = runtime
    if mode == "post_callback_native" and os.name == "nt":
        pytest.skip("Windows namespace locks prevent this replacement; fault injection runs on both OSes")
    capture = Capture()
    guard.cloud_preservation_client = capture
    calls = []
    held = []
    secret = b"already-written"
    path = "deployment/production.yml" if mode == "blocked" else "README.md"
    if mode == "unsupported":
        (root / path).unlink()

    def callback(target):
        held.append(target)
        calls.append(target.write_bytes(secret))
        if mode == "callback_error":
            raise RepositoryBoundaryError("callback failed")
        if mode == "post_callback":
            # Exact review fault injection: real write, then post-callback validation fails.
            def replaced():
                raise RepositoryBoundaryError("repository target or ancestor was substituted")
            target._validate = replaced
        elif mode == "post_callback_native":
            (root / path).rename(root / "moved.md")
        return len(secret)

    if mode == "success":
        result = guard.boundary_for().execute_repository(callback, execution_request=request(path))
        evaluation = result["evaluation"]
    else:
        with pytest.raises((RepositoryBoundaryError, GuardExecutionBlocked)) as error:
            guard.boundary_for().execute_repository(callback, execution_request=request(path))
        evaluation = error.value.evaluation
    proof = evaluation["execution_attestation"]
    assert proof["schema_version"] == "guard_execution_attestation.v2"
    expected = {
        "success": (True, True, "succeeded", "executed", True),
        "blocked": (False, False, "not_run", "not_performed", False),
        "unsupported": (False, False, "not_run", "not_performed", False),
        "callback_error": (True, False, "failed", "unknown", None),
        "post_callback": (True, True, "failed", "unknown", None),
        "post_callback_native": (True, True, "failed", "unknown", None),
    }[mode]
    assert tuple(proof[k] for k in ("callback_invoked", "callback_completed", "execution_status", "mutation_status", "mutation_executed")) == expected
    assert len(calls) == (0 if mode in {"blocked", "unsupported"} else 1)
    if calls:
        assert (root / ("moved.md" if mode == "post_callback_native" else path)).read_bytes() == secret
        with pytest.raises(RepositoryBoundaryError, match="not active"):
            held[0].write_bytes(b"late")
    assert proof["authority_basis"]["kind"] == ("compiled_contract" if version == 1 else "published_authority")
    if version == 1:
        assert "authority_evidence_hash" not in proof["authority_basis"]
        assert "runtime_facts_hash" not in proof["authority_basis"]
    assert guard.store.load_execution_attestation(proof["run_id"]) == proof
    assert validate_execution_attestation(proof) == proof
    record = guard.store.load_run(proof["run_id"])
    assert proof["guard_receipt_hash"] == record["receipt"]["receipt_hash"]
    assert proof["execution_request_hash"] == record["receipt"]["input_hashes"]["execution_request_hash"]
    assert validate_repository_attestation(proof, record=record) == proof
    assert len(capture.packages) == 1
    saved = capture.packages[0]["saved_evaluation"]["evaluation"]
    assert saved["cloud_preservation_scope"] == "decision_only_not_final_execution"
    assert "execution_attestation" not in saved  # Final local evidence is not claimed uploaded.
    for artifact in [evaluation, proof, record, capture.packages]:
        serialized = json.dumps(artifact)
        assert secret.decode() not in serialized and root.as_posix() not in serialized
        assert json.dumps(str(root))[1:-1] not in serialized


@pytest.mark.parametrize("field", ["state", "binding", "contract", "request_hash", "receipt", "missing_receipt", "hash"])
def test_repository_attestation_tampering_fails_validation(runtime, field):
    guard, root, _ = runtime
    proof = guard.boundary_for().execute_repository(lambda p: p.write_bytes(b"updated"),
                                                   execution_request=request("README.md"))["evaluation"]["execution_attestation"]
    changed = copy.deepcopy(proof)
    if field == "state":
        changed["execution_status"] = "failed"
    elif field == "binding":
        changed["target_binding"]["workspace_binding_id"] = "workspace_other"
    elif field == "contract":
        changed["authority_basis"]["compiled_contract_hash"] = "sha256:" + "0" * 64
    elif field == "missing_receipt":
        changed["guard_receipt_hash"] = None
    else:
        changed[{"request_hash": "execution_request_hash", "receipt": "guard_receipt_hash", "hash": "attestation_hash"}[field]] = "sha256:" + "0" * 64
    with pytest.raises(GuardArtifactError):
        validate_execution_attestation(changed)
    if field in {"receipt", "missing_receipt", "contract", "binding"}:
        # Recomputing internal hashes still cannot sever the saved decision basis.
        changed["target_binding_hash"] = stable_hash(changed["target_binding"])
        changed["attestation_hash"] = stable_hash({k: v for k, v in changed.items() if k != "attestation_hash"})
        path = guard.store.execution_attestation_root / (proof["run_id"] + ".json")
        path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(GuardArtifactError):
            guard.store.load_execution_attestation(proof["run_id"])


def test_accepted_closed_workspace_refusal_has_no_fabricated_decision(runtime):
    guard, root, _ = runtime
    guard.close()
    calls = []
    with pytest.raises(RepositoryBoundaryError) as error:
        guard.boundary_for().execute_repository(lambda p: calls.append(p), execution_request=request("README.md"))
    proof = error.value.evaluation["execution_attestation"]
    assert calls == [] and proof["decision"] == "not_evaluated"
    assert proof["guard_receipt_hash"] is None and proof["decision_outcome_hash"] is None
    assert proof["callback_invoked"] is False and proof["mutation_status"] == "not_performed"
    assert guard.store.load_execution_attestation(proof["run_id"]) == proof
    assert guard.store.history() == []


@pytest.mark.parametrize("mode", ["success", "unsupported"])
def test_save_false_returns_proof_without_persistence(runtime, mode):
    guard, root, _ = runtime
    guard.cloud_preservation_client = Capture()
    if mode == "unsupported":
        (root / "README.md").unlink()
        with pytest.raises(RepositoryBoundaryError) as error:
            guard.boundary_for().execute_repository(lambda p: pytest.fail("callback ran"),
                                                    execution_request=request("README.md"), save=False)
        evaluation = error.value.evaluation
    else:
        evaluation = guard.boundary_for().execute_repository(lambda p: p.write_bytes(b"updated"),
                                                             execution_request=request("README.md"), save=False)["evaluation"]
    assert validate_execution_attestation(evaluation["execution_attestation"])["guard_receipt_hash"] is None
    assert not list(guard.store.root.rglob("*")) and guard.cloud_preservation_client.packages == []


def test_released_v1_attestation_is_validated_without_reinterpretation():
    legacy = {
        "schema_version": "guard_execution_attestation.v1", "run_id": "historical-run",
        "guard_receipt_hash": None, "authority_evidence_hash": "historical-authority",
        "runtime_facts_hash": "historical-facts", "decision": "admissible",
        "callback_invoked": True, "callback_completed": True, "execution_status": "succeeded",
        "mutation_status": "executed", "mutation_executed": True,
    }
    legacy["attestation_hash"] = stable_hash(legacy)
    before = json.dumps(legacy, separators=(",", ":"))
    assert json.dumps(validate_execution_attestation(legacy), separators=(",", ":")) == before
    changed = copy.deepcopy(legacy)
    changed["mutation_executed"] = False
    with pytest.raises(GuardArtifactError):
        validate_execution_attestation(changed)
