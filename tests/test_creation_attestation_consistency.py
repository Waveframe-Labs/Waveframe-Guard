"""Creation observations must agree with execution even after proof rehashing."""

from copy import deepcopy
import json

import pytest

from guard.runtime.identity import stable_hash
from guard.sdk import RepositoryBoundaryError
from guard.sdk.local_persistence import GuardArtifactError, validate_execution_attestation
from guard.sdk.repository_evidence import validate_repository_attestation
from test_action_policy_creation import development, request, runtime

pytestmark = development

OUTER_STATES = {
    "not_run": (False, False, "not_run", "not_performed", False),
    "unknown": (None, None, "incomplete", "unknown", None),
    "incomplete": (True, False, "incomplete", "unknown", None),
    "succeeded": (True, True, "succeeded", "executed", True),
    "failed": (True, False, "failed", "unknown", None),
    "post_callback_failed": (True, True, "failed", "unknown", None),
}
STATE_FIELDS = ("callback_invoked", "callback_completed", "execution_status",
                "mutation_status", "mutation_executed")


def rehash(proof):
    proof["attestation_hash"] = stable_hash({key: value for key, value in proof.items()
                                           if key != "attestation_hash"})
    return proof


@pytest.fixture
def creation_proofs(runtime):
    make, root = runtime
    instance = make()

    @instance.repository_tool(action="create", target="path", return_result=True)
    def create(path, content):
        return path.create_bytes(content)

    success = create("generated/new.md", b"created")["evaluation"]["execution_attestation"]
    with pytest.raises(RepositoryBoundaryError) as error:
        create("generated/new.md", b"never overwrite")
    collision = error.value.evaluation["execution_attestation"]
    assert (root / "generated/new.md").read_bytes() == b"created"
    return instance.store, {"success": success, "collision": collision}, create


def check_all_readers(store, proof, *, valid):
    record = store.load_run(proof["run_id"])
    path = store.execution_attestation_root / (proof["run_id"] + ".json")
    path.write_text(json.dumps(proof), encoding="utf-8")
    readers = (
        lambda: validate_execution_attestation(proof),
        lambda: validate_repository_attestation(proof, record=record),
        lambda: store.load_execution_attestation(proof["run_id"]),
    )
    for read in readers:
        if valid:
            assert read() == proof
        else:
            with pytest.raises(GuardArtifactError, match="operation|creation|collision"):
                read()


@pytest.mark.parametrize("base,outer,operation", [
    pytest.param("collision", None, {"created": True, "bytes_written": 3}, id="review-collision-created-and-written"),
    pytest.param("success", "not_run", {"created": False, "bytes_written": 0}, id="review-success-without-execution"),
    pytest.param("collision", None, {"created": True}, id="collision-created-empty-file"),
    pytest.param("success", "failed", {}, id="operation-success-outer-failed"),
    pytest.param("success", "incomplete", {}, id="operation-success-outer-incomplete"),
    pytest.param("success", "unknown", {"created": False, "bytes_written": 0}, id="operation-success-unknown-callback"),
    pytest.param("collision", None, {"error": None}, id="failure-without-error"),
    pytest.param("collision", None, {"error": "operation_precondition_failed"}, id="precondition-error-after-invocation"),
    pytest.param("collision", "incomplete", {}, id="terminal-failure-with-incomplete-execution"),
    pytest.param("collision", "not_run", {}, id="collision-without-execution"),
    pytest.param("collision", "unknown", {"status": "attempted", "error": None}, id="attempt-without-known-invocation"),
    pytest.param("collision", "not_run", {"status": "attempted", "error": None}, id="attempt-without-execution"),
    pytest.param("collision", "failed", {"status": "attempted", "error": None}, id="unfinished-operation-with-terminal-execution"),
    pytest.param("success", "incomplete", {"status": "not_run"}, id="not-run-operation-claims-created-file"),
    pytest.param("collision", "not_run", {"status": "not_run", "error": "post_callback_validation_failed"}, id="post-callback-error-before-execution"),
    pytest.param("collision", "incomplete", {"status": "not_run", "error": "operation_precondition_failed"}, id="precondition-error-with-incomplete-execution"),
    pytest.param("collision", "incomplete", {"status": "attempted"}, id="attempt-with-terminal-error"),
])
def test_rehashed_contradictions_rejected_by_public_and_saved_readers(creation_proofs, base, outer, operation):
    store, proofs, _ = creation_proofs
    bad = deepcopy(proofs[base])
    if outer is not None:
        bad.update(zip(STATE_FIELDS, OUTER_STATES[outer]))
    bad["repository_operation"].update(operation)
    check_all_readers(store, rehash(bad), valid=False)


@pytest.mark.parametrize("outer,status,created,count,error", [
    ("not_run", "not_run", False, 0, None),
    ("not_run", "not_run", False, 0, "operation_precondition_failed"),
    ("unknown", "not_run", False, 0, None),
    ("incomplete", "not_run", False, 0, None),
    ("incomplete", "attempted", False, 0, None),
    ("incomplete", "attempted", True, 0, None),
    ("incomplete", "attempted", True, 3, None),
    ("failed", "failed", False, 0, "exclusive_create_collision"),
    ("post_callback_failed", "failed", False, 0, "exclusive_create_collision"),
    ("failed", "failed", False, 0, "creation_or_callback_failed"),
    ("failed", "failed", True, 0, "creation_or_callback_failed"),
    ("failed", "failed", True, 3, "creation_or_callback_failed"),
    ("post_callback_failed", "failed", True, 0, "post_callback_validation_failed"),
    ("post_callback_failed", "failed", True, 3, "post_callback_validation_failed"),
    ("failed", "failed", False, 0, "post_callback_validation_failed"),
    ("succeeded", "succeeded", True, 0, None),
])
def test_valid_observation_states_remain_readable(creation_proofs, outer, status, created, count, error):
    store, proofs, _ = creation_proofs
    proof = deepcopy(proofs["success"])
    proof.update(zip(STATE_FIELDS, OUTER_STATES[outer]))
    proof["repository_operation"].update(status=status, created=created, bytes_written=count, error=error)
    check_all_readers(store, rehash(proof), valid=True)


def test_real_collision_and_zero_byte_creation_remain_readable(creation_proofs, runtime):
    store, proofs, create = creation_proofs
    for proof in proofs.values():
        check_all_readers(store, proof, valid=True)
    empty = create("generated/empty.md", b"")["evaluation"]["execution_attestation"]
    assert runtime[1].joinpath("generated/empty.md").read_bytes() == b""
    assert empty["repository_operation"]["created"] is True
    assert empty["repository_operation"]["bytes_written"] == 0
    check_all_readers(store, empty, valid=True)
