"""Authority-version-neutral repository execution proof; released v1 is unchanged."""

from copy import deepcopy
import re

from guard.runtime.identity import stable_hash
from .local_persistence import GuardArtifactError
from .repository_boundary import RepositoryBoundaryError, validate_repository_request
from .target_binding import TargetBinding


SCHEMA = "guard_execution_attestation.v2"
STATE_FIELDS = ("callback_invoked", "callback_completed", "execution_status",
                "mutation_status", "mutation_executed")


def authority_basis(contract, evaluation):
    basis = {
        "kind": "compiled_contract",
        "compiled_contract_hash": stable_hash(contract),
        "contract_id": contract["contract_id"],
        "contract_version": contract["contract_version"],
        "declared_contract_hash": contract["contract_hash"],
    }
    if "authority_evidence" in evaluation:
        basis.update(kind="published_authority",
                     authority_evidence_hash=stable_hash(evaluation["authority_evidence"]),
                     runtime_facts_hash=evaluation["runtime_facts_hash"])
    return basis


def build_repository_attestation(*, run_id, receipt_hash, contract, evaluation, **state):
    request = evaluation["accepted_execution_request"]
    binding = evaluation["target_binding"]
    proof = {
        "schema_version": SCHEMA, "run_id": run_id,
        "guard_receipt_hash": receipt_hash,
        "decision": evaluation["status"],
        "decision_outcome_hash": evaluation.get("enforcement_outcome", {}).get("outcome_hash"),
        "authority_basis": authority_basis(contract, evaluation),
        "execution_request": deepcopy(request), "execution_request_hash": stable_hash(request),
        "target_binding": deepcopy(binding), "target_binding_hash": stable_hash(binding),
        **state,
    }
    proof["attestation_hash"] = stable_hash(proof)
    return validate_repository_attestation(proof)


def validate_repository_attestation(proof, *, record=None):
    fields = {"schema_version", "run_id", "guard_receipt_hash", "decision", "decision_outcome_hash",
              "authority_basis", "execution_request", "execution_request_hash", "target_binding",
              "target_binding_hash", "attestation_hash", *STATE_FIELDS}
    def require(condition, message):
        if not condition:
            raise GuardArtifactError("repository execution attestation " + message)

    require(type(proof) is dict and set(proof) == fields, "fields do not match v2")
    require(proof["schema_version"] == SCHEMA, "schema is not v2")
    require(type(proof["run_id"]) is str and re.fullmatch(r"[A-Za-z0-9_-]+", proof["run_id"]),
            "run identity is invalid")
    for field in ("attestation_hash", "target_binding_hash", "execution_request_hash",
                  "guard_receipt_hash", "decision_outcome_hash"):
        value = proof[field]
        if field in {"guard_receipt_hash", "decision_outcome_hash"} and value is None:
            continue
        require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "hash is invalid")
    try:
        validate_repository_request(proof["execution_request"])
    except RepositoryBoundaryError:
        raise GuardArtifactError("repository execution attestation request is invalid") from None
    require(proof["execution_request_hash"] == stable_hash(proof["execution_request"]), "request hash mismatch")
    binding = proof["target_binding"]
    require(type(binding) is dict and set(binding) == set(TargetBinding.__dataclass_fields__), "binding fields are invalid")
    require(binding["schema_version"] == "guard_target_binding.v1" and binding["target_domain"] == "repository_path",
            "binding is not repository-scoped")
    require(proof["target_binding_hash"] == stable_hash(binding), "target binding hash mismatch")
    basis = proof["authority_basis"]
    require(type(basis) is dict, "authority basis is invalid")
    basis_fields = {"kind", "compiled_contract_hash", "contract_id", "contract_version", "declared_contract_hash"}
    require(basis.get("kind") in {"compiled_contract", "published_authority"}, "authority basis kind is invalid")
    if basis["kind"] == "published_authority":
        basis_fields.update({"authority_evidence_hash", "runtime_facts_hash"})
    require(set(basis) == basis_fields and all(type(value) is str and value for value in basis.values()),
            "authority basis fields are invalid")
    for field in ("compiled_contract_hash", "authority_evidence_hash", "runtime_facts_hash"):
        if field in basis:
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", basis[field]), "authority hash is invalid")
    require(basis["compiled_contract_hash"] == binding["authority_contract_hash"], "contract binding mismatch")
    decision = proof["decision"]
    require(decision in {"admissible", "blocked", "escalated", "not_evaluated"}, "decision is invalid")
    require((proof["decision_outcome_hash"] is None) == (decision == "not_evaluated"), "decision hash is missing or fabricated")
    if decision == "not_evaluated":
        require(proof["guard_receipt_hash"] is None, "unevaluated request cannot claim a decision receipt")
    for field in ("callback_invoked", "callback_completed", "mutation_executed"):
        require(proof[field] is None or type(proof[field]) is bool, "callback/mutation flag is invalid")
    state = tuple(proof[field] for field in STATE_FIELDS)
    valid = {(False, False, "not_run", "not_performed", False)}
    if decision == "admissible":
        valid.update({(True, True, "succeeded", "executed", True),
                      (True, False, "failed", "unknown", None),
                      (True, True, "failed", "unknown", None),
                      (None, None, "incomplete", "unknown", None),
                      (True, False, "incomplete", "unknown", None)})
    require(state in valid, "contains a contradictory execution state")
    require(proof["attestation_hash"] == stable_hash({k: v for k, v in proof.items() if k != "attestation_hash"}),
            "hash mismatch")
    if record is not None:
        receipt, inputs, evaluation = record["receipt"], record["inputs"], record["evaluation"]
        require(proof["run_id"] == record["run_id"] and proof["guard_receipt_hash"] == receipt["receipt_hash"],
                "decision receipt mismatch")
        require(receipt["receipt_hash"] == stable_hash({k: v for k, v in receipt.items() if k != "receipt_hash"}),
                "decision receipt integrity mismatch")
        for field in ("execution_request", "target_binding"):
            require(proof[field] == inputs[field] and proof[field + "_hash"] == receipt["input_hashes"][field + "_hash"],
                    "saved request/binding mismatch")
        require(basis == authority_basis(inputs["compiled_authority"], evaluation), "saved authority basis mismatch")
        require(proof["decision"] == evaluation["status"] and proof["decision_outcome_hash"] == evaluation["enforcement_outcome"]["outcome_hash"],
                "saved decision mismatch")
    return deepcopy(proof)
