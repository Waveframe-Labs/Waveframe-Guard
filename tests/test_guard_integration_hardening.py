from __future__ import annotations

import pytest

from guard import evaluate_runtime
from guard.adapters import (
    COMPILED_AUTHORITY_CONTRACT_V1,
    NORMALIZED_EXECUTION_REQUEST_V1,
    CompiledAuthorityIntakeError,
    ExecutionRequestNormalizationError,
    intake_compiled_authority,
    require_normalized_execution_request,
)
from guard.runtime.builders import GUARD_ENFORCEMENT_OUTCOME_V1, validate_guard_enforcement_outcome
from guard.runtime.evidence import GUARD_RUNTIME_EVIDENCE_MODEL_V1


def test_compiled_authority_intake_accepts_only_compiled_authority_contract_v1():
    authority = intake_compiled_authority(_compiled_authority())

    assert authority["schema_version"] == COMPILED_AUTHORITY_CONTRACT_V1
    assert authority["contract_id"] == "finance-policy"


def test_compiled_authority_intake_rejects_raw_policy_text_and_authority_bundles():
    with pytest.raises(CompiledAuthorityIntakeError, match="raw policy"):
        intake_compiled_authority(
            {
                "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
                "policy_text": "Managers may approve finance transfers.",
            }
        )

    with pytest.raises(CompiledAuthorityIntakeError, match="authority_bundle"):
        intake_compiled_authority(
            {
                **_compiled_authority(),
                "authority_bundle": {"semantic_extraction": {}},
            }
        )


def test_compiled_authority_intake_rejects_uncompiled_payloads():
    with pytest.raises(CompiledAuthorityIntakeError, match="schema_version"):
        intake_compiled_authority(
            {
                "contract_id": "finance-policy",
                "contract_version": "1.0.0",
                "contract_hash": "sha256:contract",
            }
        )


def test_execution_request_boundary_requires_normalized_request():
    normalized = require_normalized_execution_request(_normalized_request())

    assert normalized["schema_version"] == NORMALIZED_EXECUTION_REQUEST_V1

    with pytest.raises(ExecutionRequestNormalizationError, match="raw request"):
        require_normalized_execution_request({"raw_request": "send money"})

    with pytest.raises(ExecutionRequestNormalizationError, match="schema_version"):
        require_normalized_execution_request(
            {
                "request_id": "exec-1",
                "action": "transfer",
                "target": "wire",
                "arguments": {},
                "artifacts": [],
            }
        )


def test_runtime_emits_guard_enforcement_outcome_contract_for_every_evaluation():
    result = evaluate_runtime(
        compiled_authority=_compiled_authority(),
        execution_request=_normalized_request(),
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        evidence_posture={"approvals": []},
        evaluation_time="2026-06-03T22:30:00+00:00",
    )

    outcome = result["enforcement_outcome"]
    assert outcome["schema_version"] == GUARD_ENFORCEMENT_OUTCOME_V1
    assert outcome["status"] == "blocked"
    assert validate_guard_enforcement_outcome(outcome) == outcome


def test_runtime_evidence_model_is_materialized_before_decision():
    result = evaluate_runtime(
        compiled_authority=_compiled_authority(),
        execution_request=_normalized_request(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={
            "approvals": [{"role": "manager", "approved_by": "approver-1"}],
            "execution_context": {"surface": "sdk"},
        },
        continuity_state={"signals": []},
        replay_posture={"required": False},
        evaluation_time="2026-06-03T22:30:00+00:00",
    )

    assert result["runtime_evidence"] == {
        "schema_version": GUARD_RUNTIME_EVIDENCE_MODEL_V1,
        "actor_identity": {"id": "manager-1", "type": "human", "role": "manager"},
        "approvals": [{"role": "manager", "approved_by": "approver-1"}],
        "replay_evidence": {"required": False},
        "continuity_snapshot": {"signals": []},
        "timestamp_source": {
            "source": "caller_supplied",
            "timestamp": "2026-06-03T22:30:00+00:00",
        },
        "execution_context": {"surface": "sdk"},
    }


def _compiled_authority():
    return {
        "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:contract",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {"required": [{"role": "manager"}]},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }


def _normalized_request():
    return {
        "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
        "request_id": "exec-1",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": 500},
        "artifacts": [],
    }
