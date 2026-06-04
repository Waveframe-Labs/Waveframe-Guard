from __future__ import annotations

from guard import evaluate_runtime
from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.runtime.builders import (
    EXECUTION_ADMISSIBILITY_PROJECTION_V1,
    EXECUTION_RUNTIME_POSTURE_V1,
    GUARD_CONTINUITY_POSTURE_V1,
    GUARD_ENFORCEMENT_OUTCOME_V1,
    GUARD_EVALUATION_TRACE_V1,
    GUARD_RUNTIME_EVENT_V1,
    validate_guard_enforcement_outcome,
)
from guard.runtime.evidence import GUARD_RUNTIME_EVIDENCE_MODEL_V1


EVALUATION_TIME = "2026-06-03T22:30:00+00:00"


def test_runtime_evaluation_builds_admissible_operational_backbone():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={"approvals": [{"role": "manager", "approved_by": "approver-1"}]},
        evaluation_time=EVALUATION_TIME,
    )

    assert result["status"] == "admissible"
    assert result["admissible"] is True
    assert result["blocked"] is False
    assert result["escalated"] is False
    assert result["rationale"] == "execution is admissible against compiled authority"
    assert result["admissibility_projection"]["schema_version"] == EXECUTION_ADMISSIBILITY_PROJECTION_V1
    assert result["runtime_posture"]["schema_version"] == EXECUTION_RUNTIME_POSTURE_V1
    assert result["telemetry_events"][0]["schema_version"] == GUARD_RUNTIME_EVENT_V1
    assert result["evaluation_trace"]["schema_version"] == GUARD_EVALUATION_TRACE_V1
    assert result["continuity_posture"]["schema_version"] == GUARD_CONTINUITY_POSTURE_V1
    assert result["enforcement_outcome"]["schema_version"] == GUARD_ENFORCEMENT_OUTCOME_V1
    assert validate_guard_enforcement_outcome(result["enforcement_outcome"]) == result["enforcement_outcome"]
    assert result["runtime_evidence"]["schema_version"] == GUARD_RUNTIME_EVIDENCE_MODEL_V1
    assert result["execution_posture_surface"] == {
        "schema_version": "execution_posture_surface.v1",
        "posture": "admissible",
        "rationale": "execution is admissible against compiled authority",
        "runtime_blockers": [],
        "continuity_state": result["continuity_posture"],
        "replay_requirements": [],
        "chronology_event_ids": [
            event["event_id"]
            for event in result["telemetry_events"]
        ],
    }


def test_runtime_evaluation_blocks_on_compiled_authority_constraints():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=12_500),
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        evidence_posture={"approvals": []},
        evaluation_time=EVALUATION_TIME,
    )

    assert result["status"] == "blocked"
    assert result["admissible"] is False
    assert result["violated_constraints"] == [
        {
            "constraint": "required_role",
            "required_roles": ["manager"],
            "observed_role": "employee",
            "rationale": "actor role is not authorized by compiled authority",
        }
    ]
    assert result["required_evidence"] == [
        {
            "evidence": "approval",
            "role": "manager",
            "condition": None,
            "rationale": "required approval evidence is missing",
        },
        {
            "evidence": "approval",
            "role": "director",
            "condition": {"field": "amount", "operator": ">", "value": 10000},
            "rationale": "required approval evidence is missing",
        },
    ]
    assert result["enforcement_consequences"][0]["consequence"] == "block_execution"
    assert result["runtime_posture"]["posture"] == "blocked"


def test_runtime_evaluation_escalates_for_continuity_and_replay_requirements():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={"approvals": [{"role": "manager", "approved_by": "approver-1"}]},
        continuity_state={
            "requires_revalidation": True,
            "signals": ["AUTHORITY_SUPERSEDED_DURING_EXECUTION"],
        },
        replay_posture={
            "required": True,
            "obligations": [{"obligation": "link_replay", "replay_id": "replay-1"}],
        },
        evaluation_time=EVALUATION_TIME,
    )

    assert result["status"] == "escalated"
    assert result["continuity_requirements"] == [
        {
            "requirement": "revalidation",
            "signals": ["AUTHORITY_SUPERSEDED_DURING_EXECUTION"],
            "rationale": "continuity state requires runtime revalidation",
        }
    ]
    assert result["replay_obligations"] == [
        {"obligation": "link_replay", "replay_id": "replay-1"}
    ]
    assert result["enforcement_consequences"] == [
        {
            "consequence": "escalate_execution",
            "continuity_requirements": result["continuity_requirements"],
            "replay_obligations": result["replay_obligations"],
        }
    ]
    assert result["continuity_posture"]["requires_revalidation"] is True
    assert result["continuity_posture"]["requires_replay"] is True


def test_runtime_evaluation_is_deterministic_for_identical_inputs():
    inputs = {
        "compiled_authority": _authority(),
        "execution_request": _request(amount=500),
        "actor_identity": {"id": "manager-1", "type": "human", "role": "manager"},
        "evidence_posture": {"approvals": [{"role": "manager", "approved_by": "approver-1"}]},
        "evaluation_time": EVALUATION_TIME,
    }

    assert evaluate_runtime(**inputs) == evaluate_runtime(**inputs)


def test_runtime_chronology_and_telemetry_stream_are_ordered():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={"approvals": [{"role": "manager", "approved_by": "approver-1"}]},
        evaluation_time=EVALUATION_TIME,
        start_sequence=10,
    )

    assert [event["sequence"] for event in result["telemetry_events"]] == [10, 11, 12, 13, 14, 15, 16]
    assert [event["event_type"] for event in result["telemetry_events"]] == [
        "authority_context_resolved",
        "evaluation_pipeline_started",
        "runtime_evidence_loaded",
        "continuity_checked",
        "replay_validated",
        "admissibility_evaluated",
        "enforcement_outcome_recorded",
    ]
    assert result["telemetry_stream"] == [
        {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "sequence": event["sequence"],
            "timestamp": event["timestamp"],
            "authority_ref": event["authority_ref"],
            "event_hash": event["event_hash"],
        }
        for event in result["telemetry_events"]
    ]


def _authority():
    return {
        "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:contract",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {
            "required": [
                {"role": "manager"},
                {
                    "role": "director",
                    "condition": {"field": "amount", "operator": ">", "value": 10000},
                },
            ]
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {"separation_of_duties": True},
    }


def _request(*, amount):
    return {
        "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
        "request_id": "exec-1",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }
