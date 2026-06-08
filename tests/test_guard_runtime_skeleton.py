from __future__ import annotations

from guard import build_continuation_lease, evaluate_runtime, validate_continuation
from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.enforcement import build_release_chronology
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
from guard.runtime.continuation import (
    GUARD_CONTINUATION_LEASE_V1,
    GUARD_RELEASE_VALIDATION_V1,
    evaluate_continuation,
)
from guard.runtime.dependencies import RUNTIME_DEPENDENCY_V1, normalize_runtime_dependencies


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
    assert result["execution_state"] == "allowed"
    assert result["enforcement_outcome"]["execution_state"] == "allowed"
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
    assert result["continuation_status"]["status"] == "admissible"
    assert result["continuation_requirements"] == []
    assert result["invalidation_reasons"] == []
    assert result["runtime_condition_checks"]
    assert result["enforcement_outcome"]["continuation_status"] == result["continuation_status"]
    assert result["enforcement_outcome"]["runtime_condition_checks"] == result["runtime_condition_checks"]
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
    assert result["execution_state"] == "blocked"
    assert result["enforcement_outcome"]["execution_state"] == "blocked"
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
    assert "continuation_status" in result["enforcement_outcome"]
    assert "continuation_requirements" in result["enforcement_outcome"]
    assert "invalidation_reasons" in result["enforcement_outcome"]
    assert "runtime_condition_checks" in result["enforcement_outcome"]


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
    assert result["execution_state"] == "escalated"
    assert result["enforcement_outcome"]["execution_state"] == "escalated"
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
    assert result["continuation_status"]["status"] == "revalidation_required"
    assert result["continuation_requirements"] == [
        {
            "requirement": "revalidate_continuation",
            "rationale": "lineage continuity must be revalidated before execution can proceed",
        }
    ]
    assert result["invalidation_reasons"] == []
    assert result["runtime_condition_checks"][3] == {
        "condition": "continuity_valid",
        "valid": False,
        "rationale": "lineage continuity validity checked",
    }
    assert result["enforcement_outcome"]["continuation_status"] == result["continuation_status"]
    assert result["enforcement_outcome"]["continuation_requirements"] == result["continuation_requirements"]
    assert result["enforcement_outcome"]["runtime_condition_checks"] == result["runtime_condition_checks"]


def test_continuation_validity_engine_returns_canonical_statuses():
    assert evaluate_continuation(
        evidence_valid=True,
        replay_valid=False,
        dependency_valid=True,
        continuity_valid=False,
    )["status"] == "revalidation_required"
    assert evaluate_continuation(
        evidence_valid=True,
        replay_valid=False,
        dependency_valid=True,
        continuity_valid=True,
    )["status"] == "escalation_required"
    assert evaluate_continuation(
        evidence_valid=True,
        replay_valid=True,
        dependency_valid=False,
        continuity_valid=True,
    )["status"] == "invalidated"
    assert evaluate_continuation(
        evidence_valid=True,
        replay_valid=True,
        dependency_valid=True,
        continuity_valid=True,
        expired=True,
    )["status"] == "expired"
    assert evaluate_continuation(
        evidence_valid=True,
        replay_valid=False,
        dependency_valid=True,
        continuity_valid=True,
    )["lifecycle_state"] == "continuation_required"


def test_runtime_dependencies_normalize_to_canonical_contract():
    dependencies = normalize_runtime_dependencies(
        [
            {
                "type": "approval",
                "id": "director-approval-1",
                "hash": "sha256:approval",
                "observed_hash": "sha256:approval",
                "valid_until": "2026-06-03T22:31:00Z",
            }
        ]
    )

    assert dependencies == [
        {
            "schema_version": RUNTIME_DEPENDENCY_V1,
            "dependency_type": "approval",
            "dependency_id": "director-approval-1",
            "dependency_hash": "sha256:approval",
            "current_hash": "sha256:approval",
            "valid_until": "2026-06-03T22:31:00Z",
            "status": "valid",
        }
    ]


def test_runtime_blocks_when_dependency_expiration_invalidates_continuation():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={
            "approvals": [{"role": "manager", "approved_by": "approver-1"}],
            "runtime_dependencies": [
                {
                    "type": "approval",
                    "id": "director-approval-1",
                    "hash": "sha256:approval",
                    "linked_at": "2026-06-03T22:00:00+00:00",
                    "valid_until": "2026-06-03T22:29:00+00:00",
                }
            ],
        },
        evaluation_time=EVALUATION_TIME,
    )

    assert result["status"] == "blocked"
    assert result["runtime_lifecycle_state"] == "expired"
    assert result["enforcement_outcome"]["runtime_lifecycle_state"] == "expired"
    assert result["continuation_status"]["status"] == "expired"
    assert result["continuation_status"]["lifecycle_state"] == "expired"
    assert result["runtime_dependency_posture"]["dependencies"][0]["schema_version"] == RUNTIME_DEPENDENCY_V1
    assert result["continuation_requirements"][0]["requirement"] == "refresh_runtime_dependencies"
    assert result["invalidation_reasons"][0]["reason"] == "dependency_expired"
    assert result["runtime_condition_checks"][-1]["valid"] is False
    assert result["enforcement_outcome"]["invalidation_reasons"] == result["invalidation_reasons"]
    assert result["violated_constraints"][0]["constraint"] == "continuation_validity"
    assert result["runtime_evidence"]["runtime_dependencies"][0]["dependency_id"] == "director-approval-1"
    event_types = [event["event_type"] for event in result["telemetry_events"]]
    assert "runtime_dependency_linked" in event_types
    assert "runtime_dependency_expired" in event_types
    assert "continuation_invalidated" in event_types
    assert "continuation_evaluated" in event_types
    expired_event = next(event for event in result["telemetry_events"] if event["event_type"] == "runtime_dependency_expired")
    assert expired_event["details"]["relative_delta_ms"] == 1_740_000


def test_runtime_blocks_when_dependency_drift_invalidates_continuation():
    result = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={
            "approvals": [{"role": "manager", "approved_by": "approver-1"}],
            "runtime_dependencies": [
                {
                    "type": "approval",
                    "id": "director-approval-1",
                    "hash": "sha256:expected",
                    "observed_hash": "sha256:changed",
                    "valid_until": "2026-06-03T23:30:00+00:00",
                }
            ],
        },
        evaluation_time=EVALUATION_TIME,
    )

    assert result["status"] == "blocked"
    assert result["runtime_lifecycle_state"] == "invalidated"
    assert result["continuation_status"]["status"] == "invalidated"
    assert result["continuation_status"]["dependency_failures"][0]["reason"] == "dependency_drift"
    assert result["continuation_requirements"][0]["requirement"] == "rebuild_replay_basis"
    assert result["invalidation_reasons"][0]["reason"] == "dependency_drift"


def test_deferred_release_blocks_when_approval_expires_after_admissibility():
    evaluation = evaluate_runtime(
        compiled_authority=_authority(),
        execution_request=_request(amount=500),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        evidence_posture={
            "approvals": [{"role": "manager", "approved_by": "approver-1"}],
            "runtime_dependencies": [
                {
                    "dependency_type": "approval",
                    "dependency_id": "director-approval-1",
                    "dependency_hash": "sha256:approval",
                    "current_hash": "sha256:approval",
                    "linked_at": "2026-06-03T22:00:00+00:00",
                    "valid_until": "2026-06-03T22:30:00+00:00",
                    "status": "valid",
                }
            ],
        },
        evaluation_time="2026-06-03T22:00:00+00:00",
    )
    assert evaluation["status"] == "admissible"
    assert evaluation["runtime_lifecycle_state"] == "admissible"

    lease = build_continuation_lease(
        execution_id="exec-1",
        authority_ref="finance-policy@1.0.0",
        issued_at="2026-06-03T22:00:00+00:00",
        admissible_until="2026-06-03T22:35:00+00:00",
        runtime_dependencies=evaluation["runtime_dependency_posture"]["dependencies"],
        continuation_status=evaluation["continuation_status"],
    )
    assert lease["schema_version"] == GUARD_CONTINUATION_LEASE_V1
    assert lease["runtime_lifecycle_state"] == "admissible"
    assert lease["revalidation_required"] is False

    release_validation = validate_continuation(
        lease,
        release_time="2026-06-03T22:32:00+00:00",
    )
    assert release_validation["schema_version"] == GUARD_RELEASE_VALIDATION_V1
    assert release_validation["outcome"] == "dependency_expired"
    assert release_validation["release_allowed"] is False
    assert release_validation["release_blocked"] is True
    assert release_validation["runtime_lifecycle_state"] == "expired"
    assert release_validation["continuation_status"]["status"] == "expired"
    assert release_validation["invalidation_reasons"][0]["reason"] == "dependency_expired"

    chronology = build_release_chronology(
        authority_ref="finance-policy@1.0.0",
        timestamp="2026-06-03T22:00:00+00:00",
        continuation_lease=lease,
        release_validation=release_validation,
    )
    assert [event["event_type"] for event in chronology] == [
        "evaluation_admissible",
        "continuation_lease_issued",
        "runtime_dependency_expired",
        "continuation_invalidated",
        "release_blocked",
    ]
    assert chronology[1]["details"]["relative_delta_ms"] == 5
    assert chronology[2]["details"]["relative_delta_ms"] == 1_800_000
    assert chronology[3]["details"]["relative_delta_ms"] == 1_860_000
    assert chronology[4]["details"]["relative_delta_ms"] == 1_920_000


def test_deferred_release_allows_when_continuation_remains_valid():
    lease = build_continuation_lease(
        execution_id="exec-1",
        authority_ref="finance-policy@1.0.0",
        issued_at="2026-06-03T22:00:00+00:00",
        admissible_until="2026-06-03T22:35:00+00:00",
        runtime_dependencies=[
            {
                "dependency_type": "approval",
                "dependency_id": "director-approval-1",
                "dependency_hash": "sha256:approval",
                "current_hash": "sha256:approval",
                "linked_at": "2026-06-03T22:00:00+00:00",
                "valid_until": "2026-06-03T22:35:00+00:00",
                "status": "valid",
            }
        ],
        continuation_status=evaluate_continuation(),
    )

    release_validation = validate_continuation(
        lease,
        release_time="2026-06-03T22:10:00+00:00",
    )

    assert release_validation["outcome"] == "release_allowed"
    assert release_validation["release_allowed"] is True
    assert release_validation["release_blocked"] is False
    assert release_validation["runtime_lifecycle_state"] == "released"
    assert release_validation["continuation_status"]["status"] == "admissible"


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
