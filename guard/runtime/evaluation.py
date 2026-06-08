from __future__ import annotations

from typing import Any

from guard.adapters.compiled_authority import intake_compiled_authority
from guard.adapters.proposal_normalizer import require_normalized_execution_request
from guard.cognition import assess_admissibility
from guard.enforcement import build_chronology
from guard.projections import project_execution_surface
from guard.telemetry import telemetry_stream

from .builders import (
    build_execution_admissibility_projection,
    build_execution_runtime_posture,
    build_guard_continuity_posture,
    build_guard_enforcement_outcome,
    build_guard_evaluation_trace,
    execution_state_for_status,
)
from .continuation import (
    continuation_requirements,
    evaluate_continuation,
    evaluate_runtime_dependencies,
    invalidation_reasons,
    runtime_condition_checks,
)
from .evidence import build_runtime_evidence_model, validate_runtime_evidence_model


DEFAULT_EVALUATION_TIME = "1970-01-01T00:00:00+00:00"


def evaluate_runtime(
    *,
    compiled_authority: dict[str, Any],
    execution_request: dict[str, Any],
    actor_identity: dict[str, Any],
    continuity_state: dict[str, Any] | None = None,
    replay_posture: dict[str, Any] | None = None,
    evidence_posture: dict[str, Any] | None = None,
    evaluation_time: str = DEFAULT_EVALUATION_TIME,
    start_sequence: int = 1,
) -> dict[str, Any]:
    compiled_authority = intake_compiled_authority(compiled_authority)
    execution_request = require_normalized_execution_request(execution_request)
    runtime_evidence = build_runtime_evidence_model(
        actor_identity=actor_identity,
        approvals=(evidence_posture or {}).get("approvals", []),
        replay_evidence=replay_posture,
        continuity_snapshot=continuity_state,
        timestamp_source={
            "source": "caller_supplied",
            "timestamp": evaluation_time,
        },
        execution_context=(evidence_posture or {}).get("execution_context", {}),
        runtime_dependencies=(evidence_posture or {}).get("runtime_dependencies", []),
    )
    validate_runtime_evidence_model(runtime_evidence)

    authority_ref = _authority_ref(compiled_authority)
    dependency_posture = evaluate_runtime_dependencies(
        runtime_evidence.get("runtime_dependencies", []),
        evaluation_time=evaluation_time,
    )
    continuation_status = evaluate_continuation(
        evidence_valid=True,
        replay_valid=not bool((replay_posture or {}).get("required")),
        dependency_valid=dependency_posture["valid"],
        continuity_valid=not bool((continuity_state or {}).get("requires_revalidation")),
        expired=dependency_posture["expired"],
        dependency_failures=dependency_posture["failures"],
    )
    continuation_requirements_ = continuation_requirements(continuation_status)
    invalidation_reasons_ = invalidation_reasons(continuation_status)
    runtime_condition_checks_ = runtime_condition_checks(continuation_status)
    assessment = assess_admissibility(
        compiled_authority=compiled_authority,
        execution_request=execution_request,
        actor_identity=runtime_evidence["actor_identity"],
        continuity_state=continuity_state,
        replay_posture=replay_posture,
        evidence_posture={
            "approvals": runtime_evidence["approvals"],
            "execution_context": runtime_evidence["execution_context"],
            "runtime_dependencies": runtime_evidence["runtime_dependencies"],
            "continuation_status": continuation_status,
        },
    )
    chronology = build_chronology(
        authority_ref=authority_ref,
        timestamp=evaluation_time,
        assessment=assessment,
        start_sequence=start_sequence,
    )
    trace = build_guard_evaluation_trace(
        authority_ref=authority_ref,
        status=assessment["status"],
        rationale=assessment["rationale"],
        steps=[
            {
                "step": "compiled_authority_loaded",
                "status": "completed",
                "authority_ref": authority_ref,
            },
            {
                "step": "execution_request_projected",
                "status": "completed",
                "target": execution_request.get("target") or execution_request.get("action"),
            },
            {
                "step": "admissibility_assessed",
                "status": assessment["status"],
                "rationale": assessment["rationale"],
            },
            {
                "step": "runtime_posture_materialized",
                "status": "completed",
            },
        ],
    )
    projection = build_execution_admissibility_projection(
        authority=compiled_authority,
        execution_request=execution_request,
        actor_identity=actor_identity,
        **assessment,
    )
    continuity_posture = build_guard_continuity_posture(
        authority_ref=authority_ref,
        continuity_state=continuity_state,
        replay_posture=replay_posture,
        continuity_requirements=assessment["continuity_requirements"],
        replay_obligations=assessment["replay_obligations"],
    )
    outcome = build_guard_enforcement_outcome(
        authority_ref=authority_ref,
        status=assessment["status"],
        rationale=assessment["rationale"],
        consequences=assessment["enforcement_consequences"],
        continuation_status=continuation_status,
        continuation_requirements=continuation_requirements_,
        invalidation_reasons=invalidation_reasons_,
        runtime_condition_checks=runtime_condition_checks_,
    )
    runtime_posture = build_execution_runtime_posture(
        admissibility_projection=projection,
        continuity_posture=continuity_posture,
        enforcement_outcome=outcome,
        chronology=chronology,
    )

    return {
        "status": assessment["status"],
        "execution_state": execution_state_for_status(assessment["status"]),
        "admissible": assessment["status"] == "admissible",
        "blocked": assessment["status"] == "blocked",
        "escalated": assessment["status"] == "escalated",
        "rationale": assessment["rationale"],
        "violated_constraints": assessment["violated_constraints"],
        "required_evidence": assessment["required_evidence"],
        "replay_obligations": assessment["replay_obligations"],
        "continuity_requirements": assessment["continuity_requirements"],
        "continuation_status": continuation_status,
        "continuation_requirements": continuation_requirements_,
        "invalidation_reasons": invalidation_reasons_,
        "runtime_condition_checks": runtime_condition_checks_,
        "enforcement_consequences": assessment["enforcement_consequences"],
        "admissibility_projection": projection,
        "runtime_posture": runtime_posture,
        "telemetry_events": chronology,
        "telemetry_stream": telemetry_stream(chronology),
        "evaluation_trace": trace,
        "continuity_posture": continuity_posture,
        "enforcement_outcome": outcome,
        "runtime_evidence": runtime_evidence,
        "execution_posture_surface": project_execution_surface(runtime_posture),
    }


def _authority_ref(authority: dict[str, Any]) -> str:
    contract_id = authority.get("contract_id")
    contract_version = authority.get("contract_version")
    if contract_id and contract_version:
        return f"{contract_id}@{contract_version}"
    return str(authority.get("authority_ref") or authority.get("contract_ref") or "")
