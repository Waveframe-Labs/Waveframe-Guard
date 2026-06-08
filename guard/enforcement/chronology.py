from __future__ import annotations

from typing import Any

from guard.runtime.builders import build_guard_runtime_event
from guard.runtime.dependencies import dependency_relative_delta_ms


def build_chronology(
    *,
    authority_ref: str,
    timestamp: str,
    assessment: dict[str, Any],
    start_sequence: int = 1,
) -> list[dict[str, Any]]:
    continuation_status = assessment.get("continuation_status") or {}
    dependency_posture = assessment.get("runtime_dependency_posture") or {}
    event_specs = [
        (
            "authority_context_resolved",
            {"contract_boundary": "compiled_authority"},
        ),
        (
            "evaluation_pipeline_started",
            {"status": "started"},
        ),
        (
            "runtime_evidence_loaded",
            {
                "evidence_boundary": "guard_runtime_evidence_model.v1",
                "required_evidence": assessment["required_evidence"],
            },
        ),
        *_dependency_link_event_specs(dependency_posture),
        (
            "continuity_checked",
            {
                "continuity_requirements": assessment["continuity_requirements"],
            },
        ),
        (
            "replay_validated",
            {
                "replay_obligations": assessment["replay_obligations"],
            },
        ),
        *_continuation_event_specs(continuation_status, dependency_posture),
        (
            "admissibility_evaluated",
            {
                "status": assessment["status"],
                "runtime_lifecycle_state": assessment.get("runtime_lifecycle_state"),
                "violated_constraints": assessment["violated_constraints"],
                "required_evidence": assessment["required_evidence"],
            },
        ),
        (
            "enforcement_outcome_recorded",
            {
                "status": assessment["status"],
                "runtime_lifecycle_state": assessment.get("runtime_lifecycle_state"),
                "consequences": assessment["enforcement_consequences"],
            },
        ),
    ]
    return [
        build_guard_runtime_event(
            sequence=start_sequence + index,
            event_type=event_type,
            timestamp=timestamp,
            authority_ref=authority_ref,
            details=details,
        )
        for index, (event_type, details) in enumerate(event_specs)
    ]


def _dependency_link_event_specs(dependency_posture: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    specs: list[tuple[str, dict[str, Any]]] = []
    for index, dependency in enumerate(dependency_posture.get("dependencies") or []):
        specs.append(
            (
                "runtime_dependency_linked",
                {
                    "dependency": dependency,
                    "relative_delta_ms": dependency_relative_delta_ms(
                        dependency,
                        event="linked",
                        default_ms=5 + index,
                    ),
                },
            )
        )
    return specs


def _continuation_event_specs(
    continuation_status: dict[str, Any],
    dependency_posture: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    if not continuation_status:
        return []
    specs: list[tuple[str, dict[str, Any]]] = []
    failures = continuation_status.get("dependency_failures") or []
    dependencies = {
        dependency.get("dependency_id"): dependency
        for dependency in dependency_posture.get("dependencies") or []
    }
    for index, failure in enumerate(failures):
        event_type = "runtime_dependency_expired" if failure.get("reason") == "dependency_expired" else "runtime_dependency_invalidated"
        dependency = dependencies.get(failure.get("dependency_id"), {})
        specs.append(
            (
                event_type,
                {
                    "continuation_status": continuation_status.get("status"),
                    "dependency_failures": [failure],
                    "relative_delta_ms": dependency_relative_delta_ms(
                        dependency,
                        event="expired" if event_type == "runtime_dependency_expired" else "invalidated",
                        default_ms=1_800_000 + (index * 60_000),
                    ),
                },
            )
        )
    if continuation_status.get("status") in {"expired", "invalidated"}:
        specs.append(
            (
                "continuation_invalidated",
                {
                    "continuation_status": continuation_status,
                    "runtime_lifecycle_state": continuation_status.get("lifecycle_state"),
                    "relative_delta_ms": 1_860_000,
                },
            )
        )
    if continuation_status.get("status") != "admissible":
        specs.append(
            (
                "continuation_evaluated",
                {
                    "continuation_status": continuation_status,
                    "runtime_lifecycle_state": continuation_status.get("lifecycle_state"),
                    "relative_delta_ms": 1_920_000 if continuation_status.get("status") in {"expired", "invalidated"} else 11,
                },
            )
        )
    return specs
