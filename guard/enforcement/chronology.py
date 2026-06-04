from __future__ import annotations

from typing import Any

from guard.runtime.builders import build_guard_runtime_event


def build_chronology(
    *,
    authority_ref: str,
    timestamp: str,
    assessment: dict[str, Any],
    start_sequence: int = 1,
) -> list[dict[str, Any]]:
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
            "admissibility_cognition_completed",
            {
                "status": assessment["status"],
                "violated_constraints": assessment["violated_constraints"],
                "required_evidence": assessment["required_evidence"],
            },
        ),
        (
            "continuity_posture_evaluated",
            {
                "continuity_requirements": assessment["continuity_requirements"],
                "replay_obligations": assessment["replay_obligations"],
            },
        ),
        (
            "enforcement_outcome_recorded",
            {
                "status": assessment["status"],
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
