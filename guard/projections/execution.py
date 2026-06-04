from __future__ import annotations

from typing import Any


def project_execution_surface(runtime_posture: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "execution_posture_surface.v1",
        "posture": runtime_posture["posture"],
        "rationale": runtime_posture["rationale"],
        "runtime_blockers": runtime_posture["runtime_blockers"],
        "continuity_state": runtime_posture["continuity_state"],
        "replay_requirements": runtime_posture["replay_requirements"],
        "chronology_event_ids": runtime_posture["chronology_event_ids"],
    }
