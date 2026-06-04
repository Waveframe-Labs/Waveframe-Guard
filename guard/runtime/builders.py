from __future__ import annotations

from typing import Any

from .identity import stable_hash, stable_id


EXECUTION_ADMISSIBILITY_PROJECTION_V1 = "execution_admissibility_projection.v1"
EXECUTION_RUNTIME_POSTURE_V1 = "execution_runtime_posture.v1"
GUARD_RUNTIME_EVENT_V1 = "guard_runtime_event.v1"
GUARD_EVALUATION_TRACE_V1 = "guard_evaluation_trace.v1"
GUARD_CONTINUITY_POSTURE_V1 = "guard_continuity_posture.v1"
GUARD_ENFORCEMENT_OUTCOME_V1 = "guard_enforcement_outcome.v1"
GUARD_ENFORCEMENT_OUTCOME_STATUSES = {"admissible", "blocked", "escalated"}


class GuardEnforcementOutcomeError(ValueError):
    pass


def build_execution_admissibility_projection(
    *,
    authority: dict[str, Any],
    execution_request: dict[str, Any],
    actor_identity: dict[str, Any],
    status: str,
    rationale: str,
    violated_constraints: list[dict[str, Any]] | None = None,
    required_evidence: list[dict[str, Any]] | None = None,
    replay_obligations: list[dict[str, Any]] | None = None,
    continuity_requirements: list[dict[str, Any]] | None = None,
    enforcement_consequences: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": EXECUTION_ADMISSIBILITY_PROJECTION_V1,
        "authority_ref": _authority_ref(authority),
        "contract_hash": authority.get("contract_hash"),
        "execution_request": dict(execution_request),
        "actor_identity": dict(actor_identity),
        "status": status,
        "rationale": rationale,
        "violated_constraints": violated_constraints or [],
        "required_evidence": required_evidence or [],
        "replay_obligations": replay_obligations or [],
        "continuity_requirements": continuity_requirements or [],
        "enforcement_consequences": enforcement_consequences or [],
    }
    payload["projection_id"] = stable_id("admissibility_projection", payload)
    payload["projection_hash"] = stable_hash(payload)
    return payload


def build_execution_runtime_posture(
    *,
    admissibility_projection: dict[str, Any],
    continuity_posture: dict[str, Any],
    enforcement_outcome: dict[str, Any],
    chronology: list[dict[str, Any]],
) -> dict[str, Any]:
    blockers = list(admissibility_projection.get("violated_constraints", []))
    blockers.extend(admissibility_projection.get("required_evidence", []))
    payload = {
        "schema_version": EXECUTION_RUNTIME_POSTURE_V1,
        "posture": admissibility_projection["status"],
        "rationale": admissibility_projection["rationale"],
        "authority_ref": admissibility_projection["authority_ref"],
        "contract_hash": admissibility_projection.get("contract_hash"),
        "execution_request": admissibility_projection["execution_request"],
        "actor_identity": admissibility_projection["actor_identity"],
        "runtime_blockers": blockers,
        "continuity_state": continuity_posture,
        "replay_requirements": admissibility_projection.get("replay_obligations", []),
        "enforcement_outcome": enforcement_outcome,
        "chronology_event_ids": [event["event_id"] for event in chronology],
        "telemetry_event_types": [event["event_type"] for event in chronology],
    }
    payload["posture_id"] = stable_id("runtime_posture", payload)
    payload["posture_hash"] = stable_hash(payload)
    return payload


def build_guard_runtime_event(
    *,
    sequence: int,
    event_type: str,
    timestamp: str,
    authority_ref: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": GUARD_RUNTIME_EVENT_V1,
        "sequence": sequence,
        "event_type": event_type,
        "timestamp": timestamp,
        "authority_ref": authority_ref,
        "details": details or {},
    }
    payload["event_id"] = stable_id("guard_event", payload)
    payload["event_hash"] = stable_hash(payload)
    return payload


def build_guard_evaluation_trace(
    *,
    authority_ref: str,
    status: str,
    rationale: str,
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    payload = {
        "schema_version": GUARD_EVALUATION_TRACE_V1,
        "authority_ref": authority_ref,
        "status": status,
        "rationale": rationale,
        "steps": steps,
    }
    payload["trace_id"] = stable_id("guard_trace", payload)
    payload["trace_hash"] = stable_hash(payload)
    return payload


def build_guard_continuity_posture(
    *,
    authority_ref: str,
    continuity_state: dict[str, Any] | None = None,
    replay_posture: dict[str, Any] | None = None,
    continuity_requirements: list[dict[str, Any]] | None = None,
    replay_obligations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    continuity_state = continuity_state or {}
    replay_posture = replay_posture or {}
    payload = {
        "schema_version": GUARD_CONTINUITY_POSTURE_V1,
        "authority_ref": authority_ref,
        "continuity_state": continuity_state,
        "replay_posture": replay_posture,
        "continuity_requirements": continuity_requirements or [],
        "replay_obligations": replay_obligations or [],
        "requires_revalidation": bool(continuity_requirements),
        "requires_replay": bool(replay_obligations),
        "signals": list(continuity_state.get("signals", [])),
    }
    payload["posture_id"] = stable_id("continuity_posture", payload)
    payload["posture_hash"] = stable_hash(payload)
    return payload


def build_guard_enforcement_outcome(
    *,
    authority_ref: str,
    status: str,
    rationale: str,
    consequences: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": GUARD_ENFORCEMENT_OUTCOME_V1,
        "authority_ref": authority_ref,
        "status": status,
        "rationale": rationale,
        "consequences": consequences or [],
    }
    payload["outcome_id"] = stable_id("enforcement_outcome", payload)
    payload["outcome_hash"] = stable_hash(payload)
    validate_guard_enforcement_outcome(payload)
    return payload


def validate_guard_enforcement_outcome(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise GuardEnforcementOutcomeError("guard enforcement outcome must be an object")
    required = {
        "schema_version",
        "authority_ref",
        "status",
        "rationale",
        "consequences",
        "outcome_id",
        "outcome_hash",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise GuardEnforcementOutcomeError(
            "guard enforcement outcome missing required fields: " + ", ".join(missing)
        )
    if payload["schema_version"] != GUARD_ENFORCEMENT_OUTCOME_V1:
        raise GuardEnforcementOutcomeError(
            f"guard enforcement outcome schema_version must be {GUARD_ENFORCEMENT_OUTCOME_V1}"
        )
    if payload["status"] not in GUARD_ENFORCEMENT_OUTCOME_STATUSES:
        raise GuardEnforcementOutcomeError("guard enforcement outcome status is not recognized")
    if not isinstance(payload["consequences"], list):
        raise GuardEnforcementOutcomeError("guard enforcement outcome consequences must be a list")
    return dict(payload)


def _authority_ref(authority: dict[str, Any]) -> str:
    contract_id = authority.get("contract_id")
    contract_version = authority.get("contract_version")
    if contract_id and contract_version:
        return f"{contract_id}@{contract_version}"
    return str(authority.get("authority_ref") or authority.get("contract_ref") or "")
