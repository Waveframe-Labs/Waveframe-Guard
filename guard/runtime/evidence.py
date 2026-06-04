from __future__ import annotations

from typing import Any


GUARD_RUNTIME_EVIDENCE_MODEL_V1 = "guard_runtime_evidence_model.v1"

REQUIRED_EVIDENCE_FIELDS = {
    "schema_version",
    "actor_identity",
    "approvals",
    "replay_evidence",
    "continuity_snapshot",
    "timestamp_source",
    "execution_context",
}


class RuntimeEvidenceError(ValueError):
    pass


def build_runtime_evidence_model(
    *,
    actor_identity: dict[str, Any],
    approvals: list[dict[str, Any]] | None = None,
    replay_evidence: dict[str, Any] | None = None,
    continuity_snapshot: dict[str, Any] | None = None,
    timestamp_source: dict[str, Any] | None = None,
    execution_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": GUARD_RUNTIME_EVIDENCE_MODEL_V1,
        "actor_identity": dict(actor_identity),
        "approvals": list(approvals or []),
        "replay_evidence": dict(replay_evidence or {}),
        "continuity_snapshot": dict(continuity_snapshot or {}),
        "timestamp_source": dict(timestamp_source or {}),
        "execution_context": dict(execution_context or {}),
    }
    validate_runtime_evidence_model(payload)
    return payload


def validate_runtime_evidence_model(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeEvidenceError("runtime evidence model must be an object")
    if payload.get("schema_version") != GUARD_RUNTIME_EVIDENCE_MODEL_V1:
        raise RuntimeEvidenceError(
            f"runtime evidence schema_version must be {GUARD_RUNTIME_EVIDENCE_MODEL_V1}"
        )
    missing = sorted(REQUIRED_EVIDENCE_FIELDS - payload.keys())
    if missing:
        raise RuntimeEvidenceError("runtime evidence missing required fields: " + ", ".join(missing))
    for field in ["actor_identity", "replay_evidence", "continuity_snapshot", "timestamp_source", "execution_context"]:
        if not isinstance(payload.get(field), dict):
            raise RuntimeEvidenceError(f"runtime evidence {field} must be an object")
    if not isinstance(payload.get("approvals"), list):
        raise RuntimeEvidenceError("runtime evidence approvals must be a list")
    return dict(payload)
