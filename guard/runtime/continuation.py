from __future__ import annotations

from typing import Any


GUARD_CONTINUATION_STATUS_V1 = "guard_continuation_status.v1"
CONTINUATION_STATUSES = {
    "admissible",
    "invalidated",
    "expired",
    "revalidation_required",
    "escalation_required",
}
RUNTIME_LIFECYCLE_STATES = {
    "pending",
    "admissible",
    "continuation_required",
    "revalidation_required",
    "invalidated",
    "expired",
    "escalated",
    "blocked",
    "released",
    "executed",
}


def evaluate_continuation(
    *,
    evidence_valid: bool = True,
    replay_valid: bool = True,
    dependency_valid: bool = True,
    continuity_valid: bool = True,
    expired: bool = False,
    dependency_failures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    dependency_failures = dependency_failures or []
    if expired:
        status = "expired"
    elif not evidence_valid or not dependency_valid:
        status = "invalidated"
    elif not continuity_valid:
        status = "revalidation_required"
    elif not replay_valid:
        status = "escalation_required"
    else:
        status = "admissible"
    lifecycle_state = _continuation_lifecycle_state(status)

    return {
        "schema_version": GUARD_CONTINUATION_STATUS_V1,
        "status": status,
        "lifecycle_state": lifecycle_state,
        "admissible": status == "admissible",
        "invalidated": status == "invalidated",
        "expired": status == "expired",
        "revalidation_required": status == "revalidation_required",
        "escalation_required": status == "escalation_required",
        "evidence_valid": evidence_valid,
        "replay_valid": replay_valid,
        "dependency_valid": dependency_valid,
        "continuity_valid": continuity_valid,
        "dependency_failures": dependency_failures,
    }


def runtime_lifecycle_state(*, evaluation_status: str, continuation_status: dict[str, Any]) -> str:
    continuation_lifecycle = continuation_status.get("lifecycle_state")
    if continuation_lifecycle in {"expired", "invalidated", "revalidation_required", "continuation_required"}:
        return continuation_lifecycle
    if evaluation_status == "admissible":
        return "admissible"
    if evaluation_status == "escalated":
        return "escalated"
    return "blocked"


def continuation_requirements(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    status = continuation_status.get("status")
    if status == "revalidation_required":
        return [
            {
                "requirement": "revalidate_continuation",
                "rationale": "lineage continuity must be revalidated before execution can proceed",
            }
        ]
    if status == "escalation_required":
        return [
            {
                "requirement": "escalate_continuation",
                "rationale": "replay posture requires an external continuation decision",
            }
        ]
    if status == "expired":
        return [
            {
                "requirement": "refresh_runtime_dependencies",
                "rationale": "one or more runtime dependencies expired before execution",
            }
        ]
    if status == "invalidated":
        return [
            {
                "requirement": "rebuild_replay_basis",
                "rationale": "one or more runtime conditions diverged from the replay basis",
            }
        ]
    return []


def invalidation_reasons(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    status = continuation_status.get("status")
    if status not in {"invalidated", "expired"}:
        return []
    failures = continuation_status.get("dependency_failures") or []
    if failures:
        return failures
    return [
        {
            "reason": status,
            "rationale": "continuation validity failed before execution",
        }
    ]


def runtime_condition_checks(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "condition": "evidence_valid",
            "valid": bool(continuation_status.get("evidence_valid", True)),
            "rationale": "runtime evidence validity checked",
        },
        {
            "condition": "replay_valid",
            "valid": bool(continuation_status.get("replay_valid", True)),
            "rationale": "replay posture validity checked",
        },
        {
            "condition": "dependency_valid",
            "valid": bool(continuation_status.get("dependency_valid", True)),
            "rationale": "runtime dependency validity checked",
        },
        {
            "condition": "continuity_valid",
            "valid": bool(continuation_status.get("continuity_valid", True)),
            "rationale": "lineage continuity validity checked",
        },
        {
            "condition": "not_expired",
            "valid": not bool(continuation_status.get("expired", False)),
            "rationale": "continuation did not expire before execution",
        },
    ]


def _continuation_lifecycle_state(status: str) -> str:
    if status == "escalation_required":
        return "continuation_required"
    if status in RUNTIME_LIFECYCLE_STATES:
        return status
    return "pending"
