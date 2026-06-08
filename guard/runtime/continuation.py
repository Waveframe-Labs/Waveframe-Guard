from __future__ import annotations

from typing import Any

from .dependencies import evaluate_runtime_dependencies, normalize_runtime_dependencies
from .identity import stable_hash, stable_id


GUARD_CONTINUATION_STATUS_V1 = "guard_continuation_status.v1"
GUARD_CONTINUATION_LEASE_V1 = "guard_continuation_lease.v1"
GUARD_RELEASE_VALIDATION_V1 = "guard_release_validation.v1"
CONTINUATION_STATUSES = {
    "admissible",
    "invalidated",
    "expired",
    "revalidation_required",
    "escalation_required",
}
RELEASE_VALIDATION_OUTCOMES = {
    "release_allowed",
    "release_blocked",
    "revalidation_required",
    "continuation_invalidated",
    "dependency_expired",
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


def build_continuation_lease(
    *,
    execution_id: str,
    authority_ref: str,
    issued_at: str,
    admissible_until: str,
    runtime_dependencies: list[dict[str, Any]] | None = None,
    continuation_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    continuation_status = continuation_status or evaluate_continuation()
    dependencies = normalize_runtime_dependencies(runtime_dependencies)
    payload = {
        "schema_version": GUARD_CONTINUATION_LEASE_V1,
        "execution_id": execution_id,
        "authority_ref": authority_ref,
        "issued_at": issued_at,
        "admissible_until": admissible_until,
        "runtime_dependencies": dependencies,
        "continuation_status": continuation_status,
        "revalidation_required": continuation_status.get("status") == "revalidation_required",
        "runtime_lifecycle_state": "admissible" if continuation_status.get("status") == "admissible" else continuation_status.get("lifecycle_state", "pending"),
    }
    payload["continuation_id"] = stable_id("continuation", payload)
    payload["lease_hash"] = stable_hash(payload)
    return payload


def validate_continuation(
    continuation_lease: dict[str, Any],
    *,
    runtime_state: dict[str, Any] | None = None,
    runtime_dependencies: list[dict[str, Any]] | None = None,
    release_time: str | None = None,
) -> dict[str, Any]:
    runtime_state = runtime_state or {}
    release_time = release_time or runtime_state.get("timestamp") or continuation_lease.get("admissible_until")
    dependencies = normalize_runtime_dependencies(
        runtime_dependencies
        if runtime_dependencies is not None
        else continuation_lease.get("runtime_dependencies", [])
    )
    dependency_posture = evaluate_runtime_dependencies(
        dependencies,
        evaluation_time=release_time,
    )
    lease_expired = _lease_expired(continuation_lease.get("admissible_until"), release_time)
    continuity_valid = not bool(runtime_state.get("requires_revalidation"))
    replay_valid = not bool(runtime_state.get("replay_required"))
    continuation_status = evaluate_continuation(
        replay_valid=replay_valid,
        dependency_valid=dependency_posture["valid"],
        continuity_valid=continuity_valid,
        expired=dependency_posture["expired"] or lease_expired,
        dependency_failures=dependency_posture["failures"],
    )
    if continuation_status["status"] == "admissible":
        outcome = "release_allowed"
        lifecycle_state = "released"
    elif continuation_status["status"] == "revalidation_required":
        outcome = "revalidation_required"
        lifecycle_state = "revalidation_required"
    elif continuation_status["status"] == "expired":
        outcome = "dependency_expired"
        lifecycle_state = "expired"
    elif continuation_status["status"] == "invalidated":
        outcome = "continuation_invalidated"
        lifecycle_state = "invalidated"
    else:
        outcome = "release_blocked"
        lifecycle_state = "continuation_required"

    release_allowed = outcome == "release_allowed"
    payload = {
        "schema_version": GUARD_RELEASE_VALIDATION_V1,
        "continuation_id": continuation_lease["continuation_id"],
        "execution_id": continuation_lease["execution_id"],
        "authority_ref": continuation_lease["authority_ref"],
        "release_time": release_time,
        "outcome": outcome,
        "release_allowed": release_allowed,
        "release_blocked": not release_allowed,
        "runtime_lifecycle_state": lifecycle_state,
        "continuation_status": continuation_status,
        "runtime_dependency_posture": dependency_posture,
        "invalidation_reasons": invalidation_reasons(continuation_status),
        "runtime_state": dict(runtime_state),
    }
    payload["release_validation_id"] = stable_id("release_validation", payload)
    payload["release_validation_hash"] = stable_hash(payload)
    return payload


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


def _lease_expired(admissible_until: str | None, release_time: str | None) -> bool:
    if not admissible_until or not release_time:
        return False
    return evaluate_runtime_dependencies(
        [
            {
                "dependency_type": "continuation_lease",
                "dependency_id": "admissible_until",
                "dependency_hash": "sha256:continuation-lease",
                "valid_until": admissible_until,
            }
        ],
        evaluation_time=release_time,
    )["expired"]
