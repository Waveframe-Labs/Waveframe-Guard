from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


GUARD_CONTINUATION_STATUS_V1 = "guard_continuation_status.v1"
CONTINUATION_STATUSES = {
    "admissible",
    "invalidated",
    "expired",
    "revalidation_required",
    "escalation_required",
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

    return {
        "schema_version": GUARD_CONTINUATION_STATUS_V1,
        "status": status,
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


def evaluate_runtime_dependencies(
    dependencies: list[dict[str, Any]] | None,
    *,
    evaluation_time: str,
) -> dict[str, Any]:
    failures = []
    for dependency in dependencies or []:
        if dependency.get("valid") is False:
            failures.append(_dependency_failure(dependency, "dependency_invalidated", "runtime dependency is marked invalid"))
        if dependency.get("observed_hash") and dependency.get("hash") and dependency["observed_hash"] != dependency["hash"]:
            failures.append(_dependency_failure(dependency, "dependency_drift", "runtime dependency hash drift detected"))
        if _is_expired(dependency.get("valid_until"), evaluation_time):
            failures.append(_dependency_failure(dependency, "dependency_expired", "runtime dependency expired"))
    return {
        "valid": not failures,
        "expired": any(failure["reason"] == "dependency_expired" for failure in failures),
        "failures": failures,
    }


def _dependency_failure(dependency: dict[str, Any], reason: str, rationale: str) -> dict[str, Any]:
    return {
        "dependency_type": dependency.get("type"),
        "dependency_id": dependency.get("id"),
        "reason": reason,
        "rationale": rationale,
        "valid_until": dependency.get("valid_until"),
    }


def _is_expired(valid_until: str | None, evaluation_time: str) -> bool:
    if not valid_until:
        return False
    try:
        return _parse_time(valid_until) <= _parse_time(evaluation_time)
    except ValueError:
        return True


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
