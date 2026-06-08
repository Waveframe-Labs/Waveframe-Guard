from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


RUNTIME_DEPENDENCY_V1 = "guard_runtime_dependency.v1"
RUNTIME_DEPENDENCY_STATUSES = {"valid", "invalid", "revoked", "expired", "drifted"}


class RuntimeDependencyError(ValueError):
    pass


def normalize_runtime_dependencies(dependencies: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [normalize_runtime_dependency(dependency) for dependency in dependencies or []]


def normalize_runtime_dependency(dependency: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(dependency, dict):
        raise RuntimeDependencyError("runtime dependency must be an object")
    dependency_type = dependency.get("dependency_type") or dependency.get("type")
    dependency_id = dependency.get("dependency_id") or dependency.get("id")
    dependency_hash = dependency.get("dependency_hash") or dependency.get("hash")
    current_hash = dependency.get("current_hash") or dependency.get("observed_hash")
    if not dependency_type:
        raise RuntimeDependencyError("runtime dependency missing dependency_type")
    if not dependency_id:
        raise RuntimeDependencyError("runtime dependency missing dependency_id")
    if not dependency_hash:
        raise RuntimeDependencyError("runtime dependency missing dependency_hash")

    status = dependency.get("status")
    if status is None:
        status = "valid" if dependency.get("valid", True) is not False else "invalid"
    if status not in RUNTIME_DEPENDENCY_STATUSES:
        raise RuntimeDependencyError("runtime dependency status is not recognized")

    normalized = {
        "schema_version": dependency.get("schema_version") or RUNTIME_DEPENDENCY_V1,
        "dependency_type": dependency_type,
        "dependency_id": dependency_id,
        "dependency_hash": dependency_hash,
        "current_hash": current_hash or dependency_hash,
        "valid_until": dependency.get("valid_until"),
        "status": status,
    }
    if dependency.get("linked_at"):
        normalized["linked_at"] = dependency["linked_at"]
    if dependency.get("source"):
        normalized["source"] = dependency["source"]
    validate_runtime_dependency(normalized)
    return normalized


def validate_runtime_dependency(dependency: dict[str, Any]) -> dict[str, Any]:
    if dependency.get("schema_version") != RUNTIME_DEPENDENCY_V1:
        raise RuntimeDependencyError(f"runtime dependency schema_version must be {RUNTIME_DEPENDENCY_V1}")
    for field in ["dependency_type", "dependency_id", "dependency_hash", "current_hash", "status"]:
        if not dependency.get(field):
            raise RuntimeDependencyError(f"runtime dependency missing {field}")
    if dependency["status"] not in RUNTIME_DEPENDENCY_STATUSES:
        raise RuntimeDependencyError("runtime dependency status is not recognized")
    return dict(dependency)


def evaluate_runtime_dependencies(
    dependencies: list[dict[str, Any]] | None,
    *,
    evaluation_time: str,
) -> dict[str, Any]:
    normalized = normalize_runtime_dependencies(dependencies)
    failures = []
    for dependency in normalized:
        if dependency["status"] != "valid":
            failures.append(_dependency_failure(dependency, "dependency_invalidated", "runtime dependency is not valid"))
        if dependency["current_hash"] != dependency["dependency_hash"]:
            failures.append(_dependency_failure(dependency, "dependency_drift", "runtime dependency hash drift detected"))
        if _is_expired(dependency.get("valid_until"), evaluation_time):
            failures.append(_dependency_failure(dependency, "dependency_expired", "runtime dependency expired"))
    return {
        "schema_version": "guard_runtime_dependency_posture.v1",
        "dependencies": normalized,
        "valid": not failures,
        "expired": any(failure["reason"] == "dependency_expired" for failure in failures),
        "failures": failures,
    }


def dependency_relative_delta_ms(dependency: dict[str, Any], *, event: str, default_ms: int) -> int:
    if event == "linked":
        return default_ms
    linked_at = dependency.get("linked_at")
    valid_until = dependency.get("valid_until")
    if linked_at and valid_until:
        try:
            return max(0, int((_parse_time(valid_until) - _parse_time(linked_at)).total_seconds() * 1000))
        except ValueError:
            return default_ms
    return default_ms


def _dependency_failure(dependency: dict[str, Any], reason: str, rationale: str) -> dict[str, Any]:
    return {
        "dependency_type": dependency.get("dependency_type"),
        "dependency_id": dependency.get("dependency_id"),
        "dependency_hash": dependency.get("dependency_hash"),
        "current_hash": dependency.get("current_hash"),
        "reason": reason,
        "rationale": rationale,
        "valid_until": dependency.get("valid_until"),
        "linked_at": dependency.get("linked_at"),
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
