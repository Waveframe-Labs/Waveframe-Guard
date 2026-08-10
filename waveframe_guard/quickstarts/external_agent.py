"""
---
title: "Waveframe Guard external agent quickstart"
filetype: "source-code"
domain: "guard-sdk"
status: "preview"
ai_assisted: "partial"
---
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from waveframe_guard import Guard


@dataclass(frozen=True)
class QuickstartSettings:
    cloud_url: str
    organization_id: str
    api_key: str
    runtime_id: str
    environment: str
    actor_id: str
    actor_role: str
    authority_ref: str

    @classmethod
    def from_environment(cls) -> "QuickstartSettings":
        return cls(
            cloud_url=_required_setting("WAVEFRAME_CLOUD_URL"),
            organization_id=_required_setting("WAVEFRAME_CLOUD_ORGANIZATION_ID"),
            api_key=_required_setting("WAVEFRAME_CLOUD_API_KEY"),
            runtime_id=_required_setting("WAVEFRAME_RUNTIME_ID"),
            environment=os.environ.get("WAVEFRAME_RUNTIME_ENVIRONMENT", "development"),
            actor_id=_required_setting("WAVEFRAME_ACTOR_ID"),
            actor_role=_required_setting("WAVEFRAME_ACTOR_ROLE"),
            authority_ref=_required_setting("WAVEFRAME_AUTHORITY_REF"),
        )


def build_guard(settings: QuickstartSettings) -> Guard:
    return Guard.cloud(
        cloud_url=settings.cloud_url,
        cloud_organization_id=settings.organization_id,
        cloud_api_key=settings.api_key,
        runtime_id=settings.runtime_id,
        environment=settings.environment,
        authority=settings.authority_ref,
        actor_identity={
            "id": settings.actor_id,
            "type": "agent",
            "role": settings.actor_role,
        },
    )


def run_quickstart(
    guard: Guard,
    settings: QuickstartSettings,
) -> dict[str, Any]:
    _require_runtime_connection(guard, settings.api_key)
    mutations: list[dict[str, Any]] = []

    @guard.tool(
        authority=settings.authority_ref,
        action="allocate_budget",
        target="account_id",
        include_arguments=("amount",),
        agent={"framework": "custom-python"},
        raise_on_block=False,
        return_result=True,
    )
    def allocate_budget(account_id: str, amount: int) -> dict[str, Any]:
        mutation = {"account_id": account_id, "amount": amount}
        mutations.append(mutation)
        return mutation

    allowed = allocate_budget("quickstart-account", 500)
    blocked = allocate_budget("quickstart-account", 12_500)

    if allowed["executed"] is not True:
        raise RuntimeError(
            _unexpected_decision_message(
                action="500-unit action",
                expected="allowed",
                result=allowed,
            )
        )
    if blocked["executed"] is not False:
        raise RuntimeError(
            _unexpected_decision_message(
                action="12,500-unit action",
                expected="blocked",
                result=blocked,
            )
        )
    if mutations != [{"account_id": "quickstart-account", "amount": 500}]:
        raise RuntimeError("Exactly-once mutation assertion failed")

    allowed_preservation = _require_cloud_preservation(
        action="allowed 500-unit action",
        result=allowed,
        api_key=settings.api_key,
    )
    blocked_preservation = _require_cloud_preservation(
        action="blocked 12,500-unit action",
        result=blocked,
        api_key=settings.api_key,
    )
    _require_cloud_operation(
        operation="runtime attestation",
        action="allowed 500-unit action",
        result=allowed.get("cloud_runtime_attestation"),
        api_key=settings.api_key,
    )
    _require_cloud_operation(
        operation="runtime attestation",
        action="blocked 12,500-unit action",
        result=blocked.get("cloud_runtime_attestation"),
        api_key=settings.api_key,
    )
    summary = {
        "runtime_id": settings.runtime_id,
        "actor_id": settings.actor_id,
        "authority_ref": allowed["outcome"]["authority_ref"],
        "allowed_decision": allowed["outcome"]["execution_state"],
        "blocked_decision": blocked["outcome"]["execution_state"],
        "mutation_count": len(mutations),
        "exactly_once": True,
        "allowed_package_id": allowed_preservation["package_id"],
        "allowed_receipt_id": allowed_preservation["receipt_id"],
        "allowed_proof_sha256": allowed_preservation["sha256"],
        "blocked_package_id": blocked_preservation["package_id"],
        "blocked_receipt_id": blocked_preservation["receipt_id"],
        "blocked_proof_sha256": blocked_preservation["sha256"],
    }

    for key, value in summary.items():
        print(f"{key}={value}")
    print("console_check=Open Activity or Executions and verify both decisions by runtime and authority.")
    return summary


def main() -> None:
    settings = QuickstartSettings.from_environment()
    run_quickstart(build_guard(settings), settings)


def _required_setting(name: str) -> str:
    value = os.environ.get(name)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _unexpected_decision_message(
    *,
    action: str,
    expected: str,
    result: dict[str, Any],
) -> str:
    evaluation = result["evaluation"]
    return (
        f"Quickstart authority produced an unexpected decision for the {action}:\n"
        f"expected decision: {expected}\n"
        f"observed execution_state: {evaluation.get('execution_state')}\n"
        f"Guard rationale: {evaluation.get('rationale')}\n"
        f"violated constraints: {evaluation.get('violated_constraints')}\n"
        f"required evidence: {evaluation.get('required_evidence')}"
    )


def _require_cloud_preservation(
    *,
    action: str,
    result: Mapping[str, Any],
    api_key: str,
) -> dict[str, Any]:
    preservation = result.get("cloud_preservation")
    required_identifiers = ("package_id", "receipt_id", "sha256", "timestamp")
    missing = [
        name
        for name in required_identifiers
        if not isinstance(_result_value(preservation, name), str)
        or not _result_value(preservation, name)
    ]
    if _result_value(preservation, "ok") is not True or missing:
        error_type = _result_value(preservation, "error_type")
        if missing and not error_type:
            error_type = "invalid_response"
        cloud_error = _result_value(preservation, "error")
        if not cloud_error and missing:
            cloud_error = (
                "Cloud preservation response missing required fields: "
                + ", ".join(missing)
            )
        if not cloud_error:
            cloud_error = _result_value(preservation, "response") or "no Cloud error returned"
        raise RuntimeError(
            _cloud_failure_message(
                operation="preservation",
                action=action,
                status_code=_result_value(preservation, "status_code"),
                error_type=error_type or "missing_result",
                cloud_error=cloud_error,
                api_key=api_key,
            )
        )
    return {name: _result_value(preservation, name) for name in required_identifiers}


def _require_cloud_operation(
    *,
    operation: str,
    action: str,
    result: Any,
    api_key: str,
) -> None:
    if _result_value(result, "ok") is True:
        return
    raise RuntimeError(
        _cloud_failure_message(
            operation=operation,
            action=action,
            status_code=_result_value(result, "status_code"),
            error_type=_result_value(result, "error_type") or "missing_result",
            cloud_error=(
                _result_value(result, "error")
                or _result_value(result, "response")
                or "no Cloud error returned"
            ),
            api_key=api_key,
        )
    )


def _require_runtime_connection(guard: Guard, api_key: str) -> None:
    connection = getattr(guard, "runtime_connection", None)
    if _result_value(connection, "ok") is True:
        return
    registration = _result_value(connection, "registration")
    heartbeat = _result_value(connection, "heartbeat")
    failed = registration
    action = "registration"
    if _result_value(registration, "ok") is True:
        failed = heartbeat
        action = "heartbeat"
    _require_cloud_operation(
        operation="runtime reporting",
        action=action,
        result=failed,
        api_key=api_key,
    )


def _cloud_failure_message(
    *,
    operation: str,
    action: str,
    status_code: Any,
    error_type: Any,
    cloud_error: Any,
    api_key: str,
) -> str:
    status = status_code if status_code is not None else "not reported"
    return (
        f"Cloud {operation} failed for the {action}:\n"
        f"HTTP status: {status}\n"
        f"error_type: {error_type}\n"
        f"Cloud error: {_sanitized_cloud_value(cloud_error, api_key)}"
    )


def _result_value(result: Any, name: str) -> Any:
    if isinstance(result, Mapping):
        return result.get(name)
    return getattr(result, name, None)


def _sanitized_cloud_value(value: Any, api_key: str) -> str:
    sanitized = _redact_sensitive_fields(value, api_key)
    if isinstance(sanitized, str):
        return sanitized
    return json.dumps(sanitized, sort_keys=True, default=str)


def _redact_sensitive_fields(value: Any, api_key: str) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in {"api_key", "secret", "token", "authorization"}
                else _redact_sensitive_fields(item, api_key)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_sensitive_fields(item, api_key) for item in value]
    if isinstance(value, str) and api_key:
        return value.replace(api_key, "[REDACTED]")
    return value


if __name__ == "__main__":
    main()
