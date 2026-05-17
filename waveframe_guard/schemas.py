from __future__ import annotations

import json
from typing import Any


GOVERNED_EXECUTION_STATE_V1 = "governed_execution_state.v1"
GOVERNED_EXECUTION_EVENT_V1 = "governed_execution.v1"
GOVERNED_EXECUTION_RESULT_V1 = "governed_execution_result.v1"


class SchemaValidationError(ValueError):
    pass


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def validate_execution_state(state: Any) -> None:
    if not isinstance(state, dict):
        raise SchemaValidationError("execution_state must be an object")
    _require_value(state, "schema_version", GOVERNED_EXECUTION_STATE_V1)
    _require_non_empty_string(state, "authority_ref")
    _require_object(state, "actor")
    _require_list(state, "approvals")
    _require_object(state, "arguments")
    _require_list(state, "artifacts")
    if state.get("action") is not None and not isinstance(state["action"], str):
        raise SchemaValidationError("execution_state action must be a string or null")
    if state.get("target") is not None and not isinstance(state["target"], str):
        raise SchemaValidationError("execution_state target must be a string or null")
    for approval in state["approvals"]:
        if not isinstance(approval, dict):
            raise SchemaValidationError("execution_state approvals must contain objects")


def validate_governed_event(event: Any) -> None:
    if not isinstance(event, dict):
        raise SchemaValidationError("governed event must be an object")
    _require_value(event, "schema_version", GOVERNED_EXECUTION_EVENT_V1)
    _require_value(event, "event_type", "governed_execution")
    _require_non_empty_string(event, "event_id")
    _require_non_empty_string(event, "timestamp")
    _require_non_empty_string(event, "decision")
    _require_non_empty_string(event, "reason")
    _require_object(event, "actor")
    _require_list(event, "approvals")
    _require_list(event, "missing_approvals")
    _require_non_empty_string(event, "authority_ref")
    _require_non_empty_string(event, "contract_ref")
    _require_non_empty_string(event, "contract_hash")
    if event["decision"] not in {"ALLOWED", "BLOCKED"}:
        raise SchemaValidationError("governed event decision must be ALLOWED or BLOCKED")
    if not isinstance(event.get("allowed"), bool):
        raise SchemaValidationError("governed event allowed must be boolean")
    if (event["decision"] == "ALLOWED") != event["allowed"]:
        raise SchemaValidationError("governed event decision and allowed disagree")
    validate_execution_state(event.get("execution_state"))


def validate_execution_result_payload(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise SchemaValidationError("execution result must be an object")
    _require_value(payload, "schema_version", GOVERNED_EXECUTION_RESULT_V1)
    _require_non_empty_string(payload, "decision")
    _require_non_empty_string(payload, "reason")
    _require_non_empty_string(payload, "authority_ref")
    _require_list(payload, "missing_approvals")
    _require_non_empty_string(payload, "contract_hash")
    if payload["decision"] not in {"ALLOWED", "BLOCKED"}:
        raise SchemaValidationError("execution result decision must be ALLOWED or BLOCKED")
    if not isinstance(payload.get("allowed"), bool):
        raise SchemaValidationError("execution result allowed must be boolean")
    if (payload["decision"] == "ALLOWED") != payload["allowed"]:
        raise SchemaValidationError("execution result decision and allowed disagree")
    validate_execution_state(payload.get("execution_state"))
    if payload.get("decision_trace") is not None and not isinstance(payload["decision_trace"], dict):
        raise SchemaValidationError("execution result decision_trace must be an object or null")


def _require_value(payload: dict[str, Any], field: str, expected: Any) -> None:
    if payload.get(field) != expected:
        raise SchemaValidationError(f"{field} must be {expected}")


def _require_non_empty_string(payload: dict[str, Any], field: str) -> None:
    if not isinstance(payload.get(field), str) or not payload[field]:
        raise SchemaValidationError(f"{field} must be a non-empty string")


def _require_object(payload: dict[str, Any], field: str) -> None:
    if not isinstance(payload.get(field), dict):
        raise SchemaValidationError(f"{field} must be an object")


def _require_list(payload: dict[str, Any], field: str) -> None:
    if not isinstance(payload.get(field), list):
        raise SchemaValidationError(f"{field} must be a list")
