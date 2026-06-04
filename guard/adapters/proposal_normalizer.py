from __future__ import annotations

from typing import Any


NORMALIZED_EXECUTION_REQUEST_V1 = "normalized_execution_request.v1"

REQUIRED_NORMALIZED_REQUEST_FIELDS = {
    "schema_version",
    "request_id",
    "action",
    "target",
    "arguments",
    "artifacts",
}

UNNORMALIZED_REQUEST_FIELDS = {
    "raw_prompt",
    "raw_request",
    "policy_text",
    "natural_language_request",
}


class ExecutionRequestNormalizationError(ValueError):
    pass


def require_normalized_execution_request(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ExecutionRequestNormalizationError("execution request must be an object")
    raw_fields = sorted(field for field in UNNORMALIZED_REQUEST_FIELDS if field in payload)
    if raw_fields:
        raise ExecutionRequestNormalizationError(
            "Guard requires a normalized execution request; raw request fields are not "
            f"admissible: {', '.join(raw_fields)}"
        )
    if payload.get("schema_version") != NORMALIZED_EXECUTION_REQUEST_V1:
        raise ExecutionRequestNormalizationError(
            f"execution request schema_version must be {NORMALIZED_EXECUTION_REQUEST_V1}"
        )
    missing = sorted(REQUIRED_NORMALIZED_REQUEST_FIELDS - payload.keys())
    if missing:
        raise ExecutionRequestNormalizationError(
            "normalized execution request missing required fields: " + ", ".join(missing)
        )
    return dict(payload)


def normalize_with_proposal_normalizer(**kwargs: Any) -> dict[str, Any]:
    from proposal_normalizer.build_proposal import build_proposal

    proposal = build_proposal(**kwargs)
    return {
        "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
        "request_id": proposal["proposal_id"],
        "action": proposal["requested_mutation"]["action"],
        "target": proposal["requested_mutation"]["resource"],
        "arguments": {},
        "artifacts": proposal.get("artifacts", []),
        "normalization": {
            "adapter": "proposal_normalizer.build_proposal",
            "proposal": proposal,
        },
    }
