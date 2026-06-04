from __future__ import annotations

from typing import Any


COMPILED_AUTHORITY_CONTRACT_V1 = "compiled_authority_contract.v1"

REQUIRED_COMPILED_AUTHORITY_FIELDS = {
    "schema_version",
    "contract_id",
    "contract_version",
    "contract_hash",
    "authority_requirements",
    "approval_requirements",
    "artifact_requirements",
    "stage_requirements",
    "invariants",
}

RAW_POLICY_FIELDS = {
    "policy",
    "policy_text",
    "raw_policy",
    "source_policy",
    "semantic_extraction",
    "authority_bundle",
}


class CompiledAuthorityIntakeError(ValueError):
    pass


def intake_compiled_authority(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CompiledAuthorityIntakeError("compiled authority must be an object")
    _reject_uncompiled_payload(payload)
    _validate_required_fields(payload)
    return dict(payload)


def _reject_uncompiled_payload(payload: dict[str, Any]) -> None:
    present_raw_fields = sorted(field for field in RAW_POLICY_FIELDS if field in payload)
    if present_raw_fields:
        raise CompiledAuthorityIntakeError(
            "Guard requires compiled authority; raw policy or semantic payload fields "
            f"are not admissible: {', '.join(present_raw_fields)}"
        )
    if payload.get("schema_version") != COMPILED_AUTHORITY_CONTRACT_V1:
        raise CompiledAuthorityIntakeError(
            f"compiled authority schema_version must be {COMPILED_AUTHORITY_CONTRACT_V1}"
        )


def _validate_required_fields(payload: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_COMPILED_AUTHORITY_FIELDS - payload.keys())
    if missing:
        raise CompiledAuthorityIntakeError(
            "compiled authority missing required fields: " + ", ".join(missing)
        )
    for field in [
        "contract_id",
        "contract_version",
        "contract_hash",
        "authority_requirements",
        "approval_requirements",
        "artifact_requirements",
        "stage_requirements",
        "invariants",
    ]:
        if payload.get(field) is None:
            raise CompiledAuthorityIntakeError(f"compiled authority {field} is required")
