from __future__ import annotations

from typing import Any


COMPILED_AUTHORITY_CONTRACT_V1 = "compiled_authority_contract.v1"
COMPILED_AUTHORITY_CONTRACT_V2 = "compiled_authority_contract.v2"

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


def intake_compiled_authority(
    payload: dict[str, Any],
    *,
    _verified_v2_authority: bool = False,
    _verified_runtime_authority: Any = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CompiledAuthorityIntakeError("compiled authority must be an object")
    if payload.get("schema_version") == "compiled_authority_contract.v3":
        from waveframe_guard.authority.runtime_facts import VerifiedRuntimeAuthority

        if type(_verified_runtime_authority) is not VerifiedRuntimeAuthority:
            raise CompiledAuthorityIntakeError("action authority requires a verified native publication")
        _verified_runtime_authority.verify_candidate_contract(payload)
        if _verified_runtime_authority.evidence()["authority_bundle"]["schema_version"] != "authority_bundle.v4":
            raise CompiledAuthorityIntakeError("action authority requires the native v4 publication pair")
        return dict(payload)
    if "action_requirements" in payload or "compiler_output" in payload:
        raise CompiledAuthorityIntakeError("action fields are forbidden in legacy authority")
    _reject_uncompiled_payload(payload, verified_v2_authority=_verified_v2_authority)
    _validate_required_fields(payload)
    return dict(payload)


def _reject_uncompiled_payload(payload: dict[str, Any], *, verified_v2_authority: bool) -> None:
    present_raw_fields = sorted(field for field in RAW_POLICY_FIELDS if field in payload)
    if present_raw_fields:
        raise CompiledAuthorityIntakeError(
            "Guard requires compiled authority; raw policy or semantic payload fields "
            f"are not admissible: {', '.join(present_raw_fields)}"
        )
    accepted = {COMPILED_AUTHORITY_CONTRACT_V1}
    if verified_v2_authority:
        accepted.add(COMPILED_AUTHORITY_CONTRACT_V2)
    if payload.get("schema_version") not in accepted:
        raise CompiledAuthorityIntakeError(
            "compiled authority schema_version must be "
            + " or ".join(sorted(accepted))
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
