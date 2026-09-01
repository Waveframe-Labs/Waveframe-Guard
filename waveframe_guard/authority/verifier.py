from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from time import perf_counter_ns
from typing import Any, Mapping

from .exceptions import AuthorityLifecycleError, AuthorityVerificationError
from .types import Bundle, LoadedAuthority, RegistryEntry


class _ProcessVerificationMarker:
    def __deepcopy__(self, memo: dict[int, Any]) -> "_ProcessVerificationMarker":
        return self


_PROCESS_VERIFICATION_MARKER = _ProcessVerificationMarker()


def _is_process_verified_v2(authority: LoadedAuthority) -> bool:
    return authority._verification_marker is _PROCESS_VERIFICATION_MARKER


class AuthorityVerifier:
    def verify(self, bundle: Bundle) -> LoadedAuthority:
        if bundle.payload.get("schema_version") == "authority_bundle.v2":
            return _verify_v2_authority(bundle)
        registry_entry = bundle.registry_entry
        contract = _bundle_contract(bundle)
        _verify_authority_ref(bundle)
        contract_hash = _verify_contract_hash(bundle, contract)
        _verify_bundle_hash(bundle)
        _verify_registry_lifecycle_state(registry_entry)
        return LoadedAuthority(
            authority_ref=registry_entry.authority_ref,
            publication_id=registry_entry.publication_id,
            contract=contract,
            contract_hash=contract_hash,
            bundle_hash=bundle.bundle_hash,
            bundle_path=bundle.bundle_path,
            lifecycle_state=registry_entry.lifecycle_state,
            published_at=registry_entry.published_at,
            published_by=registry_entry.published_by,
            authority_bundle=deepcopy(bundle.payload),
        )

    def verify_registry_entry(
        self,
        registry_entry: RegistryEntry,
        authority: LoadedAuthority,
        *,
        revalidate_publication: bool = False,
    ) -> LoadedAuthority:
        _verify_registry_lifecycle_state(registry_entry)
        if registry_entry.authority_ref != authority.authority_ref:
            raise AuthorityVerificationError(f"cached authority_ref mismatch for {registry_entry.authority_ref}")
        if authority.schema_version == "authority_bundle.v2":
            if revalidate_publication:
                return _revalidate_cached_v2(self, registry_entry, authority)
            try:
                _verify_cached_v2_integrity(registry_entry, authority)
            except AuthorityVerificationError:
                # A compact integrity failure is evidence of drift. Re-run Ledger's
                # complete provenance validators before rejecting the cache entry.
                _revalidate_cached_v2(self, registry_entry, authority)
                raise
            return authority
        if _normalize_hash(registry_entry.bundle_hash or "") != _normalize_hash(authority.bundle_hash):
            raise AuthorityVerificationError(f"cached bundle hash mismatch for {registry_entry.authority_ref}")
        if _normalize_hash(registry_entry.contract_hash) != _normalize_hash(authority.contract_hash):
            raise AuthorityVerificationError(f"cached contract hash mismatch for {registry_entry.authority_ref}")
        if authority.contract.get("contract_id") != registry_entry.contract_id:
            raise AuthorityVerificationError(f"cached contract identity mismatch for {registry_entry.authority_ref}")
        if authority.contract.get("contract_version") != registry_entry.contract_version:
            raise AuthorityVerificationError(f"cached contract version mismatch for {registry_entry.authority_ref}")
        actual_contract_hash = _normalize_hash(_compute_contract_hash(authority.contract))
        if actual_contract_hash != _normalize_hash(authority.contract_hash):
            raise AuthorityVerificationError(f"cached contract content mismatch for {registry_entry.authority_ref}")
        return authority


def _verify_v2_authority(bundle: Bundle) -> LoadedAuthority:
    validation_started_ns = perf_counter_ns()
    registry_entry = bundle.registry_entry
    if registry_entry.bundle_ref is None or registry_entry.receipt_ref is None:
        raise AuthorityVerificationError(
            f"v2 publication requires logical bundle and receipt references for {registry_entry.authority_ref}"
        )
    if bundle.bundle_ref != registry_entry.bundle_ref:
        raise AuthorityVerificationError(
            f"v2 authority bundle logical reference mismatch for {registry_entry.authority_ref}"
        )
    if bundle.receipt_ref != registry_entry.receipt_ref:
        raise AuthorityVerificationError(
            f"v2 publication receipt logical reference mismatch for {registry_entry.authority_ref}"
        )
    receipt = bundle.receipt_payload
    if not isinstance(receipt, Mapping):
        raise AuthorityVerificationError(
            f"authority_bundle.v2 requires a publication receipt: {registry_entry.authority_ref}"
        )

    try:
        from governance_ledger import (
            get_builtin_domain_pack,
            validate_authority_bundle,
            validate_publication_receipt,
            validate_runtime_fact_compatibility,
            validate_runtime_fact_schema,
        )

        payload = dict(bundle.payload)
        receipt_payload = dict(receipt)
        bundle_status = validate_authority_bundle(payload)
        receipt_status = validate_publication_receipt(payload, receipt_payload)
        runtime_fact_schema = _required_mapping(payload, "runtime_fact_schema")
        constraint_ir = _required_mapping(payload, "constraint_ir")
        domain_pack_ref = _required_mapping(payload, "domain_pack")
        validate_runtime_fact_schema(dict(runtime_fact_schema))
        installed_pack = get_builtin_domain_pack(
            _required_string(domain_pack_ref, "domain_pack_id"),
            _required_string(domain_pack_ref, "domain_pack_version"),
        )
        _require_hash_equal(
            _required_string(domain_pack_ref, "domain_pack_hash"),
            _required_string(installed_pack, "canonical_hash"),
            "installed domain-pack hash",
        )
        installed_runtime_schema = _required_mapping(installed_pack, "runtime_fact_schema")
        _require_equal(
            _required_string(runtime_fact_schema, "schema_id"),
            _required_string(installed_runtime_schema, "schema_id"),
            "installed runtime-fact-schema identity",
        )
        _require_equal(
            _required_string(runtime_fact_schema, "schema_version_number"),
            _required_string(installed_runtime_schema, "schema_version_number"),
            "installed runtime-fact-schema version",
        )
        _require_hash_equal(
            _required_string(runtime_fact_schema, "schema_hash"),
            _required_string(installed_runtime_schema, "schema_hash"),
            "installed runtime-fact-schema hash",
        )
        compatibility = validate_runtime_fact_compatibility(
            dict(constraint_ir),
            dict(runtime_fact_schema),
            domain_pack=installed_pack,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityVerificationError(
            f"Ledger rejected the v2 publication chain for {registry_entry.authority_ref}: {exc}"
        ) from exc

    if bundle_status.get("schema_version") != "authority_bundle.v2" or not bundle_status.get(
        "provenance_complete"
    ):
        raise AuthorityVerificationError(
            f"Ledger did not verify a provenance-complete authority_bundle.v2: {registry_entry.authority_ref}"
        )
    if receipt_status.get("schema_version") != "publication_receipt.v2" or not receipt_status.get(
        "provenance_complete"
    ):
        raise AuthorityVerificationError(
            f"Ledger did not verify a provenance-complete publication_receipt.v2: {registry_entry.authority_ref}"
        )
    if not compatibility.get("compatible"):
        raise AuthorityVerificationError(
            f"Ledger rejected runtime-fact compatibility for {registry_entry.authority_ref}"
        )

    authority = _required_mapping(payload, "authority")
    contract = _required_mapping(payload, "compiled_authority_contract")
    manifest = _required_mapping(payload, "publication_manifest")
    authority_ref = _required_string(authority, "authority_ref")
    authority_id = _required_string(authority, "authority_id")
    authority_version = _required_string(authority, "authority_version")
    contract_id = _required_string(contract, "contract_id")
    contract_version = _required_string(contract, "contract_version")
    contract_hash = _required_string(contract, "contract_hash")
    bundle_hash = _required_string(bundle_status, "bundle_hash")
    receipt_hash = _required_string(receipt_status, "receipt_hash")
    publication_id = _required_string(receipt_payload, "publication_id")

    _require_equal(authority_ref, registry_entry.authority_ref, "authority reference")
    _require_equal(authority_id, registry_entry.contract_id, "authority identity")
    _require_equal(authority_version, registry_entry.contract_version, "authority version")
    _require_equal(contract_id, authority_id, "compiled contract identity")
    _require_equal(contract_version, authority_version, "compiled contract version")
    _require_equal(contract.get("authority_ref"), authority_ref, "compiled contract authority reference")
    _require_hash_equal(contract_hash, registry_entry.contract_hash, "compiled contract hash")
    _require_hash_equal(bundle_hash, registry_entry.bundle_hash, "authority bundle hash")
    if registry_entry.receipt_hash is None:
        raise AuthorityVerificationError(
            f"authority_bundle.v2 registry entry is missing receipt_hash: {registry_entry.authority_ref}"
        )
    _require_hash_equal(receipt_hash, registry_entry.receipt_hash, "publication receipt hash")
    if registry_entry.publication_id is not None:
        _require_equal(publication_id, registry_entry.publication_id, "publication identity")
    _require_equal(manifest.get("publication_id"), publication_id, "publication manifest identity")
    if registry_entry.published_at is not None:
        _require_equal(receipt_payload.get("published_at"), registry_entry.published_at, "published_at")
    if registry_entry.published_by is not None:
        _require_equal(receipt_payload.get("published_by"), registry_entry.published_by, "published_by")

    domain_pack_id = _required_string(domain_pack_ref, "domain_pack_id")
    domain_pack_version = _required_string(domain_pack_ref, "domain_pack_version")
    domain_pack_hash = _required_string(domain_pack_ref, "domain_pack_hash")
    runtime_schema_id = _required_string(runtime_fact_schema, "schema_id")
    runtime_schema_version = _required_string(runtime_fact_schema, "schema_version_number")
    runtime_schema_hash = _required_string(runtime_fact_schema, "schema_hash")
    evidence: dict[str, Any] = {
        "schema_version": "guard_verified_authority_evidence.v1",
        "authority": {
            "authority_id": authority_id,
            "authority_version": authority_version,
            "authority_ref": authority_ref,
            "authority_identity_hash": _required_string(authority, "authority_identity_hash"),
        },
        "authority_bundle": {
            "schema_version": "authority_bundle.v2",
            "publication_id": publication_id,
            "bundle_hash": bundle_hash,
            "logical_ref": bundle.bundle_ref,
        },
        "publication_receipt": {
            "schema_version": "publication_receipt.v2",
            "receipt_id": _required_string(receipt_payload, "receipt_id"),
            "receipt_hash": receipt_hash,
            "logical_ref": bundle.receipt_ref,
        },
        "compiled_contract": {
            "schema_version": "compiled_authority_contract.v2",
            "contract_id": contract_id,
            "contract_version": contract_version,
            "contract_hash": contract_hash,
        },
        "domain_pack": {
            "schema_version": "domain_pack.v1",
            "domain_pack_id": domain_pack_id,
            "domain_pack_version": domain_pack_version,
            "domain_pack_hash": domain_pack_hash,
        },
        "runtime_fact_schema": {
            "schema_version": "runtime_fact_schema.v1",
            "schema_id": runtime_schema_id,
            "schema_version_number": runtime_schema_version,
            "schema_hash": runtime_schema_hash,
        },
        "constraint_ir": {
            "schema_version": "constraint_ir.v1",
            "constraint_ir_id": _required_string(constraint_ir, "ir_hash"),
            "ir_hash": _required_string(constraint_ir, "ir_hash"),
        },
        "verification": {
            "ledger_authority_bundle_validated": True,
            "ledger_publication_receipt_validated": True,
            "ledger_runtime_fact_compatible": True,
        },
    }

    required_runtime_facts = _required_runtime_fact_ids(constraint_ir, runtime_fact_schema)
    runtime_integrity_hash = _compute_runtime_integrity_hash(
        contract=contract,
        evidence=evidence,
        runtime_fact_schema=runtime_fact_schema,
        required_runtime_facts=required_runtime_facts,
    )

    _verify_registry_lifecycle_state(registry_entry)
    return LoadedAuthority(
        authority_ref=authority_ref,
        publication_id=publication_id,
        contract=deepcopy(contract),
        contract_hash=contract_hash,
        bundle_hash=bundle_hash,
        bundle_path=bundle.bundle_path,
        lifecycle_state=registry_entry.lifecycle_state,
        published_at=_required_string(receipt_payload, "published_at"),
        published_by=_required_string(receipt_payload, "published_by"),
        schema_version="authority_bundle.v2",
        receipt_id=_required_string(receipt_payload, "receipt_id"),
        receipt_hash=receipt_hash,
        receipt_path=bundle.receipt_path,
        authority_bundle=deepcopy(payload),
        publication_receipt=deepcopy(receipt_payload),
        runtime_fact_schema=deepcopy(runtime_fact_schema),
        authority_evidence=evidence,
        required_runtime_facts=required_runtime_facts,
        runtime_integrity_hash=runtime_integrity_hash,
        validation_duration_ns=perf_counter_ns() - validation_started_ns,
        _verification_marker=_PROCESS_VERIFICATION_MARKER,
    )


def _verify_cached_v2_integrity(
    registry_entry: RegistryEntry,
    authority: LoadedAuthority,
) -> None:
    if authority.authority_evidence is None or authority.runtime_fact_schema is None:
        raise AuthorityVerificationError(
            f"cached v2 authority is missing verified runtime state for {registry_entry.authority_ref}"
        )
    _require_hash_equal(authority.bundle_hash, registry_entry.bundle_hash, "cached authority bundle hash")
    _require_hash_equal(authority.contract_hash, registry_entry.contract_hash, "cached compiled contract hash")
    _require_hash_equal(authority.receipt_hash or "", registry_entry.receipt_hash, "cached publication receipt hash")
    _require_equal(authority.contract.get("contract_id"), registry_entry.contract_id, "cached contract identity")
    _require_equal(authority.contract.get("contract_version"), registry_entry.contract_version, "cached contract version")
    evidence = authority.authority_evidence
    bundle_evidence = _required_mapping(evidence, "authority_bundle")
    receipt_evidence = _required_mapping(evidence, "publication_receipt")
    contract_evidence = _required_mapping(evidence, "compiled_contract")
    _require_equal(
        bundle_evidence.get("logical_ref"), registry_entry.bundle_ref, "cached bundle logical reference"
    )
    _require_equal(
        receipt_evidence.get("logical_ref"), registry_entry.receipt_ref, "cached receipt logical reference"
    )
    _require_hash_equal(_required_string(bundle_evidence, "bundle_hash"), registry_entry.bundle_hash, "cached bundle evidence hash")
    _require_hash_equal(_required_string(receipt_evidence, "receipt_hash"), registry_entry.receipt_hash, "cached receipt evidence hash")
    _require_hash_equal(_required_string(contract_evidence, "contract_hash"), registry_entry.contract_hash, "cached contract evidence hash")
    actual_integrity_hash = _compute_runtime_integrity_hash(
        contract=authority.contract,
        evidence=evidence,
        runtime_fact_schema=authority.runtime_fact_schema,
        required_runtime_facts=authority.required_runtime_facts,
    )
    _require_hash_equal(actual_integrity_hash, authority.runtime_integrity_hash, "cached runtime authority integrity")


def _revalidate_cached_v2(
    verifier: AuthorityVerifier,
    registry_entry: RegistryEntry,
    authority: LoadedAuthority,
) -> LoadedAuthority:
    if authority.authority_bundle is None or authority.publication_receipt is None:
        raise AuthorityVerificationError(
            f"cached v2 authority is missing publication artifacts for {registry_entry.authority_ref}"
        )
    reverified = verifier.verify(
        Bundle(
            registry_entry=registry_entry,
            payload=authority.authority_bundle,
            bundle_hash=authority.bundle_hash,
            bundle_path=registry_entry.bundle_path,
            receipt_payload=authority.publication_receipt,
            receipt_hash=authority.receipt_hash,
            receipt_path=registry_entry.receipt_path,
            bundle_ref=registry_entry.bundle_ref,
            receipt_ref=registry_entry.receipt_ref,
        )
    )
    if reverified.runtime_integrity_hash != authority.runtime_integrity_hash:
        raise AuthorityVerificationError(
            f"cached runtime authority integrity mismatch for {registry_entry.authority_ref}"
        )
    return reverified


def _required_runtime_fact_ids(
    constraint_ir: Mapping[str, Any],
    runtime_fact_schema: Mapping[str, Any],
) -> tuple[str, ...]:
    facts = runtime_fact_schema.get("facts")
    constraints = constraint_ir.get("constraints")
    if not isinstance(facts, list) or not isinstance(constraints, list):
        raise AuthorityVerificationError("v2 publication has malformed runtime fact requirements")
    required = {
        definition.get("fact_id")
        for definition in facts
        if isinstance(definition, Mapping) and definition.get("required") is True
    }
    for constraint in constraints:
        referenced = constraint.get("required_runtime_facts") if isinstance(constraint, Mapping) else None
        if not isinstance(referenced, list) or not all(isinstance(item, str) and item for item in referenced):
            raise AuthorityVerificationError("v2 publication has malformed required runtime facts")
        required.update(referenced)
    if not all(isinstance(item, str) and item for item in required):
        raise AuthorityVerificationError("v2 publication has malformed required runtime facts")
    return tuple(sorted(required))


def _compute_runtime_integrity_hash(
    *,
    contract: Mapping[str, Any],
    evidence: Mapping[str, Any],
    runtime_fact_schema: Mapping[str, Any],
    required_runtime_facts: tuple[str, ...],
) -> str:
    payload = {
        "contract": contract,
        "authority_evidence": evidence,
        "runtime_fact_schema": runtime_fact_schema,
        "required_runtime_facts": list(required_runtime_facts),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_authority_ref(bundle: Bundle) -> None:
    registry_entry = bundle.registry_entry
    contract = _bundle_contract(bundle)
    authority_ref = bundle.payload.get("authority_ref")
    if not isinstance(authority_ref, str) or not authority_ref:
        raise AuthorityVerificationError(f"authority bundle is missing authority_ref: {registry_entry.authority_ref}")
    if authority_ref != registry_entry.authority_ref:
        raise AuthorityVerificationError(f"bundle authority_ref mismatch for {registry_entry.authority_ref}")
    if contract.get("contract_id") != registry_entry.contract_id:
        raise AuthorityVerificationError(f"contract identity mismatch for {registry_entry.authority_ref}")
    if contract.get("contract_version") != registry_entry.contract_version:
        raise AuthorityVerificationError(f"contract version mismatch for {registry_entry.authority_ref}")


def _verify_contract_hash(bundle: Bundle, contract: Mapping) -> str:
    registry_entry = bundle.registry_entry
    expected_hash = _normalize_hash(registry_entry.contract_hash)
    bundle_contract_hash = bundle.payload.get("contract_hash")
    if not isinstance(bundle_contract_hash, str) or not bundle_contract_hash:
        raise AuthorityVerificationError(f"authority bundle is missing contract_hash: {registry_entry.authority_ref}")
    bundle_hash = _normalize_hash(bundle_contract_hash)
    embedded_hash = _normalize_hash(str(contract.get("contract_hash") or ""))
    actual_hash = _normalize_hash(_compute_contract_hash(contract))
    if bundle_hash != actual_hash:
        raise AuthorityVerificationError(f"bundle contract hash mismatch for {registry_entry.authority_ref}")
    if embedded_hash and embedded_hash != actual_hash:
        raise AuthorityVerificationError(f"embedded contract hash mismatch for {registry_entry.authority_ref}")
    if expected_hash and expected_hash != actual_hash:
        raise AuthorityVerificationError(f"contract hash mismatch for {registry_entry.authority_ref}")
    return f"sha256:{actual_hash}"


def _verify_bundle_hash(bundle: Bundle) -> None:
    registry_entry = bundle.registry_entry
    expected_hash = _normalize_hash(registry_entry.bundle_hash or "")
    if expected_hash and expected_hash != _normalize_hash(bundle.bundle_hash):
        raise AuthorityVerificationError(f"bundle hash mismatch for {registry_entry.authority_ref}")


def _verify_registry_lifecycle_state(registry_entry: RegistryEntry) -> None:
    if registry_entry.lifecycle_state != "active":
        raise AuthorityLifecycleError(
            f"authority lifecycle invalidated: {registry_entry.authority_ref} is {registry_entry.lifecycle_state}"
        )


def _bundle_contract(bundle: Bundle) -> Mapping:
    if bundle.payload.get("schema_version") != "authority_bundle.v1":
        raise AuthorityVerificationError(
            f"authority bundle schema_version must be authority_bundle.v1: {bundle.registry_entry.authority_ref}"
        )
    contract = bundle.payload.get("authority_contract")
    if not isinstance(contract, Mapping):
        raise AuthorityVerificationError(
            f"authority bundle is missing authority_contract: {bundle.registry_entry.authority_ref}"
        )
    return contract


def _compute_contract_hash(contract: Mapping) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_hash(value: str) -> str:
    return value.removeprefix("sha256:")


def _required_mapping(payload: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    value = payload.get(field)
    if not isinstance(value, Mapping):
        raise AuthorityVerificationError(f"v2 publication artifact is missing {field}")
    return value


def _required_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise AuthorityVerificationError(f"v2 publication artifact is missing {field}")
    return value


def _require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AuthorityVerificationError(f"v2 {label} mismatch")


def _require_hash_equal(actual: str, expected: str | None, label: str) -> None:
    if expected is None or _normalize_hash(actual) != _normalize_hash(expected):
        raise AuthorityVerificationError(f"v2 {label} mismatch")
