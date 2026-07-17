from __future__ import annotations

import hashlib
import json
from typing import Mapping

from .exceptions import AuthorityLifecycleError, AuthorityVerificationError
from .types import Bundle, LoadedAuthority, RegistryEntry


class AuthorityVerifier:
    def verify(self, bundle: Bundle) -> LoadedAuthority:
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
        )

    def verify_registry_entry(
        self,
        registry_entry: RegistryEntry,
        authority: LoadedAuthority,
    ) -> LoadedAuthority:
        _verify_registry_lifecycle_state(registry_entry)
        if registry_entry.authority_ref != authority.authority_ref:
            raise AuthorityVerificationError(f"cached authority_ref mismatch for {registry_entry.authority_ref}")
        if _normalize_hash(registry_entry.bundle_hash or "") != _normalize_hash(authority.bundle_hash):
            raise AuthorityVerificationError(f"cached bundle hash mismatch for {registry_entry.authority_ref}")
        if _normalize_hash(registry_entry.contract_hash) != _normalize_hash(authority.contract_hash):
            raise AuthorityVerificationError(f"cached contract hash mismatch for {registry_entry.authority_ref}")
        if authority.contract.get("contract_id") != registry_entry.contract_id:
            raise AuthorityVerificationError(f"cached contract identity mismatch for {registry_entry.authority_ref}")
        if authority.contract.get("contract_version") != registry_entry.contract_version:
            raise AuthorityVerificationError(f"cached contract version mismatch for {registry_entry.authority_ref}")
        return authority


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
