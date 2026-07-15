from __future__ import annotations

import hashlib
import json
from typing import Mapping

from .exceptions import AuthorityLifecycleError, AuthorityVerificationError
from .types import Bundle, LoadedAuthority


ACTIVE_LIFECYCLE_STATES = {"active", "published"}


class AuthorityVerifier:
    def verify(self, bundle: Bundle) -> LoadedAuthority:
        registry_entry = bundle.registry_entry
        _verify_authority_ref(bundle)
        contract_hash = _verify_contract_hash(bundle)
        _verify_bundle_hash(bundle)
        _verify_lifecycle_state(bundle)
        return LoadedAuthority(
            authority_ref=registry_entry.authority_ref,
            publication_id=registry_entry.publication_id,
            contract=bundle.contract,
            contract_hash=contract_hash,
            bundle_hash=bundle.bundle_hash,
            bundle_path=bundle.bundle_path,
            lifecycle_state=registry_entry.lifecycle_state,
            published_at=registry_entry.published_at,
            published_by=registry_entry.published_by,
        )


def _verify_authority_ref(bundle: Bundle) -> None:
    registry_entry = bundle.registry_entry
    if bundle.contract.get("contract_id") != registry_entry.contract_id:
        raise AuthorityVerificationError(f"contract identity mismatch for {registry_entry.authority_ref}")
    if bundle.contract.get("contract_version") != registry_entry.contract_version:
        raise AuthorityVerificationError(f"contract version mismatch for {registry_entry.authority_ref}")


def _verify_contract_hash(bundle: Bundle) -> str:
    registry_entry = bundle.registry_entry
    expected_hash = _normalize_hash(registry_entry.contract_hash)
    embedded_hash = _normalize_hash(str(bundle.contract.get("contract_hash") or ""))
    actual_hash = _normalize_hash(_compute_contract_hash(bundle.contract))
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


def _verify_lifecycle_state(bundle: Bundle) -> None:
    registry_entry = bundle.registry_entry
    if registry_entry.lifecycle_state not in ACTIVE_LIFECYCLE_STATES:
        raise AuthorityLifecycleError(
            f"authority lifecycle invalidated: {registry_entry.authority_ref} is {registry_entry.lifecycle_state}"
        )


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
