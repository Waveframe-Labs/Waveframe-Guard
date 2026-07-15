from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .exceptions import AuthorityLifecycleError, AuthorityVerificationError, InvalidAuthorityRef
from .types import LoadedAuthority, RegistryEntry


ACTIVE_LIFECYCLE_STATES = {"active", "published"}


def load_authority(authority_ref: str) -> LoadedAuthority:
    from .resolver import LocalRegistryResolver

    resolver = LocalRegistryResolver()
    loader = BundleLoader()
    return loader.load(resolver.resolve(authority_ref))


class BundleLoader:
    def load(self, registry_entry: RegistryEntry) -> LoadedAuthority:
        contract = _read_json(registry_entry.bundle_path)
        _verify_authority_ref(registry_entry, contract)
        contract_hash = _verify_contract_hash(registry_entry, contract)
        bundle_hash = _verify_bundle_hash(registry_entry)
        _verify_lifecycle_state(registry_entry)
        return LoadedAuthority(
            authority_ref=registry_entry.authority_ref,
            publication_id=registry_entry.publication_id,
            contract=contract,
            contract_hash=contract_hash,
            bundle_hash=bundle_hash,
            bundle_path=registry_entry.bundle_path,
            lifecycle_state=registry_entry.lifecycle_state,
            published_at=registry_entry.published_at,
            published_by=registry_entry.published_by,
        )


def parse_authority_ref(authority_ref: str) -> tuple[str, str]:
    if not isinstance(authority_ref, str):
        raise InvalidAuthorityRef("authority_ref must be a string")
    if "/" in authority_ref or "\\" in authority_ref or authority_ref.endswith(".json"):
        raise InvalidAuthorityRef("authority_ref must be an explicit name@version, not a path")
    if authority_ref.count("@") != 1:
        raise InvalidAuthorityRef("authority_ref must be an explicit name@version")
    name, version = authority_ref.split("@", 1)
    if not name or not version:
        raise InvalidAuthorityRef("authority_ref must include both name and version")
    if version == "latest":
        raise InvalidAuthorityRef("authority_ref must not use implicit versions such as latest")
    return name, version


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise AuthorityVerificationError("authority bundle must be a JSON object")
    return payload


def _verify_authority_ref(registry_entry: RegistryEntry, contract: Mapping[str, Any]) -> None:
    if contract.get("contract_id") != registry_entry.contract_id:
        raise AuthorityVerificationError(f"contract identity mismatch for {registry_entry.authority_ref}")
    if contract.get("contract_version") != registry_entry.contract_version:
        raise AuthorityVerificationError(f"contract version mismatch for {registry_entry.authority_ref}")


def _verify_contract_hash(registry_entry: RegistryEntry, contract: Mapping[str, Any]) -> str:
    expected_hash = _normalize_hash(registry_entry.contract_hash)
    embedded_hash = _normalize_hash(str(contract.get("contract_hash") or ""))
    actual_hash = _normalize_hash(_compute_contract_hash(contract))
    if embedded_hash and embedded_hash != actual_hash:
        raise AuthorityVerificationError(f"embedded contract hash mismatch for {registry_entry.authority_ref}")
    if expected_hash and expected_hash != actual_hash:
        raise AuthorityVerificationError(f"contract hash mismatch for {registry_entry.authority_ref}")
    return f"sha256:{actual_hash}"


def _verify_bundle_hash(registry_entry: RegistryEntry) -> str:
    actual_hash = _file_hash(registry_entry.bundle_path)
    expected_hash = _normalize_hash(registry_entry.bundle_hash or "")
    if expected_hash and expected_hash != actual_hash:
        raise AuthorityVerificationError(f"bundle hash mismatch for {registry_entry.authority_ref}")
    return f"sha256:{actual_hash}"


def _verify_lifecycle_state(registry_entry: RegistryEntry) -> None:
    if registry_entry.lifecycle_state not in ACTIVE_LIFECYCLE_STATES:
        raise AuthorityLifecycleError(
            f"authority lifecycle invalidated: {registry_entry.authority_ref} is {registry_entry.lifecycle_state}"
        )


def _compute_contract_hash(contract: Mapping[str, Any]) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_hash(value: str) -> str:
    return value.removeprefix("sha256:")
