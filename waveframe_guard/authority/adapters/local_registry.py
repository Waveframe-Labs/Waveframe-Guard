from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..exceptions import AuthorityNotFound, MalformedAuthorityRegistry
from ..loader import parse_authority_ref
from ..types import RegistryEntry
from .common import validate_registry_entry


class LocalRegistryResolver:
    def __init__(self, registry_path: str | Path | None = None, *, workspace_root: str | Path | None = None):
        self.workspace_root = Path(workspace_root) if workspace_root is not None else Path.cwd()
        self.registry_path = Path(registry_path) if registry_path is not None else self.workspace_root / "contracts" / "index.json"
        if not self.registry_path.is_absolute():
            self.registry_path = self.workspace_root / self.registry_path

    def resolve(self, authority_ref: str) -> RegistryEntry:
        contract_id, contract_version = parse_authority_ref(authority_ref)
        registry = _read_json(self.registry_path)
        _verify_registry_hash(registry)
        for entry in _registry_entries(registry):
            entry_contract_id = entry.get("contract_id") or _entry_contract_id_from_ref(entry)
            entry_version = entry.get("contract_version") or entry.get("version") or _entry_version_from_ref(entry)
            if entry_contract_id != contract_id or entry_version != contract_version:
                continue
            return validate_registry_entry(
                _registry_entry_from_mapping(
                    authority_ref=authority_ref,
                    contract_id=contract_id,
                    contract_version=contract_version,
                    entry=entry,
                    workspace_root=self.workspace_root,
                )
            )

        raise AuthorityNotFound(f"authority not found: {authority_ref}")


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise MalformedAuthorityRegistry("authority registry must be a JSON object")
    return payload


def _registry_entries(registry: dict):
    contracts = registry.get("contracts", registry)
    if isinstance(contracts, dict):
        for key, value in contracts.items():
            if isinstance(value, dict):
                yield {"authority_ref": key, **value}
        return
    if isinstance(contracts, list):
        yield from contracts


def _registry_entry_from_mapping(
    *,
    authority_ref: str,
    contract_id: str,
    contract_version: str,
    entry: dict,
    workspace_root: Path,
) -> RegistryEntry:
    bundle_path_value = entry.get("bundle_path")
    if not isinstance(bundle_path_value, str) or not bundle_path_value:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing bundle_path: {authority_ref}")
    bundle_hash = entry.get("bundle_hash")
    if not isinstance(bundle_hash, str) or not bundle_hash:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing bundle_hash: {authority_ref}")
    contract_hash = entry.get("contract_hash")
    if not isinstance(contract_hash, str) or not contract_hash:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing contract_hash: {authority_ref}")
    lifecycle_state = entry.get("lifecycle_state") or entry.get("status")
    if lifecycle_state is None:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing lifecycle_state: {authority_ref}")
    bundle_path = Path(bundle_path_value)
    if not bundle_path.is_absolute():
        bundle_path = workspace_root / bundle_path
    return RegistryEntry(
        authority_ref=authority_ref,
        contract_id=contract_id,
        contract_version=contract_version,
        contract_hash=contract_hash,
        bundle_path=bundle_path,
        publication_id=entry.get("publication_id"),
        bundle_hash=bundle_hash,
        lifecycle_state=lifecycle_state,
        published_at=entry.get("published_at"),
        published_by=entry.get("published_by"),
        raw=entry,
    )


def _verify_registry_hash(registry: dict[str, Any]) -> None:
    registry_hash = registry.get("registry_hash")
    if not isinstance(registry_hash, str) or not registry_hash:
        raise MalformedAuthorityRegistry("authority registry is missing registry_hash")
    canonical_registry = {
        key: value
        for key, value in registry.items()
        if key != "registry_hash"
    }
    actual_hash = _canonical_hash(canonical_registry)
    if registry_hash.removeprefix("sha256:") != actual_hash:
        raise MalformedAuthorityRegistry("authority registry hash mismatch")


def _canonical_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _entry_contract_id_from_ref(entry: dict) -> str | None:
    authority_ref = entry.get("authority_ref") or entry.get("contract_ref")
    if isinstance(authority_ref, str) and "@" in authority_ref:
        return authority_ref.split("@", 1)[0]
    return None


def _entry_version_from_ref(entry: dict) -> str | None:
    authority_ref = entry.get("authority_ref") or entry.get("contract_ref")
    if isinstance(authority_ref, str) and "@" in authority_ref:
        return authority_ref.split("@", 1)[1]
    return None
