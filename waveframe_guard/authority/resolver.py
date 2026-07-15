from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .exceptions import AuthorityNotFound
from .loader import parse_authority_ref
from .types import RegistryEntry


class AuthorityResolver(Protocol):
    def resolve(self, authority_ref: str) -> RegistryEntry:
        ...


class LocalRegistryResolver:
    def __init__(self, registry_path: str | Path | None = None):
        self.registry_path = Path(registry_path) if registry_path is not None else _default_registry_path()

    def resolve(self, authority_ref: str) -> RegistryEntry:
        contract_id, contract_version = parse_authority_ref(authority_ref)
        registry = _read_json(self.registry_path)
        for entry in _registry_entries(registry):
            entry_contract_id = entry.get("contract_id") or _entry_contract_id_from_ref(entry)
            entry_version = entry.get("contract_version") or entry.get("version") or _entry_version_from_ref(entry)
            if entry_contract_id != contract_id or entry_version != contract_version:
                continue
            return _registry_entry_from_mapping(
                authority_ref=authority_ref,
                contract_id=contract_id,
                contract_version=contract_version,
                entry=entry,
                registry_path=self.registry_path,
            )

        raise AuthorityNotFound(f"authority not found: {authority_ref}")


def _default_registry_path() -> Path:
    return Path.cwd() / "contracts" / "index.json"


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


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
    registry_path: Path,
) -> RegistryEntry:
    bundle_path_value = entry.get("bundle_path") or entry.get("path") or entry.get("contract_path")
    if not bundle_path_value:
        raise AuthorityNotFound(f"authority registry entry is missing a bundle path: {authority_ref}")
    bundle_path = Path(bundle_path_value)
    if not bundle_path.is_absolute():
        bundle_path = registry_path.parent / bundle_path
    lifecycle_state = entry.get("lifecycle_state") or entry.get("status") or entry.get("authority_status") or "active"
    return RegistryEntry(
        authority_ref=authority_ref,
        contract_id=contract_id,
        contract_version=contract_version,
        contract_hash=str(entry.get("contract_hash") or ""),
        bundle_path=bundle_path,
        publication_id=entry.get("publication_id"),
        bundle_hash=entry.get("bundle_hash"),
        lifecycle_state=lifecycle_state,
        published_at=entry.get("published_at"),
        published_by=entry.get("published_by"),
        raw=entry,
    )


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
