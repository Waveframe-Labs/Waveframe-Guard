from __future__ import annotations

import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from ..exceptions import AuthorityNotFound, MalformedAuthorityRegistry
from ..loader import parse_authority_ref
from ..types import RegistryEntry
from .common import validate_logical_artifact_ref, validate_registry_entry


class LocalRegistryResolver:
    def __init__(self, registry_path: str | Path | None = None, *, workspace_root: str | Path | None = None):
        self.workspace_root = (
            Path(workspace_root).resolve() if workspace_root is not None else Path.cwd().resolve()
        )
        if registry_path is None:
            self.registry_path = self.workspace_root / "contracts" / "index.json"
        else:
            selected_registry_path = Path(registry_path)
            self.registry_path = (
                selected_registry_path
                if selected_registry_path.is_absolute()
                else self.workspace_root / selected_registry_path
            )

    def resolve(self, authority_ref: str) -> RegistryEntry:
        contract_id, contract_version = parse_authority_ref(authority_ref)
        registry = _read_json(self.registry_path)
        _verify_registry_hash(registry)
        matches = []
        for entry in _registry_entries(registry):
            entry_contract_id = entry.get("contract_id") or _entry_contract_id_from_ref(entry)
            entry_version = entry.get("contract_version") or entry.get("version") or _entry_version_from_ref(entry)
            if entry_contract_id != contract_id or entry_version != contract_version:
                continue
            matches.append(entry)

        if len(matches) > 1:
            raise MalformedAuthorityRegistry(f"duplicate authority_ref in registry: {authority_ref}")
        if len(matches) == 1:
            return validate_registry_entry(
                _registry_entry_from_mapping(
                    authority_ref=authority_ref,
                    contract_id=contract_id,
                    contract_version=contract_version,
                    entry=matches[0],
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
    bundle_ref = validate_logical_artifact_ref(bundle_path_value, authority_ref=authority_ref, field="bundle_path")
    bundle_path = _resolve_logical_ref(workspace_root, bundle_ref, authority_ref=authority_ref)
    receipt_path_value = entry.get("receipt_path") or entry.get("publication_receipt_path")
    receipt_hash = entry.get("receipt_hash") or entry.get("publication_receipt_hash")
    if (receipt_path_value is None) != (receipt_hash is None):
        raise MalformedAuthorityRegistry(
            f"authority registry receipt_path and receipt_hash must be supplied together: {authority_ref}"
        )
    receipt_path = None
    if receipt_path_value is not None:
        if not isinstance(receipt_path_value, str) or not receipt_path_value:
            raise MalformedAuthorityRegistry(
                f"authority registry entry has invalid receipt_path: {authority_ref}"
            )
        if not isinstance(receipt_hash, str) or not receipt_hash:
            raise MalformedAuthorityRegistry(
                f"authority registry entry has invalid receipt_hash: {authority_ref}"
            )
        receipt_ref = validate_logical_artifact_ref(
            receipt_path_value,
            authority_ref=authority_ref,
            field="receipt_path",
        )
        receipt_path = _resolve_logical_ref(workspace_root, receipt_ref, authority_ref=authority_ref)
    else:
        receipt_ref = None
    return RegistryEntry(
        authority_ref=authority_ref,
        contract_id=contract_id,
        contract_version=contract_version,
        contract_hash=contract_hash,
        bundle_path=bundle_path,
        receipt_path=receipt_path,
        publication_id=entry.get("publication_id"),
        bundle_hash=bundle_hash,
        receipt_hash=receipt_hash,
        bundle_ref=bundle_ref,
        receipt_ref=receipt_ref,
        lifecycle_state=lifecycle_state,
        published_at=entry.get("published_at"),
        published_by=entry.get("published_by"),
        raw=entry,
    )


def _resolve_logical_ref(workspace_root: Path, logical_ref: str, *, authority_ref: str) -> Path:
    root = workspace_root.resolve()
    resolved = root.joinpath(*PurePosixPath(logical_ref).parts).resolve()
    if not resolved.is_relative_to(root):
        raise MalformedAuthorityRegistry(
            f"authority registry logical artifact reference escapes its storage root: {authority_ref}"
        )
    return resolved


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
