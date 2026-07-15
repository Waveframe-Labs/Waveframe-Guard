from __future__ import annotations

from pathlib import Path

from ..exceptions import MalformedAuthorityRegistry
from ..loader import parse_authority_ref
from ..types import RegistryEntry


CANONICAL_LIFECYCLE_STATES = {"active", "superseded", "revoked"}


def validate_registry_entry(entry: RegistryEntry) -> RegistryEntry:
    contract_id, contract_version = parse_authority_ref(entry.authority_ref)
    if entry.contract_id != contract_id:
        raise MalformedAuthorityRegistry(f"registry entry contract_id mismatch: {entry.authority_ref}")
    if entry.contract_version != contract_version:
        raise MalformedAuthorityRegistry(f"registry entry contract_version mismatch: {entry.authority_ref}")
    if not isinstance(entry.contract_hash, str) or not entry.contract_hash:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing contract_hash: {entry.authority_ref}")
    if not isinstance(entry.bundle_hash, str) or not entry.bundle_hash:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing bundle_hash: {entry.authority_ref}")
    if not isinstance(entry.bundle_path, Path):
        raise MalformedAuthorityRegistry(f"authority registry entry is missing bundle_path: {entry.authority_ref}")
    if not isinstance(entry.lifecycle_state, str) or not entry.lifecycle_state:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing lifecycle_state: {entry.authority_ref}")
    if entry.lifecycle_state not in CANONICAL_LIFECYCLE_STATES:
        raise MalformedAuthorityRegistry(
            f"authority registry entry has unknown lifecycle_state for {entry.authority_ref}: {entry.lifecycle_state}"
        )
    return entry
