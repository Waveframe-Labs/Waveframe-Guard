from __future__ import annotations

from pathlib import Path, PurePosixPath
import re

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
    if entry.bundle_ref is not None:
        validate_logical_artifact_ref(
            entry.bundle_ref, authority_ref=entry.authority_ref, field="bundle_ref"
        )
    if (entry.receipt_path is None) != (entry.receipt_hash is None):
        raise MalformedAuthorityRegistry(
            f"authority registry receipt_path and receipt_hash must be supplied together: {entry.authority_ref}"
        )
    if entry.receipt_path is not None and not isinstance(entry.receipt_path, Path):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has invalid receipt_path: {entry.authority_ref}"
        )
    if entry.receipt_hash is not None and (
        not isinstance(entry.receipt_hash, str) or not entry.receipt_hash
    ):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has invalid receipt_hash: {entry.authority_ref}"
        )
    if entry.receipt_ref is not None and (entry.receipt_path is None or not entry.receipt_ref):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has invalid receipt_ref: {entry.authority_ref}"
        )
    if entry.receipt_ref is not None:
        validate_logical_artifact_ref(
            entry.receipt_ref, authority_ref=entry.authority_ref, field="receipt_ref"
        )
    if not isinstance(entry.lifecycle_state, str) or not entry.lifecycle_state:
        raise MalformedAuthorityRegistry(f"authority registry entry is missing lifecycle_state: {entry.authority_ref}")
    if entry.lifecycle_state not in CANONICAL_LIFECYCLE_STATES:
        raise MalformedAuthorityRegistry(
            f"authority registry entry has unknown lifecycle_state for {entry.authority_ref}: {entry.lifecycle_state}"
        )
    return entry


def validate_logical_artifact_ref(value: str, *, authority_ref: str, field: str) -> str:
    """Validate a portable opaque registry identifier without normalizing it."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise MalformedAuthorityRegistry(
            f"authority registry entry has invalid logical {field}: {authority_ref}"
        )
    if "\\" in value or "\x00" in value or re.match(r"^[A-Za-z]:", value):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has ambiguous logical {field}: {authority_ref}"
        )
    parts = value.split("/")
    if value.startswith("/") or "//" in value or any(part in {"", ".", ".."} for part in parts):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has unsafe logical {field}: {authority_ref}"
        )
    if PurePosixPath(value).as_posix() != value or any(ord(character) < 32 for character in value):
        raise MalformedAuthorityRegistry(
            f"authority registry entry has ambiguous logical {field}: {authority_ref}"
        )
    return value
