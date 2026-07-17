from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..exceptions import AuthorityNotFound, MalformedAuthorityRegistry
from ..loader import parse_authority_ref
from ..types import RegistryEntry
from .common import validate_registry_entry


class MemoryAuthorityResolver:
    def __init__(self, entries: Mapping[str, RegistryEntry] | Iterable[RegistryEntry]):
        self.entries = _normalize_entries(entries)

    def resolve(self, authority_ref: str) -> RegistryEntry:
        parse_authority_ref(authority_ref)
        try:
            return self.entries[authority_ref]
        except KeyError as exc:
            raise AuthorityNotFound(f"authority not found: {authority_ref}") from exc


def _normalize_entries(entries: Mapping[str, RegistryEntry] | Iterable[RegistryEntry]) -> dict[str, RegistryEntry]:
    normalized = {}
    if isinstance(entries, Mapping):
        candidates = entries.items()
    else:
        candidates = ((entry.authority_ref, entry) for entry in entries)

    for key, entry in candidates:
        if not isinstance(entry, RegistryEntry):
            raise MalformedAuthorityRegistry("memory authority entries must be RegistryEntry objects")
        parse_authority_ref(key)
        if key != entry.authority_ref:
            raise MalformedAuthorityRegistry(f"memory entry key does not match authority_ref: {key}")
        if key in normalized:
            raise MalformedAuthorityRegistry(f"duplicate authority reference: {key}")
        normalized[key] = validate_registry_entry(entry)
    return normalized
