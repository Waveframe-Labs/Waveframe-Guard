from __future__ import annotations

from copy import deepcopy
from typing import Protocol

from .types import LoadedAuthority


class AuthorityCache(Protocol):
    def get(self, authority_ref: str, bundle_hash: str) -> LoadedAuthority | None:
        ...

    def put(self, authority: LoadedAuthority) -> None:
        ...


class MemoryAuthorityCache:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], LoadedAuthority] = {}

    def get(self, authority_ref: str, bundle_hash: str) -> LoadedAuthority | None:
        authority = self._entries.get((authority_ref, _normalize_hash(bundle_hash)))
        return deepcopy(authority) if authority is not None else None

    def put(self, authority: LoadedAuthority) -> None:
        self._entries[(authority.authority_ref, _normalize_hash(authority.bundle_hash))] = deepcopy(authority)

    def __len__(self) -> int:
        return len(self._entries)


def _normalize_hash(value: str) -> str:
    return value.removeprefix("sha256:")
