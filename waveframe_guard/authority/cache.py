from __future__ import annotations

from copy import deepcopy
from threading import RLock
from typing import Protocol

from .types import LoadedAuthority


class AuthorityCache(Protocol):
    def get(self, authority_ref: str, bundle_hash: str) -> LoadedAuthority | None:
        ...

    def put(self, authority: LoadedAuthority) -> None:
        ...


class MemoryAuthorityCache:
    """Process-local verified cache with atomic copy-on-read replacement."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], LoadedAuthority] = {}
        self._lock = RLock()

    def get(self, authority_ref: str, bundle_hash: str) -> LoadedAuthority | None:
        with self._lock:
            authority = self._entries.get((authority_ref, _normalize_hash(bundle_hash)))
            return deepcopy(authority) if authority is not None else None

    def put(self, authority: LoadedAuthority) -> None:
        if authority.schema_version in {"authority_bundle.v2", "authority_bundle.v3"}:
            from .exceptions import AuthorityVerificationError
            from .verifier import _is_process_verified_v2, _is_process_verified_v3

            verified = (
                _is_process_verified_v2(authority)
                if authority.schema_version == "authority_bundle.v2"
                else _is_process_verified_v3(authority)
            )
            if not verified:
                major = authority.schema_version.rsplit(".", 1)[-1]
                raise AuthorityVerificationError(
                    f"{major} authority must complete publication validation before cache insertion"
                )
        replacement = deepcopy(authority)
        with self._lock:
            self._entries[(authority.authority_ref, _normalize_hash(authority.bundle_hash))] = replacement

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def _normalize_hash(value: str) -> str:
    return value.removeprefix("sha256:")
