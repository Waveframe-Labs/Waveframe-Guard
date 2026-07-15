from __future__ import annotations

from typing import Protocol

from .types import RegistryEntry


class AuthorityResolver(Protocol):
    def resolve(self, authority_ref: str) -> RegistryEntry:
        ...
