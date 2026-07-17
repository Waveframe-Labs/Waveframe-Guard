from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from waveframe_guard.authority import AuthorityCache, AuthorityResolver, load_authority


@dataclass(frozen=True)
class AuthoritySource:
    authorities: dict[str, dict[str, Any]]
    authority_loader: Callable[[str], dict[str, Any]] | None
    default_authority_ref: str | None = None

    @classmethod
    def from_inputs(
        cls,
        *,
        authority: str | None = None,
        authority_resolver: AuthorityResolver | None = None,
        authority_cache: AuthorityCache | None = None,
        contract: dict[str, Any] | None = None,
        authorities: dict[str, dict[str, Any]] | None = None,
        authority_loader: Callable[[str], dict[str, Any]] | None = None,
    ) -> "AuthoritySource":
        if authority is not None and contract is not None:
            raise ValueError("authority and contract are mutually exclusive authority sources")
        if authority is None and authority_resolver is not None:
            raise ValueError("authority_resolver requires authority")

        normalized_authorities = dict(authorities or {})
        default_authority_ref = None

        if contract is not None:
            contract_ref = _contract_authority_ref(contract)
            _install_authority(normalized_authorities, contract_ref, contract)
            default_authority_ref = contract_ref

        if authority is not None:
            loaded_authority = load_authority(authority, resolver=authority_resolver, cache=authority_cache)
            _install_authority(
                normalized_authorities,
                loaded_authority.authority_ref,
                dict(loaded_authority.contract),
            )
            default_authority_ref = loaded_authority.authority_ref

        return cls(
            authorities=normalized_authorities,
            authority_loader=authority_loader,
            default_authority_ref=default_authority_ref,
        )


def _contract_authority_ref(contract: dict[str, Any]) -> str:
    contract_id = contract.get("contract_id")
    contract_version = contract.get("contract_version")
    if not contract_id or not contract_version:
        raise ValueError("contract must include contract_id and contract_version")
    return f"{contract_id}@{contract_version}"


def _install_authority(
    authorities: dict[str, dict[str, Any]],
    authority_ref: str,
    contract: dict[str, Any],
) -> None:
    existing = authorities.get(authority_ref)
    if existing is not None and _canonical(existing) != _canonical(contract):
        raise ValueError(f"conflicting authority source for {authority_ref}")
    authorities[authority_ref] = contract


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
