from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from waveframe_guard.authority import AuthorityResolver, load_authority


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
        contract: dict[str, Any] | None = None,
        authorities: dict[str, dict[str, Any]] | None = None,
        authority_loader: Callable[[str], dict[str, Any]] | None = None,
    ) -> "AuthoritySource":
        normalized_authorities = dict(authorities or {})
        default_authority_ref = None

        if contract is not None:
            contract_ref = _contract_authority_ref(contract)
            normalized_authorities[contract_ref] = contract
            default_authority_ref = contract_ref

        if authority is not None:
            loaded_authority = load_authority(authority, resolver=authority_resolver)
            normalized_authorities[loaded_authority.authority_ref] = dict(loaded_authority.contract)
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
