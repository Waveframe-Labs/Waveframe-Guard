from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .exceptions import AuthorityVerificationError
from .types import LoadedAuthority
from .verifier import _compute_runtime_integrity_hash


class RuntimeFactError(AuthorityVerificationError):
    """Raised before evaluation when trusted runtime facts cannot be supplied."""


@dataclass(frozen=True)
class RuntimeFactProviderKey:
    domain_pack_id: str
    domain_pack_version: str
    domain_pack_hash: str
    schema_id: str
    schema_version: str
    schema_hash: str


@dataclass(frozen=True)
class DerivedRuntimeFacts:
    provider_key: RuntimeFactProviderKey
    facts: Mapping[str, Any]
    canonical_hash: str
    evaluation_request: Mapping[str, Any]
    evaluation_actor: Mapping[str, Any]


@dataclass(frozen=True)
class VerifiedRuntimeAuthority:
    """Immutable, compact warm-path projection of a cold-verified publication."""

    authority_ref: str
    contract_json: str
    evidence_json: str
    runtime_fact_schema_json: str
    required_runtime_facts: tuple[str, ...]
    integrity_hash: str
    cold_validation_duration_ns: int | None

    @classmethod
    def from_loaded(cls, authority: LoadedAuthority) -> "VerifiedRuntimeAuthority":
        if not isinstance(authority.authority_evidence, Mapping) or not isinstance(
            authority.runtime_fact_schema, Mapping
        ):
            raise RuntimeFactError("verified v2 authority is missing verified runtime state")
        if not isinstance(authority.runtime_integrity_hash, str):
            raise RuntimeFactError("verified v2 authority is missing its runtime integrity binding")
        actual = _compute_runtime_integrity_hash(
            contract=authority.contract,
            evidence=authority.authority_evidence,
            runtime_fact_schema=authority.runtime_fact_schema,
            required_runtime_facts=authority.required_runtime_facts,
        )
        if actual != authority.runtime_integrity_hash:
            raise RuntimeFactError("verified v2 runtime authority integrity mismatch")
        return cls(
            authority_ref=authority.authority_ref,
            contract_json=_canonical_json(authority.contract),
            evidence_json=_canonical_json(authority.authority_evidence),
            runtime_fact_schema_json=_canonical_json(authority.runtime_fact_schema),
            required_runtime_facts=tuple(authority.required_runtime_facts),
            integrity_hash=authority.runtime_integrity_hash,
            cold_validation_duration_ns=authority.validation_duration_ns,
        )

    def contract(self) -> dict[str, Any]:
        return json.loads(self.contract_json)

    def evidence(self) -> dict[str, Any]:
        return json.loads(self.evidence_json)

    def runtime_fact_schema(self) -> dict[str, Any]:
        return json.loads(self.runtime_fact_schema_json)

    def verify_candidate_contract(self, candidate: Mapping[str, Any]) -> None:
        if _canonical_json(candidate) != self.contract_json:
            raise RuntimeFactError("verified v2 compiled contract changed after activation")


class RepositoryChangesFactProvider:
    """Trusted deterministic binding for repository-changes/1.0.0 only."""

    def derive(
        self,
        *,
        authority: LoadedAuthority | VerifiedRuntimeAuthority,
        execution_request: Mapping[str, Any],
        actor_identity: Mapping[str, Any],
    ) -> DerivedRuntimeFacts:
        runtime_authority = (
            authority
            if isinstance(authority, VerifiedRuntimeAuthority)
            else VerifiedRuntimeAuthority.from_loaded(authority)
        )
        schema = runtime_authority.runtime_fact_schema()
        key = runtime_fact_provider_key(authority)
        if key != _trusted_repository_provider_key():
            raise RuntimeFactError(
                "unsupported runtime fact schema: "
                f"{key.schema_id}@{key.schema_version} ({key.schema_hash})"
            )

        permitted = _schema_fact_index(schema)
        _reject_fact_injection(execution_request, permitted)
        _reject_fact_injection(
            {
                key_: value
                for key_, value in actor_identity.items()
                if key_ not in {"id", "type", "role"}
            },
            permitted,
        )
        candidates = {
            "actor.subject_kind": actor_identity.get("type"),
            "actor.principal_id": actor_identity.get("id"),
            "actor.role": actor_identity.get("role"),
            "proposal.action": execution_request.get("action"),
            "proposal.resource.kind": (
                "repository_path"
                if isinstance(execution_request.get("target"), str)
                and bool(execution_request.get("target"))
                else None
            ),
            "proposal.resource.path": execution_request.get("target"),
        }
        facts = {
            fact_id: candidates[fact_id]
            for fact_id in permitted
            if fact_id in candidates and candidates[fact_id] is not None
        }
        required = set(runtime_authority.required_runtime_facts)

        missing = sorted(required - facts.keys())
        if missing:
            raise RuntimeFactError("missing required runtime facts: " + ", ".join(missing))
        for fact_id, value in facts.items():
            _validate_fact_value(fact_id, value, permitted[fact_id])

        fact_set = dict(sorted(facts.items()))
        return DerivedRuntimeFacts(
            provider_key=key,
            facts=fact_set,
            canonical_hash=_canonical_hash(fact_set),
            evaluation_request={
                "schema_version": "normalized_execution_request.v1",
                "request_id": execution_request.get("request_id"),
                "action": fact_set["proposal.action"],
                "target": fact_set.get("proposal.resource.path"),
                "arguments": {},
                "artifacts": [],
            },
            evaluation_actor={
                key_: value
                for key_, value in {
                    "id": fact_set.get("actor.principal_id"),
                    "type": fact_set.get("actor.subject_kind"),
                    "role": fact_set.get("actor.role"),
                }.items()
                if value is not None
            },
        )


def runtime_fact_provider_key(
    authority: LoadedAuthority | VerifiedRuntimeAuthority,
) -> RuntimeFactProviderKey:
    evidence = (
        authority.evidence()
        if isinstance(authority, VerifiedRuntimeAuthority)
        else authority.authority_evidence
    )
    if not isinstance(evidence, Mapping):
        raise RuntimeFactError("v2 authority is missing verified authority evidence")
    pack = evidence.get("domain_pack")
    schema = evidence.get("runtime_fact_schema")
    if not isinstance(pack, Mapping) or not isinstance(schema, Mapping):
        raise RuntimeFactError("v2 authority evidence is missing fact-provider identity")
    try:
        return RuntimeFactProviderKey(
            domain_pack_id=str(pack["domain_pack_id"]),
            domain_pack_version=str(pack["domain_pack_version"]),
            domain_pack_hash=str(pack["domain_pack_hash"]),
            schema_id=str(schema["schema_id"]),
            schema_version=str(schema["schema_version_number"]),
            schema_hash=str(schema["schema_hash"]),
        )
    except KeyError as exc:
        raise RuntimeFactError("v2 authority evidence is missing fact-provider identity") from exc


def _trusted_repository_provider_key() -> RuntimeFactProviderKey:
    return RuntimeFactProviderKey(
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        domain_pack_hash="sha256:4b6ff9a3ebf3b419151fbaa3f899012dca39ff354de8e768da05146ad0c64b80",
        schema_id="repository-changes-runtime",
        schema_version="1.0.0",
        schema_hash="sha256:c1595ef8d77165a7a486151673f01eda5a93000786f47e1f048875f17eb396a1",
    )


def _schema_fact_index(schema: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    definitions = schema.get("facts")
    if not isinstance(definitions, list):
        raise RuntimeFactError("runtime fact schema facts must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for definition in definitions:
        if not isinstance(definition, Mapping):
            raise RuntimeFactError("runtime fact schema contains a malformed fact definition")
        fact_id = definition.get("fact_id")
        if not isinstance(fact_id, str) or not fact_id or fact_id in result:
            raise RuntimeFactError("runtime fact schema contains an invalid fact identity")
        result[fact_id] = definition
    return result


def _validate_fact_value(fact_id: str, value: Any, definition: Mapping[str, Any]) -> None:
    fact_type = definition.get("type")
    if fact_type == "string":
        valid = isinstance(value, str)
    elif fact_type == "enum":
        valid = isinstance(value, str) and value in (definition.get("enum_values") or [])
    else:
        raise RuntimeFactError(
            f"repository-changes fact provider does not support runtime fact type: {fact_type}"
        )
    if not valid:
        raise RuntimeFactError(f"runtime fact {fact_id} has incorrect type or value")


def _canonical_hash(value: Mapping[str, Any]) -> str:
    canonical = _canonical_json(value)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _reject_fact_injection(
    execution_request: Mapping[str, Any],
    permitted: Mapping[str, Mapping[str, Any]],
) -> None:
    reserved_interfaces = {
        "facts",
        "runtime_facts",
        "enforcement_facts",
        "derived_facts",
        "actor",
        "proposal",
    }

    def inspect(value: Any) -> bool:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if isinstance(key, str) and (
                    key in reserved_interfaces
                    or key in permitted
                    or key.startswith("actor.")
                    or key.startswith("proposal.")
                ):
                    return True
                if inspect(nested):
                    return True
        elif isinstance(value, (list, tuple)):
            return any(inspect(item) for item in value)
        return False

    if inspect(execution_request):
        raise RuntimeFactError(
            "caller-supplied enforcement facts are not accepted; Guard derives the fact set"
        )
