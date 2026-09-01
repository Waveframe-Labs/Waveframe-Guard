from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .exceptions import AuthorityVerificationError
from .types import LoadedAuthority


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


class RepositoryChangesFactProvider:
    """Trusted deterministic binding for repository-changes/1.0.0 only."""

    def derive(
        self,
        *,
        authority: LoadedAuthority,
        execution_request: Mapping[str, Any],
        actor_identity: Mapping[str, Any],
    ) -> DerivedRuntimeFacts:
        schema = authority.runtime_fact_schema
        bundle = authority.authority_bundle
        if not isinstance(schema, Mapping) or not isinstance(bundle, Mapping):
            raise RuntimeFactError("verified v2 authority is missing its runtime fact schema")
        key = runtime_fact_provider_key(authority)
        if key != _installed_repository_provider_key():
            raise RuntimeFactError(
                "unsupported runtime fact schema: "
                f"{key.schema_id}@{key.schema_version} ({key.schema_hash})"
            )

        permitted = _schema_fact_index(schema)
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
        required = {
            fact_id for fact_id, definition in permitted.items() if definition.get("required") is True
        }
        constraint_ir = bundle.get("constraint_ir")
        if not isinstance(constraint_ir, Mapping):
            raise RuntimeFactError("verified v2 authority is missing Constraint IR")
        constraints = constraint_ir.get("constraints")
        if not isinstance(constraints, list):
            raise RuntimeFactError("verified v2 authority has malformed Constraint IR constraints")
        for constraint in constraints:
            if not isinstance(constraint, Mapping):
                raise RuntimeFactError("verified v2 authority has malformed Constraint IR constraint")
            referenced = constraint.get("required_runtime_facts")
            if not isinstance(referenced, list):
                raise RuntimeFactError("verified v2 authority has malformed required runtime facts")
            required.update(referenced)

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


def runtime_fact_provider_key(authority: LoadedAuthority) -> RuntimeFactProviderKey:
    evidence = authority.authority_evidence
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


def _installed_repository_provider_key() -> RuntimeFactProviderKey:
    try:
        from governance_ledger import get_builtin_domain_pack

        pack = get_builtin_domain_pack("repository-changes", "1.0.0")
    except (ImportError, TypeError, ValueError) as exc:
        raise RuntimeFactError(
            "the released repository-changes/1.0.0 fact provider is unavailable"
        ) from exc
    schema = pack["runtime_fact_schema"]
    return RuntimeFactProviderKey(
        domain_pack_id=pack["domain_pack_id"],
        domain_pack_version=pack["domain_pack_version"],
        domain_pack_hash=pack["canonical_hash"],
        schema_id=schema["schema_id"],
        schema_version=schema["schema_version_number"],
        schema_hash=schema["schema_hash"],
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
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
