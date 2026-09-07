"""Trusted target semantics, separate from cached normative authority artifacts."""

from dataclasses import asdict, dataclass
from collections.abc import Mapping

from guard.runtime.identity import stable_hash
from .repository_boundary import RepositoryBoundaryError


@dataclass(frozen=True)
class TargetBinding:
    target_domain: str
    workspace_binding_id: str | None
    adapter_version: str
    assurance_class: str
    authority_contract_hash: str
    domain_resolver: str
    schema_version: str = "guard_target_binding.v1"

    def evidence(self):
        return asdict(self)

    @property
    def canonical_hash(self):
        return stable_hash(self.evidence())


def reject_binding_override(value):
    """Do not accept request-supplied copies of trusted provenance."""
    reserved = {"target_binding", "target_binding_hash", "target_domain", "repository_root",
                "workspace_binding_id", "adapter_version", "assurance_class", "domain_resolver"}
    if isinstance(value, Mapping):
        if reserved.intersection(value):
            raise RepositoryBoundaryError("caller-supplied target binding is not accepted")
        for nested in value.values():
            reject_binding_override(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            reject_binding_override(nested)
