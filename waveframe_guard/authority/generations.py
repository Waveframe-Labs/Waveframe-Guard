"""Exact SDK support bindings; Ledger still verifies the complete approval chain."""

from collections.abc import Mapping

from .development import require_action_policy_development
from .exceptions import AuthorityVerificationError


# catalog hash, pack hash, runtime hash, enforcement point
_GENERATIONS = {
    "2.0.0": (
        "sha256:8530e82761a333c5e7e8cc0ccb0b2949310ea91b470d548613c98078896f030a",
        "sha256:ec260daef10cdb3f97ca0a5137deb658a0fc997f22997299153cd848a12323a0",
        "sha256:bd79503e01d79583ab564be98890fddaa8124e935e7eb81a8a40786cc6d2c01d",
        "waveframe.guard.repository-change.v2-development",
    ),
    "3.0.0": (
        "sha256:bd7fd23eb59b5521ef6780edec0667ce9b7ba9b5738dfa2701a575fb3efce930",
        "sha256:78783654a8131cb7a6547ee2ed9507e1dced640aebe32d35057c385bb1dc4459",
        "sha256:3fcf3af0a61f91a78b171ccd6247db9f0f908e1baf44aa50ece12349c44bb582",
        "waveframe.guard.repository-change.v2",
    ),
}


def require_action_generation(contract):
    """Recheck opt-ins on every use, including immutable warm runtime snapshots.

    This establishes SDK support only. It cannot confer publication verification.
    """
    provenance = contract.get("provenance", {})
    for version, (_, pack, runtime, _) in _GENERATIONS.items():
        if (provenance.get("domain_pack_hash"), provenance.get("runtime_fact_schema_hash")) == (pack, runtime):
            if version == "2.0.0":
                require_action_policy_development()
            return version
    raise AuthorityVerificationError("unsupported or mixed action policy generation")


def verify_publication_generation(payload):
    """Bind catalog, pack, runtime and confirmed enforcement points exactly."""
    try:
        version = require_action_generation(payload["compiled_authority_contract"])
        catalog_hash, pack_hash, runtime_hash, enforcement = _GENERATIONS[version]
        commitment = payload["policy_translation_commitment"]
        expected_catalog = dict(catalog_id="waveframe.coding-agent.repository-change",
                                catalog_version=version, catalog_hash=catalog_hash)
        expected_pack = dict(domain_pack_id="repository-changes",
                             domain_pack_version=version, domain_pack_hash=pack_hash)
        schema = payload["runtime_fact_schema"]
        if (commitment["capability_catalog"] != expected_catalog
            or payload["domain_pack"] != expected_pack
            or payload["constraint_ir"]["domain_pack"] != expected_pack
            or (schema["schema_id"], schema["schema_version_number"], schema["schema_hash"])
                != ("repository-changes-runtime", version, runtime_hash)):
            raise ValueError("catalog/pack/runtime bindings disagree")
        for clause in commitment["clauses"]:
            for record in clause["controls"]:
                if record["candidate_control"]["enforcement_point"] != enforcement:
                    raise ValueError("unsupported enforcement point")
        # Confirm that the installed dependency supplies the exact catalog and
        # public validators. Never fall back to a shared envelope version.
        from governance_ledger.policy_translation import get_policy_translation_capability_catalog
        from governance_ledger.action_policy_publication import validate_compiled_authority_contract_v3

        catalog = get_policy_translation_capability_catalog(catalog_version=version)
        if any(catalog.get(key) != value for key, value in expected_catalog.items()):
            raise ValueError("installed catalog identity differs")
        validate_compiled_authority_contract_v3(dict(payload["compiled_authority_contract"]))
        return version
    except AuthorityVerificationError:
        raise
    except (ImportError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AuthorityVerificationError(
            "action publication requires Ledger's exact catalog and complete public validators: " + str(exc)
        ) from exc
