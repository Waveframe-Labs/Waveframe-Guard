"""Release-only generation and complete-approval rejection probes."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from tools.acceptance.action_policy_creation import FIXTURES, resolver
from waveframe_guard.authority import load_authority, MemoryAuthorityCache
from waveframe_guard.authority.loader import BundleLoader
from waveframe_guard.authority.verifier import AuthorityVerifier
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from guard.adapters.compiled_authority import intake_compiled_authority, CompiledAuthorityIntakeError

RELEASE = FIXTURES.parent / "action_policy_release_v4"
REF = "repository-create-only@3.0.0"


@pytest.fixture(autouse=True)
def release_environment(monkeypatch):
    from governance_ledger.policy_translation import get_policy_translation_capability_catalog
    try:
        get_policy_translation_capability_catalog(catalog_version="3.0.0")
    except (TypeError, ValueError):
        pytest.skip("historical dependency baseline lacks catalog 3; release CI requires these cases")
    for name in ("WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"):
        monkeypatch.delenv(name, raising=False)


def test_complete_public_validators_and_cache(monkeypatch):
    import governance_ledger
    calls = []
    for name in ("validate_authority_bundle", "validate_publication_receipt"):
        original = getattr(governance_ledger, name)
        def verify(*args, _original=original, _name=name, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)
        monkeypatch.setattr(governance_ledger, name, verify)
    source, cache = resolver("create-only", RELEASE), MemoryAuthorityCache()
    loaded = load_authority(REF, resolver=source, cache=cache)
    assert calls == ["validate_authority_bundle", "validate_publication_receipt"]
    assert load_authority(REF, resolver=source, cache=cache) == loaded
    assert loaded.authority_bundle == json.loads((RELEASE / "create-only/authority-bundle.json").read_text())


@pytest.mark.parametrize("field", ["capability_catalog", "approval_record", "enforcement_point", "pack", "runtime", "unknown", "receipt"])
def test_mixed_or_stale_approval_rejected(field):
    bundle = BundleLoader().load(resolver("create-only", RELEASE).resolve(REF))
    payload, receipt = deepcopy(bundle.payload), deepcopy(bundle.receipt_payload)
    old = json.loads((FIXTURES / "create-only/authority-bundle.json").read_text())
    if field == "capability_catalog":
        payload["policy_translation_commitment"][field] = old["policy_translation_commitment"][field]
    elif field == "approval_record":
        payload[field] = old[field]
    elif field == "enforcement_point":
        payload["policy_translation_commitment"]["clauses"][0]["controls"][0]["candidate_control"][field] = "waveframe.guard.repository-change.v2-development"
    elif field == "pack":
        payload["domain_pack"] = old["domain_pack"]
    elif field == "runtime":
        payload["runtime_fact_schema"] = old["runtime_fact_schema"]
    elif field == "unknown":
        payload["policy_translation_commitment"]["capability_catalog"]["catalog_version"] = "4.0.0"
    else:
        receipt = json.loads((FIXTURES / "create-only/publication-receipt.json").read_text())
    # Even recomputed outer hashes do not supply fresh human approval.
    from governance_ledger.constraint_ir import artifact_hash
    payload["bundle_hash"] = artifact_hash(payload, "bundle_hash")
    receipt["receipt_hash"] = artifact_hash(receipt, "receipt_hash")
    with pytest.raises(AuthorityVerificationError):
        AuthorityVerifier().verify(replace(bundle, payload=payload, receipt_payload=receipt))


@pytest.mark.parametrize("kwargs", [{}, {"_verified_v2_authority": True}, {"_verified_runtime_authority": True}])
def test_release_compiled_alone_never_authorizes(kwargs):
    contract = json.loads((RELEASE / "create-only/compiled-authority.json").read_text())
    with pytest.raises(CompiledAuthorityIntakeError):
        intake_compiled_authority(contract, **kwargs)


def test_missing_release_dependency_has_useful_diagnostic(monkeypatch):
    import governance_ledger.action_policy_publication as api
    monkeypatch.delattr(api, "validate_compiled_authority_contract_v3")
    with pytest.raises(AuthorityVerificationError, match="exact catalog and complete public validators"):
        load_authority(REF, resolver=resolver("create-only", RELEASE))


@pytest.mark.parametrize("field", ["contract", "receipt", "evidence", "schema", "marker"])
def test_release_cached_substitution(field):
    source, cache = resolver("create-only", RELEASE), MemoryAuthorityCache()
    loaded = load_authority(REF, resolver=source, cache=cache)
    if field == "contract": loaded.contract["action_requirements"]["create"]["allow"] = []
    elif field == "receipt": loaded.publication_receipt["published_by"] = "substituted"
    elif field == "evidence": loaded.authority_evidence["domain_pack"]["domain_pack_version"] = "2.0.0"
    elif field == "schema": loaded.runtime_fact_schema["schema_version_number"] = "2.0.0"
    else: loaded = replace(loaded, _verification_marker=None)
    with pytest.raises(AuthorityVerificationError):
        cache.put(loaded)
        load_authority(REF, resolver=source, cache=cache)
