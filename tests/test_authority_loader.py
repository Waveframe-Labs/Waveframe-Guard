from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from waveframe_guard.authority import LoadedAuthority, load_authority
from waveframe_guard.authority.exceptions import (
    AuthorityLifecycleError,
    AuthorityVerificationError,
    InvalidAuthorityRef,
)
from waveframe_guard.authority.loader import BundleLoader
from waveframe_guard.authority.resolver import LocalRegistryResolver
from waveframe_guard.authority.types import Bundle
from waveframe_guard.authority.verifier import AuthorityVerifier


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_load_authority_returns_first_class_authority_object():
    authority = load_authority("finance-policy@1.0.0")

    assert isinstance(authority, LoadedAuthority)
    assert authority.authority_ref == "finance-policy@1.0.0"
    assert authority.contract["contract_id"] == "finance-policy"
    assert authority.contract["contract_version"] == "1.0.0"
    assert authority.contract_hash == "sha256:e4fd822ae1ac5f0228c9042dfd81c7c96b2774bf7e1e5516d9db95880b1aab70"
    assert authority.bundle_hash.startswith("sha256:")
    assert authority.bundle_path.name == "finance-policy-1.0.0.contract.json"
    assert authority.lifecycle_state == "active"


@pytest.mark.parametrize(
    "authority_ref",
    [
        "finance-policy",
        "finance-policy@latest",
        "contracts/finance-policy-1.0.0.contract.json",
        "finance-policy-1.0.0.contract.json",
        "finance-policy@",
        "@1.0.0",
    ],
)
def test_load_authority_accepts_only_explicit_authority_refs(authority_ref):
    with pytest.raises(InvalidAuthorityRef):
        load_authority(authority_ref)


def test_local_registry_resolver_returns_registry_entry_for_explicit_ref(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)

    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")

    assert entry.authority_ref == "finance-policy@1.2.0"
    assert entry.publication_id == "pub_123"
    assert entry.lifecycle_state == "active"
    assert entry.bundle_path == tmp_path / "finance-policy-1.2.0.contract.json"


def test_bundle_loader_only_loads_bundle_without_verifying_authority(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")

    bundle = BundleLoader().load(entry)

    assert isinstance(bundle, Bundle)
    assert bundle.registry_entry == entry
    assert bundle.contract["contract_id"] == "finance-policy"
    assert bundle.bundle_hash.startswith("sha256:")


def test_authority_verifier_verifies_bundle_and_returns_loaded_authority(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    authority = AuthorityVerifier().verify(bundle)

    assert authority.authority_ref == "finance-policy@1.2.0"
    assert authority.publication_id == "pub_123"
    assert authority.published_by == "ledger"
    assert authority.published_at == "2026-07-14T00:00:00+00:00"
    assert authority.contract["contract_id"] == "finance-policy"


def test_bundle_loader_rejects_contract_hash_mismatch(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"contract_hash": "sha256:bad"},
    )
    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityVerificationError, match="contract hash mismatch"):
        AuthorityVerifier().verify(bundle)


def test_bundle_loader_rejects_bundle_hash_mismatch(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"bundle_hash": "sha256:bad"},
    )
    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityVerificationError, match="bundle hash mismatch"):
        AuthorityVerifier().verify(bundle)


def test_bundle_loader_rejects_lifecycle_states_that_are_not_loadable(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"lifecycle_state": "revoked"},
    )
    entry = LocalRegistryResolver(registry_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityLifecycleError, match="revoked"):
        AuthorityVerifier().verify(bundle)


def test_authority_loading_invariant_is_documented():
    source = (REPO_ROOT / "docs" / "architecture" / "AUTHORITY_LOADING_BOUNDARY.md").read_text(
        encoding="utf-8"
    )

    assert "AuthorityLoader never modifies authority" in source
    assert "AuthorityLoader never upgrades authority" in source
    assert "AuthorityLoader never recompiles authority" in source
    assert "AuthorityLoader never repairs authority" in source
    assert "AuthorityLoader only loads verified published authority" in source


def _write_authority_fixture(tmp_path: Path, *, registry_overrides=None) -> Path:
    contract = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "1.2.0",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    contract["contract_hash"] = _contract_hash(contract)
    bundle_path = tmp_path / "finance-policy-1.2.0.contract.json"
    bundle_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    entry = {
        "authority_ref": "finance-policy@1.2.0",
        "contract_id": "finance-policy",
        "contract_version": "1.2.0",
        "contract_hash": f"sha256:{contract['contract_hash']}",
        "bundle_hash": f"sha256:{_file_hash(bundle_path)}",
        "path": bundle_path.name,
        "publication_id": "pub_123",
        "lifecycle_state": "active",
        "published_at": "2026-07-14T00:00:00+00:00",
        "published_by": "ledger",
    }
    entry.update(registry_overrides or {})
    registry_path = tmp_path / "index.json"
    registry_path.write_text(json.dumps({"contracts": [entry]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry_path


def _contract_hash(contract: dict) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()
