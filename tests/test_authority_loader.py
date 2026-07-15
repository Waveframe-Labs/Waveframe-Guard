from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from waveframe_guard.authority import LoadedAuthority, load_authority
from waveframe_guard.authority.adapters import LocalRegistryResolver, MemoryAuthorityResolver
from waveframe_guard.authority.exceptions import (
    AuthorityLifecycleError,
    AuthorityNotFound,
    AuthorityVerificationError,
    InvalidAuthorityRef,
    MalformedAuthorityRegistry,
)
from waveframe_guard.authority.loader import BundleLoader
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
    assert authority.bundle_path.name == "finance-policy-1.0.0.authority-bundle.json"
    assert authority.lifecycle_state == "active"


@pytest.mark.parametrize(
    "authority_ref",
    [
        "finance-policy",
        "finance-policy@latest",
        "finance-policy@active",
        "finance-policy@banana",
        "finance-policy@1",
        "finance-policy@1.2",
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

    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")

    assert entry.authority_ref == "finance-policy@1.2.0"
    assert entry.publication_id == "pub_123"
    assert entry.lifecycle_state == "active"
    assert entry.bundle_path == tmp_path / "contracts" / "finance-policy-1.2.0.authority-bundle.json"


@pytest.mark.parametrize("resolver_factory", ["local", "memory"])
def test_resolver_contract_is_shared_by_local_and_memory_adapters(tmp_path, resolver_factory):
    registry_path = _write_authority_fixture(tmp_path)
    local_resolver = LocalRegistryResolver(registry_path, workspace_root=tmp_path)
    local_entry = local_resolver.resolve("finance-policy@1.2.0")
    resolver = local_resolver if resolver_factory == "local" else MemoryAuthorityResolver([local_entry])

    entry = resolver.resolve("finance-policy@1.2.0")

    assert entry.authority_ref == "finance-policy@1.2.0"
    assert entry.contract_id == "finance-policy"
    assert entry.contract_version == "1.2.0"
    assert entry.bundle_path == local_entry.bundle_path
    assert entry.lifecycle_state == local_entry.lifecycle_state


def test_load_authority_accepts_injected_memory_resolver(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    resolver = MemoryAuthorityResolver({"finance-policy@1.2.0": entry})

    authority = load_authority("finance-policy@1.2.0", resolver=resolver)

    assert authority.authority_ref == "finance-policy@1.2.0"
    assert authority.contract["contract_id"] == "finance-policy"


def test_memory_resolver_rejects_duplicate_authority_references(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")

    with pytest.raises(MalformedAuthorityRegistry, match="duplicate"):
        MemoryAuthorityResolver([entry, entry])


def test_memory_resolver_missing_reference_raises_authority_not_found(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    resolver = MemoryAuthorityResolver([entry])

    with pytest.raises(AuthorityNotFound):
        resolver.resolve("finance-policy@1.2.1")


@pytest.mark.parametrize("resolver_factory", ["local", "memory"])
def test_invalid_explicit_refs_fail_consistently_across_adapters(tmp_path, resolver_factory):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    resolver = (
        LocalRegistryResolver(registry_path, workspace_root=tmp_path)
        if resolver_factory == "local"
        else MemoryAuthorityResolver([entry])
    )

    with pytest.raises(InvalidAuthorityRef):
        resolver.resolve("finance-policy@latest")


def test_resolvers_do_not_open_bundle_files(tmp_path, monkeypatch):
    registry_path = _write_authority_fixture(tmp_path)
    local_resolver = LocalRegistryResolver(registry_path, workspace_root=tmp_path)
    entry = local_resolver.resolve("finance-policy@1.2.0")
    entry.bundle_path.unlink()
    memory_resolver = MemoryAuthorityResolver([entry])

    assert local_resolver.resolve("finance-policy@1.2.0").bundle_path == entry.bundle_path
    assert memory_resolver.resolve("finance-policy@1.2.0").bundle_path == entry.bundle_path


def test_resolver_supplied_lifecycle_state_is_preserved_unchanged(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"lifecycle_state": "superseded"},
    )
    registry_path = _rewrite_registry_hash(registry_path)

    local_entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    memory_entry = MemoryAuthorityResolver([local_entry]).resolve("finance-policy@1.2.0")

    assert local_entry.lifecycle_state == "superseded"
    assert memory_entry.lifecycle_state == "superseded"


def test_custom_resolver_can_be_injected_without_changing_loader_code(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")

    class CustomResolver:
        def resolve(self, authority_ref):
            assert authority_ref == "finance-policy@1.2.0"
            return entry

    authority = load_authority("finance-policy@1.2.0", resolver=CustomResolver())

    assert authority.authority_ref == "finance-policy@1.2.0"


def test_bundle_loader_only_loads_bundle_without_verifying_authority(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")

    bundle = BundleLoader().load(entry)

    assert isinstance(bundle, Bundle)
    assert bundle.registry_entry == entry
    assert bundle.payload["contract"]["contract_id"] == "finance-policy"
    assert bundle.bundle_hash.startswith("sha256:")


def test_authority_verifier_verifies_bundle_and_returns_loaded_authority(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
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
    registry_path = _rewrite_registry_hash(registry_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityVerificationError, match="contract hash mismatch"):
        AuthorityVerifier().verify(bundle)


def test_bundle_loader_rejects_bundle_hash_mismatch(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"bundle_hash": "sha256:bad"},
    )
    registry_path = _rewrite_registry_hash(registry_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityVerificationError, match="bundle hash mismatch"):
        AuthorityVerifier().verify(bundle)


def test_bundle_loader_rejects_lifecycle_states_that_are_not_loadable(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"lifecycle_state": "revoked"},
    )
    registry_path = _rewrite_registry_hash(registry_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityLifecycleError, match="revoked"):
        AuthorityVerifier().verify(bundle)


def test_local_registry_resolver_verifies_registry_hash_before_trusting_entries(tmp_path):
    registry_path = _write_authority_fixture(tmp_path)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["contracts"][0]["bundle_hash"] = "sha256:tampered"
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(MalformedAuthorityRegistry, match="registry hash mismatch"):
        LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")


@pytest.mark.parametrize("missing_field", ["bundle_path", "bundle_hash", "contract_hash", "lifecycle_state"])
def test_local_registry_resolver_requires_canonical_bundle_fields(tmp_path, missing_field):
    registry_path = _write_authority_fixture(tmp_path)
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["contracts"][0].pop(missing_field)
    registry_path.write_text(json.dumps(_with_registry_hash(registry), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(MalformedAuthorityRegistry, match=missing_field):
        LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")


def test_local_registry_resolver_rejects_unknown_lifecycle_state(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"lifecycle_state": "paused"},
    )
    registry_path = _rewrite_registry_hash(registry_path)

    with pytest.raises(MalformedAuthorityRegistry, match="unknown lifecycle_state"):
        LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")


def test_bundle_loader_rejects_raw_contract_files_as_authority_bundles(tmp_path):
    registry_path = _write_authority_fixture(
        tmp_path,
        registry_overrides={"bundle_path": "contracts/finance-policy-1.2.0.contract.json"},
        write_raw_contract=True,
    )
    registry_path = _rewrite_registry_hash(registry_path)
    entry = LocalRegistryResolver(registry_path, workspace_root=tmp_path).resolve("finance-policy@1.2.0")
    bundle = BundleLoader().load(entry)

    with pytest.raises(AuthorityVerificationError, match="missing contract"):
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
    assert "verifies `registry_hash` before trusting registry entries" in source
    assert "workspace-root-relative" in source
    assert "`active` is loadable" in source
    assert "missing lifecycle state is malformed" in source
    assert "The pipeline shape is fixed" in source
    assert "MemoryAuthorityResolver" in source
    assert "Resolvers must not return bundles" in source


def _write_authority_fixture(
    tmp_path: Path,
    *,
    registry_overrides=None,
    write_raw_contract=False,
) -> Path:
    contracts_dir = tmp_path / "contracts"
    contracts_dir.mkdir()
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
    raw_contract_path = contracts_dir / "finance-policy-1.2.0.contract.json"
    if write_raw_contract:
        raw_contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    bundle = {
        "authority_ref": "finance-policy@1.2.0",
        "bundle_schema_version": "published_authority_bundle.v1",
        "contract": contract,
        "publication": {
            "publication_id": "pub_123",
            "published_at": "2026-07-14T00:00:00+00:00",
            "published_by": "ledger",
        },
    }
    bundle_path = contracts_dir / "finance-policy-1.2.0.authority-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    entry = {
        "authority_ref": "finance-policy@1.2.0",
        "contract_id": "finance-policy",
        "contract_version": "1.2.0",
        "contract_hash": f"sha256:{contract['contract_hash']}",
        "bundle_hash": f"sha256:{_canonical_hash(bundle)}",
        "bundle_path": "contracts/finance-policy-1.2.0.authority-bundle.json",
        "publication_id": "pub_123",
        "lifecycle_state": "active",
        "published_at": "2026-07-14T00:00:00+00:00",
        "published_by": "ledger",
    }
    entry.update(registry_overrides or {})
    registry_path = tmp_path / "index.json"
    registry_path.write_text(json.dumps(_with_registry_hash({"contracts": [entry]}), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry_path


def _contract_hash(contract: dict) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_hash(payload) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _with_registry_hash(registry: dict) -> dict:
    registry = {
        key: value
        for key, value in registry.items()
        if key != "registry_hash"
    }
    return {
        **registry,
        "registry_hash": f"sha256:{_canonical_hash(registry)}",
    }


def _rewrite_registry_hash(registry_path: Path) -> Path:
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry_path.write_text(json.dumps(_with_registry_hash(registry), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return registry_path
