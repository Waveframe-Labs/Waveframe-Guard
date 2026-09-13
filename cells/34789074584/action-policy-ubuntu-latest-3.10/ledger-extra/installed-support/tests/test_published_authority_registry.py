# ---
# title: "Published Authority Registry Invariant Tests"
# filetype: "source"
# type: "test"
# domain: "governance-publication"
# version: "0.5.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# ai_assisted: "partial"
# ---

import pytest

from governance_ledger.registry import build_contract_registry, validate_registry_identity


def _entry(*, bundle_hash: str, lifecycle_state: str = "active") -> dict[str, str]:
    return {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "authority_ref": "finance-policy@0.1.0",
        "contract_ref": "finance-policy@0.1.0",
        "contract_hash": "sha256:" + "a" * 64,
        "path": "contracts/finance-policy-0.1.0.contract.json",
        "bundle_path": "contracts/finance-policy-0.1.0.authority-bundle.json",
        "bundle_hash": bundle_hash,
        "lifecycle_state": lifecycle_state,
        "publication_id": "pub_20260713_0001",
        "published_at": "2026-07-13T12:00:00Z",
        "published_by": "governance-team",
    }


def test_registry_identity_rejects_same_contract_with_different_bundle_hash() -> None:
    existing = {"contracts": [_entry(bundle_hash="sha256:" + "b" * 64)]}
    candidate = _entry(bundle_hash="sha256:" + "c" * 64)

    with pytest.raises(ValueError, match="different bundle_hash"):
        validate_registry_identity(existing, candidate)


def test_registry_rejects_invalid_lifecycle_state() -> None:
    with pytest.raises(ValueError, match="Invalid lifecycle_state"):
        build_contract_registry(
            [_entry(bundle_hash="sha256:" + "b" * 64, lifecycle_state="reovked")],
            generated_at="2026-07-13T12:00:00Z",
        )
