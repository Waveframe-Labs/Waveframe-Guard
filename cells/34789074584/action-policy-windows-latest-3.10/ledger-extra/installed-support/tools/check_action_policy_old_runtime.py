"""Read-only published Guard compatibility probe. Run with python -I.

Install Guard 0.18.0 with published Ledger 0.7.0 or 0.8.0 in its own venv.
No candidate compiler or candidate Ledger is installed in this environment.
"""
import copy
import argparse
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import sys

from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.authority.types import Bundle, RegistryEntry
from waveframe_guard.authority.verifier import AuthorityVerifier

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixtures", choices=["action_policy_v4", "action_policy_release_v4"], default="action_policy_v4")
fixture_name = parser.parse_args().fixtures
FIXTURES = ROOT / "tests/fixtures" / fixture_name
assert metadata.version("waveframe-guard") == "0.18.0"
assert metadata.version("governance-ledger") in {"0.7.0", "0.8.0"}
assert metadata.distribution("governance-ledger").read_text("direct_url.json") is None
assert metadata.distribution("cricore-contract-compiler").read_text("direct_url.json") is None


def hash_json(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def probe(payload, receipt):
    contract = payload["compiled_authority_contract"]
    entry = RegistryEntry(authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
        contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
        bundle_path=FIXTURES / "modify-only/authority-bundle.json",
        publication_id=receipt["publication_id"], bundle_hash=payload["bundle_hash"],
        receipt_hash=receipt["receipt_hash"], published_by=receipt["published_by"],
        published_at=receipt["published_at"], receipt_path=ROOT / "unused-receipt.json",
        bundle_ref="contracts/development.authority-bundle.json",
        receipt_ref="contracts/development.publication-receipt.json")
    bundle = Bundle(registry_entry=entry, payload=payload, bundle_hash=payload["bundle_hash"],
        bundle_path=entry.bundle_path, receipt_payload=receipt, receipt_hash=receipt["receipt_hash"],
        receipt_path=entry.receipt_path, bundle_ref=entry.bundle_ref, receipt_ref=entry.receipt_ref)
    try:
        AuthorityVerifier().verify(bundle)
    except AuthorityVerificationError as exc:
        return {"rejected": True, "reason": str(exc)}
    return {"rejected": False}


results = []
for name in ("create-only", "modify-only", "mixed"):
    folder = FIXTURES / name
    original = json.loads((folder / "authority-bundle.json").read_text())
    receipt = json.loads((folder / "publication-receipt.json").read_text())
    for bundle_version, receipt_version in [
        ("authority_bundle.v4", "publication_receipt.v4"),
        ("authority_bundle.v3", "publication_receipt.v3"),
        ("authority_bundle.v2", "publication_receipt.v2"),
        ("authority_bundle.v1", "publication_receipt.v1"),
        ("authority_bundle.v3", "publication_receipt.v4"),
        ("authority_bundle.v4", "publication_receipt.v3"),
        (None, None),
        ("authority_bundle.v99", "publication_receipt.v99"),
    ]:
        bundle, pair_receipt = copy.deepcopy(original), copy.deepcopy(receipt)
        if bundle_version is None:
            bundle.pop("schema_version")
            pair_receipt.pop("schema_version")
        else:
            bundle["schema_version"] = bundle_version
            pair_receipt["schema_version"] = receipt_version
        bundle["bundle_hash"] = hash_json({k:v for k,v in bundle.items() if k != "bundle_hash"})
        pair_receipt["bundle_hash"] = bundle["bundle_hash"]
        pair_receipt["receipt_hash"] = hash_json({k:v for k,v in pair_receipt.items() if k != "receipt_hash"})
        result = probe(bundle, pair_receipt)
        results.append({"fixture": name, "bundle_version": bundle_version,
                        "receipt_version": receipt_version, **result})
        assert result["rejected"], results[-1]

report = {"python": sys.version.split()[0], "ledger": metadata.version("governance-ledger"),
          "fixtures": fixture_name,
          "guard": metadata.version("waveframe-guard"), "compiler": metadata.version("cricore-contract-compiler"),
          "environment": "ordinary published packages; isolated Python imports", "results": results,
          "limits": "Native fixtures and discriminator downgrade/mixed pairs only. Not proof against arbitrary forged legacy envelopes or filesystem creation acceptance."}
print(json.dumps(report, indent=2))
