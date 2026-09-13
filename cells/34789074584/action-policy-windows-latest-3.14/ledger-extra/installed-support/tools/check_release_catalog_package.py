"""Installed catalog-3 fixture and identity acceptance; run with python -I."""
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import runpy
import sys

import governance_ledger
from governance_ledger.action_policy import DEV_ENV
from governance_ledger.action_policy_publication import validate_compiled_authority_contract_v3
from governance_ledger.domain_packs import get_builtin_domain_pack
from governance_ledger.policy_translation import get_policy_translation_capability_catalog
from governance_ledger.publication_provenance import canonical_sha256, validate_publication_receipt

ROOT = Path(__file__).resolve().parents[1]
assert DEV_ENV not in os.environ
assert Path(sys.prefix).resolve() in Path(governance_ledger.__file__).resolve().parents
assert get_policy_translation_capability_catalog()["catalog_version"] == "1.0.0"
example = runpy.run_path(str(ROOT / "examples/native_v4_release.py"))
fixture_root = ROOT / "tests/fixtures/action_policy_release_v4"
catalog = get_policy_translation_capability_catalog(catalog_version="3.0.0")
pack = get_builtin_domain_pack("repository-changes", "3.0.0")
for name, value in {"catalog": catalog, "domain-pack": pack, "runtime-fact-schema": pack["runtime_fact_schema"]}.items():
    assert value == json.loads((fixture_root / (name + ".json")).read_text(encoding="utf-8"))
results = {}
for name in example["POLICIES"]:
    fixture = example["build_fixture"](name)
    for key, value in fixture.items():
        path = fixture_root / name / (key + (".txt" if key == "source" else ".json"))
        retained = path.read_text(encoding="utf-8")
        assert value == (retained if key == "source" else json.loads(retained))
    compiler = sys.modules.pop("compiler", None)
    sys.modules["compiler"] = None
    try:
        assert validate_compiled_authority_contract_v3(fixture["compiled-authority"])["valid"]
        assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]
    finally:
        sys.modules["compiler"] = compiler
    results[name] = {"full_artifact_hashes": {key: canonical_sha256(value) for key, value in fixture.items()},
                     "bundle_hash": fixture["authority-bundle"]["bundle_hash"],
                     "receipt_hash": fixture["publication-receipt"]["receipt_hash"],
                     "approval_id": fixture["approval"]["approval_id"]}
old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed/compiled-authority.json").read_text())
try:
    validate_compiled_authority_contract_v3(old)
except ValueError as exc:
    assert "explicit" in str(exc)
else:
    raise AssertionError("development authority validated without its opt-in")
assert DEV_ENV not in os.environ
print(json.dumps({"python": sys.version, "ledger_import": governance_ledger.__file__,
    "compiler_version": metadata.version("cricore-contract-compiler"), "development_flags_absent": True,
    "catalog": {k: catalog[k] for k in ("catalog_id", "catalog_version", "catalog_hash")},
    "domain_pack": {k: pack[k] for k in ("domain_pack_id", "domain_pack_version", "canonical_hash")},
    "runtime": {k: pack["runtime_fact_schema"][k] for k in ("schema_id", "schema_version_number", "schema_hash")},
    "enforcement_point": catalog["enforcement_points"][0]["enforcement_point_id"],
    "fixtures": results, "runtime_activation_ready": False}, indent=2))
