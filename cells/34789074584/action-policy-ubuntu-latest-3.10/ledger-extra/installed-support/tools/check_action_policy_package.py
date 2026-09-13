"""Installed-wheel acceptance. Run with python -I in a candidate-package venv."""
import importlib.metadata as metadata
import json
from pathlib import Path
import runpy
import sys

import governance_ledger
from governance_ledger.action_policy import DEV_ENV
from governance_ledger.publication_provenance import validate_publication_receipt

ROOT = Path(__file__).resolve().parents[1]
assert Path(sys.prefix).resolve() in Path(governance_ledger.__file__).resolve().parents
assert Path(governance_ledger.__file__).resolve().parent != ROOT / "governance_ledger"
example = runpy.run_path(str(ROOT / "examples/native_v4_development.py"))
for name in example["POLICIES"]:
    fixture = example["build_fixture"](name)
    for key, value in fixture.items():
        suffix = ".txt" if key == "source" else ".json"
        retained = (ROOT / "tests/fixtures/action_policy_v4" / name / (key + suffix)).read_text(encoding="utf-8")
        assert value == (retained if key == "source" else json.loads(retained))
    # Import denial proves validation relies on retained approved public semantics.
    compiler = sys.modules.pop("compiler", None)
    sys.modules["compiler"] = None
    try:
        assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]
    finally:
        sys.modules["compiler"] = compiler
print(json.dumps({"python": sys.version.split()[0], "ledger": metadata.version("governance-ledger"),
    "ledger_import": governance_ledger.__file__,
    "compiler": metadata.version("cricore-contract-compiler"),
    "installed_wheel": True, "fixtures_reproduced": list(example["POLICIES"]),
    "private_provider_or_compiler_required_for_verification": False}, indent=2))
