"""Verify archive origins and all installed module/resource bytes in the wheel set."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_provenance import compiler_provenance, installed_archive

expected = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
result = {"python": sys.version, "executable": sys.executable, "distributions": {}}
result["distributions"]["cricore-contract-compiler"] = compiler_provenance(sys.argv[1])
for name, version, modules in (("governance-ledger", "0.9.0", ["governance_ledger"]),
                               ("waveframe-guard", "0.19.0", ["waveframe_guard", "guard"])):
    result["distributions"][name] = installed_archive(
        name, version, modules, expected["distributions"][name], expected.get("install_report"))
print(json.dumps(result, indent=2))
