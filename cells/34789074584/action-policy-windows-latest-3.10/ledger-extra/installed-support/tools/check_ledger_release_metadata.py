"""Exact issue #23 metadata policy; semantic immutability is checked separately."""
import json
from pathlib import Path
import subprocess
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
BASE = "40e0875ee9a973254bb3a4d0c228cad4fdce2bc0"
project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
before = tomllib.loads(subprocess.check_output(["git", "show", f"{BASE}:pyproject.toml"], cwd=ROOT).decode())
before["project"]["version"] = "0.9.0"
before["project"]["optional-dependencies"]["guard"] = ["waveframe-guard>=0.19.0,<0.20.0"]
before["tool"]["waveframe"]["guard-compatibility"] = {
    "status": "pending-release-coordination", "ledger": "0.9.0", "guard": "0.19.0",
    "guard_ledger_requirement": ">=0.9.0,<0.10.0",
    "install_compatibility": "pending", "execution_compatibility": "pending",
}
assert project == before, "Only the specified release metadata changes are allowed"
assert project["project"]["dependencies"] == ["cricore-contract-compiler>=0.5.0,<0.6.0"]
print(json.dumps({"base": BASE, "version": project["project"]["version"],
    "compiler": project["project"]["dependencies"],
    "guard": project["project"]["optional-dependencies"]["guard"],
    "compatibility": project["tool"]["waveframe"]["guard-compatibility"]}, indent=2))
