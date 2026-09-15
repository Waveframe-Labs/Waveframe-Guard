"""Record installed candidate module/resource bytes and actual source origins."""
import argparse
import hashlib
import importlib
from importlib.metadata import distribution
import json
from pathlib import Path
import sys


def snapshot():
    result = {"python": sys.version, "executable": sys.executable, "distributions": {}}
    for name, module in (("governance-ledger", "governance_ledger"),
                         ("cricore-contract-compiler", "compiler")):
        dist = distribution(name)
        root = Path(importlib.import_module(module).__file__).resolve().parent
        assert root.is_relative_to(Path(sys.prefix).resolve()), root
        result["distributions"][name] = {
            "version": dist.version, "module_root": str(root),
            "origin": json.loads(dist.read_text("direct_url.json") or "null"),
            "runtime_sha256": {p.relative_to(root.parent).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sorted(root.rglob("*"))
                               if p.is_file() and "__pycache__" not in p.parts},
        }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(snapshot(), indent=2) + "\n", encoding="utf-8")
