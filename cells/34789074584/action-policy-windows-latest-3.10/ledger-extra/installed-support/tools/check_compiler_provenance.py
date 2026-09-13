"""Validate exact Git or explicitly supplied verified Compiler archive provenance."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_provenance import compiler_provenance

if __name__ == "__main__":
    print(json.dumps(compiler_provenance(), indent=2))
