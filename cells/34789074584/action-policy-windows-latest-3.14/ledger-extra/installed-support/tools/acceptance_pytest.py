"""Run pytest while recording and enforcing the selected Ledger import boundary."""
import json
import os
from pathlib import Path
import sys

import pytest


class ImportBoundary:
    def pytest_sessionfinish(self, session, exitstatus):
        expected = Path(os.environ["LEDGER_EXPECT_IMPORT_ROOT"]).resolve()
        paths = {
            name: str(Path(module.__file__).resolve())
            for name, module in list(sys.modules.items())
            if (name == "governance_ledger" or name.startswith("governance_ledger."))
            and getattr(module, "__file__", None)
        }
        Path(os.environ["LEDGER_IMPORT_REPORT"]).write_text(
            json.dumps({"python": sys.version, "executable": sys.executable,
                        "expected_root": str(expected), "imports": paths}, indent=2),
            encoding="utf-8",
        )
        assert paths and all(expected in Path(path).parents for path in paths.values()), paths


if __name__ == "__main__":
    # In installed mode this is a copied support tree with no Ledger source package.
    sys.path.insert(0, str(Path.cwd()))
    raise SystemExit(pytest.main(sys.argv[1:], plugins=[ImportBoundary()]))
