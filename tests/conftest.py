import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

for module_name, module in list(sys.modules.items()):
    if module_name == "waveframe_guard" or module_name.startswith("waveframe_guard."):
        module_file = getattr(module, "__file__", None)
        if module_file is not None and not Path(module_file).resolve().is_relative_to(REPO_ROOT):
            del sys.modules[module_name]

from waveframe_guard.context import clear_context


@pytest.fixture(autouse=True)
def reset_guard_context():
    clear_context()
    yield
    clear_context()
