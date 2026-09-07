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


@pytest.fixture(autouse=True)
def strict_cri(monkeypatch):
    """Anticipate CRI-CORE #2 across legacy AND modern regression suites."""
    from copy import deepcopy
    import importlib
    import cricore.api

    original = cricore.api.evaluate_structured
    api_module = importlib.import_module(original.__module__)
    pipeline = api_module.run_execution_pipeline
    pipeline_module = importlib.import_module(pipeline.__module__)
    calls = []

    def require_strict(mode, run_context):
        assert mode == "strict", "CRI argument mode must be explicit strict"
        assert run_context["mode"] == mode, "CRI/context modes must agree"

    def strict_only(*, mode=None, run_context=None, **kwargs):
        require_strict(mode, run_context)
        return original(mode=mode, run_context=run_context, **kwargs)

    def strict_pipeline(*, mode=None, run_context=None, **kwargs):
        require_strict(mode, run_context)
        calls.append(deepcopy({"mode": mode, "run_context": run_context, **kwargs}))
        return pipeline(mode=mode, run_context=run_context, **kwargs)

    monkeypatch.setattr(cricore.api, "evaluate_structured", strict_only)
    monkeypatch.setattr(api_module, "evaluate_structured", strict_only)
    monkeypatch.setattr(api_module, "run_execution_pipeline", strict_pipeline)
    monkeypatch.setattr(pipeline_module, "run_execution_pipeline", strict_pipeline)
    for module_name in ("waveframe_guard.execute", "waveframe_guard.runtime"):
        module = importlib.import_module(module_name)
        for name, replacement in (("evaluate_structured", strict_only),
                                  ("run_execution_pipeline", strict_pipeline)):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, replacement)
    return calls
