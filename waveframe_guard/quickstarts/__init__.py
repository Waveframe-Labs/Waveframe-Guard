"""
---
title: "Waveframe Guard packaged quickstarts"
filetype: "source-code"
domain: "guard-sdk"
status: "preview"
ai_assisted: "partial"
---
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .external_agent import QuickstartSettings, build_guard, main, run_quickstart

__all__ = ["QuickstartSettings", "build_guard", "main", "run_quickstart"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(".external_agent", __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
