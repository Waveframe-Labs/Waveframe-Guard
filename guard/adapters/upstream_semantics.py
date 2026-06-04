from __future__ import annotations

from importlib import import_module
from typing import Any


UPSTREAM_SEMANTICS_MODULES = (
    "governance_ledger.semantics.execution_projection",
    "governance_ledger.semantics.compiler",
    "cricore.api",
)


class UpstreamSemanticsAdapterError(RuntimeError):
    pass


def load_upstream_semantics_adapters() -> dict[str, Any]:
    adapters = {}
    for module_name in UPSTREAM_SEMANTICS_MODULES:
        try:
            adapters[module_name] = import_module(module_name)
        except ImportError:
            adapters[module_name] = None
    if not any(adapters.values()):
        raise UpstreamSemanticsAdapterError("no upstream compiled authority semantics adapters are available")
    return adapters
