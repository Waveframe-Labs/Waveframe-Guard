from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GovernedExecutionResult:
    allowed: bool
    reason: str
    contract_id: str | None = None
    contract_version: str | None = None
    contract_hash: str | None = None
    value: Any = None
    error: str | None = None
