from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .schemas import (
    GOVERNED_EXECUTION_RESULT_V1,
    validate_execution_result_payload,
)


@dataclass(frozen=True)
class GovernedExecutionResult:
    allowed: bool
    reason: str
    contract_id: str | None = None
    contract_version: str | None = None
    contract_hash: str | None = None
    authority_lifecycle: dict[str, Any] | None = field(default=None, compare=False)
    value: Any = None
    error: str | None = None
    event: dict[str, Any] | None = field(default=None, compare=False)
    audit_receipt: dict[str, Any] | None = field(default=None, compare=False)
    missing_approvals: list[dict[str, Any]] = field(default_factory=list, compare=False)
    execution_state: dict[str, Any] | None = field(default=None, compare=False)
    decision_trace: dict[str, Any] | None = field(default=None, compare=False)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": GOVERNED_EXECUTION_RESULT_V1,
            "decision": "ALLOWED" if self.allowed else "BLOCKED",
            "allowed": self.allowed,
            "reason": self.reason,
            "missing_approvals": self.missing_approvals,
            "authority_ref": _authority_ref(self.contract_id, self.contract_version),
            "contract_id": self.contract_id,
            "contract_version": self.contract_version,
            "contract_hash": self.contract_hash,
            "source_hash": (self.execution_state or {}).get("source_hash"),
            "compilation_report_hash": (self.execution_state or {}).get("compilation_report_hash"),
            "execution_state": self.execution_state,
            "decision_trace": self.decision_trace,
            "event_id": (self.event or {}).get("event_id"),
            "event_hash": (self.audit_receipt or {}).get("event_hash"),
        }
        if self.authority_lifecycle is not None:
            payload["authority_lifecycle"] = self.authority_lifecycle
        if self.error is not None:
            payload["error"] = self.error
        validate_execution_result_payload(payload)
        return payload


def _authority_ref(contract_id: str | None, contract_version: str | None) -> str:
    if not contract_id or not contract_version:
        return ""
    return f"{contract_id}@{contract_version}"
