from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvaluateRequest(BaseModel):
    action: Dict[str, Any]
    actor: str
    context: Optional[Dict[str, Any]] = None
    policy: Optional[str] = Field(
        default="finance-policy.json",
        description="Path or identifier for the policy file",
    )


class EvaluateResponse(BaseModel):
    event_id: str
    timestamp: str
    allowed: bool
    reason: str


class EventRecord(BaseModel):
    event_id: str
    timestamp: str
    actor: str
    action_type: str
    action: Dict[str, Any]
    context: Dict[str, Any]
    allowed: bool
    reason: str
    policy: str

    @classmethod
    def create(
        cls,
        *,
        actor: str,
        action: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        allowed: bool,
        reason: str,
        policy: str,
    ) -> "EventRecord":
        return cls(
            event_id=f"evt_{uuid4().hex}",
            timestamp=utc_now_iso(),
            actor=actor,
            action_type=str(action.get("type", "unknown")),
            action=action,
            context=context or {},
            allowed=allowed,
            reason=reason,
            policy=policy,
        )