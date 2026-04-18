from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

import requests


class GuardDecision:
    """Canonical decision object returned from Waveframe Guard."""

    def __init__(
        self,
        allowed: bool,
        reason: str,
        decision_trace: list,
        resolved_identities: dict,
        impact: Optional[list] = None,
        summary: Optional[str] = None,
        trace_hash: Optional[str] = None,
    ):
        self.allowed = allowed
        self.reason = reason
        self.decision_trace = decision_trace
        self.resolved_identities = resolved_identities
        self.impact = impact or []
        self.summary = summary
        self.trace_hash = trace_hash

    def __repr__(self) -> str:
        status = "ALLOWED" if self.allowed else "BLOCKED"
        return f"<GuardDecision {status}: {self.reason}>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "decision_trace": self.decision_trace,
            "resolved_identities": self.resolved_identities,
            "impact": self.impact,
            "summary": self.summary,
            "trace_hash": self.trace_hash,
        }


class WaveframeGuard:
    """
    Waveframe Guard SDK client.

    Supports two modes:
    - Sandbox mode: initialize with `policy=...` and evaluate against `/validate`
    - Production mode: initialize with `policy_ref=...` and optional `api_key`
      to evaluate against `/v1/enforce`
    """

    def __init__(
        self,
        policy: Optional[Dict[str, Any]] = None,
        *,
        base_url: str = "http://localhost:8000",
        policy_ref: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.policy = policy
        self.policy_ref = policy_ref
        self.api_key = api_key

    def evaluate(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GuardDecision:
        """Evaluate whether an action is allowed to execute."""

        context = self._normalize_context(context)
        payload = self._build_payload(action=action, actor=actor, context=context)
        endpoint = "/validate" if self.policy is not None else "/v1/enforce"

        res = requests.post(
            f"{self.base_url}{endpoint}",
            json=payload,
            headers=self._build_headers(),
            timeout=10,
        )

        if res.status_code != 200:
            raise RuntimeError(
                f"Guard evaluation failed: {res.status_code} {res.text}"
            )

        return self._decision_from_response(res.json())

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Optional[Dict[str, Any]] = None,
        execute_fn: Optional[Callable[[], Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate the action and optionally execute it if allowed.

        If `execute_fn` is omitted, returns the decision payload directly for
        compatibility with older SDK examples in this repository.
        """

        decision = self.evaluate(action=action, actor=actor, context=context)
        record = self._build_decision_record(
            decision=decision,
            action=action,
            actor=actor,
            context=self._normalize_context(context),
        )

        if execute_fn is None:
            return decision.to_dict()

        if decision.allowed:
            result = execute_fn()
            return {
                "executed": True,
                "result": result,
                "decision": record,
            }

        return {
            "blocked": True,
            "reason": decision.reason,
            "decision": record,
        }

    def _build_payload(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "action": action,
            "actor": actor,
            "context": context,
        }

        if self.policy is not None:
            payload["policy"] = self.policy
        else:
            payload["policy_ref"] = self.policy_ref

        return payload

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _normalize_context(
        self,
        context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if context is None:
            return {}
        if not isinstance(context, dict):
            raise TypeError("context must be a dictionary")
        return context

    def _decision_from_response(self, data: Dict[str, Any]) -> GuardDecision:
        return GuardDecision(
            allowed=data.get("allowed", False),
            reason=data.get("reason", "Unknown"),
            decision_trace=data.get("decision_trace", []),
            resolved_identities=data.get("resolved_identities", {}),
            impact=data.get("impact", []),
            summary=data.get("summary"),
            trace_hash=data.get("trace_hash"),
        )

    def _build_decision_record(
        self,
        decision: GuardDecision,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build an immutable decision record for executed flows."""

        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        trace_hash = decision.trace_hash or hashlib.sha256(
            json.dumps(decision.decision_trace, sort_keys=True).encode()
        ).hexdigest()

        return {
            "decision_id": decision_id,
            "timestamp": timestamp,
            "policy_ref": self.policy_ref or (
                self.policy.get("contract_id") if isinstance(self.policy, dict) else None
            ),
            "actor": actor,
            "action": action,
            "context": context,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "summary": decision.summary,
            "impact": decision.impact,
            "trace_hash": trace_hash,
            "decision_trace": decision.decision_trace,
            "resolved_identities": decision.resolved_identities,
        }


Guard = WaveframeGuard

