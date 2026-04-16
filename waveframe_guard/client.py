from __future__ import annotations

import requests
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Callable


class GuardDecision:
    """
    Canonical decision object returned from Waveframe Guard.
    """

    def __init__(
        self,
        allowed: bool,
        reason: str,
        decision_trace: list,
        resolved_identities: dict,
    ):
        self.allowed = allowed
        self.reason = reason
        self.decision_trace = decision_trace
        self.resolved_identities = resolved_identities

    def __repr__(self) -> str:
        status = "ALLOWED" if self.allowed else "BLOCKED"
        return f"<GuardDecision {status}: {self.reason}>"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "decision_trace": self.decision_trace,
            "resolved_identities": self.resolved_identities,
        }


class Guard:
    """
    Waveframe Guard SDK client.

    Product surface:
    - evaluate → returns decision
    - execute → enforces execution boundary + logs decision (core product)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        policy_ref: str = "finance-core-v1",
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.policy_ref = policy_ref
        self.api_key = api_key

    # ---------------------------
    # CORE: EVALUATE
    # ---------------------------

    def evaluate(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
    ) -> GuardDecision:
        """
        Evaluate whether an action is allowed to execute.
        """

        payload = {
            "action": action,
            "actor": actor,
            "policy_ref": self.policy_ref,
            "context": context,
        }

        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        res = requests.post(
            f"{self.base_url}/v1/enforce",
            json=payload,
            headers=headers,
            timeout=10,
        )

        if res.status_code != 200:
            raise RuntimeError(
                f"Guard evaluation failed: {res.status_code} {res.text}"
            )

        data = res.json()

        return GuardDecision(
            allowed=data.get("allowed", False),
            reason=data.get("reason", "Unknown"),
            decision_trace=data.get("decision_trace", []),
            resolved_identities=data.get("resolved_identities", {}),
        )

    # ---------------------------
    # INTERNAL: DECISION RECORD
    # ---------------------------

    def _build_decision_record(
        self,
        decision: GuardDecision,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Builds an immutable decision record (compliance artifact).
        """

        decision_id = f"dec_{uuid.uuid4().hex[:12]}"

        timestamp = datetime.now(timezone.utc).isoformat()

        trace_raw = str(decision.decision_trace).encode()
        trace_hash = hashlib.sha256(trace_raw).hexdigest()

        return {
            "decision_id": decision_id,
            "timestamp": timestamp,
            "policy_ref": self.policy_ref,
            "actor": actor,
            "action": action,
            "context": context,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "trace_hash": trace_hash,
            "decision_trace": decision.decision_trace,
            "resolved_identities": decision.resolved_identities,
        }

    # ---------------------------
    # INTERNAL: LOGGING
    # ---------------------------

    def _send_log(self, record: Dict[str, Any]) -> None:
        """
        Sends decision record to backend telemetry endpoint.
        Fails silently (does not break execution path).
        """

        try:
            headers = {"Content-Type": "application/json"}

            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            requests.post(
                f"{self.base_url}/api/log",
                json=record,
                headers=headers,
                timeout=5,
            )
        except Exception:
            # Logging must never break execution path
            pass

    # ---------------------------
    # CORE: EXECUTE (THE PRODUCT)
    # ---------------------------

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
        execute_fn: Callable[[], Any],
    ) -> Any:
        """
        Enforces execution boundary.

        ALWAYS:
        - evaluates
        - builds decision record
        - logs decision

        IF allowed:
            executes function
        ELSE:
            blocks execution
        """

        decision = self.evaluate(action, actor, context)

        record = self._build_decision_record(
            decision=decision,
            action=action,
            actor=actor,
            context=context,
        )

        # Always log (allowed OR blocked)
        self._send_log(record)

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