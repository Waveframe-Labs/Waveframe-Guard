from __future__ import annotations

import requests
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

    This is the product surface:
    - evaluate → returns decision
    - execute → enforces execution boundary
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
            f"{self.base_url}/validate",
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

        If allowed → executes function
        If blocked → prevents execution
        """

        decision = self.evaluate(action, actor, context)

        if decision.allowed:
            return execute_fn()

        return {
            "blocked": True,
            "reason": decision.reason,
            "decision": decision.to_dict(),
        }