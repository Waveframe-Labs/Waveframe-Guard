"""
Waveframe Guard — Client Interface

This is the primary entrypoint for developers.

Goal:
Provide a simple, frictionless interface to determine whether an AI-driven
action is allowed to execute.

All internal complexity (proposal building, contract binding, CRI-CORE execution)
is abstracted away from the user.

The user should only think in terms of:
- action
- actor
- allowed vs blocked
"""

from typing import Any, Dict, Optional


class WaveframeGuard:
    """
    WaveframeGuard

    Primary SDK interface for governed execution.

    Example usage:

        guard = WaveframeGuard()

        result = guard.execute(
            action={"type": "reallocate_budget", "amount": 2_000_000},
            actor="ai-agent"
        )

        if result["allowed"]:
            perform_action()
        else:
            print(result["reason"])
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        policy: Optional[str] = None,
    ) -> None:
        """
        Initialize the Waveframe Guard client.

        Args:
            api_key (Optional[str]):
                Reserved for future hosted control layer / dashboard integration.

            policy (Optional[str]):
                Optional policy identifier (e.g., "finance-default").
                Currently not enforced — placeholder for future contract selection.
        """
        self.api_key = api_key
        self.policy = policy or "default"

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether an action is allowed to execute.

        This method:
        1. Accepts a simple action + actor input
        2. Internally orchestrates governance enforcement
        3. Returns a deterministic allow/block decision

        Args:
            action (Dict[str, Any]):
                The proposed action to evaluate.

            actor (str):
                The identity performing the action (e.g., "ai-agent", "user-123").

            context (Optional[Dict[str, Any]]):
                Optional execution context (metadata, environment, etc.).

        Returns:
            Dict[str, Any]:
                {
                    "allowed": bool,
                    "reason": str,
                    "details": dict
                }
        """

        # --- Step 1: Validate minimal input ---
        if not isinstance(action, dict):
            return self._blocked("Invalid action format (must be dict)")

        if not actor:
            return self._blocked("Actor is required")

        # --- Step 2: Build internal execution payload ---
        # NOTE:
        # This is where proposal normalization, contract binding,
        # and run construction will occur in future iterations.
        payload = {
            "action": action,
            "actor": actor,
            "context": context or {},
            "policy": self.policy,
        }

        # --- Step 3: Execute enforcement (stub for now) ---
        # This will later call CRI-CORE via internal orchestration layer.
        enforcement_result = self._enforce(payload)

        return enforcement_result

    # ---------------------------------------------------------------------
    # Internal Methods (hidden from user)
    # ---------------------------------------------------------------------

    def _enforce(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Internal enforcement execution.

        This is a placeholder implementation.
        In the next step, this will:
        - Build proposal
        - Attach compiled contract
        - Construct run artifact
        - Call CRI-CORE kernel

        For now, we simulate basic behavior.
        """

        action = payload["action"]

        # --- Example rule (temporary stub logic) ---
        if action.get("type") == "reallocate_budget" and action.get("amount", 0) > 1_000_000:
            return self._blocked(
                "Action exceeds allowed threshold without approval",
                details={"threshold": 1_000_000},
            )

        return self._allowed()

    def _allowed(self) -> Dict[str, Any]:
        return {
            "allowed": True,
            "reason": "Action permitted",
            "details": {},
        }

    def _blocked(
        self,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "allowed": False,
            "reason": reason,
            "details": details or {},
        }