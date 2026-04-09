"""
Waveframe Guard — Client Interface

Execution-gated interface for AI actions.

This implementation uses CRI-CORE's governed_execute to ensure that
actions only execute if they pass deterministic enforcement.
"""

from typing import Any, Callable, Dict, Optional

from cricore.interface.governed_execute import governed_execute


class WaveframeGuard:
    def __init__(
        self,
        api_key: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.api_key = api_key
        self.policy = policy or {}

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        execute_fn: Callable[[Dict[str, Any]], Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an action through the governance gate.

        Args:
            action: Proposed action
            actor: Actor performing the action
            execute_fn: Function that performs the actual mutation
            context: Optional metadata

        Returns:
            {
                "allowed": bool,
                "result": Any,
                "reason": str
            }
        """

        if not isinstance(action, dict):
            return self._blocked("Invalid action format (must be dict)")

        if not actor:
            return self._blocked("Actor is required")

        # --------------------------------------------------
        # Step 1: Build proposal (minimal for now)
        # --------------------------------------------------
        proposal = self._build_proposal(
            action=action,
            actor=actor,
            context=context or {},
        )

        # --------------------------------------------------
        # Step 2: Wrap execution
        # --------------------------------------------------
        def wrapped_execute_fn(proposal_input: Dict[str, Any]):
            return execute_fn(action)

        # --------------------------------------------------
        # Step 3: Call CRI-CORE enforcement
        # --------------------------------------------------
        result = governed_execute(
            proposal=proposal,
            policy=self.policy,
            execute_fn=wrapped_execute_fn,
        )

        # --------------------------------------------------
        # Step 4: Normalize output
        # --------------------------------------------------
        if result["commit_allowed"]:
            return {
                "allowed": True,
                "result": result.get("result"),
                "reason": "Execution permitted",
            }

        return self._blocked(result.get("summary", "Execution blocked"))

    # ---------------------------------------------------------------------
    # Internal
    # ---------------------------------------------------------------------

    def _build_proposal(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Minimal proposal builder.

        This will later integrate with:
        - proposal normalizer
        - contract compiler
        """

        return {
            "proposal_id": "temp-id",
            "actor": {
                "id": actor,
                "type": "agent",
            },
            "requested_mutation": action,
            "context": context,
        }

    def _blocked(self, reason: str) -> Dict[str, Any]:
        return {
            "allowed": False,
            "result": None,
            "reason": reason,
        }