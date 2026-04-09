"""
Waveframe Guard — Client Interface

Execution-gated interface for AI actions using CRI-CORE.
"""

from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from cricore.interface.governed_execute import governed_execute
from proposal_normalizer.build_proposal import build_proposal


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

        if not isinstance(action, dict):
            return self._blocked("Invalid action format (must be dict)")

        if not actor:
            return self._blocked("Actor is required")

        # --------------------------------------------------
        # Step 1: Build canonical proposal via normalizer
        # --------------------------------------------------
        proposal = build_proposal(
            proposal_id=str(uuid4()),
            actor={
                "id": actor,
                "type": "agent",
            },
            artifact_paths=[],
            mutation=action,
            contract=self._default_contract(),
            run_context=context or {},
        )

        # --------------------------------------------------
        # Step 2: Wrap execution
        # --------------------------------------------------
        def wrapped_execute_fn(proposal_input: Dict[str, Any]):
            return execute_fn(action)

        # --------------------------------------------------
        # Step 3: Enforcement
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

    def _default_contract(self) -> Dict[str, Any]:
        """
        Temporary contract placeholder.

        Will later be replaced by:
        - compiled contracts
        - policy selection
        - dashboard configuration
        """
        return {
            "id": "default",
            "version": "0.1.0",
            "hash": "dev",
        }

    def _blocked(self, reason: str) -> Dict[str, Any]:
        return {
            "allowed": False,
            "result": None,
            "reason": reason,
        }