"""
Waveframe Guard — Client Interface

Execution-gated interface for AI actions using CRI-CORE,
proposal normalizer, and contract compiler.
"""

from typing import Any, Callable, Dict, Optional
from uuid import uuid4

from cricore.interface.governed_execute import governed_execute
from proposal_normalizer.build_proposal import build_proposal
from compiler.compile_policy import compile_policy, PolicyCompilationError


class WaveframeGuard:
    def __init__(
        self,
        api_key: Optional[str] = None,
        policy: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.api_key = api_key

        if policy is None:
            self._compiled_contract = self._default_contract()
        else:
            self._compiled_contract = self._compile_policy(policy)

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
        # Step 1: Build canonical proposal
        # --------------------------------------------------
        proposal = build_proposal(
            proposal_id=str(uuid4()),
            actor={
                "id": actor,
                "type": "agent",
            },
            artifact_paths=[],
            mutation=action,
            contract=self._map_contract(self._compiled_contract),
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
            policy=self._compiled_contract,
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

    def _compile_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return compile_policy(policy)
        except PolicyCompilationError as e:
            raise ValueError(f"Invalid policy: {str(e)}") from e

    def _map_contract(self, compiled: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map compiled contract → proposal contract format
        """

        return {
            "id": compiled["contract_id"],
            "version": compiled["contract_version"],
            "hash": compiled["contract_hash"],
        }

    def _default_contract(self) -> Dict[str, Any]:
        return {
            "contract_id": "default",
            "contract_version": "0.1.0",
            "contract_hash": "dev",
        }

    def _blocked(self, reason: str) -> Dict[str, Any]:
        return {
            "allowed": False,
            "result": None,
            "reason": reason,
        }