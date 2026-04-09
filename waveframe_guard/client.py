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
        debug: bool = True,  # 👈 enable debug visibility
    ) -> None:
        self.api_key = api_key
        self.debug = debug

        if policy is None:
            self._compiled_contract = self._default_contract()
        else:
            self._compiled_contract = self._compile_policy(policy)

        if self.debug:
            print("\n[DEBUG] Compiled Contract:")
            print(self._compiled_contract)

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        roles: Optional[Dict[str, str]],
        execute_fn: Callable[[Dict[str, Any]], Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        if not isinstance(action, dict):
            return self._blocked("Invalid action format (must be dict)")

        if not actor:
            return self._blocked("Actor is required")

        # --------------------------------------------------
        # Step 1: Normalize mutation
        # --------------------------------------------------
        mutation = self._normalize_mutation(action)

        # --------------------------------------------------
        # Step 2: Build run_context with identities
        # --------------------------------------------------
        run_context = context.copy() if context else {}

        identities = self._build_identities(actor, roles)
        run_context["identities"] = identities

        # --------------------------------------------------
        # Step 3: Build canonical proposal
        # --------------------------------------------------
        proposal = build_proposal(
            proposal_id=str(uuid4()),
            actor={
                "id": actor,
                "type": "agent",
            },
            artifact_paths=[],
            mutation=mutation,
            contract=self._map_contract(self._compiled_contract),
            run_context=run_context,
        )

        if self.debug:
            print("\n[DEBUG] Proposal:")
            print(proposal)

        # --------------------------------------------------
        # Step 4: Wrap execution
        # --------------------------------------------------
        def wrapped_execute_fn(proposal_input: Dict[str, Any]):
            return execute_fn(action)

        # --------------------------------------------------
        # Step 5: Enforcement
        # --------------------------------------------------
        result = governed_execute(
            proposal=proposal,
            policy=self._compiled_contract,
            execute_fn=wrapped_execute_fn,
        )

        if self.debug:
            print("\n[DEBUG] Enforcement Result:")
            print(result)

        # --------------------------------------------------
        # Step 6: Normalize output
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

    def _normalize_mutation(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert user-friendly action into canonical mutation format
        required by the proposal normalizer.
        """

        if all(k in action for k in ("domain", "resource", "action")):
            return action

        action_type = action.get("type")
        if not action_type:
            raise ValueError("Action must include 'type'")

        return {
            "domain": "finance",
            "resource": "budget",
            "action": action_type,
            **{k: v for k, v in action.items() if k != "type"},
        }

    def _build_identities(
        self,
        actor: str,
        roles: Optional[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Construct identity structure for CRI-CORE enforcement.

        CRITICAL: We align structure with expected role separation logic.
        """

        identities: Dict[str, Any] = {}

        if roles:
            # 👇 Explicit role mapping (important for separation_of_duties)
            for role, identity in roles.items():
                identities[role] = {
                    "id": identity,
                    "type": "agent" if "ai" in identity else "human",
                }

            # 👇 ALSO include top-level actor (important for some kernels)
            identities["actor"] = {
                "id": actor,
                "type": "agent",
            }

        else:
            identities["actor"] = {
                "id": actor,
                "type": "agent",
            }

        return identities

    def _compile_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return compile_policy(policy)
        except PolicyCompilationError as e:
            raise ValueError(f"Invalid policy: {str(e)}") from e

    def _map_contract(self, compiled: Dict[str, Any]) -> Dict[str, Any]:
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