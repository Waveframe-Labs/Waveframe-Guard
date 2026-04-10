from typing import Any, Dict, Optional
import uuid
import tempfile
import json
from pathlib import Path

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


class WaveframeGuard:
    """
    Waveframe Guard

    Evaluates whether an AI-generated action is allowed to execute
    using CRI-CORE enforcement.
    """

    def __init__(self, policy: Any):
        self.policy_path = self._resolve_policy_path(policy)
        self.compiled_contract = self._compile_policy(self.policy_path)

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------

    def execute(
        self,
        action: Dict[str, Any],
        actor: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        # -----------------------------
        # Input validation
        # -----------------------------

        if not isinstance(action, dict) or "type" not in action:
            return {
                "allowed": False,
                "reason": "Invalid action: missing 'type' field",
            }

        if context is not None and not isinstance(context, dict):
            return {
                "allowed": False,
                "reason": "Invalid context: must be a dictionary",
            }

        context = context or {}
        approved_by = context.get("approved_by")

        # -----------------------------
        # Normalize action → mutation (FIX)
        # -----------------------------

        mutation = self._normalize_action(action)

        # -----------------------------
        # Build run_context
        # -----------------------------

        identities = {
            "proposer": {
                "id": actor,
                "type": "agent"
            }
        }

        if approved_by:
            identities["approver"] = {
                "id": approved_by,
                "type": "human"
            }

        run_context = {
            "identities": identities,
            "integrity": {},
            "publication": {}
        }

        # -----------------------------
        # Build proposal
        # -----------------------------

        proposal = build_proposal(
            proposal_id=str(uuid.uuid4()),
            actor={"id": actor, "type": "agent"},
            artifact_paths=[],
            mutation=mutation,
            contract=self.compiled_contract,
            run_context=run_context
        )

        # -----------------------------
        # Evaluate
        # -----------------------------

        try:
            result = evaluate_proposal(proposal)
        except Exception:
            return {
                "allowed": False,
                "reason": "Blocked: internal enforcement error",
            }

        if result.get("commit_allowed") is True:
            return {
                "allowed": True,
                "reason": "Execution permitted",
            }

        return {
            "allowed": False,
            "reason": self._extract_reason(result),
        }

    # --------------------------------------------------
    # Action → Mutation Adapter (CRITICAL)
    # --------------------------------------------------

    def _normalize_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        action_type = action["type"]

        if action_type == "transfer":
            return {
                "domain": "finance",
                "resource": "funds",
                "action": "transfer"
            }

        if action_type == "get_balance":
            return {
                "domain": "finance",
                "resource": "account",
                "action": "read"
            }

        # default fallback
        return {
            "domain": "general",
            "resource": "unknown",
            "action": action_type
        }

    # --------------------------------------------------
    # Internal helpers
    # --------------------------------------------------

    def _resolve_policy_path(self, policy: Any) -> Path:
        if isinstance(policy, str):
            path = Path(policy)
            if not path.exists():
                raise FileNotFoundError(f"Policy file not found: {policy}")
            return path

        if isinstance(policy, dict):
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
            with open(temp_file.name, "w") as f:
                json.dump(policy, f)
            return Path(temp_file.name)

        raise ValueError("Policy must be dict or file path")

    def _compile_policy(self, policy_path: Path) -> Dict[str, Any]:
        temp_output = tempfile.NamedTemporaryFile(delete=False, suffix=".json")

        output_path = compile_policy_file(policy_path, Path(temp_output.name))

        with open(output_path, "r") as f:
            return json.load(f)

    def _extract_reason(self, result: Dict[str, Any]) -> str:
        try:
            failed = result.get("result").failed_stages
        except Exception:
            return "Blocked: policy enforcement failed"

        if "independence" in failed:
            return "Blocked: same actor cannot propose and approve"

        if "publication-commit" in failed:
            return "Blocked: approval required for financial action"

        return "Blocked: policy violation"