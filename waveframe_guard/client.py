from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import json
import tempfile
import uuid

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


class WaveframeGuard:
    """
    Waveframe Guard

    Product-facing SDK that hides compiler + normalizer + CRI-CORE complexity
    behind a simple execution decision interface.
    """

    def __init__(self, policy: Any):
        self.policy_path = self._resolve_policy_path(policy)
        self.raw_policy = self._load_policy_json(self.policy_path)
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
        if not isinstance(action, dict):
            return {
                "allowed": False,
                "reason": "Invalid action: must be a dictionary",
            }

        if "type" not in action:
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
        action_type = action["type"]
        approved_by = context.get("approved_by")

        # -----------------------------
        # Read raw policy business rules
        # -----------------------------
        rules = self.raw_policy.get("rules", {})
        action_rules = rules.get(action_type, {})

        requires_approval = action_rules.get("requires_approval", False)
        read_only = action_rules.get("read_only", False)

        # -----------------------------
        # Product-level fast checks
        # -----------------------------
        if read_only:
            return {
                "allowed": True,
                "reason": "Execution permitted (read-only action)",
            }

        if requires_approval:
            if not approved_by:
                return {
                    "allowed": False,
                    "reason": "Blocked: approval required for financial action",
                }

            if approved_by == actor:
                return {
                    "allowed": False,
                    "reason": "Blocked: same actor cannot propose and approve",
                }

        # -----------------------------
        # Normalize action -> mutation
        # -----------------------------
        mutation = self._normalize_action(action)

        # -----------------------------
        # Build kernel-native run_context
        # -----------------------------
        run_context = self._build_run_context(
            actor=actor,
            approved_by=approved_by,
        )

        # -----------------------------
        # Build canonical proposal via normalizer
        # -----------------------------
        try:
            proposal = build_proposal(
                proposal_id=str(uuid.uuid4()),
                actor={"id": actor, "type": "agent"},
                artifact_paths=[],
                mutation=mutation,
                contract=self._proposal_contract_binding(self.compiled_contract),
                run_context=run_context,
            )
        except Exception:
            return {
                "allowed": False,
                "reason": "Blocked: internal proposal construction error",
            }

        # -----------------------------
        # Evaluate with CRI-CORE
        # -----------------------------
        try:
            result = evaluate_proposal(proposal, self.compiled_contract)
        except Exception:
            return {
                "allowed": False,
                "reason": "Blocked: internal enforcement error",
            }

        # -----------------------------
        # Translate result
        # -----------------------------
        if getattr(result, "commit_allowed", False):
            return {
                "allowed": True,
                "reason": "Execution permitted",
            }

        return {
            "allowed": False,
            "reason": self._extract_reason(result),
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
            temp_path = Path(temp_file.name)
            temp_file.close()
            temp_path.write_text(json.dumps(policy), encoding="utf-8")
            return temp_path

        raise ValueError("Policy must be a file path or dictionary")

    def _load_policy_json(self, policy_path: Path) -> Dict[str, Any]:
        with policy_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _compile_policy(self, policy_path: Path) -> Dict[str, Any]:
        temp_output = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        output_path = Path(temp_output.name)
        temp_output.close()

        compiled_path = compile_policy_file(policy_path, output_path)

        with Path(compiled_path).open("r", encoding="utf-8") as f:
            return json.load(f)

    def _proposal_contract_binding(self, compiled_contract: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate compiler output into the exact contract shape expected by
        proposal_normalizer.bind_contract().
        """
        return {
            "id": compiled_contract["contract_id"],
            "version": compiled_contract["contract_version"],
            "hash": compiled_contract["contract_hash"],
        }

    def _normalize_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate product-facing action input into the canonical mutation shape
        expected by proposal_normalizer.bind_mutation().
        """
        action_type = action["type"]

        if action_type == "transfer":
            return {
                "domain": "finance",
                "resource": "funds",
                "action": "transfer",
            }

        if action_type == "get_balance":
            return {
                "domain": "finance",
                "resource": "account",
                "action": "read",
            }

        return {
            "domain": "general",
            "resource": "unknown",
            "action": action_type,
        }

    def _build_run_context(
        self,
        actor: str,
        approved_by: Optional[str],
    ) -> Dict[str, Any]:
        """
        Build the identity structure expected by CRI-CORE independence enforcement.
        """
        actors = [
            {
                "id": actor,
                "type": "agent",
                "role": "proposer",
            }
        ]

        if approved_by:
            actors.append(
                {
                    "id": approved_by,
                    "type": "human",
                    "role": "approver",
                }
            )

        return {
            "identities": {
                "actors": actors,
                "required_roles": ["proposer", "approver"],
                "conflict_flags": {},
            },
            "integrity": {},
            "publication": {},
        }

    def _extract_reason(self, result: Any) -> str:
        """
        Translate CRI-CORE failure stages into business-readable output.
        """
        failed_stages = getattr(result, "failed_stages", None)
        summary = getattr(result, "summary", None)

        if not failed_stages:
            return summary or "Blocked: policy violation"

        if "independence" in failed_stages:
            return "Blocked: same actor cannot propose and approve"

        if "publication-commit" in failed_stages:
            return "Blocked: approval required for financial action"

        if "integrity" in failed_stages:
            return "Blocked: required execution data missing"

        if "publication" in failed_stages:
            return "Blocked: execution context incomplete"

        return summary or "Blocked: policy violation"