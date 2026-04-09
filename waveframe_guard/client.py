"""
Waveframe Guard Client (Hardened)
"""

from typing import Any, Dict, Optional

from cricore.interface.evaluate_proposal import evaluate_proposal


READ_ONLY_ACTIONS = {
    "get_balance",
    "view_account",
    "read_data",
}


def _validate_action(action: Any) -> Optional[str]:
    if not isinstance(action, dict):
        return "Invalid action: must be a dictionary"

    if "type" not in action:
        return "Invalid action: missing 'type' field"

    if not isinstance(action["type"], str) or not action["type"].strip():
        return "Invalid action: 'type' must be a non-empty string"

    return None


def _is_read_only(action_type: str) -> bool:
    return action_type in READ_ONLY_ACTIONS


def _translate_failure(result) -> str:
    if not result.failed_stages:
        return "Execution permitted"

    if "independence" in result.failed_stages:
        return "Blocked: same actor cannot propose and approve"

    if "integrity" in result.failed_stages:
        return "Blocked: required execution data missing"

    return "Blocked: governance requirements not satisfied"


class WaveframeGuard:
    def __init__(
        self,
        policy: Dict,
        *,
        default_domain: str = "finance",
    ):
        self.policy = policy
        self.default_domain = default_domain

    def execute(
        self,
        *,
        action: Any,
        actor: str,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        # -----------------------------
        # Validate context
        # -----------------------------
        if context is not None and not isinstance(context, dict):
            return {
                "allowed": False,
                "reason": "Invalid context: must be a dictionary",
            }

        context = context or {}

        # -----------------------------
        # Validate action
        # -----------------------------
        error = _validate_action(action)
        if error:
            return {
                "allowed": False,
                "reason": error,
            }

        action_type = action["type"]

        # -----------------------------
        # Read-only shortcut
        # -----------------------------
        if _is_read_only(action_type):
            return {
                "allowed": True,
                "reason": "Execution permitted (read-only action)",
            }

        approved_by = context.get("approved_by")

        # -----------------------------
        # Approval enforcement
        # -----------------------------
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
        # Build proposal safely
        # -----------------------------
        try:
            proposal = self._build_proposal(
                action=action,
                actor=actor,
                approved_by=approved_by,
            )

            result = evaluate_proposal(proposal, self.policy)

        except Exception:
            return {
                "allowed": False,
                "reason": "Blocked: internal validation error",
            }

        # -----------------------------
        # Translate result
        # -----------------------------
        if result.commit_allowed:
            return {
                "allowed": True,
                "reason": "Execution permitted",
            }

        return {
            "allowed": False,
            "reason": _translate_failure(result),
        }

    def _build_proposal(
        self,
        *,
        action: Dict,
        actor: str,
        approved_by: str,
    ) -> Dict[str, Any]:
        return {
            "proposal_id": "generated",
            "timestamp": "now",
            "actor": {
                "id": actor,
                "type": "agent",
            },
            "contract": {
                "id": self.policy.get("contract_id"),
                "version": self.policy.get("contract_version"),
                "hash": self.policy.get("contract_hash"),
            },
            "requested_mutation": {
                "domain": self.default_domain,
                "resource": action.get("type"),
                "action": action.get("type"),
            },
            "artifacts": [],
            "run_context": {
                "identities": {
                    "actors": [
                        {
                            "id": actor,
                            "type": "agent",
                            "role": "proposer",
                        },
                        {
                            "id": approved_by,
                            "type": "human",
                            "role": "approver",
                        },
                    ],
                    "required_roles": ["proposer", "approver"],
                    "conflict_flags": {},
                },
                "integrity": {},
                "publication": {},
            },
        }