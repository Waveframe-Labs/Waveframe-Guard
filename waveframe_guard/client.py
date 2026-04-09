"""
---
title: "Waveframe Guard Client"
filetype: "source"
type: "sdk"
domain: "execution"
version: "0.3.0"
status: "Active"
created: "2026-04-09"
updated: "2026-04-09"

author:
  name: "Shawn C. Wright"

maintainer:
  name: "Waveframe Labs"

license: "Apache-2.0"

ai_assisted: "partial"

anchors:
  - "Waveframe-Guard-Client-v0.3.0"
---
"""

from typing import Any, Dict, Optional

from cricore.interface.evaluate_proposal import evaluate_proposal


# -----------------------------
# Human-readable translation
# -----------------------------

def _translate_failure(result) -> str:
    """
    Convert CRI-CORE failures into business-readable language.
    """

    if not result.failed_stages:
        return "Execution permitted"

    stage_map = {
        "independence": "Blocked: same actor cannot propose and approve",
        "integrity": "Blocked: required integrity data missing",
        "integrity-finalization": "Blocked: integrity checks not finalized",
        "publication": "Blocked: execution context incomplete",
        "publication-commit": "Blocked: action failed governance checks",
    }

    for stage in result.failed_stages:
        if stage in stage_map:
            return stage_map[stage]

    return "Blocked: governance requirements not satisfied"


# -----------------------------
# Guard Client
# -----------------------------

class WaveframeGuard:
    """
    Waveframe Guard SDK

    Determines whether an action is allowed to execute.
    Does NOT execute the action.
    """

    def __init__(
        self,
        policy: Dict,
        *,
        default_domain: str = "finance",
    ):
        self.policy = policy
        self.default_domain = default_domain

    # -----------------------------
    # Core decision function
    # -----------------------------

    def execute(
        self,
        *,
        action: Dict,
        actor: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate whether an action is allowed.

        Returns:
            {
                "allowed": bool,
                "reason": str
            }
        """

        context = context or {}
        approved_by = context.get("approved_by")

        # -----------------------------
        # HARD GUARANTEE (product-level invariant)
        # -----------------------------
        # Enforce separation-of-duties BEFORE kernel
        # This ensures correctness even if upstream contracts drift
        # -----------------------------

        if approved_by is None:
            return {
                "allowed": False,
                "reason": "Blocked: approval required for this action",
            }

        if approved_by == actor:
            return {
                "allowed": False,
                "reason": "Blocked: same actor cannot propose and approve",
            }

        # -----------------------------
        # Build proposal
        # -----------------------------

        proposal = self._build_proposal(
            action=action,
            actor=actor,
            approved_by=approved_by,
        )

        # -----------------------------
        # Evaluate via CRI-CORE
        # -----------------------------

        result = evaluate_proposal(proposal, self.policy)

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

    # -----------------------------
    # Internal proposal builder
    # -----------------------------

    def _build_proposal(
        self,
        *,
        action: Dict,
        actor: str,
        approved_by: str,
    ) -> Dict[str, Any]:
        """
        Convert inputs into canonical proposal structure.
        """

        proposal = {
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
                "resource": action.get("type", "unknown"),
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

        return proposal