from __future__ import annotations

import json
import hashlib
from typing import Any, Dict, List, Optional

from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


# ---------------------------
# BASIC HELPERS
# ---------------------------

def normalize(v: Optional[str]) -> str:
    if not v:
        return ""
    return v.strip().lower().replace("_", "-")


def contract_hash(compiled_contract: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(compiled_contract, sort_keys=True).encode()
    ).hexdigest()


def contract_required_roles(compiled_contract: Dict[str, Any]) -> List[str]:
    authority = compiled_contract.get("authority_requirements", {})
    if isinstance(authority, dict):
        return authority.get("required_roles", [])
    return []


# ---------------------------
# ACTION VALIDATION
# ---------------------------

def validate_action(action: dict):
    if not isinstance(action, dict):
        return False, "Action must be a dictionary"

    if "type" not in action:
        return False, "Missing required field: type"

    if action["type"] == "transfer":
        if "amount" not in action:
            return False, "Missing amount for transfer"

    return True, None


# ---------------------------
# CORE ENGINE
# ---------------------------

def run_validation(
    compiled_contract: Dict[str, Any],
    action: Dict[str, Any],
    actor: str = "ai-agent",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    context = context or {}

    is_valid, error = validate_action(action)
    if not is_valid:
        return {
            "allowed": False,
            "reason": error,
            "risk_level": "high",
            "decision_trace": [],
        }

    required_roles = contract_required_roles(compiled_contract)

    proposal = build_proposal(
        proposal_id="sdk-run",
        actor={"id": actor, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": action.get("system", "unknown"),
            "resource": action.get("resource", "unknown"),
            "action": action.get("type", "unknown"),
        },
        contract={
            "id": compiled_contract["contract_id"],
            "version": compiled_contract["contract_version"],
            "hash": contract_hash(compiled_contract),
        },
        run_context={
            "identities": {
                "actors": [
                    {"id": actor, "type": "agent", "role": "proposer"},
                ],
                "required_roles": required_roles,
                "conflict_flags": {},
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True},
        },
    )

    result = evaluate_proposal(proposal, compiled_contract)

    allowed = getattr(result, "commit_allowed", False)

    return {
        "allowed": allowed,
        "reason": "Blocked by governance policy" if not allowed else "Allowed",
        "decision_trace": getattr(result, "stage_results", []),
        "trace_hash": contract_hash(compiled_contract),
    }
    