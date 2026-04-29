from __future__ import annotations

import getpass
import hashlib
import json
import os
import uuid
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar

from cricore.interface.evaluate_proposal import evaluate_proposal
from proposal_normalizer.build_proposal import build_proposal

F = TypeVar("F", bound=Callable[..., Any])

DEFAULT_COMPILED_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "finance-core": {
        "contract_id": "finance-core",
        "contract_version": "1.2.0",
        "authority_requirements": {
            "required_roles": ["proposer", "responsible", "accountable"]
        },
        "artifact_requirements": {
            "artifacts_present": True
        },
        "stage_requirements": {
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True}
        },
        "invariants": [
            {"type": "separation_of_duties", "roles": ["responsible", "accountable"]}
        ],
        "approval_requirements": {
            "thresholds": [
                {
                    "field": "amount",
                    "operator": ">",
                    "value": 10000,
                    "requires_role": "approver",
                }
            ]
        },
    }
}


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
        return list(authority.get("required_roles", []))
    return []


def load_compiled_contract(policy: str) -> Dict[str, Any]:
    if policy in DEFAULT_COMPILED_CONTRACTS:
        return json.loads(json.dumps(DEFAULT_COMPILED_CONTRACTS[policy]))

    with open(Path(policy), "r", encoding="utf-8") as f:
        return json.load(f)


def extract_reason(stage_results: List[Any]) -> str:
    for stage in stage_results:
        if getattr(stage, "passed", True):
            continue

        messages = getattr(stage, "messages", []) or []
        if messages:
            return str(messages[0])

        return f"{getattr(stage, 'stage_id', 'unknown')} failed"

    return "Allowed"


def evaluate_approval_requirements(
    compiled_contract: Dict[str, Any],
    action: Dict[str, Any],
    context: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    approval_rules = compiled_contract.get("approval_requirements", {}).get("thresholds", [])

    for rule in approval_rules:
        field = rule.get("field")
        operator = rule.get("operator")
        value = rule.get("value")

        if field not in action:
            continue

        action_value = action.get(field)
        triggered = False

        if operator == ">" and action_value > value:
            triggered = True
        elif operator == ">=" and action_value >= value:
            triggered = True
        elif operator == "<" and action_value < value:
            triggered = True
        elif operator == "<=" and action_value <= value:
            triggered = True
        elif operator == "==" and action_value == value:
            triggered = True

        if triggered and not context.get("approved_by"):
            return {
                "reason": f"Approval required: {field} {operator} {value}",
                "impact": "Prevented unauthorized financial mutation",
            }

    return None


def format_amount(value: Any) -> Optional[str]:
    if value is None:
        return None

    try:
        amount = float(value)
    except (TypeError, ValueError):
        return None

    if amount.is_integer():
        return f"${int(amount):,}"
    return f"${amount:,.2f}"


# ---------------------------
# ACTION VALIDATION
# ---------------------------

def validate_action(action: dict):
    if not isinstance(action, dict):
        return False, "Action must be a dictionary"

    if "type" not in action:
        return False, "Missing required field: type"

    if action["type"] == "transfer" and "amount" not in action:
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
            "impact": "Prevented unauthorized mutation",
            "risk_level": "high",
            "decision_trace": [],
            "trace_hash": contract_hash(compiled_contract),
        }

    approval_failure = evaluate_approval_requirements(compiled_contract, action, context)
    if approval_failure:
        return {
            "allowed": False,
            "reason": approval_failure["reason"],
            "impact": approval_failure["impact"],
            "risk_level": "high",
            "decision_trace": [],
            "trace_hash": contract_hash(compiled_contract),
        }

    required_roles = contract_required_roles(compiled_contract)
    actors = [{"id": actor, "type": "agent", "role": "proposer"}]

    if "responsible" in required_roles:
        actors.append(
            {
                "id": context.get("responsible", "sdk-responsible"),
                "type": "human",
                "role": "responsible",
            }
        )

    if "accountable" in required_roles:
        actors.append(
            {
                "id": context.get("accountable", "sdk-accountable"),
                "type": "human",
                "role": "accountable",
            }
        )

    if "approver" in required_roles:
        actors.append(
            {
                "id": context.get("approved_by", "sdk-approver"),
                "type": "human",
                "role": "approver",
            }
        )

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": actor, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": action.get("system", "local"),
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
                "actors": actors,
                "required_roles": required_roles,
                "conflict_flags": {},
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True},
        },
    )

    result = evaluate_proposal(proposal, compiled_contract)
    allowed = getattr(result, "commit_allowed", False)
    decision_trace = getattr(result, "stage_results", [])
    reason = extract_reason(decision_trace)

    return {
        "allowed": allowed,
        "reason": reason,
        "impact": "Execution allowed under current governance policy" if allowed else "Prevented unauthorized mutation",
        "decision_trace": decision_trace,
        "trace_hash": contract_hash(compiled_contract),
    }


class GuardViolation(Exception):
    pass


class Guard:
    def __init__(self, policy: str, mode: str = "shadow"):
        if mode not in {"shadow", "block"}:
            raise ValueError("mode must be 'shadow' or 'block'")

        self.policy = policy
        self.mode = mode
        self.compiled_contract = load_compiled_contract(policy)
        self.context = {
            "responsible": "sdk-responsible",
            "accountable": "sdk-accountable",
        }

    def _format_violation(self, action: Dict[str, Any], decision: Dict[str, Any]) -> str:
        action_type = action.get("type", "unknown")
        system = action.get("system", "local")
        resource = action.get("resource", "unknown")
        amount = format_amount(action.get("amount"))
        reason = decision.get("reason", "Blocked by governance policy")
        impact = decision.get("impact", "Prevented unauthorized mutation")
        amount_line = f"Amount: {amount}\n" if amount else ""
        return (
            "[Waveframe Guard] BLOCKED\n"
            f"Action: {action_type} -> {system}/{resource}\n"
            f"{amount_line}"
            f"Reason: {reason}\n"
            f"Impact: {impact}\n"
            "Execution prevented before mutation"
        )

    def _format_allowed(self, action: Dict[str, Any]) -> str:
        action_type = action.get("type", "unknown")
        system = action.get("system", "local")
        resource = action.get("resource", "unknown")
        amount = format_amount(action.get("amount"))
        amount_line = f"\nAmount: {amount}" if amount else ""
        return (
            "[Waveframe Guard] ALLOWED\n"
            f"Action: {action_type} -> {system}/{resource}"
            f"{amount_line}"
        )

    def enforce(self, action_type: str, resource: str):
        if "/" in resource:
            system, resource_name = resource.split("/", 1)
        else:
            system = "finance" if action_type == "transfer" else "local"
            resource_name = resource

        def decorator(fn: F) -> F:
            @wraps(fn)
            def wrapper(*args: Any, **kwargs: Any):
                action = {
                    "type": action_type,
                    "system": system,
                    "resource": resource_name,
                }
                if "amount" in kwargs:
                    action["amount"] = kwargs["amount"]
                elif args and isinstance(args[0], (int, float)):
                    action["amount"] = args[0]
                context = {
                    "proposer": getpass.getuser(),
                    "env": os.getenv("ENV", "local"),
                    "responsible": self.context["responsible"],
                    "accountable": self.context["accountable"],
                }

                decision = run_validation(
                    compiled_contract=self.compiled_contract,
                    action=action,
                    actor=context["proposer"],
                    context=context,
                )

                if not decision["allowed"]:
                    message = self._format_violation(action, decision)
                    if self.mode == "block":
                        raise GuardViolation(message)
                    print(message)
                else:
                    print(self._format_allowed(action))

                return fn(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator
