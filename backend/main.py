from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


app = FastAPI(
    title="Waveframe Guard",
    version="1.0.0",
)

# ---------------------------
# 🔥 Identity Normalization (NEW)
# ---------------------------

def normalize_id(value: str) -> str:
    if not value:
        return ""
    return (
        value.strip()
        .lower()
        .replace("_", "-")
        .lstrip("0")
    )


# ---------------------------
# Helpers
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    action_type = action.get("type")

    if action_type == "transfer":
        amount = action.get("amount")
        if isinstance(amount, (int, float)):
            return f"AI attempted to transfer ${amount:,.0f}"
        return "AI attempted to transfer funds"

    if action_type == "get_balance":
        return "AI attempted to check account balance"

    if action_type == "reallocate_budget":
        amount = action.get("amount")
        if isinstance(amount, (int, float)):
            return f"AI attempted to reallocate ${amount:,.0f} in budget"
        return "AI attempted to reallocate budget"

    return f"AI attempted action: {action_type or 'unknown'}"


def build_contract_binding(compiled_contract: Dict[str, Any]) -> Dict[str, Any]:
    contract_json = json.dumps(compiled_contract, sort_keys=True).encode()
    contract_hash = hashlib.sha256(contract_json).hexdigest()

    return {
        "id": compiled_contract.get("contract_id", "user-policy"),
        "version": compiled_contract.get("contract_version", "1.0.0"),
        "hash": contract_hash,
    }


def extract_stage_messages(result: Any) -> List[str]:
    stage_results = getattr(result, "stage_results", None)
    if not stage_results:
        return []

    messages: List[str] = []
    for stage in stage_results:
        stage_messages = getattr(stage, "messages", None)
        if stage_messages:
            messages.extend([str(m) for m in stage_messages])
    return messages


def interpret_reason(result: Any) -> str:
    failed_stages = getattr(result, "failed_stages", None) or []
    summary = getattr(result, "summary", "") or ""
    messages = extract_stage_messages(result)
    combined = " ".join([summary] + messages).lower()

    if "separation_of_duties" in combined:
        return "Blocked: same individual assigned to conflicting governance roles"

    if "identity reused across required roles" in combined:
        return "Blocked: same individual assigned to multiple required roles"

    if "required role not satisfied" in combined:
        return "Blocked: required governance roles are missing"

    if "multiple candidates" in combined:
        return "Blocked: governance role assignment is ambiguous"

    if "approval" in combined and "required" in combined:
        return "Blocked: approval required but not provided"

    if "independence" in failed_stages:
        return "Blocked: governance independence requirements not satisfied"

    return "Blocked: policy requirements were not satisfied"


def extract_result(result: Any) -> tuple[bool, str]:
    allowed = getattr(result, "allowed", None)

    if allowed is None:
        allowed = getattr(result, "commit_allowed", None)

    if allowed is None:
        allowed = getattr(result, "passed", False)

    if bool(allowed):
        return True, "Allowed: roles verified and policy conditions satisfied"

    return False, interpret_reason(result)


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    action_type = action.get("type")

    if action_type == "transfer":
        return {"domain": "finance", "resource": "funds", "action": "transfer"}

    if action_type == "get_balance":
        return {"domain": "finance", "resource": "account", "action": "read"}

    if action_type == "reallocate_budget":
        return {"domain": "finance", "resource": "budget", "action": "reallocate"}

    return {"domain": "general", "resource": "unknown", "action": str(action_type or "unknown")}


# ---------------------------
# 🚨 Role Enforcement (fixed)
# ---------------------------

def enforce_required_roles(policy: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str | None]:
    required_roles = policy.get("roles", {}).get("required", [])

    if not required_roles:
        return True, None

    provided_roles = set()

    if context.get("responsible"):
        provided_roles.add("responsible")

    if context.get("accountable"):
        provided_roles.add("accountable")

    if context.get("approved_by"):
        provided_roles.add("approver")

    provided_roles.add("proposer")

    missing = [r for r in required_roles if r not in provided_roles]

    if missing:
        return False, f"Blocked: required governance roles missing: {', '.join(missing)}"

    return True, None


def normalize_context(actor: str, context: Dict[str, Any] | None) -> Dict[str, Any]:
    context = context or {}

    actor_id = normalize_id(actor)

    actors = [
        {"id": actor_id, "type": "agent", "role": "proposer"}
    ]

    if context.get("responsible"):
        actors.append({
            "id": normalize_id(context["responsible"]),
            "type": "human",
            "role": "responsible"
        })

    if context.get("accountable"):
        actors.append({
            "id": normalize_id(context["accountable"]),
            "type": "human",
            "role": "accountable"
        })

    if context.get("approved_by"):
        actors.append({
            "id": normalize_id(context["approved_by"]),
            "type": "human",
            "role": "approver"
        })

    return {
        "identities": {
            "actors": actors,
            "required_roles": [a["role"] for a in actors],
            "conflict_flags": {},
        },
        "integrity": {},
        "publication": {},
    }


# ---------------------------
# Core validation pipeline
# ---------------------------

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict | None):
    context = context or {}

    # 🔥 Approval enforcement
    constraints = policy.get("constraints", [])
    for c in constraints:
        if c.get("type") == "approval_required":
            threshold = c.get("threshold", 0)
            amount = action.get("amount", 0)

            if amount > threshold and not context.get("approved_by"):
                return {
                    "allowed": False,
                    "reason": f"Blocked: approval required for transfers above ${threshold:,.0f}",
                    "summary": summarize_action(action),
                }

    try:
        # 🔥 Pre-check
        valid, error = enforce_required_roles(policy, context)
        if not valid:
            return {
                "allowed": False,
                "reason": error,
                "summary": summarize_action(action),
            }

        # Compile policy
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as policy_file:
            json.dump(policy, policy_file)
            policy_path = Path(policy_file.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_path = Path(tmp.name)

        contract_path = compile_policy_file(policy_path, output_path)

        with open(contract_path, "r", encoding="utf-8") as f:
            compiled_contract = json.load(f)

        contract = build_contract_binding(compiled_contract)

        proposal = build_proposal(
            proposal_id=str(uuid.uuid4()),
            actor={"id": normalize_id(actor), "type": "agent"},
            artifact_paths=[],
            mutation=normalize_mutation(action),
            contract=contract,
            run_context=normalize_context(actor, context),
        )

        result = evaluate_proposal(proposal, compiled_contract)
        allowed, reason = extract_result(result)

        return {
            "allowed": allowed,
            "reason": reason,
            "summary": summarize_action(action),
        }

    except Exception as e:
        return {
            "allowed": False,
            "reason": f"Validation error: {str(e)}",
            "summary": summarize_action(action),
        }


# ---------------------------
# API
# ---------------------------

@app.post("/validate")
async def validate(request: Request):
    body = await request.json()

    try:
        policy = body["policy"]
        action = body["action"]
        actor = body.get("actor", "ai-agent")
        context = body.get("context", {})
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing field: {e}")

    return JSONResponse(run_validation(policy, action, actor, context))


@app.post("/api/log")
async def receive_log(request: Request):
    data = await request.json()

    print(f"\n🚨 [TELEMETRY] Actor: {data.get('actor')} | Allowed: {data.get('allowed')}")
    print(f"Reason: {data.get('reason')}\n")

    return JSONResponse({"status": "logged"})