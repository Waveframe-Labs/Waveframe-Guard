from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


app = FastAPI(
    title="Waveframe Guard",
    version="1.2.5",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# Identity Validation (FIXED)
# ---------------------------

INVALID_IDENTITIES = {
    "",
    "none",
    "null",
    "void",
    "n/a",
    "na",
    "undefined",
}

def normalize_id(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.strip().lower()

def is_valid_identity(value: Optional[str]) -> bool:
    normalized = normalize_id(value)
    return normalized not in INVALID_IDENTITIES


# ---------------------------
# Helpers (UNCHANGED)
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    if action["type"] == "transfer":
        return f"AI attempted to transfer ${action['amount']:,.0f}"
    if action["type"] == "reallocate_budget":
        return f"AI attempted to reallocate ${action['amount']:,.0f}"
    return "AI attempted action"


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
        if getattr(stage, "messages", None):
            messages.extend([str(m) for m in stage.messages])
    return messages


def interpret_reason(result: Any) -> str:
    messages = extract_stage_messages(result)
    combined = " ".join(messages).lower()

    if "separation_of_duties" in combined or "conflict" in combined:
        return "Blocked: same individual assigned to multiple required roles"

    if "approval" in combined:
        return "Blocked: approval required but not provided"

    if "required role" in combined:
        return "Blocked: required roles not properly assigned"

    return "Blocked: policy requirements were not satisfied"


def extract_result(result: Any) -> tuple[bool, str]:
    allowed = getattr(result, "allowed", None)
    if allowed is None:
        allowed = getattr(result, "commit_allowed", False)

    if allowed:
        return True, "Allowed: policy conditions satisfied"

    return False, interpret_reason(result)


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    if action["type"] == "transfer":
        return {"domain": "finance", "resource": "funds", "action": "transfer"}
    if action["type"] == "reallocate_budget":
        return {"domain": "finance", "resource": "budget", "action": "reallocate"}
    return {"domain": "general", "resource": "unknown", "action": "unknown"}


# ---------------------------
# NEW: Identity Gate (CRITICAL)
# ---------------------------

def validate_identities(context: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    responsible = context.get("responsible")
    accountable = context.get("accountable")
    approver = context.get("approved_by")

    if not is_valid_identity(responsible) or not is_valid_identity(accountable):
        return False, "Blocked: required governance roles missing"

    # Only enforce approver validity if it exists (threshold handled later)
    if approver is not None and approver != "":
        if not is_valid_identity(approver):
            return False, "Blocked: invalid approver identity"

    return True, None


# ---------------------------
# Context normalization (SAFE)
# ---------------------------

def normalize_context(actor: str, context: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    actors = [{"id": normalize_id(actor), "type": "agent", "role": "proposer"}]

    for role in ["responsible", "accountable", "approved_by"]:
        value = context.get(role)
        if value:
            actors.append({
                "id": normalize_id(value),
                "type": "human",
                "role": role if role != "approved_by" else "approver"
            })

    return {
        "identities": {
            "actors": actors,
            "required_roles": policy.get("roles", {}).get("required", []),
            "conflict_flags": {},
        },
        "integrity": {},
        "publication": {},
    }


# ---------------------------
# CORE PIPELINE (PRESERVED)
# ---------------------------

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict):

    # SAFE normalization (fix crash)
    context = {
        "responsible": (context.get("responsible") or "").strip(),
        "accountable": (context.get("accountable") or "").strip(),
        "approved_by": (context.get("approved_by") or "").strip(),
    }

    # 🔥 NEW: identity validation BEFORE pipeline
    valid, error = validate_identities(context)
    if not valid:
        return {
            "allowed": False,
            "reason": error,
            "summary": summarize_action(action),
        }

    # Compile policy
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
        json.dump(policy, f)
        policy_path = Path(f.name)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = Path(tmp.name)

    contract_path = compile_policy_file(policy_path, output_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    contract = build_contract_binding(compiled)

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": normalize_id(actor), "type": "agent"},
        artifact_paths=[],
        mutation=normalize_mutation(action),
        contract=contract,
        run_context=normalize_context(actor, context, policy),
    )

    result = evaluate_proposal(proposal, compiled)
    allowed, reason = extract_result(result)

    return {
        "allowed": allowed,
        "reason": reason,
        "summary": summarize_action(action),
    }


# ---------------------------
# API (UNCHANGED)
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