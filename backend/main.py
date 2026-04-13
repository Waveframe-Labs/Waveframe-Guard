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
        return "Blocked: separation of duties violated (conflicting roles assigned to the same actor)"

    if "identity reused across required roles" in combined:
        return "Blocked: separation of duties violated (the same actor cannot hold conflicting required roles)"

    if "required role not satisfied" in combined:
        return "Blocked: required governance roles are missing for this action"

    if "multiple candidates" in combined:
        return "Blocked: governance role assignment is ambiguous"

    if "approval" in combined and "required" in combined:
        return "Blocked: approval required (no approver provided)"

    if "independence" in failed_stages:
        return "Blocked: governance independence requirements were not satisfied"

    return "Blocked: policy requirements were not satisfied"


def extract_result(result: Any) -> tuple[bool, str]:
    allowed = getattr(result, "allowed", None)

    if allowed is None:
        allowed = getattr(result, "commit_allowed", None)

    if allowed is None:
        allowed = getattr(result, "passed", False)

    if bool(allowed):
        return True, "Allowed: execution permitted"

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
# 🚨 FIXED ROLE ENFORCEMENT
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

    # proposer always exists (actor)
    provided_roles.add("proposer")

    missing = [r for r in required_roles if r not in provided_roles]

    if missing:
        return False, f"Blocked: required governance roles missing: {', '.join(missing)}"

    return True, None


def normalize_context(actor: str, context: Dict[str, Any] | None) -> Dict[str, Any]:
    context = context or {}

    actors = [
        {"id": str(actor), "type": "agent", "role": "proposer"}
    ]

    if context.get("responsible"):
        actors.append({
            "id": str(context["responsible"]),
            "type": "human",
            "role": "responsible"
        })

    if context.get("accountable"):
        actors.append({
            "id": str(context["accountable"]),
            "type": "human",
            "role": "accountable"
        })

    if context.get("approved_by"):
        actors.append({
            "id": str(context["approved_by"]),
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

    try:
        # 🔥 PRE-CHECK (NEW)
        valid, error = enforce_required_roles(policy, context)
        if not valid:
            return {
                "allowed": False,
                "reason": error,
                "summary": summarize_action(action),
            }

        # --- Compile policy ---
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
            actor={"id": actor, "type": "agent"},
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


# ---------------------------
# UI
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def ui():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Waveframe Guard</title>
    <style>
        body { font-family: Arial; background: #0f1115; color: white; padding: 40px; }
        textarea { width: 100%; height: 250px; background: #1a1d24; color: white; border: 1px solid #333; padding: 10px; }
        input { width: 100%; padding: 10px; background: #1a1d24; color: white; border: 1px solid #333; }
        .container { display: flex; gap: 30px; }
        .section { flex: 1; }
        button { margin-top: 20px; padding: 12px; background: orange; border: none; font-weight: bold; cursor: pointer; }
        .result { margin-top: 20px; padding: 20px; border-radius: 8px; }
        .blocked { background: rgba(255,100,0,0.2); border: 1px solid orange; }
        .allowed { background: rgba(0,200,100,0.2); border: 1px solid green; }
        .context { margin-top: 30px; }
    </style>
</head>
<body>

<h1>Waveframe Guard</h1>
<p>Validate AI actions before they execute.</p>

<div class="container">
    <div class="section">
        <h3>Policy</h3>
        <textarea id="policy">
{
  "contract_id": "finance-raci",
  "contract_version": "0.1.0",
  "roles": {
    "required": ["proposer", "responsible", "accountable"]
  },
  "constraints": [
    {
      "type": "separation_of_duties",
      "roles": ["responsible", "accountable"]
    }
  ]
}
        </textarea>
    </div>

    <div class="section">
        <h3>Action</h3>
        <textarea id="action">
{ "type": "transfer", "amount": 5000 }
        </textarea>
    </div>
</div>

<div class="context">
    <h3>Governance Context (who is involved)</h3>

    <label>Responsible</label>
    <input id="responsible" placeholder="e.g. ops-manager-1" />

    <label style="margin-top:10px;">Accountable</label>
    <input id="accountable" placeholder="e.g. finance-director-1" />

    <label style="margin-top:10px;">Approved By (optional)</label>
    <input id="approved_by" placeholder="e.g. human-approver-1" />
</div>

<button onclick="runValidation()">Validate Action</button>

<div id="output"></div>

<script>
async function runValidation() {
    const policy = JSON.parse(document.getElementById("policy").value);
    const action = JSON.parse(document.getElementById("action").value);

    const responsible = document.getElementById("responsible").value;
    const accountable = document.getElementById("accountable").value;
    const approved_by = document.getElementById("approved_by").value;

    const context = {};

    if (responsible) context.responsible = responsible;
    if (accountable) context.accountable = accountable;
    if (approved_by) context.approved_by = approved_by;

    const res = await fetch("/validate", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            policy,
            action,
            actor: "ai-agent",
            context
        })
    });

    const data = await res.json();
    const div = document.getElementById("output");

    div.className = "result " + (data.allowed ? "allowed" : "blocked");

    div.innerHTML = `
        <h2>${data.allowed ? "ALLOWED" : "BLOCKED"}</h2>
        <p><strong>${data.summary}</strong></p>
        <p>${data.reason}</p>
    `;
}
</script>

</body>
</html>
"""