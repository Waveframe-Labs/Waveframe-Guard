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
    version="1.2.0",
)


# ---------------------------
# Identity normalization
# ---------------------------

def normalize_id(value: str) -> str:
    if not value:
        return ""

    normalized = value.strip().lower().replace("_", "-")

    number_map = {
        "one": "1",
        "two": "2",
        "three": "3",
        "four": "4",
        "five": "5",
    }

    for word, num in number_map.items():
        normalized = normalized.replace(word, num)

    normalized = normalized.replace("-0", "-")

    return normalized


# ---------------------------
# Helpers
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    action_type = action.get("type")

    if action_type == "transfer":
        amount = action.get("amount")
        return f"AI attempted to transfer ${amount:,.0f}"

    if action_type == "reallocate_budget":
        amount = action.get("amount")
        return f"AI attempted to reallocate ${amount:,.0f}"

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
        if getattr(stage, "messages", None):
            messages.extend([str(m) for m in stage.messages])
    return messages


def interpret_reason(result: Any) -> str:
    messages = extract_stage_messages(result)
    combined = " ".join(messages).lower()

    if "separation_of_duties" in combined:
        return "Blocked: same individual assigned to conflicting roles"

    if "approval" in combined:
        return "Blocked: approval required but not provided"

    if "required role" in combined:
        return "Blocked: required governance roles missing"

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
# Policy enforcement
# ---------------------------

def enforce_required_roles(policy: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str | None]:
    required_roles = policy.get("roles", {}).get("required", [])

    provided_roles = {"proposer"}

    if context.get("responsible", "").strip():
        provided_roles.add("responsible")

    if context.get("accountable", "").strip():
        provided_roles.add("accountable")

    if context.get("approved_by", "").strip():
        provided_roles.add("approver")

    missing = [r for r in required_roles if r not in provided_roles]

    if missing:
        return False, f"Blocked: required roles missing: {', '.join(missing)}"

    return True, None


def normalize_context(actor: str, context: Dict[str, Any]) -> Dict[str, Any]:
    actors = [{"id": normalize_id(actor), "type": "agent", "role": "proposer"}]

    if context.get("responsible"):
        actors.append({"id": normalize_id(context["responsible"]), "type": "human", "role": "responsible"})

    if context.get("accountable"):
        actors.append({"id": normalize_id(context["accountable"]), "type": "human", "role": "accountable"})

    if context.get("approved_by"):
        actors.append({"id": normalize_id(context["approved_by"]), "type": "human", "role": "approver"})

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

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict):
    valid, error = enforce_required_roles(policy, context)
    if not valid:
        return {"allowed": False, "reason": error, "summary": summarize_action(action)}

    for c in policy.get("constraints", []):
        if c.get("type") == "approval_required":
            if action["amount"] > c["threshold"] and not context.get("approved_by"):
                return {
                    "allowed": False,
                    "reason": f"Blocked: approval required above ${c['threshold']:,.0f}",
                    "summary": summarize_action(action),
                }

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
        run_context=normalize_context(actor, context),
    )

    result = evaluate_proposal(proposal, compiled)
    allowed, reason = extract_result(result)

    return {"allowed": allowed, "reason": reason, "summary": summarize_action(action)}


# ---------------------------
# API
# ---------------------------

@app.post("/validate")
async def validate(request: Request):
    body = await request.json()
    return JSONResponse(run_validation(body["policy"], body["action"], body.get("actor", "ai-agent"), body.get("context", {})))


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
body { font-family: Arial; background:#0f1115; color:white; padding:40px; max-width:900px; margin:auto; }
input, select { width:100%; padding:10px; margin-bottom:12px; background:#1a1d24; color:white; border:1px solid #333; }
button { padding:14px; width:100%; background:orange; border:none; font-weight:bold; }
.box { margin-top:20px; padding:20px; border-radius:8px; }
.allowed { border:1px solid green; background:rgba(0,200,100,0.15); }
.blocked { border:1px solid orange; background:rgba(255,100,0,0.15); }
</style>
</head>

<body>

<h1>Waveframe Guard</h1>
<p>Stop unsafe AI actions before they execute.</p>

<h3>Action</h3>
<select id="actionType">
<option value="transfer">Transfer Funds</option>
<option value="reallocate_budget">Reallocate Budget</option>
</select>
<input id="amount" type="number" value="5000" />

<h3>Roles</h3>
<input id="responsible" placeholder="Responsible">
<input id="accountable" placeholder="Accountable">
<input id="approved_by" placeholder="Approver">

<h3>Policy</h3>
<label><input type="checkbox" id="requireApproval" checked> Require approval</label>
<input id="threshold" type="number" value="5000">

<div id="rules" style="margin-top:15px;"></div>

<button onclick="run()">Check if this action will execute</button>

<div id="out"></div>

<script>
function updateRules(){
    const threshold = document.getElementById("threshold").value;
    document.getElementById("rules").innerHTML = `
        <strong>Enforced Rules</strong>
        <ul>
            <li>Roles must be assigned</li>
            <li>Responsible and Accountable must be different</li>
            <li>Approval required above $${Number(threshold).toLocaleString()}</li>
        </ul>
    `;
}
updateRules();

async function run(){
    updateRules();

    const res = await fetch("/validate",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
            policy:{
                contract_id:"dynamic",
                contract_version:"1.0",
                roles:{required:["proposer","responsible","accountable"]},
                constraints:[
                    {type:"separation_of_duties",roles:["responsible","accountable"]},
                    {type:"approval_required",threshold:Number(document.getElementById("threshold").value)}
                ]
            },
            action:{
                type:document.getElementById("actionType").value,
                amount:Number(document.getElementById("amount").value)
            },
            context:{
                responsible:document.getElementById("responsible").value,
                accountable:document.getElementById("accountable").value,
                approved_by:document.getElementById("approved_by").value
            }
        })
    });

    const d = await res.json();

    document.getElementById("out").innerHTML = `
        <div class="box ${d.allowed ? "allowed":"blocked"}">
            <h2>${d.allowed ? "ALLOWED":"BLOCKED"}</h2>
            <p><strong>${d.summary}</strong></p>
            <p>${d.reason}</p>
            <p style="opacity:0.6;">Decision made at execution boundary</p>
        </div>
    `;
}
</script>

</body>
</html>
"""