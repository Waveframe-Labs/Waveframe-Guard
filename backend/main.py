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
    version="1.3.0",
    description="Stop unsafe AI actions before they execute.",
)


# ---------------------------
# Identity resolver
# ---------------------------

IDENTITY_REGISTRY_PATH = Path(__file__).resolve().parent / "identities.json"


def load_identity_registry() -> Dict[str, Dict[str, Any]]:
    if not IDENTITY_REGISTRY_PATH.exists():
        raise FileNotFoundError(
            f"Identity registry not found: {IDENTITY_REGISTRY_PATH}"
        )

    with open(IDENTITY_REGISTRY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Identity registry must be a JSON object")

    return data


def normalize_lookup_key(value: Optional[str]) -> str:
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


def resolve_identity(raw_value: Optional[str], registry: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    lookup = normalize_lookup_key(raw_value)

    if not lookup:
        return {
            "found": False,
            "input": raw_value,
            "reason": "blank identity",
        }

    record = registry.get(lookup)
    if not record:
        return {
            "found": False,
            "input": raw_value,
            "reason": f"unknown identity: {lookup}",
        }

    canonical_id = record.get("canonical_id")
    if not canonical_id:
        return {
            "found": False,
            "input": raw_value,
            "reason": f"identity record missing canonical_id: {lookup}",
        }

    return {
        "found": True,
        "input": raw_value,
        "lookup": lookup,
        "canonical_id": canonical_id,
        "display_name": record.get("display_name", canonical_id),
        "type": record.get("type", "human"),
        "roles": record.get("roles", []),
        "source": "local_registry",
    }


def resolve_context_identities(context: Dict[str, Any]) -> tuple[bool, Dict[str, Any] | None, str | None]:
    registry = load_identity_registry()

    responsible_input = context.get("responsible")
    accountable_input = context.get("accountable")
    approved_by_input = context.get("approved_by")

    responsible = resolve_identity(responsible_input, registry)
    accountable = resolve_identity(accountable_input, registry)

    if not responsible["found"]:
        return False, None, "Blocked: responsible actor could not be resolved"

    if not accountable["found"]:
        return False, None, "Blocked: accountable actor could not be resolved"

    approver: Dict[str, Any] | None = None
    if approved_by_input:
        approver = resolve_identity(approved_by_input, registry)
        if not approver["found"]:
            return False, None, "Blocked: approver actor could not be resolved"

    normalized = {
        "responsible": responsible["canonical_id"],
        "accountable": accountable["canonical_id"],
        "approved_by": approver["canonical_id"] if approver else None,
        "resolved": {
            "responsible": responsible,
            "accountable": accountable,
            "approved_by": approver,
        },
    }

    return True, normalized, None


# ---------------------------
# Helpers
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    action_type = action.get("type")

    if action_type == "transfer":
        return f"AI attempted to transfer ${action.get('amount', 0):,.0f}"

    if action_type == "reallocate_budget":
        return f"AI attempted to reallocate ${action.get('amount', 0):,.0f}"

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
    action_type = action.get("type")

    if action_type == "transfer":
        return {"domain": "finance", "resource": "funds", "action": "transfer"}

    if action_type == "reallocate_budget":
        return {"domain": "finance", "resource": "budget", "action": "reallocate"}

    return {"domain": "general", "resource": "unknown", "action": "unknown"}


# ---------------------------
# Policy enforcement
# ---------------------------

def enforce_required_roles(policy: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str | None]:
    required_roles = policy.get("roles", {}).get("required", [])

    provided_roles = {"proposer"}

    if context.get("responsible"):
        provided_roles.add("responsible")

    if context.get("accountable"):
        provided_roles.add("accountable")

    if context.get("approved_by"):
        provided_roles.add("approver")

    missing = [r for r in required_roles if r not in provided_roles]

    if missing:
        return False, f"Blocked: required roles missing: {', '.join(missing)}"

    return True, None


def detect_identity_conflict(context: Dict[str, Any]) -> bool:
    ids = []

    for role in ["responsible", "accountable"]:
        value = context.get(role)
        if value:
            ids.append(value)

    return len(ids) != len(set(ids))


def normalize_context(actor: str, context: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    actors = [{"id": normalize_lookup_key(actor), "type": "agent", "role": "proposer"}]

    if context.get("responsible"):
        actors.append({
            "id": context["responsible"],
            "type": "human",
            "role": "responsible",
        })

    if context.get("accountable"):
        actors.append({
            "id": context["accountable"],
            "type": "human",
            "role": "accountable",
        })

    if context.get("approved_by"):
        actors.append({
            "id": context["approved_by"],
            "type": "human",
            "role": "approver",
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
# Core validation pipeline
# ---------------------------

def run_validation(policy: Dict[str, Any], action: Dict[str, Any], actor: str, context: Dict[str, Any]):
    context = context or {}

    try:
        resolved_ok, resolved_context, resolve_error = resolve_context_identities(context)
        if not resolved_ok:
            return {
                "allowed": False,
                "reason": resolve_error,
                "summary": summarize_action(action),
            }

        assert resolved_context is not None

        if detect_identity_conflict(resolved_context):
            return {
                "allowed": False,
                "reason": "Blocked: same individual assigned to multiple required roles",
                "summary": summarize_action(action),
            }

        valid, error = enforce_required_roles(policy, resolved_context)
        if not valid:
            return {
                "allowed": False,
                "reason": error,
                "summary": summarize_action(action),
            }

        for constraint in policy.get("constraints", []):
            if constraint.get("type") == "approval_required":
                threshold = constraint.get("threshold", 0)
                amount = action.get("amount", 0)

                if amount > threshold and not resolved_context.get("approved_by"):
                    return {
                        "allowed": False,
                        "reason": f"Blocked: approval required above ${threshold:,.0f}",
                        "summary": summarize_action(action),
                    }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as f:
            json.dump(policy, f)
            policy_path = Path(f.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_path = Path(tmp.name)

        contract_path = compile_policy_file(policy_path, output_path)

        with open(contract_path, "r", encoding="utf-8") as f:
            compiled = json.load(f)

        contract = build_contract_binding(compiled)

        proposal = build_proposal(
            proposal_id=str(uuid.uuid4()),
            actor={"id": normalize_lookup_key(actor), "type": "agent"},
            artifact_paths=[],
            mutation=normalize_mutation(action),
            contract=contract,
            run_context=normalize_context(actor, resolved_context, policy),
        )

        result = evaluate_proposal(proposal, compiled)
        allowed, reason = extract_result(result)

        return {
            "allowed": allowed,
            "reason": reason,
            "summary": summarize_action(action),
        }

    except FileNotFoundError as e:
        return {
            "allowed": False,
            "reason": f"Validation error: {str(e)}",
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
<label><input type="checkbox" id="requireApproval" checked onchange="updateRules()"> Require approval</label>
<input id="threshold" type="number" value="5000" onchange="updateRules()">

<div id="rules" style="margin-top:15px;"></div>

<button onclick="run()">Check if this action will execute</button>

<div id="out"></div>

<script>
function updateRules(){
    const threshold = Number(document.getElementById("threshold").value);
    const requireApproval = document.getElementById("requireApproval").checked;

    let approvalRule = requireApproval
        ? `<li>Approval required above $${threshold.toLocaleString()}</li>`
        : `<li>No approval required</li>`;

    document.getElementById("rules").innerHTML = `
        <strong>Enforced Rules</strong>
        <ul>
            <li>Roles must resolve to known identities</li>
            <li>Responsible and Accountable must be different</li>
            ${approvalRule}
        </ul>
    `;
}

updateRules();

async function run(){
    updateRules();

    const constraints = [
        {type:"separation_of_duties",roles:["responsible","accountable"]}
    ];

    if (document.getElementById("requireApproval").checked) {
        constraints.push({
            type:"approval_required",
            threshold:Number(document.getElementById("threshold").value)
        });
    }

    const res = await fetch("/validate",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
            policy:{
                contract_id:"dynamic",
                contract_version:"1.0.0",
                roles:{required:["proposer","responsible","accountable"]},
                constraints: constraints
            },
            action:{
                type:document.getElementById("actionType").value,
                amount:Number(document.getElementById("amount").value)
            },
            actor:"ai-agent",
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