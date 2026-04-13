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
    version="1.1.0",
)


# ---------------------------
# Identity normalization (IMPROVED)
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
        "five": "5"
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
        if isinstance(amount, (int, float)):
            return f"AI attempted to transfer ${amount:,.0f}"
        return "AI attempted to transfer funds"

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
        return True, "Allowed: no policy violations detected"

    return False, interpret_reason(result)


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "domain": "finance",
        "resource": "funds",
        "action": "transfer",
    }


# ---------------------------
# Policy enforcement
# ---------------------------

def enforce_required_roles(policy: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, str | None]:
    required_roles = policy.get("roles", {}).get("required", [])

    if not required_roles:
        return True, None

    provided_roles = {"proposer"}

    if context.get("responsible"):
        provided_roles.add("responsible")

    if context.get("accountable"):
        provided_roles.add("accountable")

    if context.get("approved_by"):
        provided_roles.add("approver")

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
        actors.append(
            {
                "id": normalize_id(context["responsible"]),
                "type": "human",
                "role": "responsible",
            }
        )

    if context.get("accountable"):
        actors.append(
            {
                "id": normalize_id(context["accountable"]),
                "type": "human",
                "role": "accountable",
            }
        )

    if context.get("approved_by"):
        actors.append(
            {
                "id": normalize_id(context["approved_by"]),
                "type": "human",
                "role": "approver",
            }
        )

    required_roles = list(dict.fromkeys(a["role"] for a in actors))

    return {
        "identities": {
            "actors": actors,
            "required_roles": required_roles,
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
        valid, error = enforce_required_roles(policy, context)
        if not valid:
            return {
                "allowed": False,
                "reason": error,
                "summary": summarize_action(action),
            }

        constraints = policy.get("constraints", [])
        for c in constraints:
            if c.get("type") == "approval_required":
                threshold = c.get("threshold", 0)
                amount = action.get("amount", 0)

                if amount > threshold and not context.get("approved_by"):
                    return {
                        "allowed": False,
                        "reason": f"Blocked: approval required above ${threshold:,.0f}",
                        "summary": summarize_action(action),
                    }

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
</head>

<body style="font-family: Arial; background:#0f1115; color:white; padding:40px; max-width:900px; margin:auto;">

<h1>Waveframe Guard</h1>
<p>Stop unsafe AI actions before they execute.</p>

<h3>Action</h3>
<input id="amount" type="number" value="5000" />

<h3>Roles</h3>
<input id="responsible" placeholder="Responsible" />
<input id="accountable" placeholder="Accountable" />
<input id="approved_by" placeholder="Approver (if required)" />

<h3>Policy</h3>
<label><input type="checkbox" id="requireApproval" checked /> Require approval</label>
<input id="approvalThreshold" type="number" value="5000" />

<button onclick="runValidation()">Check if this action will execute</button>

<div id="output" style="margin-top:20px;"></div>

<script>
async function runValidation() {
    const amount = parseFloat(document.getElementById("amount").value);

    const policy = {
        contract_id: "dynamic-policy",
        contract_version: "1.0.0",
        roles: {
            required: ["proposer","responsible","accountable"]
        },
        constraints: [
            { type: "separation_of_duties", roles: ["responsible","accountable"] }
        ]
    };

    if (document.getElementById("requireApproval").checked) {
        policy.constraints.push({
            type: "approval_required",
            threshold: parseFloat(document.getElementById("approvalThreshold").value)
        });
    }

    const context = {
        responsible: document.getElementById("responsible").value,
        accountable: document.getElementById("accountable").value,
        approved_by: document.getElementById("approved_by").value
    };

    const res = await fetch("/validate", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
            policy,
            action:{type:"transfer",amount},
            actor:"ai-agent",
            context
        })
    });

    const data = await res.json();

    document.getElementById("output").innerHTML = `
        <h2>${data.allowed ? "ALLOWED" : "BLOCKED"}</h2>
        <p><strong>${data.summary}</strong></p>
        <p>${data.reason}</p>
        <p style="opacity:0.6;">Decision made at execution boundary</p>
    `;
}
</script>

</body>
</html>
"""