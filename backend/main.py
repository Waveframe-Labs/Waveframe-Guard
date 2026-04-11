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

    if "circularity" in combined:
        return "Blocked: separation of duties violated (circular role assignment detected)"

    if "required role not satisfied" in combined:
        return "Blocked: required governance roles are missing for this action"

    if "multiple candidates" in combined:
        return "Blocked: governance role assignment is ambiguous (multiple actors assigned to a required role)"

    if "approval" in combined and "required" in combined:
        return "Blocked: approval required (no approver provided)"

    if "independence" in failed_stages:
        return "Blocked: governance independence requirements were not satisfied"

    if "integrity" in failed_stages:
        return "Blocked: required execution data is incomplete"

    if "publication" in failed_stages or "publication-commit" in failed_stages:
        return "Blocked: action failed governance checks and cannot execute"

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
        return {
            "domain": "finance",
            "resource": "funds",
            "action": "transfer",
        }

    if action_type == "get_balance":
        return {
            "domain": "finance",
            "resource": "account",
            "action": "read",
        }

    if action_type == "reallocate_budget":
        return {
            "domain": "finance",
            "resource": "budget",
            "action": "reallocate",
        }

    return {
        "domain": "general",
        "resource": "unknown",
        "action": str(action_type or "unknown"),
    }


def normalize_context(actor: str, context: Dict[str, Any] | None) -> Dict[str, Any]:
    context = context or {}

    approved_by = context.get("approved_by")
    responsible = context.get("responsible")
    accountable = context.get("accountable")

    actors = []

    proposer_id = str(actor)
    actors.append(
        {
            "id": proposer_id,
            "type": "agent",
            "role": "proposer",
        }
    )

    if responsible:
        actors.append(
            {
                "id": str(responsible),
                "type": "human" if "human" in str(responsible).lower() else "agent",
                "role": "responsible",
            }
        )

    if accountable:
        actors.append(
            {
                "id": str(accountable),
                "type": "human" if "human" in str(accountable).lower() else "agent",
                "role": "accountable",
            }
        )

    if approved_by:
        actors.append(
            {
                "id": str(approved_by),
                "type": "human" if "human" in str(approved_by).lower() else "agent",
                "role": "approver",
            }
        )

    required_roles = []
    for actor_item in actors:
        role = actor_item["role"]
        if role not in required_roles:
            required_roles.append(role)

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
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as policy_file:
            json.dump(policy, policy_file)
            policy_path = Path(policy_file.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_path = Path(tmp.name)

        contract_path = compile_policy_file(policy_path, output_path)

        with open(contract_path, "r", encoding="utf-8") as f:
            compiled_contract = json.load(f)

        contract = build_contract_binding(compiled_contract)
        mutation = normalize_mutation(action)
        run_context = normalize_context(actor, context)

        proposal = build_proposal(
            proposal_id=str(uuid.uuid4()),
            actor={"id": actor, "type": "agent"},
            artifact_paths=[],
            mutation=mutation,
            contract=contract,
            run_context=run_context,
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

    result = run_validation(policy, action, actor, context)
    return JSONResponse(result)


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
        body {
            font-family: Arial, Helvetica, sans-serif;
            background: #0f1115;
            color: white;
            margin: 0;
            padding: 40px;
        }

        h1 {
            margin: 0 0 8px;
        }

        p.sub {
            color: #b8c0cc;
            margin: 0 0 28px;
        }

        .container {
            display: flex;
            gap: 32px;
            align-items: flex-start;
        }

        textarea {
            width: 100%;
            height: 320px;
            background: #1a1d24;
            color: white;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 12px;
            font-family: Consolas, monospace;
            font-size: 14px;
        }

        .panel {
            flex: 1;
        }

        button {
            margin-top: 20px;
            padding: 12px 20px;
            background: orange;
            border: none;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
        }

        .result {
            margin-top: 24px;
            padding: 20px;
            border-radius: 12px;
        }

        .blocked {
            background: rgba(255,100,0,0.16);
            border: 1px solid orange;
        }

        .allowed {
            background: rgba(0,200,100,0.16);
            border: 1px solid #22c55e;
        }

        .label {
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #b8c0cc;
            margin-bottom: 8px;
        }

        .reason {
            margin-top: 10px;
            line-height: 1.5;
        }
    </style>
</head>

<body>

<h1>Waveframe Guard</h1>
<p class="sub">Validate AI actions before they execute.</p>

<div class="container">
    <div class="panel">
        <div class="label">Policy</div>
        <textarea id="policy">{
  "contract_id": "finance-raci",
  "contract_version": "0.1.0",
  "roles": {
    "required": [
      "proposer",
      "responsible",
      "accountable"
    ]
  },
  "constraints": [
    {
      "type": "separation_of_duties",
      "roles": [
        "responsible",
        "accountable"
      ]
    }
  ]
}</textarea>
    </div>

    <div class="panel">
        <div class="label">Action</div>
        <textarea id="action">{
  "type": "transfer",
  "amount": 5000
}</textarea>
    </div>
</div>

<button onclick="runValidation()">Validate Action</button>

<div id="output"></div>

<script>
async function runValidation() {
    try {
        const policy = JSON.parse(document.getElementById("policy").value);
        const action = JSON.parse(document.getElementById("action").value);

        const res = await fetch("/validate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                policy,
                action,
                actor: "ai-agent",
                context: {}
            })
        });

        const data = await res.json();
        const div = document.getElementById("output");

        div.className = "result " + (data.allowed ? "allowed" : "blocked");
        div.innerHTML = `
            <h2>${data.allowed ? "ALLOWED" : "BLOCKED"}</h2>
            <p><strong>${data.summary}</strong></p>
            <p class="reason">${data.reason}</p>
        `;
    } catch (err) {
        const div = document.getElementById("output");
        div.className = "result blocked";
        div.innerHTML = `<h2>ERROR</h2><p>${err}</p>`;
    }
}
</script>

</body>
</html>
"""