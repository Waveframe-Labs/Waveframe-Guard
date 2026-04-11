from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

# --- Your components ---
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

    return f"AI attempted action: {action_type or 'unknown'}"


# ---------------------------
# Core validation pipeline
# ---------------------------

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict | None):
    try:
        # --- 1. Write policy JSON → temp file ---
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as policy_file:
            json.dump(policy, policy_file)
            policy_path = Path(policy_file.name)

        # --- 2. Compile policy → contract ---
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_path = Path(tmp.name)

        contract_path = compile_policy_file(policy_path, output_path)

        with open(contract_path, "r") as f:
            compiled_contract = json.load(f)

        # --- 3. Build proposal ---
        proposal = build_proposal(
            proposal_id=str(uuid.uuid4()),
            actor={"id": actor, "type": "agent"},
            artifact_paths=[],
            mutation={
                "domain": "finance",
                "resource": "account",
                "action": action,
            },
            contract=compiled_contract,
            run_context=context or {},
        )

        # --- 4. Evaluate ---
        result = evaluate_proposal(proposal)

        allowed = result.get("allowed", False)
        reason = result.get("reason", "Unknown")

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
# UI (product surface)
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
            font-family: Arial;
            background: #0f1115;
            color: white;
            margin: 0;
            padding: 40px;
        }

        h1 {
            margin-bottom: 10px;
        }

        .container {
            display: flex;
            gap: 40px;
        }

        textarea {
            width: 100%;
            height: 300px;
            background: #1a1d24;
            color: white;
            border: 1px solid #333;
            padding: 10px;
        }

        .panel {
            flex: 1;
        }

        button {
            margin-top: 20px;
            padding: 12px 20px;
            background: orange;
            border: none;
            font-weight: bold;
            cursor: pointer;
        }

        .result {
            margin-top: 20px;
            padding: 20px;
            border-radius: 8px;
        }

        .blocked {
            background: rgba(255,100,0,0.2);
            border: 1px solid orange;
        }

        .allowed {
            background: rgba(0,200,100,0.2);
            border: 1px solid green;
        }
    </style>
</head>

<body>

<h1>Waveframe Guard</h1>
<p>Validate AI actions before they execute.</p>

<div class="container">

    <div class="panel">
        <h3>Policy</h3>
        <textarea id="policy">{}</textarea>
    </div>

    <div class="panel">
        <h3>Action</h3>
        <textarea id="action">{ "type": "transfer", "amount": 5000 }</textarea>
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
            <p>${data.reason}</p>
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