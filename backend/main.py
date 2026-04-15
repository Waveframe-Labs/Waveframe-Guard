from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal

app = FastAPI(
    title="Waveframe Guard",
    version="2.1.0",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# IDENTITY
# ---------------------------

def load_identity_registry() -> Dict[str, Any]:
    """Safely loads identities, with a fallback so the app doesn't crash if the file is missing."""
    identity_path = Path(__file__).resolve().parent / "data" / "identities.json"
    
    if identity_path.exists():
        with open(identity_path, "r", encoding="utf-8") as f:
            return json.load(f)
            
    # Default fallback registry for the Sandbox
    return {
        "identities": {
            "user-alice": {"canonical_id": "usr_111", "aliases": ["alice"]},
            "user-bob": {"canonical_id": "usr_222", "aliases": ["bob"]},
            "user-charlie": {"canonical_id": "usr_333", "aliases": ["charlie"]},
            "ai-agent-v2": {"canonical_id": "agt_999", "aliases": ["agent"]}
        }
    }

def normalize(v: Optional[str]) -> str:
    if not v:
        return ""
    return v.strip().lower().replace("_", "-")

def resolve_identity(value: str, registry: Dict[str, Any]) -> str | None:
    if not value:
        return None
        
    key = normalize(value)
    for k, v in registry["identities"].items():
        if key == normalize(k) or key in [normalize(a) for a in v.get("aliases", [])]:
            return v["canonical_id"]
            
    return key # If not in registry, just return the raw normalized string for now

# ---------------------------
# STAGE / REASON
# ---------------------------

def extract_stages(result: Any) -> List[Dict[str, Any]]:
    stages = getattr(result, "stage_results", [])
    out = []
    for s in stages:
        out.append({
            "stage": getattr(s, "stage_id", "unknown"),
            "passed": getattr(s, "passed", False),
            "messages": getattr(s, "messages", []),
        })
    return out

def extract_reason(stages: List[Dict[str, Any]]) -> str:
    for s in stages:
        if not s["passed"]:
            msgs = " ".join(s.get("messages", [])).lower()

            if "separation" in msgs:
                return "Same person assigned to multiple required roles"
            if "required_roles" in msgs:
                return "Required roles not properly assigned"
            if "approval" in msgs:
                return "Approval missing or threshold exceeded"
            if msgs:
                return msgs

            return f"{s['stage']} failed"

    return "Action structurally aligned with governance policy"

# ---------------------------
# CORE
# ---------------------------

def run_validation(policy: Dict[str, Any], action: Dict[str, Any], actor: str, context: Dict[str, Any]) -> Dict[str, Any]:
    registry = load_identity_registry()

    r = resolve_identity(context.get("responsible"), registry)
    a = resolve_identity(context.get("accountable"), registry)
    p = resolve_identity(context.get("approved_by"), registry)

    if not r or not a:
        return {
            "allowed": False,
            "summary": f"AI attempted action: {action.get('type')}",
            "reason": "Identity resolution failed: missing required human context",
            "decision_trace": [],
            "resolved_identities": {}
        }

    # Compile the dynamically provided policy
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8") as policy_file:
        json.dump(policy, policy_file)
        policy_path = Path(policy_file.name)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        compiled_path = Path(tmp.name)

    contract_path = compile_policy_file(policy_path, compiled_path)

    with open(contract_path, "r", encoding="utf-8") as f:
        compiled = json.load(f)

    required_roles = compiled.get("roles", {}).get("required", ["proposer", "responsible", "accountable"])

    contract_hash = hashlib.sha256(json.dumps(compiled, sort_keys=True).encode()).hexdigest()

    actors_list = [
        {"id": normalize(actor), "type": "agent", "role": "proposer"},
        {"id": r, "type": "human", "role": "responsible"},
        {"id": a, "type": "human", "role": "accountable"},
    ]
    if p:
        actors_list.append({"id": p, "type": "human", "role": "approver"})

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": normalize(actor), "type": "agent"},
        artifact_paths=[],
        mutation={"domain": "finance", "resource": "funds", "action": action.get("type", "unknown")},
        contract={
            "id": compiled.get("contract_id", "dynamic-policy"),
            "version": compiled.get("contract_version", "1.0.0"),
            "hash": contract_hash,
        },
        run_context={
            "identities": {
                "actors": actors_list,
                "required_roles": required_roles,
                "conflict_flags": {},
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True}
        },
    )

    result = evaluate_proposal(proposal, compiled)

    allowed = getattr(result, "commit_allowed", False)
    stages = extract_stages(result)
    reason = extract_reason(stages)

    return {
        "allowed": allowed,
        "summary": f"AI attempted to transfer ${action.get('amount', 0):,.0f}",
        "reason": reason,
        "decision_trace": stages,
        "resolved_identities": {
            "proposer": normalize(actor),
            "responsible": r,
            "accountable": a,
            "approver": p,
        },
    }

# ---------------------------
# API
# ---------------------------

@app.post("/validate")
async def validate(request: Request):
    """The Sandbox Endpoint: Compiles and evaluates rules on the fly for the web UI."""
    body = await request.json()

    return JSONResponse(run_validation(
        policy=body.get("policy", {}),
        action=body.get("action", {}),
        actor=body.get("actor", "ai-agent-v2"),
        context=body.get("context", {}),
    ))

@app.post("/api/log")
async def receive_log(request: Request):
    """The Telemetry Endpoint: Catches live execution logs from installed SDKs."""
    data = await request.json()
    print(f"\n🚨 [TELEMETRY] Agent: '{data.get('actor')}' | Allowed: {data.get('allowed')} | Reason: {data.get('reason')}\n")
    return JSONResponse({"status": "logged"})

@app.get("/identities")
def identities():
    registry = load_identity_registry()
    return {
        "identities": [
            {"id": v["canonical_id"], "name": v.get("display_name", v["canonical_id"])}
            for v in registry["identities"].values()
        ]
    }

# ---------------------------
# UI
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def ui():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Waveframe Guard | Sandbox</title>
    <style>
        :root {
            --bg-dark: #0f1115;
            --panel-bg: #1a1d24;
            --border: #333;
            --text-main: #ffffff;
            --text-muted: #8b949e;
            --accent-orange: #ff7b00;
            --accent-green: #2ea043;
            --accent-red: #da3633;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-dark);
            color: var(--text-main);
            padding: 40px 20px;
            margin: 0;
            display: flex;
            justify-content: center;
        }

        .dashboard-container { width: 100%; max-width: 900px; }
        .header { margin-bottom: 30px; }
        .header h1 { margin: 0 0 10px 0; font-size: 28px; font-weight: 600; }
        .header p { margin: 0; color: var(--text-muted); font-size: 16px; }

        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .panel { background: var(--panel-bg); border: 1px solid var(--border); border-radius: 8px; padding: 24px; }
        .panel h3 { margin-top: 0; margin-bottom: 20px; font-size: 16px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }

        .form-group { margin-bottom: 16px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 500; color: var(--text-muted); }
        
        input, select {
            width: 100%; padding: 10px 12px; background: var(--bg-dark); color: var(--text-main);
            border: 1px solid var(--border); border-radius: 6px; font-size: 14px; box-sizing: border-box;
        }
        input:focus, select:focus { outline: none; border-color: var(--text-muted); }

        button {
            width: 100%; padding: 14px; background: var(--text-main); color: var(--bg-dark);
            border: none; border-radius: 6px; font-size: 16px; font-weight: 600;
            cursor: pointer; margin-top: 24px; transition: opacity 0.2s;
        }
        button:hover { opacity: 0.9; }

        /* Result Card Styling */
        #output { margin-top: 24px; padding: 24px; border-radius: 8px; display: none; }
        .result-title { font-size: 20px; font-weight: bold; margin-top: 0; margin-bottom: 8px; }
        .result-summary { font-size: 16px; margin-bottom: 12px; }
        .result-reason { font-family: monospace; font-size: 14px; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 4px; margin: 0; }
        
        .trace-list { list-style: none; padding: 0; margin: 16px 0 0 0; font-family: monospace; font-size: 13px; }
        .trace-list li { margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }

        .status-blocked { display: block !important; background: rgba(218, 54, 51, 0.1); border: 1px solid var(--accent-red); }
        .status-blocked .result-title { color: #ff6b6b; }

        .status-allowed { display: block !important; background: rgba(46, 160, 67, 0.1); border: 1px solid var(--accent-green); }
        .status-allowed .result-title { color: #7ee787; }
    </style>
</head>
<body>

<div class="dashboard-container">
    <div class="header">
        <h1>Waveframe Guard Sandbox</h1>
        <p>Test deterministic execution control against governance policies.</p>
    </div>

    <div class="grid">
        <div class="panel">
            <h3>Proposed Action</h3>
            <div class="form-group">
                <label>Action Type</label>
                <select id="actionType" disabled>
                    <option value="transfer">Transfer Funds</option>
                </select>
            </div>
            <div class="form-group">
                <label>Amount ($)</label>
                <input id="amount" type="number" value="5000" />
            </div>

            <h3 style="margin-top: 32px;">Policy Controls</h3>
            <div class="form-group">
                <label>Require human approval above ($)</label>
                <input id="approvalThreshold" type="number" value="1000" />
            </div>
        </div>

        <div class="panel">
            <h3>Execution Context (Identities)</h3>
            <div class="form-group">
                <label>Proposing Actor</label>
                <input value="ai-agent-v2" disabled style="opacity: 0.7;" />
            </div>
            <div class="form-group">
                <label>Responsible Role</label>
                <select id="responsible">
                    <option value="user-alice" selected>Alice (Admin)</option>
                    <option value="user-bob">Bob (Finance)</option>
                    <option value="user-charlie">Charlie (Auditor)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Accountable Role</label>
                <select id="accountable">
                    <option value="user-alice">Alice (Admin)</option>
                    <option value="user-bob">Bob (Finance)</option>
                    <option value="user-charlie">Charlie (Auditor)</option>
                </select>
            </div>
            <div class="form-group">
                <label>Approver Role</label>
                <select id="approved_by">
                    <option value="">-- None --</option>
                    <option value="user-alice">Alice (Admin)</option>
                    <option value="user-bob">Bob (Finance)</option>
                    <option value="user-charlie">Charlie (Auditor)</option>
                </select>
            </div>
        </div>
    </div>

    <button onclick="runValidation()" id="submitBtn">Evaluate Action</button>

    <div id="output">
        <h2 class="result-title" id="resTitle"></h2>
        <div class="result-summary" id="resSummary"></div>
        <pre class="result-reason" id="resReason"></pre>
        <div id="resTrace"></div>
    </div>
</div>

<script>
async function runValidation() {
    const btn = document.getElementById("submitBtn");
    btn.innerText = "Evaluating...";
    btn.disabled = true;

    try {
        const amount = parseFloat(document.getElementById("amount").value);
        const responsible = document.getElementById("responsible").value;
        const accountable = document.getElementById("accountable").value;
        const approved_by = document.getElementById("approved_by").value;
        const threshold = parseFloat(document.getElementById("approvalThreshold").value || 0);

        const policy = {
            contract_id: "demo-finance-policy",
            contract_version: "1.0.0",
            roles: { required: ["proposer", "responsible", "accountable"] },
            constraints: [
                { type: "separation_of_duties", roles: ["responsible", "accountable"] },
                { type: "approval_required", threshold: threshold }
            ]
        };

        const action = { type: "transfer", amount: amount };
        const context = {};
        if (responsible) context.responsible = responsible;
        if (accountable) context.accountable = accountable;
        if (approved_by) context.approved_by = approved_by;

        const res = await fetch("/validate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ policy, action, actor: "ai-agent-v2", context })
        });

        const data = await res.json();
        
        const outputDiv = document.getElementById("output");
        outputDiv.className = data.allowed ? "status-allowed" : "status-blocked";
        
        document.getElementById("resTitle").innerText = data.allowed ? "✅ ALLOWED" : "🚫 BLOCKED";
        document.getElementById("resSummary").innerHTML = `<strong>Action:</strong> ${data.summary}`;
        document.getElementById("resReason").innerText = data.reason;

        // Render the Execution Trace
        let traceHtml = `<h4 style="margin: 20px 0 8px 0; color: var(--text-muted); border-bottom: 1px solid var(--border); padding-bottom: 6px;">Execution Trace</h4><ul class="trace-list">`;
        data.decision_trace.forEach(stage => {
            const icon = stage.passed ? "✅" : "❌";
            const color = stage.passed ? "var(--text-muted)" : "var(--accent-red)";
            traceHtml += `<li style="color: ${color};">${icon} <span>${stage.stage}</span></li>`;
        });
        traceHtml += `</ul>`;
        document.getElementById("resTrace").innerHTML = traceHtml;

    } catch (err) {
        console.error(err);
        alert("Failed to connect to backend. Check console.");
    } finally {
        btn.innerText = "Evaluate Action";
        btn.disabled = false;
    }
}
</script>

</body>
</html>
"""