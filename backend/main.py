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
    version="3.0.0",
    description="Decide whether AI actions are allowed to execute — before they happen.",
)

# ---------------------------
# PATHS / REGISTRY
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

IDENTITY_PATH = Path(__file__).resolve().parent / "data" / "identities.json"

POLICY_REGISTRY = {
    "finance-core-v1": BASE_DIR / "finance-policy.json"
}


# ---------------------------
# IDENTITY
# ---------------------------

def load_identity_registry():
    with open(IDENTITY_PATH) as f:
        return json.load(f)


def normalize(v: Optional[str]) -> str:
    if not v:
        return ""
    return v.strip().lower().replace("_", "-")


def resolve_identity(value: Optional[str], registry):
    if not value:
        return None

    key = normalize(value)

    for k, v in registry["identities"].items():
        if key == k or key in [normalize(a) for a in v.get("aliases", [])]:
            return v["canonical_id"]

    return None


# ---------------------------
# STAGE EXTRACTION (CANONICAL)
# ---------------------------

def extract_decision_trace(result) -> List[Dict[str, Any]]:
    stage_results = getattr(result, "stage_results", [])
    trace = []

    for s in stage_results:
        trace.append({
            "stage": getattr(s, "stage_id", "unknown"),
            "status": "pass" if getattr(s, "passed", False) else "fail",
            "message": (getattr(s, "messages", []) or [""])[0]
        })

    return trace


def extract_reason(trace: List[Dict[str, Any]]) -> str:
    for s in trace:
        if s["status"] == "fail":
            return s["message"] or f"{s['stage']} failed"
    return "Allowed: policy conditions satisfied"


# ---------------------------
# CORE
# ---------------------------

def run_validation(payload: Dict[str, Any]):

    action = payload.get("action", {})
    actor = payload.get("actor", "ai-agent")
    policy_ref = payload.get("policy_ref", "finance-core-v1")
    context = payload.get("context", {})

    # ---------------------------
    # Resolve policy
    # ---------------------------

    if policy_ref not in POLICY_REGISTRY:
        return {
            "allowed": False,
            "reason": f"Unknown policy_ref: {policy_ref}",
            "resolved_identities": {},
            "decision_trace": []
        }

    policy_path = POLICY_REGISTRY[policy_ref]

    # ---------------------------
    # Resolve identities
    # ---------------------------

    registry = load_identity_registry()

    proposer = normalize(actor)
    responsible = resolve_identity(context.get("responsible"), registry)
    accountable = resolve_identity(context.get("accountable"), registry)
    approver = resolve_identity(context.get("approved_by"), registry)

    if not responsible or not accountable:
        return {
            "allowed": False,
            "reason": "Identity resolution failed",
            "resolved_identities": {
                "proposer": proposer,
                "responsible": responsible,
                "accountable": accountable,
                "approver": approver
            },
            "decision_trace": []
        }

    # ---------------------------
    # Compile policy
    # ---------------------------

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        compiled_path = Path(tmp.name)

    contract_path = compile_policy_file(policy_path, compiled_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    # ---------------------------
    # Required roles (safe default)
    # ---------------------------

    required_roles = compiled.get("roles", {}).get("required")
    if not required_roles:
        required_roles = ["proposer", "responsible", "accountable"]

    # ---------------------------
    # Contract binding
    # ---------------------------

    contract_hash = hashlib.sha256(
        json.dumps(compiled, sort_keys=True).encode()
    ).hexdigest()

    # ---------------------------
    # Build proposal
    # ---------------------------

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": proposer, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": "finance",
            "resource": "funds",
            "action": "transfer"
        },
        contract={
            "id": compiled["contract_id"],
            "version": compiled["contract_version"],
            "hash": contract_hash,
        },
        run_context={
            "identities": {
                "actors": [
                    {"id": proposer, "type": "agent", "role": "proposer"},
                    {"id": responsible, "type": "human", "role": "responsible"},
                    {"id": accountable, "type": "human", "role": "accountable"},
                ] + (
                    [{"id": approver, "type": "human", "role": "approver"}]
                    if approver else []
                ),
                "required_roles": required_roles,
                "conflict_flags": {},
            },
            "integrity": {
                "artifacts_present": True
            },
            "publication": {
                "ready": True
            }
        },
    )

    # ---------------------------
    # Evaluate
    # ---------------------------

    result = evaluate_proposal(proposal, compiled)

    allowed = getattr(result, "commit_allowed", False)

    decision_trace = extract_decision_trace(result)
    reason = extract_reason(decision_trace)

    return {
        "allowed": allowed,
        "reason": reason,
        "resolved_identities": {
            "proposer": proposer,
            "responsible": responsible,
            "accountable": accountable,
            "approver": approver
        },
        "decision_trace": decision_trace
    }


# ---------------------------
# API
# ---------------------------

@app.post("/validate")
async def validate(request: Request):
    body = await request.json()
    return JSONResponse(run_validation(body))


@app.get("/identities")
def identities():
    registry = load_identity_registry()

    return {
        "identities": [
            {
                "id": v["canonical_id"],
                "name": v.get("display_name", v["canonical_id"])
            }
            for v in registry["identities"].values()
        ]
    }


# ---------------------------
# UI (UNCHANGED VISUALLY, CONTRACT FIXED)
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def ui():
    return """
<!DOCTYPE html>
<html>
<head>
<title>Waveframe Guard | Sandbox</title>
<style>
body { background:#0f1115; color:white; font-family:Arial; padding:40px; }
.panel { background:#1a1d24; padding:20px; margin-bottom:20px; border-radius:8px; }
button { padding:12px; width:100%; background:white; border:none; cursor:pointer; }
.allowed { color:#2ea043; }
.blocked { color:#da3633; }
</style>
</head>
<body>

<h1>Waveframe Guard</h1>

<div class="panel">
<label>Responsible</label>
<select id="r">
<option value="user-alice">Alice</option>
<option value="user-bob">Bob</option>
</select>

<label>Accountable</label>
<select id="a">
<option value="user-alice">Alice</option>
<option value="user-bob">Bob</option>
</select>

<label>Approver</label>
<select id="p">
<option value="">None</option>
<option value="user-alice">Alice</option>
<option value="user-bob">Bob</option>
</select>

<button onclick="run()">Evaluate</button>
</div>

<div class="panel">
<h2 id="decision"></h2>
<p id="reason"></p>
<pre id="trace"></pre>
</div>

<script>
async function run() {
    const res = await fetch("/validate", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
            action:{type:"transfer", amount:5000},
            actor:"ai-agent-v2",
            policy_ref:"finance-core-v1",
            context:{
                responsible:r.value,
                accountable:a.value,
                approved_by:p.value
            }
        })
    });

    const d = await res.json();

    document.getElementById("decision").innerText =
        d.allowed ? "ALLOWED" : "BLOCKED";

    document.getElementById("decision").className =
        d.allowed ? "allowed" : "blocked";

    document.getElementById("reason").innerText = d.reason;

    document.getElementById("trace").innerText =
        JSON.stringify(d.decision_trace, null, 2);
}
</script>

</body>
</html>
"""