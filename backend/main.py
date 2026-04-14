from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


app = FastAPI(
    title="Waveframe Guard",
    version="2.1.0",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# PATHS
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = BASE_DIR / "finance-policy.json"
IDENTITY_PATH = Path(__file__).resolve().parent / "data" / "identities.json"


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


def resolve_identity(value: str, registry):
    key = normalize(value)

    for k, v in registry["identities"].items():
        if key == k or key in [normalize(a) for a in v.get("aliases", [])]:
            return v["canonical_id"]

    return None


# ---------------------------
# STAGE / REASON
# ---------------------------

def extract_stages(result):
    stages = getattr(result, "stage_results", [])
    out = []

    for s in stages:
        out.append({
            "stage": getattr(s, "stage_id", "unknown"),
            "passed": getattr(s, "passed", False),
            "messages": getattr(s, "messages", []),
        })

    return out


def extract_reason(stages):
    for s in stages:
        if not s["passed"]:
            msgs = " ".join(s.get("messages", [])).lower()

            if "separation" in msgs:
                return "Same person assigned to multiple required roles"

            if "required_roles" in msgs:
                return "Required roles not properly assigned"

            if "approval" in msgs:
                return "Approval missing"

            if msgs:
                return msgs

            return f"{s['stage']} failed"

    return "Policy conditions satisfied"


# ---------------------------
# CORE
# ---------------------------

def run_validation(action, actor, context):

    registry = load_identity_registry()

    r = resolve_identity(context.get("responsible"), registry)
    a = resolve_identity(context.get("accountable"), registry)
    p = resolve_identity(context.get("approved_by"), registry) if context.get("approved_by") else None

    if not r or not a:
        return {
            "allowed": False,
            "reason": "Identity resolution failed",
            "stages": [],
            "resolved": {}
        }

    # Compile policy
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        compiled_path = Path(tmp.name)

    contract_path = compile_policy_file(POLICY_PATH, compiled_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    # Fix required_roles (critical)
    required_roles = compiled.get("roles", {}).get("required")
    if not required_roles:
        required_roles = ["responsible", "accountable"]

    # Contract binding
    contract_hash = hashlib.sha256(
        json.dumps(compiled, sort_keys=True).encode()
    ).hexdigest()

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": normalize(actor), "type": "agent"},
        artifact_paths=[],
        mutation={"domain": "finance", "resource": "funds", "action": "transfer"},
        contract={
            "id": compiled["contract_id"],
            "version": compiled["contract_version"],
            "hash": contract_hash,
        },
        run_context={
            "identities": {
                "actors": [
                    {"id": normalize(actor), "type": "agent", "role": "proposer"},
                    {"id": r, "type": "human", "role": "responsible"},
                    {"id": a, "type": "human", "role": "accountable"},
                ] + (
                    [{"id": p, "type": "human", "role": "approver"}] if p else []
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

    result = evaluate_proposal(proposal, compiled)

    allowed = getattr(result, "commit_allowed", False)
    stages = extract_stages(result)
    reason = extract_reason(stages)

    return {
        "allowed": allowed,
        "reason": reason,
        "stages": stages,
        "resolved": {
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
    body = await request.json()

    return run_validation(
        action=body.get("action", {}),
        actor="ai-agent",
        context=body.get("context", {}),
    )


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
<html>
<head>
<title>Waveframe Guard</title>
<style>
body { background:#0e0e0e; color:white; font-family:Arial; padding:20px; }
.container { display:flex; gap:20px; }
.left { flex:3; }
.right { flex:1; background:#1a1a1a; padding:10px; }
.section { margin-bottom:20px; padding:15px; background:#151515; }
select, button { width:100%; padding:10px; margin-top:5px; }
button { background:orange; border:none; font-weight:bold; }
.allowed { color:lime; font-size:20px; }
.blocked { color:red; font-size:20px; }
.stage { margin-top:5px; padding:5px; background:#222; }
</style>
</head>

<body>

<h1>Waveframe Guard</h1>

<div class="container">

<div class="left">

<div class="section">
<h3>AI Action</h3>
Transfer $1 from Marketing → Operations
</div>

<div class="section">
<h3>Actors</h3>

<label>Responsible</label>
<select id="r"></select>

<label>Accountable</label>
<select id="a"></select>

<label>Approver</label>
<select id="p"></select>

<button onclick="run()">Evaluate</button>
</div>

<div class="section">
<h3>Decision</h3>
<div id="decision"></div>
<div id="reason"></div>
</div>

<div class="section">
<h3>Execution Stages</h3>
<div id="stages"></div>
</div>

</div>

<div class="right">
<h3>Resolved Identities</h3>
<div id="identitiesPanel"></div>
</div>

</div>

<script>

async function load() {
    const res = await fetch("/identities");
    const data = await res.json();

    ["r","a","p"].forEach(id => {
        const el = document.getElementById(id);
        el.innerHTML = "<option value=''>Select</option>";

        data.identities.forEach(i => {
            el.innerHTML += `<option value="${i.id}">${i.name}</option>`;
        });
    });
}

async function run() {

    const res = await fetch("/validate", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
            action:{type:"transfer", amount:1},
            context:{
                responsible: r.value,
                accountable: a.value,
                approved_by: p.value
            }
        })
    });

    const d = await res.json();

    document.getElementById("decision").innerHTML =
        `<div class="${d.allowed ? "allowed" : "blocked"}">
            ${d.allowed ? "ALLOWED" : "BLOCKED"}
        </div>`;

    document.getElementById("reason").innerText = d.reason;

    document.getElementById("stages").innerHTML =
        d.stages.map(s =>
            `<div class="stage">
                ${s.stage} → ${s.passed ? "PASS" : "FAIL"}
                <br/>${(s.messages || []).join(", ")}
            </div>`
        ).join("");

    document.getElementById("identitiesPanel").innerHTML =
        Object.entries(d.resolved).map(([k,v]) =>
            `<div>${k}: ${v || "None"}</div>`
        ).join("");
}

load();

</script>

</body>
</html>
"""