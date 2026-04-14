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
    version="1.4.0",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# Paths
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent.parent  # <-- IMPORTANT FIX
POLICY_PATH = BASE_DIR / "finance-policy.json"

IDENTITY_PATH = Path(__file__).resolve().parent / "data" / "identities.json"


# ---------------------------
# Identity Resolver
# ---------------------------

def load_identity_registry() -> Dict[str, Any]:
    if not IDENTITY_PATH.exists():
        raise FileNotFoundError(f"Identity registry not found: {IDENTITY_PATH}")

    with open(IDENTITY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_lookup_key(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.strip().lower().replace("_", "-")


def resolve_identity(raw_value: Optional[str], registry: Dict[str, Any]) -> Dict[str, Any]:
    lookup = normalize_lookup_key(raw_value)

    identities = registry.get("identities", {})

    if lookup in identities:
        record = identities[lookup]
        return {"found": True, "canonical_id": record["canonical_id"]}

    for record in identities.values():
        if lookup in [normalize_lookup_key(a) for a in record.get("aliases", [])]:
            return {"found": True, "canonical_id": record["canonical_id"]}

    return {"found": False}


def resolve_context(context: Dict[str, Any]):
    registry = load_identity_registry()

    r = resolve_identity(context.get("responsible"), registry)
    a = resolve_identity(context.get("accountable"), registry)

    if not r["found"]:
        return False, None, "Blocked: responsible not found"
    if not a["found"]:
        return False, None, "Blocked: accountable not found"

    ap = None
    if context.get("approved_by"):
        ap = resolve_identity(context["approved_by"], registry)
        if not ap["found"]:
            return False, None, "Blocked: approver not found"

    return True, {
        "responsible": r["canonical_id"],
        "accountable": a["canonical_id"],
        "approved_by": ap["canonical_id"] if ap else None,
    }, None


# ---------------------------
# Helpers
# ---------------------------

def summarize(action: Dict[str, Any]) -> str:
    return f"AI attempted to transfer ${action.get('amount', 0):,.0f}"


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    return {"domain": "finance", "resource": "funds", "action": "transfer"}


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
        return "Blocked: same individual assigned to multiple required roles"

    if "approval" in combined:
        return "Blocked: approval required but not provided"

    if "required role" in combined:
        return "Blocked: required roles not properly assigned"

    # fallback — but still useful
    if messages:
        return "Blocked: " + messages[0]

    return "Blocked: policy conditions not satisfied"


def extract_result(result: Any):
    allowed = getattr(result, "commit_allowed", False)

    if allowed:
        return True, "Allowed: policy conditions satisfied"

    return False, interpret_reason(result)


def build_contract_binding(compiled: Dict[str, Any]) -> Dict[str, Any]:
    h = hashlib.sha256(json.dumps(compiled, sort_keys=True).encode()).hexdigest()

    return {
        "id": compiled["contract_id"],
        "version": compiled["contract_version"],
        "hash": h,
    }


# ---------------------------
# CORE PIPELINE (FIXED)
# ---------------------------

def run_validation(action: Dict, actor: str, context: Dict):

    ok, resolved, error = resolve_context(context)

    if not ok:
        return {"allowed": False, "reason": error, "summary": summarize(action)}

    # 🔥 LOAD REAL POLICY FILE (THIS FIXES YOUR BUG)
    with open(POLICY_PATH, "r") as f:
        policy = json.load(f)

    # Compile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = Path(tmp.name)

    contract_path = compile_policy_file(POLICY_PATH, output_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    contract = build_contract_binding(compiled)

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": normalize_lookup_key(actor), "type": "agent"},
        artifact_paths=[],
        mutation=normalize_mutation(action),
        contract=contract,
        run_context={
            "identities": {
                "actors": [
                    {"id": normalize_lookup_key(actor), "type": "agent", "role": "proposer"},
                    {"id": resolved["responsible"], "type": "human", "role": "responsible"},
                    {"id": resolved["accountable"], "type": "human", "role": "accountable"},
                ],
                "required_roles": compiled.get("roles", {}).get("required", []),
                "conflict_flags": {},
            }
        },
    )

    result = evaluate_proposal(proposal, compiled)
    allowed, reason = extract_result(result)

    return {
        "allowed": allowed,
        "reason": reason,
        "summary": summarize(action),
    }


# ---------------------------
# API
# ---------------------------

@app.post("/validate")
async def validate(request: Request):
    body = await request.json()

    return JSONResponse(
        run_validation(
            action=body["action"],
            actor=body.get("actor", "ai-agent"),
            context=body.get("context", {}),
        )
    )


@app.get("/identities")
def identities():
    registry = load_identity_registry()

    return {
        "identities": [
            {
                "id": v["canonical_id"],
                "name": v.get("display_name", v["canonical_id"]),
            }
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
    <body style="background:#111;color:white;font-family:Arial;padding:40px;">

    <h2>Waveframe Guard</h2>

    <label>Responsible</label><br/>
    <select id="r"></select><br/>

    <label>Accountable</label><br/>
    <select id="a"></select><br/>

    <label>Approver</label><br/>
    <select id="p"></select><br/><br/>

    <button onclick="run()">Check</button>

    <pre id="out"></pre>

    <script>
    async function load(){
        const res = await fetch("/identities");
        const data = await res.json();

        ["r","a","p"].forEach(id=>{
            const el = document.getElementById(id);
            el.innerHTML = "<option value=''>Select</option>";
            data.identities.forEach(i=>{
                el.innerHTML += `<option value="${i.id}">${i.name}</option>`;
            });
        });
    }

    async function run(){
        const res = await fetch("/validate",{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body: JSON.stringify({
                action:{type:"transfer",amount:1},
                context:{
                    responsible: r.value,
                    accountable: a.value,
                    approved_by: p.value
                }
            })
        });

        const d = await res.json();

        out.textContent =
            (d.allowed?"ALLOWED":"BLOCKED") +
            "\\n" + d.summary +
            "\\n" + d.reason;
    }

    load();
    </script>

    </body>
    </html>
    """