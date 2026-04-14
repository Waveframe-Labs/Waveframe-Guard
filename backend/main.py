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
# Identity Resolver
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent
IDENTITY_PATH = BASE_DIR / "data" / "identities.json"


def load_identity_registry() -> Dict[str, Any]:
    if not IDENTITY_PATH.exists():
        raise FileNotFoundError(f"Identity registry not found: {IDENTITY_PATH}")

    with open(IDENTITY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Identity registry must be a JSON object")

    return data


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
        aliases = [normalize_lookup_key(a) for a in record.get("aliases", [])]
        if lookup in aliases:
            return {"found": True, "canonical_id": record["canonical_id"]}

    return {"found": False}


def resolve_context_identities(context: Dict[str, Any]):
    registry = load_identity_registry()

    r = resolve_identity(context.get("responsible"), registry)
    a = resolve_identity(context.get("accountable"), registry)
    ap = resolve_identity(context.get("approved_by"), registry) if context.get("approved_by") else None

    if not r["found"]:
        return False, None, "Blocked: responsible actor could not be resolved"
    if not a["found"]:
        return False, None, "Blocked: accountable actor could not be resolved"
    if context.get("approved_by") and not ap["found"]:
        return False, None, "Blocked: approver actor could not be resolved"

    return True, {
        "responsible": r["canonical_id"],
        "accountable": a["canonical_id"],
        "approved_by": ap["canonical_id"] if ap else None,
    }, None


# ---------------------------
# Helpers
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    if action["type"] == "transfer":
        return f"AI attempted to transfer ${action['amount']:,.0f}"
    return "AI attempted action"


def build_contract_binding(compiled_contract: Dict[str, Any]) -> Dict[str, Any]:
    contract_json = json.dumps(compiled_contract, sort_keys=True).encode()
    return {
        "id": compiled_contract.get("contract_id", "user-policy"),
        "version": compiled_contract.get("contract_version", "1.0.0"),
        "hash": hashlib.sha256(contract_json).hexdigest(),
    }


def extract_result(result: Any):
    allowed = getattr(result, "commit_allowed", False)
    if allowed:
        return True, "Allowed"
    return False, "Blocked"


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    return {"domain": "finance", "resource": "funds", "action": "transfer"}


# ---------------------------
# Core pipeline
# ---------------------------

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict):
    ok, resolved, error = resolve_context_identities(context)

    if not ok:
        return {"allowed": False, "reason": error, "summary": summarize_action(action)}

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
        json.dump(policy, f)
        policy_path = Path(f.name)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = Path(tmp.name)

    contract_path = compile_policy_file(policy_path, output_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": actor, "type": "agent"},
        artifact_paths=[],
        mutation=normalize_mutation(action),
        contract=build_contract_binding(compiled),
        run_context={
            "identities": {
                "actors": [
                    {"id": actor, "type": "agent", "role": "proposer"},
                    {"id": resolved["responsible"], "type": "human", "role": "responsible"},
                    {"id": resolved["accountable"], "type": "human", "role": "accountable"},
                ]
            }
        },
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
    return JSONResponse(run_validation(
        body["policy"],
        body["action"],
        body.get("actor", "ai-agent"),
        body.get("context", {})
    ))


@app.get("/identities")
def get_identities():
    registry = load_identity_registry()
    return {
        "identities": [
            {
                "id": i["canonical_id"],
                "name": i.get("display_name", i["canonical_id"]),
            }
            for i in registry.get("identities", {}).values()
        ]
    }


# ---------------------------
# UI (single source of truth)
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def ui():
    return """
    <html>
    <body style="font-family: Arial; padding: 40px; background: #111; color: white;">
        <h2>Waveframe Guard</h2>

        <label>Responsible</label><br>
        <select id="r"></select><br><br>

        <label>Accountable</label><br>
        <select id="a"></select><br><br>

        <button onclick="run()">Check</button>

        <pre id="out"></pre>

        <script>
            async function load() {
                const res = await fetch("/identities");
                const data = await res.json();

                ["r","a"].forEach(id => {
                    const el = document.getElementById(id);
                    data.identities.forEach(i => {
                        const o = document.createElement("option");
                        o.value = i.id;
                        o.textContent = i.name;
                        el.appendChild(o);
                    });
                });
            }

            async function run() {
                const res = await fetch("/validate", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                        policy: { roles: { required: ["responsible","accountable"] }},
                        action: { type: "transfer", amount: 1 },
                        context: {
                            responsible: document.getElementById("r").value,
                            accountable: document.getElementById("a").value
                        }
                    })
                });

                const data = await res.json();
                document.getElementById("out").textContent =
                    (data.allowed ? "ALLOWED" : "BLOCKED") + "\\n" + data.reason;
            }

            load();
        </script>
    </body>
    </html>
    """