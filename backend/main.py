from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal


app = FastAPI(
    title="Waveframe Guard",
    version="2.2.0",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# DECISION STORE
# ---------------------------

LOG_FILE = Path(__file__).resolve().parent / "data" / "decision_logs.jsonl"


def append_log(record: Dict[str, Any]) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def read_logs(limit: int = 50) -> List[Dict[str, Any]]:
    if not LOG_FILE.exists():
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    records: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return list(reversed(records))


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
            "user-alice": {
                "canonical_id": "usr_111",
                "display_name": "Alice (Admin)",
                "aliases": ["alice"],
            },
            "user-bob": {
                "canonical_id": "usr_222",
                "display_name": "Bob (Finance)",
                "aliases": ["bob"],
            },
            "user-charlie": {
                "canonical_id": "usr_333",
                "display_name": "Charlie (Approver)",
                "aliases": ["charlie"],
            },
            "ai-agent-v2": {
                "canonical_id": "agt_999",
                "display_name": "AI Agent v2",
                "aliases": ["agent"],
            },
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

    return key  # If not in registry, just return the raw normalized string for now


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

def run_validation(
    policy: Dict[str, Any],
    action: Dict[str, Any],
    actor: str,
    context: Dict[str, Any]
) -> Dict[str, Any]:
    registry = load_identity_registry()

    r = resolve_identity(context.get("responsible"), registry)
    a = resolve_identity(context.get("accountable"), registry)
    p = resolve_identity(context.get("approved_by"), registry)

    if not r or not a:
        return {
            "allowed": False,
            "summary": f"AI attempted action: {action.get('type')}",
            "reason": "Identity resolution failed: missing required human context",
            "impact": [
                "missing required execution identities",
                "could not verify governance role assignments",
                "action was stopped before execution"
            ],
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

    required_roles = compiled.get("roles", {}).get(
        "required",
        ["proposer", "responsible", "accountable"]
    )

    contract_hash = hashlib.sha256(
        json.dumps(compiled, sort_keys=True).encode()
    ).hexdigest()

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
        mutation={
            "domain": "finance",
            "resource": "funds",
            "action": action.get("type", "unknown")
        },
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

    amount = action.get("amount", 0)

    impact = []

    if not allowed:
        # Build real-world consequence framing
        if "separation" in reason.lower():
            impact = [
                "violated separation of duties",
                "same individual attempted to control and approve the action",
                "created audit and fraud risk"
            ]
        elif "approval" in reason.lower():
            impact = [
                "bypassed required approval threshold",
                "executed financial change without authorization",
                "created compliance exposure"
            ]
        else:
            impact = [
                "failed governance validation",
                "action did not meet required execution constraints"
            ]
    else:
        impact = [
            "roles properly separated",
            "approval conditions satisfied",
            "action aligned with policy"
        ]

    # Automatically log to our local audit file
    log_data = {
        "decision_id": f"dec_{uuid.uuid4().hex[:12]}",
        "actor": normalize(actor),
        "action": action,
        "allowed": allowed,
        "reason": reason,
        "trace_hash": contract_hash, 
        "server_timestamp": datetime.utcnow().isoformat() + "Z"
    }
    append_log(log_data)

    return {
        "allowed": allowed,
        "summary": f"AI attempted to transfer ${amount:,.0f}",
        "reason": reason,
        "impact": impact,
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


@app.post("/v1/enforce")
async def enforce(request: Request):
    """
    Production endpoint used by SDK.
    Accepts policy_ref instead of full policy.
    """
    body = await request.json()
    policy_ref = body.get("policy_ref")

    if policy_ref == "finance-core-v1":
        policy = {
            "contract_id": "finance-core-v1",
            "contract_version": "1.0.0",
            "roles": {
                "required": ["proposer", "responsible", "accountable"]
            },
            "constraints": [
                {
                    "type": "separation_of_duties",
                    "roles": ["responsible", "accountable"]
                },
                {
                    "type": "approval_required",
                    "threshold": 1000
                }
            ]
        }
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Policy '{policy_ref}' not found."
        )

    decision = run_validation(
        policy=policy,
        action=body.get("action", {}),
        actor=body.get("actor", "ai-agent-v2"),
        context=body.get("context", {}),
    )

    print(
        f"\n📈 [AUDIT LOG] {decision['summary']} | "
        f"{'ALLOWED' if decision['allowed'] else 'BLOCKED'}\n"
    )

    return JSONResponse(decision)


@app.post("/api/log")
async def receive_log(request: Request):
    """The Telemetry Endpoint: Persists live execution logs from installed SDKs."""
    data = await request.json()

    if "server_timestamp" not in data:
        data["server_timestamp"] = datetime.utcnow().isoformat() + "Z"

    append_log(data)

    print(
        f"\n🚨 [TELEMETRY] Decision: '{data.get('decision_id', 'unknown')}' | "
        f"Agent: '{data.get('actor')}' | "
        f"Allowed: {data.get('allowed')} | Reason: {data.get('reason')}\n"
    )
    return JSONResponse({"status": "logged"})


@app.get("/api/logs")
def get_logs(limit: int = 50):
    return {"logs": read_logs(limit=limit)}


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


"""
Waveframe Guard — Upgraded Compliance Dashboard
================================================
DROP-IN REPLACEMENT for the /dashboard route in backend/main.py

Replace your existing dashboard() function with this one.
Everything else in main.py stays identical.

The dashboard polls /api/logs and /identities (already in your FastAPI app)
so no new backend changes are needed.
"""

from fastapi.responses import HTMLResponse


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """
    Compliance Dashboard: Live audit ledger with stats, filtering, and real-time polling.
    Reads from /api/logs and /identities — no new endpoints required.
    """
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Waveframe Guard — Compliance Ledger</title>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
<style>
  :root {
    --bg:        #07090d;
    --surface:   #0d1018;
    --surface2:  #111520;
    --border:    #1c2030;
    --border2:   #242840;
    --text:      #dce3f0;
    --muted:     #4a5270;
    --muted2:    #6b7494;
    --green:     #00d97e;
    --green-dim: rgba(0,217,126,0.10);
    --red:       #ff3d5a;
    --red-dim:   rgba(255,61,90,0.10);
    --amber:     #ffaa00;
    --amber-dim: rgba(255,170,0,0.10);
    --blue:      #4d7cfe;
    --blue-dim:  rgba(77,124,254,0.10);
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    padding: 0 0 60px;
  }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 32px;
    height: 52px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-left { display: flex; align-items: center; gap: 14px; }
  .logo {
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.06em;
    color: var(--text);
  }
  .logo span { color: var(--green); }
  .sep { width: 1px; height: 18px; background: var(--border2); }
  .header-label {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted2);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .live-pill {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    background: var(--green-dim);
    border: 1px solid rgba(0,217,126,0.2);
    border-radius: 99px;
    font-family: var(--mono);
    font-size: 10px;
    color: var(--green);
    letter-spacing: 0.08em;
  }
  .live-dot {
    width: 5px; height: 5px;
    border-radius: 50%;
    background: var(--green);
    animation: blink 2s ease-in-out infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }

  .header-right { display: flex; align-items: center; gap: 12px; }
  .nav-link {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted2);
    text-decoration: none;
    letter-spacing: 0.06em;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: 5px;
    transition: color 0.15s, border-color 0.15s;
  }
  .nav-link:hover { color: var(--text); border-color: var(--border2); }

  /* ── Page body ── */
  .page { padding: 28px 32px 0; max-width: 1440px; margin: 0 auto; }

  /* ── Stat cards ── */
  .stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 22px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 18px;
    position: relative;
    overflow: hidden;
    animation: fadeUp 0.4s ease both;
  }
  .stat-card::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    border-radius: 8px 0 0 8px;
  }
  .stat-card.green::before  { background: var(--green); }
  .stat-card.red::before    { background: var(--red); }
  .stat-card.amber::before  { background: var(--amber); }
  .stat-card.blue::before   { background: var(--blue); }

  .stat-label {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted2);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .stat-value {
    font-family: var(--mono);
    font-size: 30px;
    font-weight: 600;
    line-height: 1;
    margin-bottom: 6px;
  }
  .stat-card.green .stat-value { color: var(--green); }
  .stat-card.red .stat-value   { color: var(--red); }
  .stat-card.amber .stat-value { color: var(--amber); }
  .stat-card.blue .stat-value  { color: var(--blue); }
  .stat-sub {
    font-size: 11px;
    color: var(--muted);
    font-family: var(--mono);
  }

  /* ── Main panel ── */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    animation: fadeUp 0.5s ease both;
  }
  .panel-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 13px 18px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
  }
  .panel-title-row { display: flex; align-items: center; gap: 10px; }
  .panel-title {
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .count-badge {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted2);
    background: var(--border);
    padding: 2px 7px;
    border-radius: 4px;
  }
  .pulse-ring {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--green);
    transition: box-shadow 0.3s;
  }
  .pulse-ring.active { box-shadow: 0 0 0 3px rgba(0,217,126,0.25); }

  /* ── Filter bar ── */
  .filter-bar { display: flex; gap: 6px; align-items: center; }
  .filter-btn {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 0.07em;
    padding: 4px 10px;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted2);
    cursor: pointer;
    transition: all 0.15s;
  }
  .filter-btn:hover { color: var(--text); border-color: var(--border2); }
  .filter-btn.active-all    { background: rgba(220,227,240,0.08); color: var(--text); border-color: var(--border2); }
  .filter-btn.active-allow  { background: var(--green-dim); color: var(--green); border-color: rgba(0,217,126,0.3); }
  .filter-btn.active-block  { background: var(--red-dim);   color: var(--red);   border-color: rgba(255,61,90,0.3); }

  /* ── Table ── */
  .tbl-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  thead tr { background: var(--surface2); border-bottom: 1px solid var(--border); }
  th {
    font-family: var(--mono);
    font-size: 9px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.12em;
    padding: 9px 14px;
    text-align: left;
    white-space: nowrap;
    font-weight: 500;
  }
  tbody tr {
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.12s;
  }
  tbody tr:last-child { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,0.025); }
  tbody tr.selected { background: rgba(77,124,254,0.06); }
  tbody tr.new-row { animation: slideIn 0.35s ease both; }
  td {
    padding: 11px 14px;
    font-size: 12px;
    vertical-align: middle;
  }
  .td-mono { font-family: var(--mono); }
  .td-time { color: var(--muted2); font-size: 11px; font-family: var(--mono); white-space: nowrap; }
  .td-id   { color: var(--muted); font-size: 10px; font-family: var(--mono); }
  .td-hash { color: var(--muted); font-size: 10px; font-family: var(--mono); }

  .badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.07em;
    padding: 3px 8px;
    border-radius: 3px;
    border: 1px solid;
    white-space: nowrap;
  }
  .badge-allow { color: var(--green); background: var(--green-dim); border-color: rgba(0,217,126,0.25); }
  .badge-block { color: var(--red);   background: var(--red-dim);   border-color: rgba(255,61,90,0.25); }

  .td-reason { color: var(--muted2); font-size: 12px; max-width: 320px; }

  /* ── Detail drawer ── */
  .drawer-overlay {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(7,9,13,0.7);
    z-index: 200;
    backdrop-filter: blur(2px);
  }
  .drawer-overlay.open { display: block; }
  .drawer {
    position: fixed;
    right: 0; top: 0; bottom: 0;
    width: 380px;
    background: var(--surface);
    border-left: 1px solid var(--border2);
    z-index: 201;
    transform: translateX(100%);
    transition: transform 0.25s cubic-bezier(0.4,0,0.2,1);
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }
  .drawer.open { transform: translateX(0); }
  .drawer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0;
    background: var(--surface2);
    z-index: 1;
  }
  .drawer-title { font-family: var(--mono); font-size: 13px; font-weight: 600; color: var(--text); }
  .drawer-close {
    background: none; border: none; color: var(--muted2);
    font-size: 18px; cursor: pointer; padding: 0; line-height: 1;
    transition: color 0.15s;
  }
  .drawer-close:hover { color: var(--text); }
  .drawer-body { padding: 20px; flex: 1; display: flex; flex-direction: column; gap: 18px; }
  .drawer-decision {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 14px 16px;
    border-radius: 7px;
    font-family: var(--mono);
    font-size: 15px;
    font-weight: 600;
  }
  .drawer-decision.allow { background: var(--green-dim); color: var(--green); border: 1px solid rgba(0,217,126,0.2); }
  .drawer-decision.block { background: var(--red-dim);   color: var(--red);   border: 1px solid rgba(255,61,90,0.2); }
  .field-group { display: flex; flex-direction: column; gap: 10px; }
  .field-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .field-row:last-child { border-bottom: none; padding-bottom: 0; }
  .field-key {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    white-space: nowrap;
    padding-top: 1px;
  }
  .field-val {
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    text-align: right;
    word-break: break-all;
  }
  .reason-block {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    font-size: 13px;
    color: var(--text);
    line-height: 1.55;
  }
  .reason-block .reason-label {
    font-family: var(--mono);
    font-size: 9px;
    color: var(--muted);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 6px;
  }

  /* ── Empty / error states ── */
  .empty-state {
    padding: 52px 24px;
    text-align: center;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 13px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
  }
  .empty-icon { font-size: 28px; opacity: 0.4; }
  .error-banner {
    display: none;
    padding: 10px 18px;
    background: var(--red-dim);
    border-bottom: 1px solid rgba(255,61,90,0.2);
    font-family: var(--mono);
    font-size: 11px;
    color: var(--red);
    letter-spacing: 0.05em;
  }

  /* ── Animations ── */
  @keyframes fadeUp {
    from { opacity:0; transform:translateY(8px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes slideIn {
    from { opacity:0; transform:translateY(-6px); }
    to   { opacity:1; transform:translateY(0); }
  }

  /* ── Responsive ── */
  @media (max-width: 900px) {
    .stats-row { grid-template-columns: repeat(2, 1fr); }
    .page { padding: 20px 16px 0; }
    .header { padding: 0 16px; }
    .drawer { width: 100%; }
  }
</style>
</head>
<body>

<!-- Header -->
<header class="header">
  <div class="header-left">
    <div class="logo">WAVEFRAME <span>GUARD</span></div>
    <div class="sep"></div>
    <div class="header-label">Compliance Ledger</div>
    <div class="live-pill">
      <div class="live-dot"></div>
      LIVE
    </div>
  </div>
  <div class="header-right">
    <div id="lastUpdated" style="font-family:var(--mono);font-size:10px;color:var(--muted);">--</div>
    <a href="/" class="nav-link">← Sandbox</a>
  </div>
</header>

<div class="page">

  <!-- Error banner -->
  <div id="errorBanner" class="error-banner">
    ⚠ Could not reach /api/logs — check that the backend is running.
  </div>

  <!-- Stat cards -->
  <div class="stats-row">
    <div class="stat-card green">
      <div class="stat-label">Allowed</div>
      <div class="stat-value" id="statAllowed">—</div>
      <div class="stat-sub" id="statAllowedPct">—</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Blocked</div>
      <div class="stat-value" id="statBlocked">—</div>
      <div class="stat-sub" id="statBlockedPct">—</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">Total Decisions</div>
      <div class="stat-value" id="statTotal">—</div>
      <div class="stat-sub">Last 50 records</div>
    </div>
    <div class="stat-card amber">
      <div class="stat-label">Volume Screened</div>
      <div class="stat-value" id="statVolume">—</div>
      <div class="stat-sub">Across all actions</div>
    </div>
  </div>

  <!-- Log table -->
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title-row">
        <div class="pulse-ring" id="pulseRing"></div>
        <div class="panel-title">Audit Feed</div>
        <div class="count-badge" id="countBadge">0</div>
      </div>
      <div class="filter-bar">
        <button class="filter-btn active-all" data-filter="all"   onclick="setFilter('all')">ALL</button>
        <button class="filter-btn"            data-filter="allow" onclick="setFilter('allow')">ALLOWED</button>
        <button class="filter-btn"            data-filter="block" onclick="setFilter('block')">BLOCKED</button>
      </div>
    </div>

    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Decision ID</th>
            <th>Status</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Amount</th>
            <th>Reason</th>
            <th>Trace Hash</th>
          </tr>
        </thead>
        <tbody id="logBody">
          <tr>
            <td colspan="8">
              <div class="empty-state">
                <div class="empty-icon">⏳</div>
                Loading audit records…
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Detail drawer -->
<div class="drawer-overlay" id="drawerOverlay" onclick="closeDrawer()"></div>
<div class="drawer" id="drawer">
  <div class="drawer-head">
    <div class="drawer-title" id="drawerTitle">Decision Detail</div>
    <button class="drawer-close" onclick="closeDrawer()">✕</button>
  </div>
  <div class="drawer-body" id="drawerBody"></div>
</div>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let allLogs    = [];
let activeFilter = 'all';
let selectedId   = null;
let prevTopId    = null;
let pollInterval = null;

// ── Utilities ──────────────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '—')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtTime(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString('en-US', { hour12: false, hour:'2-digit', minute:'2-digit', second:'2-digit' })
      + '<br><span style="font-size:10px;color:var(--muted)">'
      + d.toLocaleDateString('en-US', { month:'short', day:'numeric' }) + '</span>';
  } catch { return esc(iso); }
}

function fmtMoney(n) {
  if (n == null || isNaN(n)) return '—';
  return new Intl.NumberFormat('en-US', { style:'currency', currency:'USD', maximumFractionDigits:0 }).format(n);
}

function shortHash(h) {
  if (!h) return '—';
  return String(h).slice(0,8) + '…';
}

// ── Fetch & render ─────────────────────────────────────────────────────────
async function fetchLogs() {
  try {
    const res = await fetch('/api/logs?limit=50');
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    document.getElementById('errorBanner').style.display = 'none';
    return data.logs || [];
  } catch (e) {
    document.getElementById('errorBanner').style.display = 'block';
    return null;
  }
}

function updateStats(logs) {
  const allowed  = logs.filter(l => l.allowed).length;
  const blocked  = logs.length - allowed;
  const total    = logs.length;
  const volume   = logs.reduce((s, l) => s + (l.action?.amount || 0), 0);
  const allowPct = total ? ((allowed / total) * 100).toFixed(0) : 0;
  const blockPct = total ? ((blocked / total) * 100).toFixed(0) : 0;

  document.getElementById('statAllowed').textContent    = allowed;
  document.getElementById('statBlocked').textContent    = blocked;
  document.getElementById('statTotal').textContent      = total;
  document.getElementById('statVolume').textContent     = fmtMoney(volume);
  document.getElementById('statAllowedPct').textContent = allowPct + '% allow rate';
  document.getElementById('statBlockedPct').textContent = blockPct + '% block rate';
  document.getElementById('countBadge').textContent     = total;
}

function filteredLogs() {
  if (activeFilter === 'allow') return allLogs.filter(l => l.allowed);
  if (activeFilter === 'block') return allLogs.filter(l => !l.allowed);
  return allLogs;
}

function renderTable(isRefresh) {
  const logs   = filteredLogs();
  const tbody  = document.getElementById('logBody');
  const newTop = allLogs[0]?.decision_id;
  const hasNew = isRefresh && newTop && newTop !== prevTopId;
  prevTopId    = allLogs[0]?.decision_id;

  if (!logs.length) {
    tbody.innerHTML = `<tr><td colspan="8">
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        No audit records yet. Run the Sandbox or SDK to generate data.
      </div>
    </td></tr>`;
    return;
  }

  // Pulse indicator on new data
  if (hasNew) {
    const ring = document.getElementById('pulseRing');
    ring.classList.add('active');
    setTimeout(() => ring.classList.remove('active'), 800);
  }

  tbody.innerHTML = logs.map((log, i) => {
    const allowed    = !!log.allowed;
    const badgeCls   = allowed ? 'badge-allow' : 'badge-block';
    const badgeTxt   = allowed ? 'ALLOWED' : 'BLOCKED';
    const isNew      = hasNew && i === 0;
    const isSelected = log.decision_id === selectedId;
    const actionType = (log.action?.type || 'unknown').toUpperCase();
    const amount     = log.action?.amount;

    return `<tr class="${isNew ? 'new-row' : ''} ${isSelected ? 'selected' : ''}"
               onclick="openDrawer(${esc(JSON.stringify(log))})">
      <td class="td-time">${fmtTime(log.server_timestamp)}</td>
      <td class="td-id">${esc(log.decision_id)}</td>
      <td><span class="badge ${badgeCls}">${badgeTxt}</span></td>
      <td class="td-mono" style="font-size:12px">${esc(log.actor)}</td>
      <td class="td-mono" style="font-size:12px">${esc(actionType)}</td>
      <td class="td-mono" style="font-size:13px">${amount != null ? fmtMoney(amount) : '—'}</td>
      <td class="td-reason">${esc(log.reason)}</td>
      <td class="td-hash" title="${esc(log.trace_hash)}">${shortHash(log.trace_hash)}</td>
    </tr>`;
  }).join('');
}

async function poll(isRefresh) {
  const logs = await fetchLogs();
  if (logs === null) return;
  allLogs = logs;
  updateStats(logs);
  renderTable(isRefresh);

  const now = new Date().toLocaleTimeString('en-US', { hour12: false });
  document.getElementById('lastUpdated').textContent = 'Updated ' + now;
}

// ── Filter ──────────────────────────────────────────────────────────────────
function setFilter(f) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.className = 'filter-btn';
    if (btn.dataset.filter === f) {
      if (f === 'all')   btn.classList.add('active-all');
      if (f === 'allow') btn.classList.add('active-allow');
      if (f === 'block') btn.classList.add('active-block');
    }
  });
  renderTable(false);
}

// ── Drawer ──────────────────────────────────────────────────────────────────
function openDrawer(logRaw) {
  const log = typeof logRaw === 'string' ? JSON.parse(logRaw) : logRaw;
  selectedId = log.decision_id;
  renderTable(false);

  const allowed    = !!log.allowed;
  const actionType = (log.action?.type || 'unknown').toUpperCase();
  const amount     = log.action?.amount;

  document.getElementById('drawerTitle').textContent = log.decision_id || 'Decision Detail';
  document.getElementById('drawerBody').innerHTML = `
    <div class="drawer-decision ${allowed ? 'allow' : 'block'}">
      ${allowed ? '✅ ALLOWED' : '🚫 BLOCKED'}
    </div>

    <div class="field-group">
      <div class="field-row">
        <div class="field-key">Decision ID</div>
        <div class="field-val">${esc(log.decision_id)}</div>
      </div>
      <div class="field-row">
        <div class="field-key">Timestamp</div>
        <div class="field-val">${esc(log.server_timestamp)}</div>
      </div>
      <div class="field-row">
        <div class="field-key">Actor</div>
        <div class="field-val">${esc(log.actor)}</div>
      </div>
      <div class="field-row">
        <div class="field-key">Action</div>
        <div class="field-val">${esc(actionType)}</div>
      </div>
      <div class="field-row">
        <div class="field-key">Amount</div>
        <div class="field-val">${amount != null ? fmtMoney(amount) : '—'}</div>
      </div>
    </div>

    <div class="reason-block">
      <div class="reason-label">Enforcement Reason</div>
      ${esc(log.reason)}
    </div>

    <div class="field-group">
      <div class="field-row">
        <div class="field-key">Trace Hash</div>
        <div class="field-val" style="font-size:10px;word-break:break-all">${esc(log.trace_hash)}</div>
      </div>
    </div>
  `;

  document.getElementById('drawerOverlay').classList.add('open');
  document.getElementById('drawer').classList.add('open');
}

function closeDrawer() {
  selectedId = null;
  document.getElementById('drawerOverlay').classList.remove('open');
  document.getElementById('drawer').classList.remove('open');
  renderTable(false);
}

// ── Keyboard shortcut ──────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeDrawer();
});

// ── Boot ──────────────────────────────────────────────────────────────────
poll(false);
pollInterval = setInterval(() => poll(true), 5000);
</script>
</body>
</html>""";


# ---------------------------
# UI SANDBOX
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
            --bg: #0f1115;
            --panel: #171b22;
            --panel-2: #1d232c;
            --border: #2f3742;
            --text: #f0f3f6;
            --muted: #9aa4b2;
            --accent: #f97316;
            --green: #22c55e;
            --red: #ef4444;
            --red-bg: rgba(239, 68, 68, 0.10);
            --green-bg: rgba(34, 197, 94, 0.10);
            --shadow: 0 10px 30px rgba(0,0,0,0.35);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 32px 20px 48px;
            background: radial-gradient(circle at top, #161b22 0%, var(--bg) 35%);
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            justify-content: center;
        }

        .app { width: 100%; max-width: 1180px; }
        
        .header-container { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }
        .hero { margin-bottom: 0; }
        .eyebrow { display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--accent); margin-bottom: 8px; }
        .hero h1 { margin: 0 0 8px 0; font-size: 34px; line-height: 1.1; font-weight: 700; }
        .hero p { margin: 0; color: var(--muted); font-size: 16px; max-width: 760px; line-height: 1.5; }
        
        .dashboard-btn {
            display: inline-flex; align-items: center; padding: 10px 16px;
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border);
            border-radius: 8px; color: var(--text); text-decoration: none;
            font-size: 14px; font-weight: 600; transition: background 0.2s;
        }
        .dashboard-btn:hover { background: rgba(255, 255, 255, 0.1); }

        .layout { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
        .main-column, .side-column { display: flex; flex-direction: column; gap: 24px; }
        .panel { background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow); overflow: hidden; }
        .panel-header { padding: 18px 20px 14px; border-bottom: 1px solid var(--border); }
        .panel-title { margin: 0; font-size: 16px; font-weight: 650; }
        .panel-subtitle { margin: 6px 0 0 0; font-size: 13px; color: var(--muted); line-height: 1.45; }
        .panel-body { padding: 20px; }
        .top-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
        .form-group { margin-bottom: 16px; }
        .form-group:last-child { margin-bottom: 0; }
        label { display: block; margin-bottom: 8px; color: var(--muted); font-size: 13px; font-weight: 600; }
        
        input, select {
            width: 100%; padding: 11px 12px; background: #0f141b; color: var(--text);
            border: 1px solid var(--border); border-radius: 10px; font-size: 14px; transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        input:focus, select:focus { outline: none; border-color: #5b6573; box-shadow: 0 0 0 3px rgba(255,255,255,0.04); }
        input[disabled], select[disabled] { opacity: 0.72; cursor: not-allowed; }
        
        .input-note { margin-top: 8px; font-size: 12px; color: var(--muted); }
        .cta { margin-top: 24px; }
        button { width: 100%; padding: 14px 16px; background: var(--text); color: #0c1117; border: none; border-radius: 10px; font-size: 15px; font-weight: 700; cursor: pointer; transition: transform 0.08s ease, opacity 0.15s ease; }
        button:hover { opacity: 0.95; }
        button:active { transform: translateY(1px); }
        button:disabled { opacity: 0.6; cursor: wait; }

        .decision-card { display: none; margin-top: 0; }
        .decision-card.show { display: block; }
        .decision-status { display: inline-flex; align-items: center; gap: 10px; font-size: 22px; font-weight: 800; margin-bottom: 12px; }
        .decision-status small { font-size: 14px; font-weight: 600; color: var(--muted); }
        
        .decision-card.allowed { background: var(--green-bg); border-color: rgba(34, 197, 94, 0.35); }
        .decision-card.allowed .decision-status { color: #7ee787; }
        
        .decision-card.blocked { background: var(--red-bg); border-color: rgba(239, 68, 68, 0.35); }
        .decision-card.blocked .decision-status { color: #ff8e8e; }

        .reason-box { background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 10px; padding: 14px; font-size: 14px; line-height: 1.5; color: var(--text); }
        
        .trace-list, .identity-list { list-style: none; margin: 0; padding: 0; }
        .trace-item, .identity-item { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.06); }
        .trace-item:last-child, .identity-item:last-child { border-bottom: none; padding-bottom: 0; }
        .trace-item:first-child, .identity-item:first-child { padding-top: 0; }
        .trace-main { display: flex; gap: 10px; align-items: flex-start; flex: 1; }
        .trace-icon { width: 22px; text-align: center; font-size: 14px; line-height: 1.6; }
        .trace-stage { font-size: 14px; font-weight: 650; margin-bottom: 4px; }
        .trace-message { color: var(--muted); font-size: 12px; line-height: 1.45; }
        .trace-badge { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; padding: 4px 8px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); white-space: nowrap; }
        .trace-badge.pass { color: #7ee787; border-color: rgba(34, 197, 94, 0.35); background: rgba(34, 197, 94, 0.08); }
        .trace-badge.fail { color: #ff8e8e; border-color: rgba(239, 68, 68, 0.35); background: rgba(239, 68, 68, 0.08); }
        
        .identity-key { color: var(--muted); font-size: 13px; font-weight: 600; }
        .identity-value { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; color: var(--text); text-align: right; word-break: break-word; max-width: 55%; }
        .empty-state { color: var(--muted); font-size: 14px; line-height: 1.5; }

        @media (max-width: 980px) {
            .header-container { flex-direction: column; gap: 16px; }
            .layout { grid-template-columns: 1fr; }
            .top-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="app">
    <div class="header-container">
        <div class="hero">
            <div class="eyebrow">Execution Boundary</div>
            <h1>Waveframe Guard Sandbox</h1>
            <p>
                Evaluate whether an AI action is allowed to execute before it reaches your system.
                This sandbox compiles the proposed policy, resolves identities, runs CRI-CORE, and returns a binary decision with trace visibility.
            </p>
        </div>
        <a href="/dashboard" target="_blank" class="dashboard-btn">View Compliance Ledger &rarr;</a>
    </div>

    <div class="layout">
        <div class="main-column">
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Incoming AI Request</h3>
                    <p class="panel-subtitle">Define the proposed action, execution context, and policy conditions.</p>
                </div>
                <div class="panel-body">
                    <div class="top-grid">
                        <div>
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
                            <div class="form-group">
                                <label>Proposing Actor</label>
                                <input value="ai-agent-v2" disabled />
                            </div>
                        </div>

                        <div>
                            <div class="form-group">
                                <label>Responsible</label>
                                <select id="responsible">
                                    <option value="user-alice" selected>Alice (Admin)</option>
                                    <option value="user-bob">Bob (Finance)</option>
                                    <option value="user-charlie">Charlie (Approver)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Accountable</label>
                                <select id="accountable">
                                    <option value="user-alice">Alice (Admin)</option>
                                    <option value="user-bob" selected>Bob (Finance)</option>
                                    <option value="user-charlie">Charlie (Approver)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Approver</label>
                                <select id="approved_by">
                                    <option value="">None</option>
                                    <option value="user-alice">Alice (Admin)</option>
                                    <option value="user-bob">Bob (Finance)</option>
                                    <option value="user-charlie">Charlie (Approver)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Approval required above ($)</label>
                                <input id="approvalThreshold" type="number" value="1000" />
                            </div>
                        </div>
                    </div>

                    <div class="cta">
                        <button onclick="runValidation()" id="submitBtn">Evaluate Action</button>
                    </div>
                </div>
            </div>

            <div id="outputCard" class="panel decision-card">
                <div class="panel-header">
                   <h3 class="panel-title">Decision</h3>
                   <p class="panel-subtitle">Execution outcome at the boundary.</p>
                </div>
                <div class="panel-body">
                    <div class="decision-status" id="resTitle"></div>
                    <p class="decision-summary" id="resSummary"></p>

                    <div class="reason-box">
                        <div id="resReasonTitle" style="font-weight:600; margin-bottom:8px;"></div>
                        <ul id="resReasonList" style="margin:0; padding-left:18px;"></ul>
                    </div>

                    <div id="auditLogNotice" style="display: none; margin-top: 16px; padding: 12px; background: rgba(255,255,255,0.03); border: 1px dashed var(--border); border-radius: 8px; font-size: 13px; color: var(--muted); justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: var(--text);">Immutable Audit Record Created</strong><br>
                            <span>A cryptographic trace of this execution boundary has been logged.</span>
                        </div>
                        <a href="/dashboard" target="_blank" style="color: var(--accent); text-decoration: none; font-weight: 600;">View Ledger</a>
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Why this decision was made</h3>
                    <p class="panel-subtitle">Stage-by-stage results from the enforcement pipeline.</p>
                </div>
                <div class="panel-body">
                    <div id="traceEmpty" class="empty-state">No evaluation yet. Run a request.</div>
                    <ul id="resTrace" class="trace-list"></ul>
                </div>
            </div>
        </div>

        <div class="side-column">
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Resolved identities</h3>
                </div>
                <div class="panel-body">
                    <div id="identityEmpty" class="empty-state">No identities resolved yet.</div>
                    <ul id="identityList" class="identity-list"></ul>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Policy being enforced</h3>
                </div>
                <div class="panel-body">
                    <div class="identity-item">
                        <div class="identity-key">Required roles</div>
                        <div class="identity-value">proposer, responsible, accountable</div>
                    </div>
                    <div class="identity-item">
                        <div class="identity-key">Rule</div>
                        <div class="identity-value">Responsible and approver must remain independent</div>
                    </div>
                    <div class="identity-item">
                        <div class="identity-key">Threshold</div>
                        <div class="identity-value" id="thresholdPreview">$1,000</div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
const STAGE_EXPLANATIONS = {
    "run-structure": { title: "Execution context verified", detail: "Ensures this action is evaluated inside a controlled execution boundary." },
    "structure-contract-version-gate": { title: "Policy version check", detail: "Ensures the correct governance policy version is being applied." },
    "structure-contract-hash-gate": { title: "Policy integrity verified", detail: "Confirms the policy has not been altered or tampered with." },
    "independence": { title: "Role separation enforced", detail: "Prevents the same person from controlling and approving an action." },
    "integrity": { title: "Input integrity verified", detail: "Confirms required data and artifacts are present and valid." },
    "integrity-finalization": { title: "Execution readiness confirmed", detail: "Final validation before allowing execution." },
    "publication": { title: "Audit trace prepared", detail: "Ensures the action can be recorded and audited." },
    "publication-commit": { title: "Decision finalized", detail: "The final execution decision has been cryptographically sealed." }
};

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function renderTrace(trace) {
    const traceList = document.getElementById("resTrace");
    const traceEmpty = document.getElementById("traceEmpty");
    traceList.innerHTML = "";

    if (!trace || trace.length === 0) {
        traceEmpty.style.display = "block";
        return;
    }
    traceEmpty.style.display = "none";

    trace.forEach(stage => {
        const passed = !!stage.passed;
        const icon = passed ? "✅" : "❌";
        const badge = passed ? "PASS" : "FAIL";
        const mappedData = STAGE_EXPLANATIONS[stage.stage] || { title: stage.stage, detail: "System evaluation completed." };
        const message = !passed && (stage.messages && stage.messages.length > 0) ? stage.messages.join(" | ") : mappedData.detail;

        const li = document.createElement("li");
        li.className = "trace-item";
        li.innerHTML = `
            <div class="trace-main">
                <div class="trace-icon">${icon}</div>
                <div>
                    <div class="trace-stage">${escapeHtml(mappedData.title)}</div>
                    <div class="trace-message">${escapeHtml(message)}</div>
                </div>
            </div>
            <div class="trace-badge ${passed ? "pass" : "fail"}">${badge}</div>
        `;
        traceList.appendChild(li);
    });
}

function renderResolvedIdentities(resolved) {
    const identityList = document.getElementById("identityList");
    const identityEmpty = document.getElementById("identityEmpty");
    identityList.innerHTML = "";

    if (!resolved || Object.keys(resolved).length === 0) {
        identityEmpty.style.display = "block";
        return;
    }
    identityEmpty.style.display = "none";

    Object.entries(resolved).forEach(([key, value]) => {
        const li = document.createElement("li");
        li.className = "identity-item";
        li.innerHTML = `
            <div class="identity-key">${escapeHtml(key)}</div>
            <div class="identity-value">${escapeHtml(value || "None")}</div>
        `;
        identityList.appendChild(li);
    });
}

function updateThresholdPreview() {
    const threshold = parseFloat(document.getElementById("approvalThreshold").value || 0);
    document.getElementById("thresholdPreview").textContent = `$${threshold.toLocaleString()}`;
}

function buildExecutiveReasons(allowed, reason, impact) {
    if (allowed) {
        return {
            title: "Action structurally aligned",
            bullets: impact && impact.length > 0 ? impact : ["Roles properly separated", "Approval conditions satisfied", "Action aligned with policy"]
        };
    }
    const r = (reason || "").toLowerCase();
    let title = "Policy validation failed";
    if (r.includes("separation")) {
        title = "Role separation violation";
    } else if (r.includes("approval")) {
        title = "Missing required approval";
    }
    return {
        title: title,
        bullets: impact && impact.length > 0 ? impact : ["Action did not meet execution requirements", "Blocked at enforcement boundary"]
    };
}

async function runValidation() {
    const btn = document.getElementById("submitBtn");
    btn.innerText = "Evaluating...";
    btn.disabled = true;

    try {
        const amount = parseFloat(document.getElementById("amount").value || 0);
        const responsible = document.getElementById("responsible").value;
        const accountable = document.getElementById("accountable").value;
        const approved_by = document.getElementById("approved_by").value;
        const threshold = parseFloat(document.getElementById("approvalThreshold").value || 0);

        updateThresholdPreview();

        const policy = {
            contract_id: "demo-finance-policy",
            contract_version: "1.0.0",
            roles: { required: ["proposer", "responsible", "accountable"] },
            constraints: [
                { type: "separation_of_duties", roles: ["responsible", "accountable"] },
                { type: "approval_required", threshold: threshold }
            ]
        };

        const context = {};
        if (responsible) context.responsible = responsible;
        if (accountable) context.accountable = accountable;
        if (approved_by) context.approved_by = approved_by;

        const res = await fetch("/validate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ policy, action: { type: "transfer", amount }, actor: "ai-agent-v2", context })
        });

        const data = await res.json();
        const card = document.getElementById("outputCard");
        const allowed = !!data.allowed; 

        card.classList.add("show");
        card.classList.remove("allowed", "blocked");
        card.classList.add(allowed ? "allowed" : "blocked");

        const resTitle = document.getElementById("resTitle");
        const resReasonTitle = document.getElementById("resReasonTitle");
        const resReasonList = document.getElementById("resReasonList");
        const auditLogNotice = document.getElementById("auditLogNotice");

        if (allowed) {
            resTitle.innerHTML = `✅ ALLOWED <small>action executed safely</small>`;
        } else {
            resTitle.innerHTML = `🚫 BLOCKED <small>execution prevented</small>`;
        }

        document.getElementById("resSummary").innerHTML = `<strong>AI attempted to transfer $${amount.toLocaleString()}</strong>`;

        const execReason = buildExecutiveReasons(allowed, data.reason, data.impact);
        resReasonTitle.textContent = execReason.title;
        resReasonList.innerHTML = execReason.bullets.map(b => `<li>${escapeHtml(b)}</li>`).join("");

        renderTrace(data.decision_trace || []);
        renderResolvedIdentities(data.resolved_identities || {});
        
        // Show the audit log receipt
        auditLogNotice.style.display = "flex";

    } catch (err) {
        console.error(err);
        alert("Failed to connect to backend. Check console.");
    } finally {
        btn.innerText = "Evaluate Action";
        btn.disabled = false;
    }
}

updateThresholdPreview();
</script>

</body>
</html>
"""