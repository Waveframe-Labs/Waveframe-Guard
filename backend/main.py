from __future__ import annotations

import json
import tempfile
import uuid
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from backend.db import init_db, get_db, Organization, APIKey, Policy, AuditLog

from compiler.compile_policy_file import compile_policy_file
from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal

app = FastAPI(
    title="Waveframe Guard",
    version="3.0.0",
)

# ---------------------------
# STARTUP
# ---------------------------

@app.on_event("startup")
def startup():
    init_db()

# ---------------------------
# AUTH
# ---------------------------

security = HTTPBearer()

def get_current_org(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db)
):
    api_key = db.query(APIKey).filter(APIKey.key_value == credentials.credentials).first()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return api_key.organization

# ---------------------------
# CORE VALIDATION
# ---------------------------

def run_validation(policy, action, actor, context):

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
        json.dump(policy, f)
        policy_path = Path(f.name)

    compiled_path = Path(tempfile.NamedTemporaryFile(delete=False).name)

    contract_path = compile_policy_file(policy_path, compiled_path)

    with open(contract_path) as f:
        compiled = json.load(f)

    contract_hash = hashlib.sha256(
        json.dumps(compiled, sort_keys=True).encode()
    ).hexdigest()

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": actor, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": "finance",
            "resource": "funds",
            "action": action.get("type", "unknown")
        },
        contract={
            "id": compiled.get("contract_id", "dynamic"),
            "version": compiled.get("contract_version", "1.0"),
            "hash": contract_hash
        },
        run_context={
            "identities": {
                "actors": [
                    {"id": actor, "type": "agent", "role": "proposer"}
                ]
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True}
        }
    )

    result = evaluate_proposal(proposal, compiled)

    allowed = getattr(result, "commit_allowed", False)

    return {
        "allowed": allowed,
        "reason": "Allowed" if allowed else "Blocked by policy",
        "trace_hash": contract_hash,
    }

# ---------------------------
# SANDBOX ENDPOINT
# ---------------------------

@app.post("/validate")
async def validate(request: Request, db: Session = Depends(get_db)):

    body = await request.json()

    action = body.get("action", {})
    actor = body.get("actor", "ai-agent")

    decision = run_validation(
        body.get("policy", {}),
        action,
        actor,
        body.get("context", {})
    )

    log = AuditLog(
        id=f"dec_{uuid.uuid4().hex[:10]}",
        organization_id=None,
        policy_version_id=None,
        actor=actor,
        action_type=action.get("type", "unknown"),
        amount=action.get("amount", 0),
        allowed=decision["allowed"],
        reason=decision["reason"],
        trace_hash=decision["trace_hash"]
    )

    db.add(log)
    db.commit()

    return JSONResponse(decision)

# ---------------------------
# PROD ENDPOINT
# ---------------------------

@app.post("/v1/enforce")
async def enforce(
    request: Request,
    current_org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db)
):

    body = await request.json()

    policy = db.query(Policy).filter(
        Policy.id == body.get("policy_ref"),
        Policy.organization_id == current_org.id
    ).first()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    version = policy.versions[0]
    policy_dict = json.loads(version.rules_json)

    action = body.get("action", {})
    actor = body.get("actor", "ai-agent")

    decision = run_validation(policy_dict, action, actor, body.get("context", {}))

    log = AuditLog(
        id=f"dec_{uuid.uuid4().hex[:10]}",
        organization_id=current_org.id,
        policy_version_id=version.id,
        actor=actor,
        action_type=action.get("type", "unknown"),
        amount=action.get("amount", 0),
        allowed=decision["allowed"],
        reason=decision["reason"],
        trace_hash=decision["trace_hash"]
    )

    db.add(log)
    db.commit()

    return JSONResponse(decision)

# ---------------------------
# LOGS API
# ---------------------------

@app.get("/api/logs")
def logs(db: Session = Depends(get_db)):
    rows = db.query(AuditLog).all()

    return {
        "logs": [
            {
                "id": r.id,
                "actor": r.actor,
                "allowed": r.allowed,
                "action": r.action_type,
                "amount": r.amount,
                "reason": r.reason
            }
            for r in rows
        ]
    }


# ---------------------------
# UI - COMPLIANCE DASHBOARD
# ---------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
    """Renders the Compliance Ledger natively."""
    logs = db.query(AuditLog).order_by(AuditLog.server_timestamp.desc()).limit(100).all()
    
    rows_html = ""
    for log in logs:
        status_color = "#2ea043" if log.allowed else "#da3633"
        status_text = "ALLOWED" if log.allowed else "BLOCKED"
        action_type = (log.action_type or "unknown").upper()
        ts = log.server_timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.server_timestamp else "Recent"
        org_name = log.organization.name if log.organization else "Unknown Org"

        rows_html += f"""
        <tr style="border-bottom: 1px solid var(--border);">
            <td class="td-time">{ts}</td>
            <td class="td-mono" style="color: var(--blue); font-weight: bold;">{org_name}</td>
            <td class="td-id">{log.id}</td>
            <td><span class="badge" style="color: {status_color}; background: {status_color}20; border-color: {status_color}40;">{status_text}</span></td>
            <td class="td-mono">{log.actor}</td>
            <td class="td-mono">{action_type}</td>
            <td class="td-mono">{f"${log.amount:,.0f}" if log.amount else "—"}</td>
            <td class="td-reason">{log.reason}</td>
            <td class="td-hash" title="{log.trace_hash}">{str(log.trace_hash)[:8]}...</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8" />
    <title>Waveframe Guard — Compliance Ledger</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
    <style>
      :root {{ --bg: #07090d; --surface: #0d1018; --surface2: #111520; --border: #1c2030; --border2: #242840; --text: #dce3f0; --muted: #4a5270; --muted2: #6b7494; --green: #00d97e; --red: #ff3d5a; --blue: #4d7cfe; --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif; }}
      * {{ box-sizing: border-box; margin: 0; padding: 0; }}
      body {{ background: var(--bg); color: var(--text); font-family: var(--sans); padding: 0 0 60px; }}
      .header {{ display: flex; align-items: center; justify-content: space-between; padding: 0 32px; height: 52px; border-bottom: 1px solid var(--border); background: var(--surface); }}
      .logo {{ font-family: var(--mono); font-size: 13px; font-weight: 600; letter-spacing: 0.06em; }}
      .logo span {{ color: var(--green); }}
      .page {{ padding: 28px 32px 0; max-width: 1440px; margin: 0 auto; }}
      .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
      .panel-head {{ padding: 13px 18px; border-bottom: 1px solid var(--border); background: var(--surface2); font-family: var(--mono); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
      table {{ width: 100%; border-collapse: collapse; }}
      thead tr {{ background: var(--surface2); border-bottom: 1px solid var(--border); }}
      th {{ font-family: var(--mono); font-size: 9px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.12em; padding: 9px 14px; text-align: left; }}
      tbody tr {{ transition: background 0.12s; cursor: pointer; }}
      tbody tr:hover {{ background: rgba(255,255,255,0.025); }}
      td {{ padding: 11px 14px; font-size: 12px; vertical-align: middle; }}
      .td-mono {{ font-family: var(--mono); font-size: 12px; }}
      .td-time, .td-id, .td-hash {{ font-family: var(--mono); font-size: 11px; color: var(--muted2); }}
      .td-reason {{ color: var(--muted2); font-size: 12px; }}
      .badge {{ font-family: var(--mono); font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 3px; border: 1px solid; }}
    </style>
    </head>
    <body>
    <header class="header">
      <div class="logo">WAVEFRAME <span>GUARD</span></div>
      <a href="/" style="color: var(--muted2); font-family: var(--mono); font-size: 11px; text-decoration: none;">← Back to Sandbox</a>
    </header>
    <div class="page">
      <div class="panel">
        <div class="panel-head">Enterprise Audit Ledger (Cross-Tenant Admin View)</div>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Tenant Org</th>
                <th>Decision ID</th>
                <th>Status</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Amount</th>
                <th>Reason</th>
                <th>Trace Hash</th>
              </tr>
            </thead>
            <tbody>
              {rows_html if rows_html else '<tr><td colspan="9" style="text-align:center; padding:20px; color:var(--muted);">No logs in database. Run Sandbox or SDK.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    </body>
    </html>
    """

# ---------------------------
# UI SANDBOX
# ---------------------------
# Your exact Sandbox UI code remains here! 
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