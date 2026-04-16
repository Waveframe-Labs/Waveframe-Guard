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

    # ---------------------------
    # Mock policy store (for now)
    # ---------------------------
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

        .app {
            width: 100%;
            max-width: 1180px;
        }

        .hero {
            margin-bottom: 24px;
        }

        .eyebrow {
            display: inline-block;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--accent);
            margin-bottom: 8px;
        }

        .hero h1 {
            margin: 0 0 8px 0;
            font-size: 34px;
            line-height: 1.1;
            font-weight: 700;
        }

        .hero p {
            margin: 0;
            color: var(--muted);
            font-size: 16px;
            max-width: 760px;
            line-height: 1.5;
        }

        .layout {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 24px;
        }

        .main-column, .side-column {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .panel {
            background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
            border: 1px solid var(--border);
            border-radius: 14px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .panel-header {
            padding: 18px 20px 14px;
            border-bottom: 1px solid var(--border);
        }

        .panel-title {
            margin: 0;
            font-size: 16px;
            font-weight: 650;
        }

        .panel-subtitle {
            margin: 6px 0 0 0;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.45;
        }

        .panel-body {
            padding: 20px;
        }

        .top-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group:last-child {
            margin-bottom: 0;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: var(--muted);
            font-size: 13px;
            font-weight: 600;
        }

        input, select {
            width: 100%;
            padding: 11px 12px;
            background: #0f141b;
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 10px;
            font-size: 14px;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }

        input:focus, select:focus {
            outline: none;
            border-color: #5b6573;
            box-shadow: 0 0 0 3px rgba(255,255,255,0.04);
        }

        input[disabled], select[disabled] {
            opacity: 0.72;
            cursor: not-allowed;
        }

        .input-note {
            margin-top: 8px;
            font-size: 12px;
            color: var(--muted);
        }

        .cta {
            margin-top: 24px;
        }

        button {
            width: 100%;
            padding: 14px 16px;
            background: var(--text);
            color: #0c1117;
            border: none;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.08s ease, opacity 0.15s ease;
        }

        button:hover {
            opacity: 0.95;
        }

        button:active {
            transform: translateY(1px);
        }

        button:disabled {
            opacity: 0.6;
            cursor: wait;
        }

        .decision-card {
            display: none;
            margin-top: 0;
        }

        .decision-card.show {
            display: block;
        }

        .decision-status {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            font-size: 22px;
            font-weight: 800;
            margin-bottom: 12px;
        }

        .decision-status small {
            font-size: 14px;
            font-weight: 600;
            color: var(--muted);
        }

        .decision-card.allowed {
            background: var(--green-bg);
            border-color: rgba(34, 197, 94, 0.35);
        }

        .decision-card.allowed .decision-status {
            color: #7ee787;
        }

        .decision-card.blocked {
            background: var(--red-bg);
            border-color: rgba(239, 68, 68, 0.35);
        }

        .decision-card.blocked .decision-status {
            color: #ff8e8e;
        }

        .impact-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
            margin-top: 18px;
        }

        .impact-box {
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px;
            background: rgba(0,0,0,0.18);
        }

        .impact-box h4 {
            margin: 0 0 8px 0;
            font-size: 13px;
            color: var(--muted);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .impact-box p {
            margin: 0;
            line-height: 1.45;
            font-size: 14px;
        }

        .decision-summary {
            font-size: 16px;
            margin: 0 0 14px 0;
        }

        .reason-box {
            background: rgba(0,0,0,0.25);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text);
        }

        .trace-list, .identity-list {
            list-style: none;
            margin: 0;
            padding: 0;
        }

        .trace-item, .identity-item {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 14px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }

        .trace-item:last-child, .identity-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .trace-item:first-child, .identity-item:first-child {
            padding-top: 0;
        }

        .trace-main {
            display: flex;
            gap: 10px;
            align-items: flex-start;
            flex: 1;
        }

        .trace-icon {
            width: 22px;
            text-align: center;
            font-size: 14px;
            line-height: 1.6;
        }

        .trace-stage {
            font-size: 14px;
            font-weight: 650;
            margin-bottom: 4px;
        }

        .trace-message {
            color: var(--muted);
            font-size: 12px;
            line-height: 1.45;
        }

        .trace-badge {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 4px 8px;
            border-radius: 999px;
            border: 1px solid var(--border);
            color: var(--muted);
            white-space: nowrap;
        }

        .trace-badge.pass {
            color: #7ee787;
            border-color: rgba(34, 197, 94, 0.35);
            background: rgba(34, 197, 94, 0.08);
        }

        .trace-badge.fail {
            color: #ff8e8e;
            border-color: rgba(239, 68, 68, 0.35);
            background: rgba(239, 68, 68, 0.08);
        }

        .identity-key {
            color: var(--muted);
            font-size: 13px;
            font-weight: 600;
        }

        .identity-value {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 13px;
            color: var(--text);
            text-align: right;
            word-break: break-word;
            max-width: 55%;
        }

        .empty-state {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.5;
        }

        @media (max-width: 980px) {
            .layout { grid-template-columns: 1fr; }
            .top-grid { grid-template-columns: 1fr; }
            .impact-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="app">
    <div class="hero">
        <div class="eyebrow">Execution Boundary</div>
        <h1>Waveframe Guard Sandbox</h1>
        <p>
            Evaluate whether an AI action is allowed to execute before it reaches your system.
            This sandbox compiles the proposed policy, resolves identities, runs CRI-CORE, and returns a binary decision with trace visibility.
        </p>
    </div>

    <div class="layout">
        <div class="main-column">
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Incoming AI Request</h3>
                    <p class="panel-subtitle">
                        Define the proposed action, execution context, and policy conditions being enforced at the moment of execution.
                    </p>
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
                                <div class="input-note">
                                    The action originator is fixed in this sandbox to simulate a live AI-issued request.
                                </div>
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
                    <p class="panel-subtitle">
                        The action either executes or it does not. This surface shows what happened and why.
                    </p>
                </div>
                <div class="panel-body">
                    <div class="decision-status" id="resTitle"></div>
                    <p class="decision-summary" id="resSummary"></p>
                    <div class="reason-box" id="resReason"></div>

                    <div class="impact-grid">
                        <div class="impact-box">
                            <h4>Without Guard</h4>
                            <p id="withoutGuardText">This action would have been allowed to continue toward execution.</p>
                        </div>
                        <div class="impact-box">
                            <h4>With Guard</h4>
                            <p id="withGuardText">Execution outcome pending.</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Why this decision was made</h3>
                    <p class="panel-subtitle">
                        Stage-by-stage results from the enforcement pipeline.
                    </p>
                </div>
                <div class="panel-body">
                    <div id="traceEmpty" class="empty-state">
                        No evaluation yet. Run a request to see the enforcement stages.
                    </div>
                    <ul id="resTrace" class="trace-list"></ul>
                </div>
            </div>
        </div>

        <div class="side-column">
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Resolved identities</h3>
                    <p class="panel-subtitle">
                        Canonical identities used by the enforcement layer.
                    </p>
                </div>
                <div class="panel-body">
                    <div id="identityEmpty" class="empty-state">
                        No identities resolved yet.
                    </div>
                    <ul id="identityList" class="identity-list"></ul>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Policy being enforced</h3>
                    <p class="panel-subtitle">
                        This sandbox evaluates a transfer action with role separation and approval threshold constraints.
                    </p>
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
// --- FIX 1: The Human Mapping Dictionary ---
const STAGE_EXPLANATIONS = {
    "run-structure": {
        title: "Execution context verified",
        detail: "Ensures this action is evaluated inside a controlled execution boundary."
    },
    "structure-contract-version-gate": {
        title: "Policy version check",
        detail: "Ensures the correct governance policy version is being applied."
    },
    "structure-contract-hash-gate": {
        title: "Policy integrity verified",
        detail: "Confirms the policy has not been altered or tampered with."
    },
    "independence": {
        title: "Role separation enforced",
        detail: "Prevents the same person from controlling and approving an action."
    },
    "integrity": {
        title: "Input integrity verified",
        detail: "Confirms required data and artifacts are present and valid."
    },
    "integrity-finalization": {
        title: "Execution readiness confirmed",
        detail: "Final validation before allowing execution."
    },
    "publication": {
        title: "Audit trace prepared",
        detail: "Ensures the action can be recorded and audited."
    },
    "publication-commit": {
        title: "Decision finalized",
        detail: "The final execution decision has been cryptographically sealed."
    }
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
        
        // Match the raw stage string to our human dictionary (fallback to raw if missing)
        const mappedData = STAGE_EXPLANATIONS[stage.stage] || { 
            title: stage.stage, 
            detail: "System evaluation completed." 
        };

        // Smart logic: If it failed, show the actual error message. If it passed, show the nice detail text.
        const message = !passed && (stage.messages && stage.messages.length > 0)
            ? stage.messages.join(" | ")
            : mappedData.detail;

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
    document.getElementById("thresholdPreview").textContent =
        `$${threshold.toLocaleString()}`;
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
            roles: {
                required: ["proposer", "responsible", "accountable"]
            },
            constraints: [
                {
                    type: "separation_of_duties",
                    roles: ["responsible", "accountable"]
                },
                {
                    type: "approval_required",
                    threshold: threshold
                }
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
            body: JSON.stringify({
                policy: policy,
                action: action,
                actor: "ai-agent-v2",
                context: context
            })
        });

        const data = await res.json();

        const card = document.getElementById("outputCard");
        const allowed = !!data.allowed;

        card.classList.add("show");
        card.classList.remove("allowed", "blocked");
        card.classList.add(allowed ? "allowed" : "blocked");

        document.getElementById("resTitle").innerHTML =
            allowed
                ? `✅ ALLOWED <small>action executed safely</small>`
                : `🚫 BLOCKED <small>execution prevented</small>`;

        const amountElement = document.getElementById("amount").value;

        document.getElementById("resSummary").innerHTML =
            `<strong>AI attempted to transfer $${Number(amountElement).toLocaleString()}</strong>`;

        const reasonBox = document.getElementById("resReason");

        let impactHtml = "";

        if (data.impact && data.impact.length > 0) {
            impactHtml = `
                <div style="margin-top:12px;">
                    <strong>This would have:</strong>
                    <ul style="margin:8px 0 0 16px; padding:0;">
                        ${data.impact.map(i => `<li>${escapeHtml(i)}</li>`).join("")}
                    </ul>
                </div>
        `;
        }

        reasonBox.innerHTML = `
            <div>${escapeHtml(data.reason || "No reason provided")}</div>
            ${impactHtml}
        `;

        document.getElementById("withoutGuardText").textContent =
            `This $${Number(amountElement).toLocaleString()} transfer would have continued toward execution.`;

        document.getElementById("withGuardText").textContent =
            allowed
                ? "The action satisfied the active policy and was permitted to proceed."
                : "The action was stopped at the execution boundary before state could change.";

        renderTrace(data.decision_trace || []);
        renderResolvedIdentities(data.resolved_identities || {});
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