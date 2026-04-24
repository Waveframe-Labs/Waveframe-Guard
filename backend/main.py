from __future__ import annotations

import json
import uuid
import hashlib
import threading
import time
import random
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from backend.db import init_db, get_db, Organization, APIKey, Policy, PolicyVersion, AuditLog

from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal

app = FastAPI(
    title="Waveframe Guard",
    version="0.2.0",
    description="Local enforcement SDK and simulation environment for AI governance"
)

simulation_thread: Optional[threading.Thread] = None

# ---------------------------
# STARTUP
# ---------------------------

@app.on_event("startup")
def startup():
    global simulation_thread
    init_db()
    if simulation_thread is None or not simulation_thread.is_alive():
        simulation_thread = threading.Thread(target=simulate_activity, daemon=True)
        simulation_thread.start()

# ---------------------------
# AUTH
# ---------------------------

security = HTTPBearer()

def get_current_org(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: Session = Depends(get_db),
):
    api_key = db.query(APIKey).filter(APIKey.key_value == credentials.credentials).first()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return api_key.organization

# ---------------------------
# IDENTITY HELPERS
# ---------------------------

def load_identity_registry() -> Dict[str, Any]:
    identity_path = Path(__file__).resolve().parent / "data" / "identities.json"

    if identity_path.exists():
        with open(identity_path, "r", encoding="utf-8") as f:
            return json.load(f)

    return {
        "identities": {
            "user-alice": {
                "canonical_id": "usr_111",
                "display_name": "Alice (Platform Admin)",
                "aliases": ["alice"],
            },
            "user-bob": {
                "canonical_id": "usr_222",
                "display_name": "Bob (System Owner)",
                "aliases": ["bob"],
            },
            "user-charlie": {
                "canonical_id": "usr_333",
                "display_name": "Charlie (Security Lead)",
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

def resolve_identity(
    value: Optional[str],
    registry: Dict[str, Any],
    require_registered: bool = False,
) -> Optional[str]:
    if not value:
        return None

    key = normalize(value)
    for k, v in registry["identities"].items():
        aliases = [normalize(a) for a in v.get("aliases", [])]
        if key == normalize(k) or key in aliases:
            return v["canonical_id"]

    if require_registered:
        return None

    return key

def validate_action(action: dict):
    """
    Stage 0 - Action Validation Gate

    Ensures the action itself is structurally valid
    before governance enforcement.
    """

    if not isinstance(action, dict):
        return False, "Action must be a dictionary", "invalid_action_type"

    if "type" not in action:
        return False, "Missing required field: type", "missing_action_type"

    action_type = action.get("type")

    if action_type == "transfer":
        if "amount" not in action:
            return False, "Missing required field: amount for transfer", "missing_amount"

        try:
            float(action.get("amount", 0))
        except Exception:
            return False, "Invalid amount value", "invalid_amount"

    return True, None, None

def extract_stages(result: Any) -> List[Dict[str, Any]]:
    stages = getattr(result, "stage_results", [])
    out: List[Dict[str, Any]] = []
    for s in stages:
        out.append(
            {
                "stage": getattr(s, "stage_id", "unknown"),
                "passed": getattr(s, "passed", False),
                "messages": getattr(s, "messages", []),
            }
        )
    return out

def extract_reason(stages: List[Dict[str, Any]]) -> str:
    for s in stages:
        if not s["passed"]:
            msgs = " ".join(s.get("messages", [])).lower()

            if "separation" in msgs or "independence" in msgs:
                return "Same person assigned to multiple required roles"
            if "required_roles" in msgs:
                return "Required roles not properly assigned"
            if "approval" in msgs:
                return "Approval missing or threshold exceeded"
            if msgs:
                return msgs

            return f"{s['stage']} failed"

    return "Action structurally aligned with governance policy"

def compute_risk_level(
    action: Dict[str, Any],
    allowed: bool,
    impact: List[str],
    reason: str,
) -> str:
    action_type = action.get("type", "")
    system = action.get("system", "")
    amount = action.get("amount", 0) or 0

    if not allowed and ("approval" in reason.lower() or amount > 5000):
        return "critical"

    if system in ["infra", "production"] or action_type in ["delete", "deploy"]:
        return "high"

    if amount > 1000:
        return "medium"

    return "low"

def contract_hash(compiled_contract: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(compiled_contract, sort_keys=True).encode()
    ).hexdigest()

def contract_required_roles(compiled_contract: Dict[str, Any]) -> List[str]:
    authority = compiled_contract.get("authority_requirements", {})

    if isinstance(authority, dict):
        roles = authority.get("required_roles", [])
    elif isinstance(authority, list):
        roles = []
        for requirement in authority:
            if not isinstance(requirement, dict):
                continue
            if requirement.get("type") == "required_roles":
                roles.extend(requirement.get("roles", []))
            elif requirement.get("role"):
                roles.append(requirement["role"])
    else:
        roles = []

    return list(dict.fromkeys(role for role in roles if role))

def validate_compiled_contract(compiled_contract: Dict[str, Any]) -> Optional[str]:
    if not isinstance(compiled_contract, dict):
        return "Compiled contract must be an object"

    for field in ("contract_id", "contract_version", "authority_requirements"):
        if not compiled_contract.get(field):
            return f"Missing compiled contract field: {field}"

    if not contract_required_roles(compiled_contract):
        return "Compiled contract does not declare authority requirements"

    return None

def attach_development_metadata(decision: Dict[str, Any]) -> Dict[str, Any]:
    decision["environment"] = "development"
    decision["guarantees"] = [
        "no durability guarantee",
        "no immutable audit guarantee",
        "no policy lifecycle enforcement",
    ]
    decision["execution_context"] = {
        "mode": "local",
        "record_type": "simulation",
        "attestable": False,
    }
    return decision

# ---------------------------
# CORE VALIDATION
# ---------------------------

def run_validation(
    compiled_contract: Dict[str, Any],
    action: Dict[str, Any],
    actor: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:
    registry = load_identity_registry()
    requested_approver = context.get("approved_by")

    proposer = normalize(actor)
    responsible = resolve_identity(context.get("responsible"), registry)
    accountable = resolve_identity(context.get("accountable"), registry)
    approver = resolve_identity(requested_approver, registry)

    if not responsible or not accountable:
        impact = [
            "missing required execution identities",
            "could not verify governance role assignments",
            "action was stopped before execution",
        ]
        reason = "Identity resolution failed: missing required human context"
        return {
            "allowed": False,
            "status": "blocked",
            "summary": f"AI proposed action: {action.get('type')}",
            "reason": reason,
            "impact": impact,
            "decision_trace": [],
            "resolved_identities": {},
            "trace_hash": contract_hash(compiled_contract if isinstance(compiled_contract, dict) else {}),
            "error_code": "identity_resolution_failed",
            "risk_level": compute_risk_level(action, False, impact, reason),
        }

    contract_error = validate_compiled_contract(compiled_contract)
    if contract_error:
        impact = [
            "invalid stored compiled contract",
            "execution blocked before kernel evaluation",
            "policy version requires operator review",
        ]
        return {
            "allowed": False,
            "status": "blocked",
            "summary": f"AI proposed action: {action.get('type')}",
            "reason": contract_error,
            "impact": impact,
            "decision_trace": [],
            "resolved_identities": {
                "proposer": proposer,
                "responsible": responsible,
                "accountable": accountable,
                "approver": approver,
            },
            "trace_hash": contract_hash(compiled_contract if isinstance(compiled_contract, dict) else {}),
            "error_code": "invalid_compiled_contract",
            "risk_level": compute_risk_level(action, False, impact, contract_error),
        }

    trace_hash = contract_hash(compiled_contract)
    required_roles = contract_required_roles(compiled_contract)

    # Guard builds the proposal shape and hands execution semantics to the kernel.
    actors_list = [
        {"id": proposer, "type": "agent", "role": "proposer"},
        {"id": responsible, "type": "human", "role": "responsible"},
        {"id": accountable, "type": "human", "role": "accountable"},
    ]

    if approver:
        actors_list.append({"id": approver, "type": "human", "role": "approver"})

    proposal = build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": proposer, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": action.get("system", "unknown"),
            "resource": action.get("resource", "unknown"),
            "action": action.get("type", "unknown"),
        },
        contract={
            "id": compiled_contract["contract_id"],
            "version": compiled_contract["contract_version"],
            "hash": trace_hash,
        },
        run_context={
            "identities": {
                "actors": actors_list,
                "required_roles": required_roles,
                "conflict_flags": {},
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True},
        },
    )

    # 🛡️ CRYPTOGRAPHIC STRUCTURAL LOGIC (CRI-CORE LAYER)
    result = evaluate_proposal(proposal, compiled_contract)
    stages = extract_stages(result)
    allowed = getattr(result, "commit_allowed", False)
    reason = extract_reason(stages)
    status = "allowed" if allowed else ("pending" if "approval" in reason.lower() else "blocked")

    if not allowed:
        if "separation" in reason.lower() or "multiple required roles" in reason.lower():
            impact = [
                "violated separation of duties",
                "same individual attempted to control multiple required roles",
                "created audit and fraud risk",
            ]
        elif "approval" in reason.lower():
            impact = [
                "awaiting required authorization before execution",
                "execution held at the governance boundary",
                "kernel evaluation did not permit commit",
            ]
        else:
            impact = [
                "failed governance validation",
                "action did not meet required execution constraints",
            ]
    else:
        impact = [
            "roles properly separated",
            "approval conditions satisfied",
            "action aligned with policy",
        ]

    action_type = action.get("type", "unknown")
    action_system = action.get("system", "unknown")
    action_resource = action.get("resource", "unknown")
    risk_level = compute_risk_level(action, allowed, impact, reason)

    return {
        "allowed": allowed,
        "status": status,
        "summary": f"AI proposed {action_type} on {action_system}/{action_resource}",
        "reason": reason,
        "impact": impact,
        "risk_level": risk_level,
        "decision_trace": stages,
        "trace_hash": trace_hash,
        "resolved_identities": {
            "proposer": proposer,
            "responsible": responsible,
            "accountable": accountable,
            "approver": approver,
        },
    }

# ---------------------------
# DEV ENVIRONMENT ENDPOINT
# ---------------------------

@app.post("/validate")
async def validate(request: Request, db: Session = Depends(get_db)):
    """Public Dev Environment. No API Key required."""
    body = await request.json()

    sandbox = db.query(Organization).filter_by(name="Dev Environment").first()
    if not sandbox:
        sandbox = Organization(name="Dev Environment")
        db.add(sandbox)
        db.commit()
        db.refresh(sandbox)

    action = body.get("action", {})
    actor = body.get("actor", "ai-agent-v2")
    context = body.get("context", {})

    compiled_contract = body.get("compiled_contract") or body.get("contract") or {}

    decision = run_validation(
        compiled_contract,
        action,
        actor,
        context,
    )

    log = AuditLog(
        id=f"dec_{uuid.uuid4().hex[:10]}",
        organization_id=sandbox.id,
        policy_version_id=None,
        actor=actor,
        action_type=action.get("type", "unknown"),
        action_domain=action.get("system", "unknown"),
        amount=action.get("amount", 0),
        allowed=decision["allowed"],
        risk_level=decision.get("risk_level", "low"),
        reason=decision["reason"],
        decision_trace=json.dumps(decision.get("decision_trace", [])),
        resolved_identities=json.dumps(decision.get("resolved_identities", {})),
        impact=json.dumps(decision.get("impact", [])),
        trace_hash=decision["trace_hash"],
    )

    db.add(log)
    db.commit()

    attach_development_metadata(decision)

    return JSONResponse(decision)

# ---------------------------
# PROD ENDPOINT (MULTI-TENANT)
# ---------------------------

@app.post("/v1/enforce")
async def enforce(
    request: Request,
    current_org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    # ⚠️ DEVELOPMENT MODE ONLY
    # This endpoint simulates enforcement locally.
    # It does NOT provide durability, immutability, or compliance guarantees.
    """Production Endpoint. Requires API Key. Enforces Org Isolation."""
    body = await request.json()

    policy_id = body.get("policy_id")

    if not policy_id:
        raise HTTPException(status_code=400, detail="policy_id is required")

    policy_version = (
        db.query(PolicyVersion)
        .join(Policy)
        .filter(
            Policy.name == policy_id,
            Policy.organization_id == current_org.id,
        )
        .order_by(PolicyVersion.version.desc())
        .first()
    )

    if not policy_version:
        raise HTTPException(status_code=404, detail="Policy not found")

    compiled_contract = json.loads(policy_version.compiled_contract_json)

    action = body.get("action", {})
    actor = body.get("actor", "ai-agent-v2")
    context = body.get("context", {})
    action_type = action.get("type", "unknown") if isinstance(action, dict) else "unknown"
    action_amount = action.get("amount", 0) if isinstance(action, dict) else 0

    # ---------------------------
    # STAGE 0 - ACTION VALIDATION
    # ---------------------------

    is_valid, error_reason, error_code = validate_action(action)

    if not is_valid:
        invalid_impact = [
            "invalid action structure",
            "failed pre-execution validation",
            "execution blocked before governance evaluation"
        ]
        decision = {
            "allowed": False,
            "status": "blocked",
            "summary": f"AI attempted action: {action_type}",
            "reason": error_reason,
            "impact": invalid_impact,
            "risk_level": compute_risk_level(action, False, invalid_impact, error_reason),
            "decision_trace": [
                {
                    "stage": "action-validation",
                    "passed": False,
                    "messages": [error_reason],
                }
            ],
            "trace_hash": contract_hash(compiled_contract),
            "error_code": error_code,
            "resolved_identities": {},
        }
    else:
        decision = run_validation(compiled_contract, action, actor, context)

    log = AuditLog(
        id=f"dec_{uuid.uuid4().hex[:10]}",
        organization_id=current_org.id,
        policy_version_id=policy_version.id,
        actor=actor,
        action_type=action_type,
        action_domain=action.get("system", "unknown"),
        amount=action_amount,
        allowed=decision["allowed"],
        risk_level=decision.get("risk_level", "low"),
        reason=decision["reason"],
        decision_trace=json.dumps(decision.get("decision_trace", [])),
        resolved_identities=json.dumps(decision.get("resolved_identities", {})),
        impact=json.dumps(decision.get("impact", [])),
        trace_hash=decision["trace_hash"],
    )

    db.add(log)
    db.commit()

    attach_development_metadata(decision)

    return JSONResponse(decision)

# ---------------------------
# LOGS & IDENTITIES API
# ---------------------------

def serialize_audit_logs(rows: List[AuditLog]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "logs": [
            {
                "decision_id": r.id,
                "organization": r.organization.name if r.organization else "Dev Environment",
                "domain": r.action_domain or "unknown",
                "actor": r.actor,
                "allowed": r.allowed,
                "risk_level": r.risk_level or "low",
                "action": {
                    "type": r.action_type,
                    "amount": r.amount,
                },
                "amount": r.amount,
                "reason": r.reason,
                "trace_hash": r.trace_hash,
                "server_timestamp": r.server_timestamp.isoformat() + "Z" if r.server_timestamp else None,
                "decision_trace": json.loads(r.decision_trace or "[]"),
                "resolved_identities": json.loads(r.resolved_identities or "{}"),
                "impact": json.loads(r.impact or "[]"),
            }
            for r in rows
        ]
    }

@app.get("/api/logs")
def logs(limit: int = 50, org: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(AuditLog)

    if org:
        query = query.join(Organization).filter(Organization.name == org)

    rows = query.order_by(AuditLog.server_timestamp.desc()).limit(limit).all()
    return serialize_audit_logs(rows)

@app.get("/api/log/{id}")
def log_detail(id: str, db: Session = Depends(get_db)):
    log = db.query(AuditLog).filter(AuditLog.id == id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    resolved_identities = json.loads(log.resolved_identities or "{}")
    policy_version = (
        db.query(PolicyVersion).filter(PolicyVersion.id == log.policy_version_id).first()
        if log.policy_version_id
        else None
    )
    policy_id = policy_version.policy.name if policy_version and policy_version.policy else None

    return {
        "decision_id": log.id,
        "policy_id": policy_id,
        "proposer": resolved_identities.get("proposer"),
        "responsible": resolved_identities.get("responsible"),
        "accountable": resolved_identities.get("accountable"),
        "approver": resolved_identities.get("approver"),
        "allowed": log.allowed,
        "risk_level": log.risk_level or "low",
        "action": {
            "type": log.action_type,
            "amount": log.amount,
        },
        "amount": log.amount,
        "reason": log.reason,
        "trace_hash": log.trace_hash,
        "server_timestamp": log.server_timestamp.isoformat() + "Z" if log.server_timestamp else None,
        "decision_trace": json.loads(log.decision_trace or "[]"),
        "resolved_identities": resolved_identities,
        "impact": json.loads(log.impact or "[]"),
    }

@app.get("/api/audit/{decision_id}")
def get_audit_record(decision_id: str, db: Session = Depends(get_db)):
    log = db.query(AuditLog).filter(AuditLog.id == decision_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Decision not found")

    policy_version = None
    if log.policy_version_id:
        policy_version = db.query(PolicyVersion).filter(
            PolicyVersion.id == log.policy_version_id
        ).first()

    return {
        "decision_id": log.id,
        "timestamp": log.server_timestamp.isoformat() + "Z" if log.server_timestamp else None,
        "actor": log.actor,
        "action": {
            "type": log.action_type,
            "domain": log.action_domain,
            "amount": log.amount,
        },
        "allowed": log.allowed,
        "reason": log.reason,
        "trace_hash": log.trace_hash,
        "risk_level": getattr(log, "risk_level", "unknown"),
        "policy": {
            "version_id": log.policy_version_id,
            "compiled_contract": json.loads(policy_version.compiled_contract_json) if policy_version else None,
        },
        "decision_trace": json.loads(log.decision_trace or "[]"),
        "resolved_identities": json.loads(log.resolved_identities or "{}"),
        "impact": json.loads(log.impact or "[]"),
    }

@app.get("/api/orgs")
def get_orgs(db: Session = Depends(get_db)):
    orgs = db.query(Organization).all()
    return {"orgs": [o.name for o in orgs]}

@app.get("/v1/logs")
def tenant_logs(
    limit: int = 50,
    current_org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    rows = db.query(AuditLog).filter(
        AuditLog.organization_id == current_org.id
    ).order_by(AuditLog.server_timestamp.desc()).limit(limit).all()

    return serialize_audit_logs(rows)

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


def simulate_activity():
    """Continuously generates fake AI actions for demo realism."""
    from backend.db import SessionLocal

    while True:
        db = None
        try:
            db = SessionLocal()

            sandbox = db.query(Organization).filter_by(name="Acme Corp").first()
            if not sandbox:
                sandbox = Organization(name="Acme Corp")
                db.add(sandbox)
                db.commit()
                db.refresh(sandbox)

            systems = ["infra", "crm", "finance", "hr"]
            resources = ["prod-db", "user-records", "payroll", "api-cluster"]
            actions = ["transfer", "delete", "write", "deploy"]

            system = random.choice(systems)
            resource = random.choice(resources)
            action_type = random.choice(actions)

            amount = random.randint(100, 10000)

            context = {
                "responsible": "user-alice",
                "accountable": "user-bob",
                "approved_by": random.choice([None, "user-charlie"]),
            }

            action = {
                "type": action_type,
                "amount": amount,
                "system": system,
                "resource": resource,
            }

            compiled_contract = {
                "contract_id": "demo-policy",
                "contract_version": "1.0.0",
                "authority_requirements": {
                    "required_roles": ["proposer", "responsible", "accountable"],
                },
                "artifact_requirements": {
                    "artifacts_present": True,
                },
                "stage_requirements": {
                    "integrity": {"artifacts_present": True},
                    "publication": {"ready": True},
                },
                "invariants": [
                    {"type": "separation_of_duties", "roles": ["responsible", "accountable"]},
                ],
            }

            decision = run_validation(compiled_contract, action, "ai-agent-v2", context)

            log = AuditLog(
                id=f"dec_{uuid.uuid4().hex[:10]}",
                organization_id=sandbox.id,
                actor="ai-agent-v2",
                action_type=action_type,
                action_domain=system,
                amount=amount,
                allowed=decision["allowed"],
                risk_level=decision.get("risk_level", "low"),
                reason=decision["reason"],
                decision_trace=json.dumps(decision.get("decision_trace", [])),
                resolved_identities=json.dumps(decision.get("resolved_identities", {})),
                impact=json.dumps(decision.get("impact", [])),
                trace_hash=decision["trace_hash"],
            )

            db.add(log)
            db.commit()

        except Exception as e:
            print("Simulation error:", e)
        finally:
            if db is not None:
                db.close()

        time.sleep(random.randint(3, 6))

# ---------------------------
# UI - COMPLIANCE DASHBOARD
# ---------------------------

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(db: Session = Depends(get_db)):
    return RedirectResponse(url="/#live-console", status_code=307)

@app.get("/dashboard/embed", response_class=HTMLResponse)
def dashboard_embed(db: Session = Depends(get_db)):
    """Renders the Live Enforcement Console."""
    logs = db.query(AuditLog).order_by(AuditLog.server_timestamp.desc()).limit(100).all()
    latest_org = "Global View"
    allowed_count = sum(1 for log in logs if log.allowed)
    blocked_count = len(logs) - allowed_count

    rows_html = ""
    for log in logs:
        risk_level = (log.risk_level or "low").lower()
        action_type = log.action_type or "unknown"
        ts = log.server_timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.server_timestamp else "Recent"
        system_display = f"{log.action_domain or 'unknown'}/{action_type}"
        details_display = f"{action_type} | ${log.amount:,.0f}" if log.amount else action_type

        rows_html += f"""
        <tr style="border-bottom: 1px solid var(--border);">
            <td class="td-time">{ts}</td>
            <td class="td-mono">{system_display}</td>
            <td class="td-id">{log.id}</td>
            <td><span class="badge risk-{risk_level}">{risk_level.upper()}</span></td>
            <td class="td-mono">{log.actor}</td>
            <td class="td-reason">{details_display}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8" />
    <title>Waveframe Guard - Live Enforcement Console</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet" />
    <style>
      :root {{ --bg: #07090d; --surface: #0d1018; --surface2: #111520; --surface3: #161b27; --border: #1c2030; --border2: #242840; --text: #dce3f0; --muted: #4a5270; --muted2: #6b7494; --green: #00d97e; --red: #ff3d5a; --blue: #4d7cfe; --mono: 'IBM Plex Mono', monospace; --sans: 'IBM Plex Sans', sans-serif; }}
      * {{ box-sizing: border-box; margin: 0; padding: 0; }}
      body {{ background: radial-gradient(circle at top, #111726 0%, var(--bg) 42%); color: var(--text); font-family: var(--sans); padding: 0 0 60px; }}
      .header {{ display: flex; align-items: center; justify-content: space-between; padding: 0 32px; min-height: 72px; border-bottom: 1px solid var(--border); background: rgba(13, 16, 24, 0.92); backdrop-filter: blur(10px); position: sticky; top: 0; z-index: 5; }}
      .logo {{ font-family: var(--mono); font-size: 13px; font-weight: 600; letter-spacing: 0.06em; }}
      .logo span {{ color: var(--green); }}
      .header-actions {{ display: flex; align-items: center; gap: 12px; }}
      .console-nav {{ display: inline-flex; align-items: center; gap: 8px; padding: 10px 14px; border-radius: 999px; border: 1px solid var(--border2); background: rgba(255,255,255,0.03); color: var(--text); text-decoration: none; font-family: var(--mono); font-size: 11px; letter-spacing: 0.04em; text-transform: uppercase; }}
      .console-nav.primary {{ background: rgba(77, 124, 254, 0.12); border-color: rgba(77, 124, 254, 0.35); }}
      .console-nav:hover {{ background: rgba(255,255,255,0.08); }}
      .page {{ padding: 28px 32px 0; max-width: 1440px; margin: 0 auto; }}
      .hero {{ display: grid; grid-template-columns: 1.6fr 1fr; gap: 20px; margin-bottom: 22px; }}
      .hero-card {{ background: linear-gradient(180deg, rgba(22,27,39,0.95) 0%, rgba(13,16,24,0.98) 100%); border: 1px solid var(--border2); border-radius: 16px; padding: 22px 24px; box-shadow: 0 20px 60px rgba(0,0,0,0.28); }}
      .eyebrow {{ font-family: var(--mono); font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: var(--blue); margin-bottom: 10px; }}
      .hero-title {{ font-size: 34px; line-height: 1.05; font-weight: 600; margin-bottom: 10px; }}
      .hero-copy {{ color: var(--muted2); max-width: 760px; line-height: 1.6; }}
      .hero-meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }}
      .pill {{ display: inline-flex; align-items: center; gap: 8px; padding: 9px 12px; border-radius: 999px; border: 1px solid var(--border2); background: rgba(255,255,255,0.03); font-family: var(--mono); font-size: 11px; color: var(--muted2); text-transform: uppercase; letter-spacing: 0.05em; }}
      .live-dot {{ width: 8px; height: 8px; border-radius: 999px; background: var(--green); box-shadow: 0 0 0 6px rgba(0,217,126,0.12); }}
      .hero-stats {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }}
      .stat-card {{ background: var(--surface3); border: 1px solid var(--border2); border-radius: 14px; padding: 18px; }}
      .stat-label {{ font-family: var(--mono); font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 10px; }}
      .stat-value {{ font-size: 28px; font-weight: 600; margin-bottom: 6px; }}
      .stat-note {{ font-size: 12px; color: var(--muted2); }}
      .panel {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.22); }}
      .panel-head {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 18px; border-bottom: 1px solid var(--border); background: var(--surface2); }}
      .panel-title-wrap {{ display: flex; flex-direction: column; gap: 4px; }}
      .panel-kicker {{ font-family: var(--mono); font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.12em; color: var(--blue); }}
      .panel-title {{ font-size: 18px; font-weight: 600; }}
      .panel-subtitle {{ color: var(--muted2); font-size: 13px; }}
      .panel-status {{ display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 999px; border: 1px solid rgba(0,217,126,0.18); background: rgba(0,217,126,0.08); color: #9ff5c9; font-family: var(--mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; white-space: nowrap; }}
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
      .risk-low {{ color: #2ea043; background: rgba(46,160,67,0.12); border: 1px solid rgba(46,160,67,0.35); }}
      .risk-medium {{ color: #d29922; background: rgba(210,153,34,0.12); border: 1px solid rgba(210,153,34,0.35); }}
      .risk-high {{ color: #f85149; background: rgba(248,81,73,0.12); border: 1px solid rgba(248,81,73,0.35); }}
      .risk-critical {{ color: #ff3d5a; background: rgba(255,61,90,0.18); border: 1px solid rgba(255,61,90,0.5); box-shadow: 0 0 12px rgba(255,61,90,0.25); }}
      .btn-secondary {{ background: linear-gradient(135deg, #1f2937, #111827); border: 1px solid #374151; color: #e5e7eb; padding: 8px 12px; border-radius: 8px; cursor: pointer; }}
      .btn-secondary:hover {{ border-color: #f97316; box-shadow: 0 0 10px rgba(249,115,22,0.25); }}
      .feed-shell {{ overflow-x: auto; }}
      .feed-empty {{ text-align: center; padding: 20px; color: var(--muted); }}
      .feed-footer {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 12px 18px; border-top: 1px solid var(--border); background: rgba(255,255,255,0.02); color: var(--muted2); font-family: var(--mono); font-size: 11px; }}
      .feed-meta {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
      .feed-tag {{ padding: 6px 9px; border-radius: 999px; border: 1px solid var(--border2); background: rgba(255,255,255,0.03); }}
      @keyframes fadeInRow {{
        from {{
          opacity: 0;
          transform: translateY(-6px);
        }}
        to {{
          opacity: 1;
          transform: translateY(0);
        }}
      }}
      .new-row {{ animation: fadeInRow 0.4s ease; }}
      @media (max-width: 1040px) {{ .hero {{ grid-template-columns: 1fr; }} }}
      @media (max-width: 760px) {{ .header {{ padding: 14px 18px; flex-direction: column; align-items: flex-start; gap: 12px; }} .page {{ padding: 20px 18px 0; }} .hero-stats {{ grid-template-columns: 1fr; }} .panel-head, .feed-footer {{ align-items: flex-start; flex-direction: column; }} }}
    </style>
    </head>
    <body>
    <header class="header">
      <div class="logo">
          WAVEFRAME <span>GUARD</span><br/>
          <span style="font-size:10px; color: var(--muted);">
              Scope: All Organizations
          </span>
      </div>
      <div class="header-actions">
        <div>
          <div style="font-size:10px; color:var(--muted); margin-bottom:4px;">
              Organization Scope
          </div>
          <select id="orgFilter" onchange="refreshLogs()">
            <option value="">All Orgs</option>
          </select>
        </div>
        <a href="/" class="console-nav">Back to Dev Environment</a>
        <a href="/dashboard" target="_top" class="console-nav primary">Open Full Console</a>
      </div>
    </header>
    <div style="
        font-size:11px;
        color: var(--muted);
        margin: 6px 32px 0;
        font-family: var(--mono);
    ">
        Embedded Mode - Live Console Preview
    </div>
    <div class="page">
      <section class="hero">
        <div class="hero-card">
          <div class="eyebrow">Live Enforcement Console</div>
          <div class="hero-title">Real-time governance decisions, streamed inside the control plane.</div>
          <div class="hero-copy">
            Monitor every allow and block event as it lands, keep navigation inside the console, and use this as an active operations surface instead of a static simulator page.
          </div>
          <div class="hero-meta">
            <div class="pill"><span class="live-dot"></span> Live feed active</div>
            <div class="pill">Scope: All Organizations</div>
            <div class="pill">Environment: Live Enforcement</div>
            <div class="pill">Refresh: 2 seconds</div>
          </div>
        </div>
        <div class="hero-stats">
          <div class="stat-card">
            <div class="stat-label">Allowed Decisions</div>
            <div class="stat-value" id="allowedCount">{allowed_count}</div>
            <div class="stat-note">Successful actions cleared by policy enforcement.</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Blocked Decisions</div>
            <div class="stat-value" id="blockedCount">{blocked_count}</div>
            <div class="stat-note">Requests stopped before execution at the boundary.</div>
          </div>
        </div>
      </section>
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title-wrap">
            <div class="panel-kicker">Streaming Feed</div>
            <div class="panel-title">Live Enforcement Console</div>
            <div class="panel-subtitle">Real-time execution control layer — every AI action is evaluated before it becomes real.</div>
          </div>
          <div class="panel-status"><span class="live-dot"></span> <span id="liveStatus">Connected</span></div>
        </div>
        <div class="feed-shell">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>System</th>
                <th>Decision</th>
                <th>Status</th>
                <th>Actor</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody id="logRows">
              {rows_html if rows_html else '<tr><td colspan="6" class="feed-empty">No events yet. Trigger the dev environment or SDK to start the live feed.</td></tr>'}
            </tbody>
          </table>
        </div>
        <div class="feed-footer">
          <div class="feed-meta">
            <span class="feed-tag">Source: /api/logs</span>
            <span class="feed-tag">Window: 100 decisions</span>
          </div>
          <div id="lastUpdated">Last refresh: waiting for feed...</div>
        </div>
      </div>
      <div id="inspectorPanel" style="
          position: fixed;
          top: 0;
          right: -500px;
          width: 500px;
          height: 100%;
          background: #0d1018;
          border-left: 1px solid var(--border);
          padding: 20px;
          overflow-y: auto;
          transition: right 0.3s ease;
          z-index: 100;
      ">
          <h3>Decision Details</h3>
          <div id="inspectorContent">Click a log entry</div>
      </div>
    </div>
    <script>
    function formatAmount(amount) {{
        return amount ? `$${{Number(amount).toLocaleString()}}` : "—";
    }}

    function updateSummary(logs) {{
        const allowed = logs.filter(log => !!log.allowed).length;
        const blocked = logs.length - allowed;
        const allowedNode = document.getElementById("allowedCount");
        const blockedNode = document.getElementById("blockedCount");
        if (allowedNode) allowedNode.textContent = String(allowed);
        if (blockedNode) blockedNode.textContent = String(blocked);
    }}

    async function loadOrgs() {{
        const res = await fetch("/api/orgs");
        const data = await res.json();

        const select = document.getElementById("orgFilter");
        select.innerHTML = `<option value="">All Orgs</option>` +
            data.orgs.map(o => `<option value="${{o}}">${{o}}</option>`).join("");
    }}

    async function refreshLogs() {{
        try {{
            const org = document.getElementById("orgFilter")?.value || "";
            const res = await fetch(`/api/logs?limit=100&org=${{org}}`);
            const data = await res.json();

            const tbody = document.getElementById("logRows");
            const liveStatus = document.getElementById("liveStatus");
            const lastUpdated = document.getElementById("lastUpdated");
            if (!tbody) return;

            if (liveStatus) liveStatus.textContent = "Connected";
            updateSummary(data.logs || []);

            if (!data.logs || data.logs.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" class="feed-empty">No events yet. Trigger the dev environment or SDK to start the live feed.</td></tr>';
                window.previousLogIds = [];
                if (lastUpdated) lastUpdated.textContent = "Last refresh: live feed online, waiting for first decision";
                return;
            }}

            let previousIds = window.previousLogIds || [];

            tbody.innerHTML = data.logs.map(log => {{
                const isNew = !previousIds.includes(log.decision_id);
                const risk = log.risk_level || "low";
                const riskClass = `risk-${{risk}}`;

                const ts = log.server_timestamp
                    ? new Date(log.server_timestamp).toLocaleString()
                    : "Recent";

                return `
                <tr class="${{isNew ? 'new-row' : ''}}"
                    onclick="openInspector('${{log.decision_id}}')"
                    style="cursor:pointer; border-bottom: 1px solid var(--border);">
                    <td class="td-time">${{ts}}</td>
                    <td class="td-mono">${{log.domain}}/${{log.action.type}}</td>
                    <td class="td-id">${{log.decision_id}}</td>
                    <td>
                        <span class="badge ${{riskClass}}">
                            ${{risk.toUpperCase()}}
                        </span>
                    </td>
                    <td class="td-mono">${{log.actor}}</td>
                    <td class="td-reason">${{log.action.type}} | ${{log.action.amount ? "$" + Number(log.action.amount).toLocaleString() : ""}}</td>
                </tr>
                `;
            }}).join("");

            window.previousLogIds = data.logs.map(l => l.decision_id);

            if (lastUpdated) {{
                lastUpdated.textContent = `Last refresh: ${{new Date().toLocaleTimeString()}}`;
            }}

        }} catch (err) {{
            const liveStatus = document.getElementById("liveStatus");
            const lastUpdated = document.getElementById("lastUpdated");
            if (liveStatus) liveStatus.textContent = "Reconnect";
            if (lastUpdated) lastUpdated.textContent = "Last refresh: feed error";
            console.error("Live refresh failed", err);
        }}
    }}

    function closeInspector() {{
        const panel = document.getElementById("inspectorPanel");
        if (!panel) return;
        panel.style.right = "-500px";
        panel.dataset.activeId = "";
    }}

    async function openInspector(id) {{
        const panel = document.getElementById("inspectorPanel");
        const content = document.getElementById("inspectorContent");

        if (panel.dataset.activeId === id && panel.style.right === "0px") {{
            closeInspector();
            return;
        }}

        panel.dataset.activeId = id;
        panel.style.right = "0px";
        content.innerHTML = "Loading...";

        try {{
            const res = await fetch(`/api/log/${{id}}`);
            const log = await res.json();

            content.innerHTML = `
                <div style="margin-bottom:12px;">
                    <span class="badge risk-${{log.risk_level || "low"}}">
                        ${{(log.risk_level || "low").toUpperCase()}} RISK
                    </span>
                </div>
                <div style="margin-bottom:16px;">
                    <div style="font-size:12px; color:gray;">Proposed Action</div>
                    <div><strong>${{log.action.type}}</strong></div>
                    <div style="color:gray; font-size:12px;">
                        ${{log.amount ? "$" + Number(log.amount).toLocaleString() : "No amount"}}
                    </div>
                </div>

                <div style="margin-bottom:16px;">
                    <div style="font-size:18px; font-weight:600;">
                        ${{log.allowed ? "✅ Execution Approved" : "🚫 Execution Blocked"}}
                    </div>
                </div>

                <p><strong>Policy:</strong> ${{log.policy_id || "finance-core"}}</p>

                <div style="margin-bottom:16px;">
                    <div style="font-size:12px; color:gray;">Summary</div>
                    <div>${{log.reason}}</div>
                </div>

                <div style="margin-bottom:16px;">
                    <div style="font-size:12px; color:gray;">Execution Roles</div>
                    <div>Proposer: ${{log.resolved_identities?.proposer || "—"}}</div>
                    <div>Responsible: ${{log.resolved_identities?.responsible || "—"}}</div>
                    <div>Accountable: ${{log.resolved_identities?.accountable || "—"}}</div>
                    <div>Approver: ${{log.resolved_identities?.approver || "—"}}</div>
                </div>

                <div style="margin-bottom:16px;">
                    <div style="font-size:12px; color:gray;">Decision Trace</div>
                    ${{(log.decision_trace || []).map(step => `
                        <div>
                            ${{step.stage}}: ${{step.passed ? "PASS" : "FAIL"}}
                        </div>
                    `).join("")}}
                </div>

                <div style="margin-bottom:16px;">
                    <div style="font-size:12px; color:gray;">Trace Hash</div>
                    <div style="word-break:break-all;">${{log.trace_hash}}</div>
                </div>

                <button id="downloadAuditBtn" class="btn-secondary">
                    Download Audit Record
                </button>

                <div style="margin-top:16px;">
                    <small>${{log.server_timestamp}}</small>
                </div>
            `;

            const decisionId = log.decision_id;
            document.getElementById("downloadAuditBtn").onclick = async () => {{
                const res = await fetch(`/api/audit/${{decisionId}}`);
                const data = await res.json();

                const blob = new Blob([JSON.stringify(data, null, 2)], {{
                    type: "application/json"
                }});

                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");

                a.href = url;
                a.download = `audit_${{decisionId}}.json`;
                a.click();

                window.URL.revokeObjectURL(url);
            }};
        }} catch (err) {{
            content.innerHTML = "Failed to load details";
        }}
    }}

    document.addEventListener("click", (e) => {{
        if (e.target.closest("tr")) return;
        if (!e.target.closest("#inspectorPanel")) {{
            closeInspector();
        }}
    }});

    setInterval(refreshLogs, 2000);
    loadOrgs();
    refreshLogs();

    if (window.self !== window.top) {{
        const navLinks = document.querySelectorAll("a.console-nav.primary");
        navLinks.forEach(link => {{
            link.innerText = "Open Full Console";
            link.setAttribute("target", "_top");
        }});
    }}
    </script>
    </body>
    </html>
    """

# ---------------------------
# UI - POLICY SIMULATION
# ---------------------------

@app.get("/", response_class=HTMLResponse)
def ui():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Waveframe Guard — Policy Simulation</title>
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
        .console-section { margin-top: 28px; }
        .console-frame { width: 100%; min-height: 1180px; border: 1px solid var(--border); border-radius: 14px; background: #0d1018; box-shadow: var(--shadow); }

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
            <h1>Waveframe Guard — Policy Simulation</h1>
            <div style="margin-top:6px; color:#6b7494; font-size:13px;">
                Running in: <strong>Dev Environment</strong>
            </div>
            <div style="
                font-size:11px;
                color: var(--muted);
                margin-top:6px;
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            ">
                Development Environment - Simulation Only (No Audit Guarantees)
            </div>
            <p>
                Simulate AI actions before submitting them to your governed environments.
            </p>
        </div>
        <a href="#live-console" class="dashboard-btn">View Compliance Ledger &rarr;</a>
    </div>

    <div class="layout">
        <div class="main-column">
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">Proposed System Action</h3>
                    <p class="panel-subtitle">Submit a proposed AI system action for governance evaluation before execution.</p>
                </div>
                <div class="panel-body">
                    <div style="
                        padding:10px 12px;
                        background: rgba(255,255,255,0.03);
                        border: 1px solid var(--border);
                        border-radius: 8px;
                        font-size:12px;
                        color: var(--muted);
                        margin-bottom: 16px;
                    ">
                        Every action submitted here is evaluated against governance policy before execution.
                    </div>
                    <div class="top-grid">
                        <div>
                            <div class="form-group">
                                <label>Target System</label>
                                <select id="system">
                                    <option value="finance">Finance System</option>
                                    <option value="hr">HR System</option>
                                    <option value="infra">Infrastructure</option>
                                    <option value="crm">Customer Data</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Target Resource</label>
                                <input id="resource" placeholder="e.g. payroll-account, prod-db, user-records" />
                            </div>
                            <div class="form-group">
                                <label>Action Type</label>
                                <select id="actionType">
                                    <option value="transfer">Transfer Funds</option>
                                    <option value="write">Write Data</option>
                                    <option value="delete">Delete Resource</option>
                                    <option value="deploy">Deploy Service</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Impact Value</label>
                                <input id="amount" type="number" value="5000" placeholder="Optional — e.g. cost, risk score, data volume" />
                            </div>
                            <div class="form-group">
                                <label>Proposing Actor</label>
                                <input value="ai-agent-v2" disabled />
                            </div>
                        </div>

                        <div>
                            <div class="form-group">
                                <label>Executor</label>
                                <select id="responsible">
                                    <option value="user-alice" selected>Alice (Platform Admin)</option>
                                    <option value="user-bob">Bob (System Owner)</option>
                                    <option value="user-charlie">Charlie (Security Lead)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>System Owner</label>
                                <select id="accountable">
                                    <option value="user-alice">Alice (Platform Admin)</option>
                                    <option value="user-bob" selected>Bob (System Owner)</option>
                                    <option value="user-charlie">Charlie (Security Lead)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Authorizer</label>
                                <select id="approved_by">
                                    <option value="">None</option>
                                    <option value="user-alice">Alice (Platform Admin)</option>
                                    <option value="user-bob">Bob (System Owner)</option>
                                    <option value="user-charlie">Charlie (Security Lead)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Policy</label>
                                <select id="policySelect">
                                    <option value="finance-core">finance-core</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Governance Policy</label>
                                <div class="reason-box">
                                    <div><strong>Policy:</strong> finance-core (v1.2)</div>
                                    <div style="margin-top:6px;"><strong>Approval threshold:</strong> $1,000</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="cta">
                        <button onclick="runValidation()" id="submitBtn">Evaluate Action</button>
                        <button onclick="sendToProduction()" style="margin-top:10px;">
                            Submit for Enforcement (Acme Corp)
                        </button>
                        <div style="margin-top:10px; font-size:12px; color:#6b7494;">
                            This action will be evaluated locally, then optionally submitted to a governed organization.
                        </div>
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
                        <a href="#live-console" style="color: var(--accent); text-decoration: none; font-weight: 600;">View Ledger</a>
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
                        <div class="identity-value">proposer, executor, system owner</div>
                    </div>
                    <div class="identity-item">
                        <div class="identity-key">Rule</div>
                        <div class="identity-value">Executor and authorizer must remain independent</div>
                    </div>
                    <div class="identity-item">
                        <div class="identity-key">Policy</div>
                        <div class="identity-value">finance-core (v1.2)</div>
                    </div>
                    <div class="identity-item">
                        <div class="identity-key">Approval threshold</div>
                        <div class="identity-value">$1,000</div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="live-console" class="console-section">
        <div class="panel">
            <div class="panel-header">
                <h3 class="panel-title">Live Enforcement Console</h3>
                <p class="panel-subtitle">Dev environment decisions and ledger monitoring now live in one place.</p>
            </div>
            <div class="panel-body" style="padding: 0;">
                <iframe
                    title="Live Enforcement Console"
                    src="/dashboard/embed"
                    class="console-frame"
                ></iframe>
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
    "publication-commit": { title: "Decision finalized", detail: "The final execution decision has been cryptographically sealed." },
    "approval-check": { title: "Approval threshold enforced", detail: "Ensures transactions exceeding threshold have authorized approval." }
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
    const roleLabels = {
        proposer: "Proposer",
        responsible: "Executor",
        accountable: "System Owner",
        approver: "Authorizer"
    };

    if (!resolved || Object.keys(resolved).length === 0) {
        identityEmpty.style.display = "block";
        return;
    }
    identityEmpty.style.display = "none";

    Object.entries(resolved).forEach(([key, value]) => {
        const li = document.createElement("li");
        li.className = "identity-item";
        li.innerHTML = `
            <div class="identity-key">${escapeHtml(roleLabels[key] || key)}</div>
            <div class="identity-value">${escapeHtml(value || "None")}</div>
        `;
        identityList.appendChild(li);
    });
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
    if (r.includes("separation") || r.includes("multiple required roles")) {
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
        const actionType = document.getElementById("actionType").value;
        const system = document.getElementById("system").value;
        const resource = document.getElementById("resource").value;
        const responsible = document.getElementById("responsible").value;
        const accountable = document.getElementById("accountable").value;
        const approved_by = document.getElementById("approved_by").value;

        const compiledContract = {
            contract_id: "finance-core",
            contract_version: "1.2.0",
            authority_requirements: {
                required_roles: ["proposer", "responsible", "accountable"]
            },
            artifact_requirements: {
                artifacts_present: true
            },
            stage_requirements: {
                integrity: { artifacts_present: true },
                publication: { ready: true }
            },
            invariants: [
                { type: "separation_of_duties", roles: ["responsible", "accountable"] }
            ]
        };

        const context = {};
        if (responsible) context.responsible = responsible;
        if (accountable) context.accountable = accountable;
        if (approved_by) context.approved_by = approved_by;

        const res = await fetch("/validate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                compiled_contract: compiledContract,
                action: {
                    type: actionType,
                    amount,
                    system,
                    resource
                },
                actor: "ai-agent-v2",
                context
            })
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

        document.getElementById("resSummary").innerHTML = `<strong>AI attempted to execute ${escapeHtml(actionType)} on ${escapeHtml(system)}/${escapeHtml(resource)}</strong>`;

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

async function sendToProduction() {
    const amount = parseFloat(document.getElementById("amount").value || 0);
    const responsible = document.getElementById("responsible").value;
    const accountable = document.getElementById("accountable").value;
    const approved_by = document.getElementById("approved_by").value;

    const context = {};
    if (responsible) context.responsible = responsible;
    if (accountable) context.accountable = accountable;
    if (approved_by) context.approved_by = approved_by;

    const res = await fetch("/v1/enforce", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer wf_test_key_123"
        },
        body: JSON.stringify({
            policy_id: document.getElementById("policySelect").value,
            action: {
                type: document.getElementById("actionType").value,
                amount,
                system: document.getElementById("system").value,
                resource: document.getElementById("resource").value
            },
            actor: "ai-agent-v2",
            context
        })
    });

    const data = await res.json();
    console.log("Production decision:", data);
    alert("Sent to production org. Check dashboard.");
}
</script>

</body>
</html>
"""
