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
    version="1.3.1",
    description="Stop unsafe AI actions before they execute.",
)

# ---------------------------
# Identity Resolver (FIXED PATH)
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent

PRIMARY_IDENTITY_PATH = BASE_DIR / "data" / "identities.json"
FALLBACK_IDENTITY_PATH = BASE_DIR / "identities.json"


def load_identity_registry() -> Dict[str, Any]:
    path = None

    if PRIMARY_IDENTITY_PATH.exists():
        path = PRIMARY_IDENTITY_PATH
    elif FALLBACK_IDENTITY_PATH.exists():
        path = FALLBACK_IDENTITY_PATH
    else:
        raise FileNotFoundError(
            f"Identity registry not found. Checked:\n"
            f"- {PRIMARY_IDENTITY_PATH}\n"
            f"- {FALLBACK_IDENTITY_PATH}"
        )

    with open(path, "r", encoding="utf-8") as f:
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

    if not lookup:
        return {"found": False, "reason": "blank identity"}

    identities = registry.get("identities", {})

    # Direct match
    if lookup in identities:
        record = identities[lookup]
        return {
            "found": True,
            "canonical_id": record["canonical_id"],
            "record": record,
        }

    # Alias match
    for record in identities.values():
        aliases = record.get("aliases", [])
        normalized_aliases = [normalize_lookup_key(a) for a in aliases]

        if lookup in normalized_aliases:
            return {
                "found": True,
                "canonical_id": record["canonical_id"],
                "record": record,
            }

    return {
        "found": False,
        "reason": f"unknown identity: {lookup}",
    }


def resolve_context_identities(context: Dict[str, Any]) -> tuple[bool, Dict[str, Any] | None, str | None]:
    registry = load_identity_registry()

    responsible = resolve_identity(context.get("responsible"), registry)
    accountable = resolve_identity(context.get("accountable"), registry)

    if not responsible["found"]:
        return False, None, "Blocked: responsible actor could not be resolved"

    if not accountable["found"]:
        return False, None, "Blocked: accountable actor could not be resolved"

    approver = None
    if context.get("approved_by"):
        approver = resolve_identity(context.get("approved_by"), registry)

        if not approver["found"]:
            return False, None, "Blocked: approver actor could not be resolved"

    return True, {
        "responsible": responsible["canonical_id"],
        "accountable": accountable["canonical_id"],
        "approved_by": approver["canonical_id"] if approver else None,
    }, None


# ---------------------------
# Helpers
# ---------------------------

def summarize_action(action: Dict[str, Any]) -> str:
    if action["type"] == "transfer":
        return f"AI attempted to transfer ${action['amount']:,.0f}"

    if action["type"] == "reallocate_budget":
        return f"AI attempted to reallocate ${action['amount']:,.0f}"

    return "AI attempted action"


def build_contract_binding(compiled_contract: Dict[str, Any]) -> Dict[str, Any]:
    contract_json = json.dumps(compiled_contract, sort_keys=True).encode()
    contract_hash = hashlib.sha256(contract_json).hexdigest()

    return {
        "id": compiled_contract.get("contract_id", "user-policy"),
        "version": compiled_contract.get("contract_version", "1.0.0"),
        "hash": contract_hash,
    }


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

    return "Blocked: policy requirements were not satisfied"


def extract_result(result: Any) -> tuple[bool, str]:
    allowed = getattr(result, "allowed", None)
    if allowed is None:
        allowed = getattr(result, "commit_allowed", False)

    if allowed:
        return True, "Allowed: policy conditions satisfied"

    return False, interpret_reason(result)


def normalize_mutation(action: Dict[str, Any]) -> Dict[str, Any]:
    if action["type"] == "transfer":
        return {"domain": "finance", "resource": "funds", "action": "transfer"}

    if action["type"] == "reallocate_budget":
        return {"domain": "finance", "resource": "budget", "action": "reallocate"}

    return {"domain": "general", "resource": "unknown", "action": "unknown"}


# ---------------------------
# Core pipeline
# ---------------------------

def run_validation(policy: Dict, action: Dict, actor: str, context: Dict):
    context = context or {}

    try:
        ok, resolved_context, error = resolve_context_identities(context)

        if not ok:
            return {
                "allowed": False,
                "reason": error,
                "summary": summarize_action(action),
            }

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
            json.dump(policy, f)
            policy_path = Path(f.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            output_path = Path(tmp.name)

        contract_path = compile_policy_file(policy_path, output_path)

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
                        {"id": resolved_context["responsible"], "type": "human", "role": "responsible"},
                        {"id": resolved_context["accountable"], "type": "human", "role": "accountable"},
                    ]
                    + (
                        [{"id": resolved_context["approved_by"], "type": "human", "role": "approver"}]
                        if resolved_context.get("approved_by")
                        else []
                    ),
                    "required_roles": policy.get("roles", {}).get("required", []),
                    "conflict_flags": {},
                },
                "integrity": {},
                "publication": {},
            },
        )

        result = evaluate_proposal(proposal, compiled)
        allowed, reason = extract_result(result)

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

    return JSONResponse(run_validation(policy, action, actor, context))