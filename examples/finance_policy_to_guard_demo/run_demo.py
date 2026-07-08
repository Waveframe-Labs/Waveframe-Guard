from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from compiler.compile_policy import compile_policy
from governance_ledger.publish import approve_review_file
from governance_ledger.runner import run_policy_file

from waveframe_guard import GovernedRuntime


POLICY_PATH = Path(__file__).with_name("policy.txt")
DEFAULT_OUTPUT_DIR = Path(__file__).with_name("demo_artifacts")
AUTHORITY_REF = "finance-policy@0.1.0"
DEMO_TIME = "2026-07-08T12:00:00+00:00"


def run_demo(
    *,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    policy_path: str | Path = POLICY_PATH,
    reset: bool = True,
    emit_output: bool = True,
) -> dict[str, Any]:
    output_root = Path(output_dir)
    if reset and output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    if emit_output:
        _phase("1", "Company writes plain-text policy", str(policy_path))

    publication = _publish_authority_from_policy(Path(policy_path), output_root)
    compiled_authority = _read_json(publication["contract_path"])
    if emit_output:
        _phase("2", "Governance-Ledger review approved", publication["review_path"])
        _phase("3", "Published compiled authority", publication["contract_path"])

    execution_log: list[dict[str, Any]] = []
    runtime = GovernedRuntime(
        registry_path=publication["registry_path"],
        audit_path=output_root / "guard" / "audit-events.jsonl",
        evidence_dir=output_root / "guard" / "evidence",
        runtime_log_path=output_root / "guard" / "runtime-log.jsonl",
        offline=True,
    )
    runtime.bind_contract(AUTHORITY_REF)
    runtime.install_actor({"id": "ai-agent-1", "type": "ai_agent", "role": "requester"})

    if emit_output:
        _phase("4", "AI attempts $2,000,000 transfer without CFO approval", "expect BLOCKED")
    blocked = runtime.execute(
        fn=lambda amount: _protected_transfer(amount, execution_log),
        args=(2_000_000,),
        approvals=[],
        raise_on_block=False,
    )
    blocked_artifacts = _persist_decision(output_root, "blocked", blocked)
    if emit_output:
        _decision("BLOCKED", blocked.reason, executed=len(execution_log))

    if emit_output:
        _phase("5", "AI retries with valid CFO approval and separation of duties", "expect ALLOWED")
    allowed = runtime.execute(
        fn=lambda amount: _protected_transfer(amount, execution_log),
        args=(2_000_000,),
        approvals=[{"role": "cfo", "approved_by": "cfo-1"}],
        raise_on_block=False,
    )
    allowed_artifacts = _persist_decision(output_root, "allowed", allowed)
    if emit_output:
        _decision("ALLOWED", allowed.reason, executed=len(execution_log))
        _phase("6", "Inspector opens local case", str(output_root / "guard"))

    result = {
        "demo": "finance_policy_to_guard",
        "authority_ref": AUTHORITY_REF,
        "policy_path": str(Path(policy_path)),
        "output_dir": str(output_root),
        "compiled_authority": compiled_authority,
        "publication": publication,
        "blocked": {
            "allowed": blocked.allowed,
            "reason": blocked.reason,
            "event_id": blocked.event["event_id"],
            "function_executions_after_decision": 0,
            "receipt_path": blocked_artifacts["receipt_path"],
            "evidence_path": blocked_artifacts["evidence_path"],
        },
        "allowed": {
            "allowed": allowed.allowed,
            "reason": allowed.reason,
            "event_id": allowed.event["event_id"],
            "function_executions_after_decision": len(execution_log),
            "value": allowed.value,
            "receipt_path": allowed_artifacts["receipt_path"],
            "evidence_path": allowed_artifacts["evidence_path"],
        },
        "transfer_execution_log": execution_log,
        "audit_path": str(output_root / "guard" / "audit-events.jsonl"),
        "evidence_dir": str(output_root / "guard" / "evidence"),
        "inspector_case_path": str(output_root / "guard"),
    }
    (output_root / "demo-result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def _publish_authority_from_policy(policy_path: Path, output_root: Path) -> dict[str, Any]:
    ledger_root = output_root / "ledger"
    generated_dir = ledger_root / "generated"
    reviews_dir = ledger_root / "reviews"
    contracts_dir = output_root / "published" / "contracts"
    receipts_dir = output_root / "published" / "receipts"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    receipts_dir.mkdir(parents=True, exist_ok=True)

    ledger_result = run_policy_file(
        policy_path,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )
    review_path = Path(ledger_result["review"])
    approved_review = approve_review_file(
        review_path,
        actor="finance-governance-board",
        timestamp=DEMO_TIME,
        note="Approved finance transfer authority for local Guard enforcement demo.",
    )

    compiler_input = _compiler_input_from_ledger_policy(_read_json(ledger_result["generated"]))
    compiler_input_path = generated_dir / f"{policy_path.stem}.compiler-input.json"
    _write_json(compiler_input_path, compiler_input)

    compiled_authority = compile_policy(compiler_input)
    contract_path = contracts_dir / (
        f"{compiled_authority['contract_id']}-{compiled_authority['contract_version']}.contract.json"
    )
    _write_json(contract_path, compiled_authority)

    registry_path = contracts_dir / "index.json"
    registry = {
        "contracts": [
            {
                "authority_ref": AUTHORITY_REF,
                "contract_ref": AUTHORITY_REF,
                "contract_id": compiled_authority["contract_id"],
                "contract_version": compiled_authority["contract_version"],
                "contract_hash": f"sha256:{compiled_authority['contract_hash']}",
                "path": contract_path.name,
                "published_at": DEMO_TIME,
                "published_by": "finance-governance-board",
                "review_id": approved_review["review_id"],
            }
        ]
    }
    registry["registry_hash"] = _stable_hash(registry)
    _write_json(registry_path, registry)

    publication_receipt = {
        "schema_version": "finance_policy_to_guard_publication_receipt.v1",
        "authority_ref": AUTHORITY_REF,
        "contract_hash": f"sha256:{compiled_authority['contract_hash']}",
        "compiler_input_path": str(compiler_input_path),
        "contract_path": str(contract_path),
        "policy_path": str(policy_path),
        "published_at": DEMO_TIME,
        "published_by": "finance-governance-board",
        "review_id": approved_review["review_id"],
        "review_path": str(review_path),
    }
    publication_receipt["receipt_hash"] = _stable_hash(publication_receipt)
    publication_receipt_path = receipts_dir / "publication-receipt.json"
    _write_json(publication_receipt_path, publication_receipt)

    return {
        "policy_path": str(policy_path),
        "generated_path": ledger_result["generated"],
        "compiler_input_path": str(compiler_input_path),
        "review_path": str(review_path),
        "contract_path": str(contract_path),
        "registry_path": str(registry_path),
        "publication_receipt_path": str(publication_receipt_path),
        "review_status": approved_review["review_status"],
    }


def _compiler_input_from_ledger_policy(ledger_policy: dict[str, Any]) -> dict[str, Any]:
    compiler_input: dict[str, Any] = {
        "contract_id": ledger_policy["contract_id"],
        "contract_version": ledger_policy["contract_version"],
    }
    approvals = ledger_policy.get("approvals") or {}
    if approvals.get("thresholds"):
        compiler_input["approvals"] = {"thresholds": approvals["thresholds"]}
    artifacts = ledger_policy.get("artifacts") or {}
    if artifacts:
        compiler_input["artifacts"] = artifacts
    if (ledger_policy.get("authority") or {}).get("separation_of_duties") is True:
        compiler_input["constraints"] = [
            {"type": "separation_of_duties", "roles": ["requester", "approver"]}
        ]
    return compiler_input


def _protected_transfer(amount: int, execution_log: list[dict[str, Any]]) -> dict[str, Any]:
    execution_log.append({"function": "protected_transfer", "amount": amount})
    return {"transfer_executed": True, "amount": amount}


def _persist_decision(output_root: Path, label: str, decision: Any) -> dict[str, str]:
    receipt_dir = output_root / "guard" / "receipts"
    evidence_dir = output_root / "guard" / "decision-evidence"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    receipt_path = receipt_dir / f"{label}-decision.json"
    evidence_path = evidence_dir / f"{label}-event.json"
    receipt_path.write_text(
        json.dumps(decision.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    evidence_path.write_text(
        json.dumps(decision.event, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {"receipt_path": str(receipt_path), "evidence_path": str(evidence_path)}


def _phase(number: str, title: str, detail: str) -> None:
    print(f"[{number}] {title}")
    print(f"    {detail}")


def _decision(decision: str, reason: str, *, executed: int) -> None:
    print(f"    Guard decision: {decision} ({reason})")
    print(f"    Protected transfer executions so far: {executed}")


def _read_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stable_hash(payload: dict[str, Any]) -> str:
    import hashlib

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


if __name__ == "__main__":
    run_demo()
