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

from waveframe_guard import Guard


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
    guard = Guard.local(
        workspace=output_root / ".guard-local",
        authorities={AUTHORITY_REF: compiled_authority},
        actor_identity={"id": "ai-agent-1", "type": "ai_agent", "role": "requester"},
        execution_context={"surface": "finance_policy_to_guard_demo", "boundary": "before_transfer"},
        evaluation_time_source=lambda: DEMO_TIME,
    )

    def transfer_impl(execution_request: dict[str, Any]) -> dict[str, Any]:
        amount = execution_request["arguments"]["amount"]
        execution_log.append({"function": "protected_transfer", "amount": amount})
        return {"transfer_executed": True, "amount": amount}

    @guard.protect(authority=AUTHORITY_REF, raise_on_block=False)
    def blocked_transfer(execution_request: dict[str, Any]) -> dict[str, Any]:
        return transfer_impl(execution_request)

    @guard.protect(
        authority=AUTHORITY_REF,
        approvals=[{"role": "cfo", "approved_by": "cfo-1"}],
        raise_on_block=False,
    )
    def approved_transfer(execution_request: dict[str, Any]) -> dict[str, Any]:
        return transfer_impl(execution_request)

    request = _normalized_transfer_request(amount=2_000_000)

    if emit_output:
        _phase("4", "AI attempts $2,000,000 transfer without CFO approval", "expect BLOCKED")
    blocked = blocked_transfer(request)
    blocked_record = guard.store.history()[-1]
    guard.store.replay(blocked_record["run_id"])
    blocked_reason = _blocked_reason(blocked_record["evaluation"])
    if emit_output:
        _decision("BLOCKED", blocked_reason, executed=len(execution_log))

    if emit_output:
        _phase("5", "AI retries with valid CFO approval and separation of duties", "expect ALLOWED")
    allowed = approved_transfer(request)
    allowed_record = guard.store.history()[-1]
    guard.store.replay(allowed_record["run_id"])
    if emit_output:
        _decision("ALLOWED", "approval evidence satisfied", executed=len(execution_log))
        _phase("6", "Inspector opens local case", str(output_root / ".guard-local"))

    result = {
        "demo": "finance_policy_to_guard",
        "authority_ref": AUTHORITY_REF,
        "policy_path": str(Path(policy_path)),
        "output_dir": str(output_root),
        "compiled_authority": compiled_authority,
        "publication": publication,
        "blocked": {
            "allowed": blocked["outcome"]["status"] == "admissible",
            "reason": blocked_reason,
            "run_id": blocked_record["run_id"],
            "outcome_id": blocked["outcome"]["outcome_id"],
            "function_executions_after_decision": 0,
            "receipt_path": _store_path(output_root, "receipts", blocked_record["run_id"]),
            "manifest_path": _store_path(output_root, "manifests", blocked_record["run_id"]),
            "replay_path": _store_path(output_root, "replays", blocked_record["run_id"]),
        },
        "allowed": {
            "allowed": allowed_record["evaluation"]["status"] == "admissible",
            "reason": "approval evidence satisfied",
            "run_id": allowed_record["run_id"],
            "outcome_id": allowed_record["guard_enforcement_outcome"]["outcome_id"],
            "function_executions_after_decision": len(execution_log),
            "value": allowed,
            "receipt_path": _store_path(output_root, "receipts", allowed_record["run_id"]),
            "manifest_path": _store_path(output_root, "manifests", allowed_record["run_id"]),
            "replay_path": _store_path(output_root, "replays", allowed_record["run_id"]),
        },
        "transfer_execution_log": execution_log,
        "guard_workspace": str(output_root / ".guard-local"),
        "history_path": str(output_root / ".guard-local" / "evaluation-history.jsonl"),
        "inspector_case_path": str(output_root / ".guard-local"),
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

    compiled_authority = _guard_sdk_authority(compile_policy(compiler_input))
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


def _guard_sdk_authority(compiled_authority: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": "compiled_authority_contract.v1", **compiled_authority}


def _normalized_transfer_request(*, amount: int) -> dict[str, Any]:
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": f"finance-transfer-{amount}",
        "action": "transfer",
        "target": "treasury_wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


def _store_path(output_root: Path, artifact_type: str, run_id: str) -> str:
    return str(output_root / ".guard-local" / artifact_type / f"{run_id}.json")


def _blocked_reason(evaluation: dict[str, Any]) -> str:
    missing = evaluation.get("required_evidence") or []
    roles = ", ".join(item["role"] for item in missing if item.get("role"))
    if roles:
        return f"required approval missing: {roles}"
    return evaluation["rationale"]


def _phase(number: str, title: str, detail: str) -> None:
    print(f"[{number}] {title}")
    print(f"    {detail}")


def _decision(decision: str, reason: str, *, executed: int) -> None:
    print(f"    Guard decision: {decision} - {reason}")
    print(f"    Protected transfer executions: {executed}")


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
