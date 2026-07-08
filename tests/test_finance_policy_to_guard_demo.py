from __future__ import annotations

import json
from pathlib import Path

from examples.finance_policy_to_guard_demo import run_demo


def test_finance_policy_to_guard_demo_runs_complete_public_sdk_loop(tmp_path):
    result = run_demo(output_dir=tmp_path / "demo", emit_output=False)

    compiled_authority = result["compiled_authority"]
    assert compiled_authority["schema_version"] == "compiled_authority_contract.v1"
    assert compiled_authority["approval_requirements"]["thresholds"] == [
        {
            "field": "amount",
            "operator": ">",
            "requires_role": "cfo",
            "value": 1000000,
        }
    ]
    assert compiled_authority["invariants"]["separation_of_duties"] == [
        ["requester", "approver"]
    ]

    assert result["publication"]["review_status"] == "approved"
    assert Path(result["publication"]["review_path"]).exists()
    assert Path(result["publication"]["contract_path"]).exists()
    assert Path(result["publication"]["registry_path"]).exists()

    assert result["blocked"]["allowed"] is False
    assert result["blocked"]["reason"] == "required approval missing: cfo"
    assert result["blocked"]["function_executions_after_decision"] == 0

    assert result["allowed"]["allowed"] is True
    assert result["allowed"]["reason"] == "approval evidence satisfied"
    assert result["allowed"]["function_executions_after_decision"] == 1
    assert result["allowed"]["value"] == {
        "amount": 2000000,
        "transfer_executed": True,
    }
    assert result["transfer_execution_log"] == [
        {"amount": 2000000, "function": "protected_transfer"}
    ]

    guard_workspace = Path(result["guard_workspace"])
    assert (guard_workspace / "evaluation-history.jsonl").exists()
    assert Path(result["blocked"]["receipt_path"]).exists()
    assert Path(result["blocked"]["manifest_path"]).exists()
    assert Path(result["blocked"]["replay_path"]).exists()
    assert Path(result["allowed"]["receipt_path"]).exists()
    assert Path(result["allowed"]["manifest_path"]).exists()
    assert Path(result["allowed"]["replay_path"]).exists()

    history = [
        json.loads(line)
        for line in Path(result["history_path"]).read_text(encoding="utf-8").splitlines()
    ]
    assert [record["guard_enforcement_outcome"]["status"] for record in history] == [
        "blocked",
        "admissible",
    ]
    assert history[0]["run_id"] == result["blocked"]["run_id"]
    assert history[0]["evaluation"]["required_evidence"] == [
        {
            "evidence": "approval",
            "role": "cfo",
            "condition": {"field": "amount", "operator": ">", "value": 1000000},
            "rationale": "required approval evidence is missing",
        }
    ]
    assert history[1]["run_id"] == result["allowed"]["run_id"]
    assert history[1]["inputs"]["runtime_evidence"]["approvals"] == [
        {"approved_by": "cfo-1", "role": "cfo"}
    ]

    blocked_receipt = _read_json(result["blocked"]["receipt_path"])
    allowed_receipt = _read_json(result["allowed"]["receipt_path"])
    assert blocked_receipt["schema_version"] == "guard_enforcement_receipt.v1"
    assert blocked_receipt["outcome_status"] == "blocked"
    assert blocked_receipt["run_id"] == result["blocked"]["run_id"]
    assert allowed_receipt["schema_version"] == "guard_enforcement_receipt.v1"
    assert allowed_receipt["outcome_status"] == "admissible"
    assert allowed_receipt["run_id"] == result["allowed"]["run_id"]


def _read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
