from __future__ import annotations

import json
from pathlib import Path

from examples.finance_policy_to_guard_demo import run_demo


def test_finance_policy_to_guard_demo_runs_complete_local_loop(tmp_path):
    result = run_demo(output_dir=tmp_path / "demo", emit_output=False)

    compiled_authority = result["compiled_authority"]
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
    assert result["allowed"]["reason"] == "execution allowed"
    assert result["allowed"]["function_executions_after_decision"] == 1
    assert result["allowed"]["value"] == {
        "amount": 2000000,
        "transfer_executed": True,
    }
    assert result["transfer_execution_log"] == [
        {"amount": 2000000, "function": "protected_transfer"}
    ]

    blocked_receipt = _read_json(result["blocked"]["receipt_path"])
    blocked_evidence = _read_json(result["blocked"]["evidence_path"])
    allowed_receipt = _read_json(result["allowed"]["receipt_path"])
    allowed_evidence = _read_json(result["allowed"]["evidence_path"])

    assert blocked_receipt["decision"] == "BLOCKED"
    assert blocked_receipt["event_id"] == result["blocked"]["event_id"]
    assert blocked_evidence["decision"] == "BLOCKED"
    assert blocked_evidence["event_id"] == result["blocked"]["event_id"]
    assert blocked_evidence["missing_approvals"] == [
        {
            "condition": {"field": "amount", "operator": ">", "value": 1000000},
            "role": "cfo",
        }
    ]

    assert allowed_receipt["decision"] == "ALLOWED"
    assert allowed_receipt["event_id"] == result["allowed"]["event_id"]
    assert allowed_evidence["decision"] == "ALLOWED"
    assert allowed_evidence["event_id"] == result["allowed"]["event_id"]
    assert allowed_evidence["approvals"] == [{"approved_by": "cfo-1", "role": "cfo"}]

    audit_events = [
        json.loads(line)
        for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()
    ]
    assert [event["decision"] for event in audit_events] == ["BLOCKED", "ALLOWED"]


def _read_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
