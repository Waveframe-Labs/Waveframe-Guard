from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path


from governance_ledger.extract import extract_constraints
from governance_ledger.cli import main as governance_cli
from governance_ledger.publish import publish_review_file
from governance_ledger.replay import replay_admissibility, replay_governance_compilation
from governance_ledger.review import build_review_report
from governance_ledger.lifecycle import transition_review_status
from compiler.compile_policy import compile_policy


def test_replay_reproduces_source_report_and_contract_hashes():
    source = "Transfers above $1000000 require manager approval."
    policy = extract_constraints(source)
    review = build_review_report(source, policy)
    contract = _compile_with_lineage(policy, review)

    replay = replay_governance_compilation(
        source_text=source,
        expected_report=review["compilation_report"],
        expected_contract=contract,
    )

    assert replay["replay_verified"] is True
    assert replay["diagnostics"] == []
    assert replay["source_governance"]["source_hash"] == review["source_hash"]
    assert replay["compilation_report"]["report_hash"] == review["compilation_report"]["report_hash"]
    assert replay["compiled_contract"]["contract_hash"] == contract["contract_hash"]


def test_replay_reproduces_admissibility_decision(monkeypatch):
    source = "Transfers above $1000000 require manager approval."
    contract = _authority_contract(extract_constraints(source))
    execution_state = {
        "schema_version": "governed_execution_state.v1",
        "authority_ref": "finance-policy@0.1.0",
        "actor": {"id": "employee-1", "type": "human", "role": "employee"},
        "approvals": [],
        "action": "transfer",
        "target": "transfer",
        "arguments": {"amount": 1250000},
        "artifacts": [],
    }

    replay = replay_admissibility(
        authority_contract=contract,
        execution_state=execution_state,
        evaluator=_evaluate_admissibility,
    )

    assert replay["schema_version"] == "governance_replay_admissibility.v1"
    assert replay["decision"] == "BLOCKED"
    assert replay["reason"] == "required approval missing: manager"
    assert replay["missing_approvals"] == [
        {
            "role": "manager",
            "condition": {
                "field": "amount",
                "operator": ">",
                "value": 1000000,
            },
        }
    ]


def test_replay_reproduces_published_authority_lineage(tmp_path):
    source = "Transfers above $1000000 require manager approval."
    policy = extract_constraints(source)
    review = build_review_report(source, policy)
    review = transition_review_status(review, "reviewed", actor="governance-team")
    review = transition_review_status(review, "approved", actor="governance-team")

    generated_dir = tmp_path / "generated"
    reviews_dir = tmp_path / "reviews"
    contracts_dir = tmp_path / "contracts"
    snapshots_dir = tmp_path / "snapshots"
    for path in [generated_dir, reviews_dir, contracts_dir, snapshots_dir]:
        path.mkdir(parents=True)

    (generated_dir / "finance_policy.generated.json").write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    review_path = reviews_dir / "finance_policy.review.json"
    review_path.write_text(
        json.dumps(review, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    publication = publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-15T12:00:00Z",
    )
    contract = json.loads(Path(publication["contract"]).read_text(encoding="utf-8"))

    replay = replay_governance_compilation(
        source_text=source,
        expected_report=review["compilation_report"],
        expected_contract=contract,
    )

    assert replay["replay_verified"] is True
    assert replay["compiled_contract"]["schema_version"] == "compiled_authority_contract.v1"
    assert replay["compiled_contract"]["lineage"]["source_hash"] == review["source_hash"]
    assert replay["compiled_contract"]["contract_hash"] == contract["contract_hash"]


def test_replay_emits_lineage_diagnostics_for_mismatched_authority_source():
    source = "Transfers above $1000000 require manager approval."
    policy = extract_constraints(source)
    review = build_review_report(source, policy)
    contract = _compile_with_explicit_lineage(
        policy,
        {
            "schema_version": "governance_authority_lineage.v1",
            "source_hash": "sha256:wrong-source",
            "compilation_report_hash": review["compilation_report"]["report_hash"],
            "review_id": review["review_id"],
        },
    )

    replay = replay_governance_compilation(
        source_text=source,
        expected_report=review["compilation_report"],
        expected_contract=contract,
    )

    assert replay["replay_verified"] is False
    assert _codes(replay) == {"G801"}
    assert replay["checks"]["authority_source_hash_match"] is False


def test_replay_emits_report_hash_diagnostic_for_mismatched_report_lineage():
    source = "Transfers above $1000000 require manager approval."
    policy = extract_constraints(source)
    review = build_review_report(source, policy)
    contract = _compile_with_explicit_lineage(
        policy,
        {
            "schema_version": "governance_authority_lineage.v1",
            "source_hash": review["source_hash"],
            "compilation_report_hash": "sha256:wrong-report",
            "review_id": review["review_id"],
        },
    )

    replay = replay_governance_compilation(
        source_text=source,
        expected_report=review["compilation_report"],
        expected_contract=contract,
    )

    assert replay["replay_verified"] is False
    assert _codes(replay) == {"G802"}
    assert replay["checks"]["authority_compilation_report_hash_match"] is False


def test_admissibility_replay_emits_missing_provenance_diagnostic(monkeypatch):
    source = "Transfers above $1000000 require manager approval."
    contract = _authority_contract(extract_constraints(source))
    execution_state = {
        "schema_version": "governed_execution_state.v1",
        "authority_ref": "finance-policy@0.1.0",
        "actor": {"id": "employee-1", "type": "human", "role": "employee"},
        "approvals": [],
        "action": "transfer",
        "target": "transfer",
        "arguments": {"amount": 1250000},
        "artifacts": [],
    }

    replay = replay_admissibility(
        authority_contract=contract,
        execution_state=execution_state,
        evaluator=_evaluate_admissibility,
    )

    assert replay["decision"] == "BLOCKED"
    assert replay["lineage_verified"] is False
    assert _codes(replay) == {"G803"}


def test_cli_verify_lineage_fails_closed_for_missing_provenance(tmp_path, capsys):
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        json.dumps(compile_policy(extract_constraints("Transfers above $1000000 require manager approval."))),
        encoding="utf-8",
    )

    exit_code = governance_cli(["verify-lineage", "--contract", str(contract_path)])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Status: FAILED" in captured.out
    assert "ERROR G803" in captured.out


def _with_lineage(policy: dict, review: dict) -> dict:
    return {
        **policy,
        "lineage": {
            "schema_version": "governance_authority_lineage.v1",
            "source_hash": review["source_hash"],
            "compilation_report_hash": review["compilation_report"]["report_hash"],
            "review_id": review["review_id"],
        },
    }


def _compile_with_lineage(policy: dict, review: dict) -> dict:
    return _compile_with_explicit_lineage(policy, _with_lineage(policy, review)["lineage"])


def _compile_with_explicit_lineage(policy: dict, lineage: dict) -> dict:
    compiled = compile_policy({**policy, "lineage": lineage})
    if compiled.get("lineage") != lineage:
        compiled = {**compiled, "lineage": lineage}
        compiled["contract_hash"] = _contract_hash(compiled)
    return compiled


def _authority_contract(policy: dict) -> dict:
    compiled = compile_policy(policy)
    if not compiled.get("approval_requirements", {}).get("required"):
        compiled = {
            **compiled,
            "approval_requirements": {
                **compiled.get("approval_requirements", {}),
                "required": policy.get("approvals", {}).get("required", []),
            },
        }
        compiled["contract_hash"] = _contract_hash(compiled)
    return compiled


def _contract_hash(contract: dict) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evaluate_admissibility(contract: dict, execution_state: dict) -> dict:
    required = contract.get("approval_requirements", {}).get("required") or []
    amount = execution_state.get("arguments", {}).get("amount")
    applicable = [
        requirement
        for requirement in required
        if _condition_applies(requirement.get("condition"), amount)
    ]
    missing = [
        {"role": requirement.get("role"), "condition": requirement.get("condition")}
        for requirement in applicable
        if not _approval_for_role(execution_state.get("approvals", []), requirement.get("role"))
    ]
    if missing:
        roles = ", ".join(item["role"] for item in missing if item.get("role"))
        reason = f"required approval missing: {roles}"
        return {
            "allowed": False,
            "reason": reason,
            "missing_approvals": missing,
            "trace": {"reason": reason},
        }
    return {
        "allowed": True,
        "reason": "approval evidence satisfied",
        "missing_approvals": [],
        "trace": {"reason": "approval evidence satisfied"},
    }


def _condition_applies(condition: dict | None, amount: int | None) -> bool:
    if not isinstance(condition, dict):
        return True
    if condition.get("operator") == ">":
        return amount is not None and amount > condition.get("value")
    return True


def _approval_for_role(approvals: list[dict], role: str | None) -> dict | None:
    for approval in approvals:
        if approval.get("role") == role and approval.get("approved_by"):
            return approval
    return None


def _codes(replay: dict) -> set[str]:
    return {diagnostic["code"] for diagnostic in replay["diagnostics"]}
