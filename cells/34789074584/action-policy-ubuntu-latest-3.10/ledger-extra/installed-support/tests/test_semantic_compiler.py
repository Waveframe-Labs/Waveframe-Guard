from __future__ import annotations

import json
from pathlib import Path

import pytest

from governance_ledger.semantics.compiler import (
    build_semantic_commit_bundle,
    compile_semantic_commit_bundle,
)
from governance_ledger.semantics.extraction import extract_governance_semantics
from governance_ledger.semantics.reconciliation import build_governance_semantic_reconciliation

ROOT = Path(__file__).resolve().parents[1]


def _complete_reconciliation() -> dict:
    extraction = extract_governance_semantics(
        "Corporate Treasury Transfer System operation: transfer funds above $250,000 "
        "requires approval from both operational governance and security oversight. "
        "Two independent approvals are required. Approval is valid for 30 days using "
        "signed execution timestamp. Resumed workflows must revalidate current governance "
        "state and revoked authorities invalidate resumed execution. Requires replay "
        "evidence and approval evidence."
    )
    extraction["ambiguities"] = []
    return build_governance_semantic_reconciliation(semantic_extraction=extraction)


def test_semantic_commit_bundle_requires_complete_reconciliation():
    extraction = extract_governance_semantics("Large financial transfers require executive review.")
    extraction["ambiguities"].append(
        {
            "ambiguity_type": "undefined_threshold",
            "summary": "Large is not a deterministic threshold.",
            "requires_operator_resolution": True,
        }
    )
    reconciliation = build_governance_semantic_reconciliation(semantic_extraction=extraction)

    with pytest.raises(ValueError, match="complete interpretation reconciliation"):
        build_semantic_commit_bundle(reconciliation)


def test_compiled_authority_contract_maps_committed_semantics_to_strict_runtime_shape():
    bundle = build_semantic_commit_bundle(_complete_reconciliation())

    compiled = compile_semantic_commit_bundle(bundle)

    assert compiled["schema_version"] == "compiled_authority_contract.v1"
    assert compiled["compiled_from"]["schema_version"] == "semantic_commit_bundle.v1"
    assert compiled["compiled_from"]["semantic_commit_hash"] == bundle["semantic_commit_hash"]
    assert compiled["authority_ref"] == f"{compiled['contract_id']}@{compiled['contract_version']}"
    assert compiled["approval_requirements"] == {
        "minimum_approvals": 2,
        "independent": True,
        "required_roles": ["operational-governance", "security-oversight"],
        "self_approval_prohibited": False,
        "attestation_required": False,
        "human_in_loop_required": False,
    }
    assert compiled["escalation_requirements"]["threshold"] == {
        "field": "amount",
        "operator": "greater_than",
        "value": 250000,
    }
    assert compiled["continuity_requirements"]["revalidation_required"] is True
    assert compiled["continuity_requirements"]["revocation_invalidates_resume"] is True
    assert compiled["continuity_requirements"]["state_snapshot_required"] is True
    assert compiled["replay_obligations"]
    assert compiled["determinism"]["same_input_same_output"] is True
    assert "does_not_call_guard" in compiled["non_goals"]
    assert "source_text" not in json.dumps(compiled, sort_keys=True)


def test_compilation_is_deterministic_for_same_semantic_commit_bundle():
    bundle = build_semantic_commit_bundle(_complete_reconciliation())

    assert compile_semantic_commit_bundle(bundle) == compile_semantic_commit_bundle(bundle)


def test_cli_compiles_semantic_commit_bundle(tmp_path, capsys):
    from governance_ledger.cli import main

    bundle = build_semantic_commit_bundle(_complete_reconciliation())
    bundle_path = tmp_path / "semantic-commit.json"
    output_path = tmp_path / "compiled-authority.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    assert main(["compile-authority", "--semantic-commit", str(bundle_path), "--output", str(output_path)]) == 0
    captured = capsys.readouterr()
    compiled = json.loads(output_path.read_text(encoding="utf-8"))

    assert "[Compiled Authority Contract]" in captured.out
    assert compiled["schema_version"] == "compiled_authority_contract.v1"
    assert compiled["compiled_from"]["semantic_commit_hash"] == bundle["semantic_commit_hash"]


def test_compiler_rejects_raw_policy_text_and_provisional_inputs():
    reconciliation = _complete_reconciliation()
    reconciliation["final_normalized_semantic_meaning"]["source_text"] = "raw policy should not compile"

    with pytest.raises(ValueError, match="raw policy text"):
        build_semantic_commit_bundle(reconciliation)

    with pytest.raises(ValueError, match="semantic_commit_bundle.v1"):
        compile_semantic_commit_bundle({"schema_version": "governance_semantic_extraction.v1"})


def test_semantic_compiler_schemas_are_canonical():
    for name, const in {
        "semantic_commit_bundle.v1.json": "semantic_commit_bundle.v1",
        "compiled_authority_contract.v1.json": "compiled_authority_contract.v1",
    }.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"]["const"] == const
