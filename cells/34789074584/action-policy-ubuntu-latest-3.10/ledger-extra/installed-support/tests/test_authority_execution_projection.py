from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from governance_ledger.semantics.compiler import build_semantic_commit_bundle, compile_semantic_commit_bundle
from governance_ledger.semantics.execution_projection import (
    build_authority_execution_projection,
    build_execution_admissibility_projection,
    build_execution_requirement_projection,
    build_guard_enforcement_projection,
    build_runtime_consequence_projection,
)
from governance_ledger.semantics.extraction import extract_governance_semantics
from governance_ledger.semantics.reconciliation import build_governance_semantic_reconciliation

ROOT = Path(__file__).resolve().parents[1]


def test_execution_requirement_projection_derives_runtime_requirements_from_compiled_contract():
    compiled = _compiled_authority()

    projection = build_execution_requirement_projection(compiled)

    assert projection["schema_version"] == "execution_requirement_projection.v1"
    assert projection["authority_ref"] == compiled["authority_ref"]
    assert projection["compiled_contract_hash"] == compiled["contract_hash"]
    assert projection["required_approvals"] == 2
    assert projection["independent_approval_required"] is True
    assert projection["required_roles"] == ["operational-governance", "security-oversight"]
    assert projection["replay_evidence_required"] is True
    assert projection["continuity_snapshot_required"] is True
    assert projection["resume_validation_required"] is True
    assert projection["temporal_validation_required"] is True
    assert projection["runtime_enforced_by"] == "Guard/Cloud"
    assert "does_not_call_guard" in projection["non_goals"]


def test_execution_admissibility_projection_lists_runtime_conditions_without_evaluating():
    projection = build_execution_admissibility_projection(_compiled_authority())

    assert projection["schema_version"] == "execution_admissibility_projection.v1"
    assert projection["projection_posture"] == "requirements_projected"
    assert projection["required_runtime_conditions"] == [
        "replay_evidence",
        "continuity_snapshot",
        "continuity_validation",
        "approval_evidence",
        "independent_approval",
        "temporal_validation",
        "active_authority_lineage",
    ]
    assert "Execution would require replay evidence." in projection["operator_summary"]
    assert "does_not_evaluate_runtime_admissibility" in projection["non_goals"]


def test_runtime_consequence_projection_expands_unsafe_runtime_requirements():
    projection = build_runtime_consequence_projection(_compiled_authority())
    consequence_types = {item["consequence_type"] for item in projection["runtime_consequences"]}

    assert projection["schema_version"] == "runtime_consequence_projection.v1"
    assert "resumed_workflows_require_revalidation" in consequence_types
    assert "continuity_snapshot_required" in consequence_types
    assert "prior_approval_evidence_may_be_stale" in consequence_types
    assert "replay_evidence_required" in consequence_types
    assert projection["what_runtime_would_require"]


def test_guard_enforcement_projection_exposes_only_guard_consumable_subset():
    projection = build_guard_enforcement_projection(_compiled_authority())
    serialized = json.dumps(projection, sort_keys=True)

    assert projection["schema_version"] == "guard_enforcement_projection.v1"
    assert projection["admissibility_requirements"]["required_approvals"] == 2
    assert projection["replay_obligations"]
    assert projection["approval_constraints"]["minimum_approvals"] == 2
    assert projection["continuity_rules"]["state_snapshot_required"] is True
    assert "capability_constraints" in projection["execution_constraints"]
    assert projection["excluded_from_guard_consumption"] == [
        "reconciliation_history",
        "extraction_provenance",
        "semantic_ambiguity",
        "ui_state",
        "registry_state",
    ]
    assert "source_text" not in serialized
    assert "semantic_provenance" not in serialized
    assert "ambiguities" not in serialized
    assert "operator_interpretation_decisions" not in serialized


def test_authority_execution_projection_is_deterministic_nondestructive_and_runtime_free(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)
    compiled = _compiled_authority()
    before = copy.deepcopy(compiled)

    projections = [build_authority_execution_projection(compiled) for _ in range(5)]

    assert all(item == projections[0] for item in projections)
    assert compiled == before
    assert projections[0]["schema_version"] == "authority_execution_projection.v1"
    assert projections[0]["guard_enforcement_projection"]["schema_version"] == "guard_enforcement_projection.v1"
    assert "Does not invoke Guard" in projections[0]["deterministic_guarantees"][1]


def test_cli_exports_authority_execution_projection(tmp_path, capsys):
    from governance_ledger.cli import main

    compiled = _compiled_authority()
    compiled_path = tmp_path / "compiled-authority.json"
    output_path = tmp_path / "authority-execution-projection.json"
    compiled_path.write_text(json.dumps(compiled), encoding="utf-8")

    assert main(["execution-projection", "--compiled-contract", str(compiled_path), "--output", str(output_path)]) == 0
    captured = capsys.readouterr()
    projection = json.loads(output_path.read_text(encoding="utf-8"))

    assert "[Authority Execution Projection]" in captured.out
    assert projection["schema_version"] == "authority_execution_projection.v1"
    assert projection["compiled_contract_hash"] == compiled["contract_hash"]


def test_execution_projection_rejects_non_compiled_input():
    with pytest.raises(ValueError, match="compiled_authority_contract.v1"):
        build_execution_requirement_projection({"schema_version": "authority_contract.v1"})


def test_authority_execution_projection_schemas_are_canonical():
    for name, const in {
        "execution_requirement_projection.v1.json": "execution_requirement_projection.v1",
        "execution_admissibility_projection.v1.json": "execution_admissibility_projection.v1",
        "runtime_consequence_projection.v1.json": "runtime_consequence_projection.v1",
        "guard_enforcement_projection.v1.json": "guard_enforcement_projection.v1",
        "authority_execution_projection.v1.json": "authority_execution_projection.v1",
    }.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"]["const"] == const


def _compiled_authority() -> dict:
    extraction = extract_governance_semantics(
        "Corporate Treasury Transfer System operation: transfer funds above $250,000 "
        "requires approval from both operational governance and security oversight. "
        "Two independent approvals are required. Approval is valid for 30 days using "
        "signed execution timestamp. Resumed workflows must revalidate current governance "
        "state and revoked authorities invalidate resumed execution. Requires replay "
        "evidence and approval evidence."
    )
    extraction["ambiguities"] = []
    reconciliation = build_governance_semantic_reconciliation(semantic_extraction=extraction)
    return compile_semantic_commit_bundle(build_semantic_commit_bundle(reconciliation))
