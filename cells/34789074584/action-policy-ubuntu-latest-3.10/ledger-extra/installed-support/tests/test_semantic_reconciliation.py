from __future__ import annotations

import json
from pathlib import Path

from governance_ledger.semantics.extraction import extract_governance_semantics
from governance_ledger.semantics.reconciliation import (
    build_governance_semantic_reconciliation,
    build_semantic_interpretation_decision,
    build_semantic_reconciliation_projection,
    build_semantic_stability_projection,
)

ROOT = Path(__file__).resolve().parents[1]


def test_unresolved_ambiguity_does_not_become_normalized_meaning():
    extraction = extract_governance_semantics("Large financial transfers require executive review.")
    extraction["ambiguities"].append(
        {
            "ambiguity_type": "undefined_threshold",
            "text": "Large financial transfers",
            "summary": "Large is not a deterministic threshold.",
            "requires_operator_resolution": True,
        }
    )

    reconciliation = build_governance_semantic_reconciliation(semantic_extraction=extraction)

    assert reconciliation["schema_version"] == "governance_semantic_reconciliation.v1"
    assert reconciliation["interpretation_completeness_posture"] == "operator_required"
    assert reconciliation["unresolved_ambiguities"]
    assert reconciliation["final_normalized_semantic_meaning"] == {}


def test_operator_decision_records_interpretation_provenance_and_normalizes_meaning():
    extraction = extract_governance_semantics("Large financial transfers require executive review.")
    extraction["ambiguities"] = [
        {
            "ambiguity_id": "ambiguity-large-transfer",
            "ambiguity_type": "undefined_threshold",
            "text": "Large financial transfers",
            "summary": "Large is not a deterministic threshold.",
            "requires_operator_resolution": True,
        }
    ]
    decision = build_semantic_interpretation_decision(
        decision_type="threshold_definition",
        ambiguity_id="ambiguity-large-transfer",
        resolved_value=250000,
        selected_interpretation="250000",
        rejected_interpretations=["undefined large transfer"],
        rationale="Treasury policy baseline",
        justification="Treasury policy baseline",
    )

    reconciliation = build_governance_semantic_reconciliation(
        semantic_extraction=extraction,
        interpretation_decisions=[decision],
    )

    assert reconciliation["interpretation_completeness_posture"] == "complete"
    assert reconciliation["unresolved_ambiguities"] == []
    assert reconciliation["operator_interpretation_decisions"] == [decision]
    assert decision["field"] == "escalation_threshold"
    assert decision["selected_interpretation"] == "250000"
    assert decision["rejected_interpretations"] == ["undefined large transfer"]
    assert decision["timestamp"]
    assert decision["justification"] == "Treasury policy baseline"
    assert reconciliation["final_normalized_semantic_meaning"]["escalation_threshold"] == 250000
    assert reconciliation["normalization_decisions"] == ["threshold normalized from operator interpretation"]


def test_operator_decisions_normalize_temporal_and_snapshot_semantics():
    extraction = extract_governance_semantics(
        "Payment Workflow approval is valid for 30 days and must revalidate on resume."
    )
    extraction["ambiguities"] = [
        {
            "ambiguity_id": "ambiguity-timestamp-source",
            "ambiguity_type": "timestamp_source_unspecified",
            "summary": "Timestamp source is unspecified.",
            "requires_operator_resolution": True,
        },
        {
            "ambiguity_id": "ambiguity-snapshot-subject",
            "ambiguity_type": "state_snapshot_subject_unspecified",
            "summary": "Snapshot subject is unspecified.",
            "requires_operator_resolution": True,
        },
    ]
    timestamp_decision = build_semantic_interpretation_decision(
        decision_type="timestamp_source_definition",
        ambiguity_id="ambiguity-timestamp-source",
        resolved_value="signed_oracle",
        rationale="Treasury approvals use signed oracle time.",
    )
    snapshot_decision = build_semantic_interpretation_decision(
        decision_type="state_snapshot_subject_definition",
        ambiguity_id="ambiguity-snapshot-subject",
        resolved_value="active_governance_state",
        rationale="Resume must compare against active governance posture.",
    )

    reconciliation = build_governance_semantic_reconciliation(
        semantic_extraction=extraction,
        interpretation_decisions=[timestamp_decision, snapshot_decision],
    )
    normalized = reconciliation["final_normalized_semantic_meaning"]

    assert reconciliation["interpretation_completeness_posture"] == "complete"
    assert normalized["temporal_semantics"]["timestamp_source"] == "signed_oracle"
    assert normalized["temporal_semantics"]["expiration_basis"] == "signed_oracle_time"
    assert normalized["temporal_semantics"]["runtime_enforced_by"] == "Guard/Cloud"
    assert normalized["state_snapshot_semantics"]["snapshot_subject"] == "active_governance_state"
    assert normalized["state_snapshot_semantics"]["runtime_enforced_by"] == "Guard/Cloud"


def test_semantic_reconciliation_projection_surfaces_completeness_posture():
    extraction = extract_governance_semantics("Large financial transfers require executive review.")
    extraction["ambiguities"].append(
        {
            "ambiguity_type": "undefined_threshold",
            "summary": "Large is not a deterministic threshold.",
            "requires_operator_resolution": True,
        }
    )
    reconciliation = build_governance_semantic_reconciliation(semantic_extraction=extraction)

    projection = build_semantic_reconciliation_projection(reconciliation)

    assert projection["schema_version"] == "semantic_reconciliation_projection.v1"
    assert projection["interpretation_completeness_posture"] == "operator_required"
    assert projection["unresolved_ambiguities"]


def test_semantic_stability_projection_detects_same_source_extraction_drift():
    previous = extract_governance_semantics("Large financial transfers require executive review.")
    current = dict(previous)
    current["candidate_authority"] = {
        **previous["candidate_authority"],
        "escalation_threshold": 250000,
    }

    projection = build_semantic_stability_projection(
        previous_extraction=previous,
        current_extraction=current,
    )

    assert projection["schema_version"] == "semantic_stability_projection.v1"
    assert projection["same_source"] is True
    assert projection["semantic_meaning_changed"] is True
    assert projection["stability_posture"] == "semantic_drift_detected"
    assert projection["stability_observations"][0]["observation_type"] == "same_source_semantic_drift"


def test_semantic_stability_projection_detects_interpretation_decision_drift():
    extraction = extract_governance_semantics("Large financial transfers require executive review.")
    previous_decision = build_semantic_interpretation_decision(
        decision_type="threshold_definition",
        ambiguity_id="ambiguity-large-transfer",
        resolved_value=250000,
        rationale="Initial threshold interpretation.",
    )
    current_decision = build_semantic_interpretation_decision(
        decision_type="threshold_definition",
        ambiguity_id="ambiguity-large-transfer",
        resolved_value=100000,
        rationale="Lower threshold interpretation.",
    )
    previous_reconciliation = build_governance_semantic_reconciliation(
        semantic_extraction=extraction,
        interpretation_decisions=[previous_decision],
    )
    current_reconciliation = build_governance_semantic_reconciliation(
        semantic_extraction=extraction,
        interpretation_decisions=[current_decision],
    )

    projection = build_semantic_stability_projection(
        previous_extraction=extraction,
        current_extraction=extraction,
        previous_reconciliation=previous_reconciliation,
        current_reconciliation=current_reconciliation,
    )

    assert projection["interpretation_decision_changes"] == [
        {
            "field": "escalation_threshold",
            "previous_interpretation": 250000,
            "current_interpretation": 100000,
            "previous_decision_id": previous_decision["decision_id"],
            "current_decision_id": current_decision["decision_id"],
        }
    ]
    assert projection["stability_posture"] == "semantic_drift_detected"


def test_semantic_reconciliation_schemas_are_canonical():
    for name, const in {
        "governance_semantic_reconciliation.v1.json": "governance_semantic_reconciliation.v1",
        "semantic_conflict.v1.json": "semantic_conflict.v1",
        "semantic_ambiguity.v1.json": "semantic_ambiguity.v1",
        "semantic_interpretation_decision.v1.json": "semantic_interpretation_decision.v1",
        "semantic_reconciliation_projection.v1.json": "semantic_reconciliation_projection.v1",
        "semantic_stability_projection.v1.json": "semantic_stability_projection.v1",
    }.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"]["const"] == const
