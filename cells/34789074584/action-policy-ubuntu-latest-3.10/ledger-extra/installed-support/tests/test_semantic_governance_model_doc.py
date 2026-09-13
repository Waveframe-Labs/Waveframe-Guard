from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "SEMANTIC_GOVERNANCE_MODEL.md"


def test_semantic_governance_model_defines_core_primitives():
    text = MODEL.read_text(encoding="utf-8")

    for term in (
        "Authority",
        "Lineage",
        "Continuity",
        "Replay Posture",
        "Drift",
        "Reconciliation",
        "Invalidation",
        "Freshness",
        "Lifecycle Event",
        "Operational Summary",
        "Active Authority",
        "Governance Activity",
        "Governance Coherence",
    ):
        assert f"### {term}" in text


def test_semantic_governance_model_locks_mutation_boundaries():
    text = MODEL.read_text(encoding="utf-8")

    for boundary in (
        "Viewing Is Not A Lifecycle Transition",
        "Rendering Is Not Approval",
        "Preview Is Not Review",
        "Export Is Not Registration",
        "Registration Is Not Admissibility",
    ):
        assert f"### {boundary}" in text


def test_semantic_governance_model_locks_projection_and_severity_taxonomy():
    text = MODEL.read_text(encoding="utf-8")

    for projection in (
        "governance_impact_preview.v1",
        "authority_diff_impact.v1",
        "governance_review_packet.v1",
        "governance_semantic_extraction.v1",
        "semantic_reconciliation_projection.v1",
        "semantic_stability_projection.v1",
        "compiled_authority_contract.v1",
        "authority_execution_projection.v1",
        "authority_bundle.v1",
        "publication_receipt.v1",
        "governance_replay_state.v1",
        "governance_replay_diff.v1",
        "semantic_lifecycle_enforcement_projection.v1",
    ):
        assert projection in text

    for severity in (
        "info",
        "warning",
        "critical",
        "continuity_risk",
        "replay_risk",
        "authority_conflict",
    ):
        assert f"### {severity}" in text


def test_semantic_governance_model_standardizes_projection_generation_metadata():
    text = MODEL.read_text(encoding="utf-8")

    for field in (
        "generated_at",
        "source_event_ids",
        "freshness_posture",
        "projection_version",
        "projection_dependencies",
    ):
        assert field in text
