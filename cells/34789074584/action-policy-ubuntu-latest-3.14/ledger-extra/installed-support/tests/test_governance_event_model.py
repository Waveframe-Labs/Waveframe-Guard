from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "GOVERNANCE_EVENT_MODEL.md"
SCHEMAS = ROOT / "schemas"

EVENT_CATEGORIES = {
    "lifecycle",
    "continuity",
    "reconciliation",
    "projection",
    "replay",
    "lineage",
    "drift",
    "publication",
    "source",
}

SEVERITIES = {
    "info",
    "warning",
    "critical",
    "continuity_risk",
    "replay_risk",
    "authority_conflict",
}


def test_governance_event_model_defines_event_architecture():
    text = MODEL.read_text(encoding="utf-8")

    for phrase in (
        "Canonical Event Categories",
        "Causality Semantics",
        "Event Immutability",
        "Event Lineage",
        "Event Replay Semantics",
        "Projection Generation Triggers",
        "Invalidation Propagation Triggers",
        "Operational Continuity Triggers",
    ):
        assert f"## {phrase}" in text

    for category in EVENT_CATEGORIES:
        assert f"`{category}`" in text


def test_base_governance_event_schema_locks_envelope():
    schema = _schema("governance_event.v1.json")

    assert schema["properties"]["schema_version"]["const"] == "governance_event.v1"
    assert schema["properties"]["immutability_posture"]["const"] == "append_only"
    assert set(schema["properties"]["event_category"]["enum"]) == EVENT_CATEGORIES
    assert set(schema["properties"]["severity"]["enum"]) == SEVERITIES
    for field in (
        "event_id",
        "event_type",
        "timestamp",
        "authority_ref",
        "authority_version",
        "caused_by_event_id",
        "event_category",
        "immutability_posture",
    ):
        assert field in schema["required"]


def test_projection_generation_event_schema_locks_freshness_metadata():
    schema = _schema("projection_generation_event.v1.json")

    assert schema["properties"]["schema_version"]["const"] == "projection_generation_event.v1"
    assert schema["properties"]["event_type"]["const"] == "projection_generated"
    assert schema["properties"]["event_category"]["const"] == "projection"
    for field in (
        "projection_name",
        "generated_at",
        "source_event_ids",
        "freshness_posture",
        "projection_version",
        "projection_dependencies",
    ):
        assert field in schema["required"]


def test_projection_invalidation_event_schema_locks_causality():
    schema = _schema("projection_invalidation_event.v1.json")

    assert schema["properties"]["schema_version"]["const"] == "projection_invalidation_event.v1"
    assert schema["properties"]["event_type"]["const"] == "projection_invalidated"
    assert schema["properties"]["event_category"]["const"] == "projection"
    for field in ("projection_name", "invalidated_by_event_id", "reason"):
        assert field in schema["required"]


def test_continuity_transition_event_schema_locks_transition_shape():
    schema = _schema("continuity_transition_event.v1.json")

    assert schema["properties"]["schema_version"]["const"] == "continuity_transition_event.v1"
    assert schema["properties"]["event_type"]["const"] == "continuity_transition"
    assert schema["properties"]["event_category"]["const"] == "continuity"
    for field in ("transition_type", "from", "to"):
        assert field in schema["required"]


def _schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
