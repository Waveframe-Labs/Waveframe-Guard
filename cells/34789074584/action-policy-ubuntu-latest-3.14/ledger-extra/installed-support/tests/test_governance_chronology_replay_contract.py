from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "GOVERNANCE_CHRONOLOGY_REPLAY.md"
SCHEMA = ROOT / "schemas" / "governance_replay_state.v1.json"


def test_governance_chronology_replay_doc_locks_rules():
    text = DOC.read_text(encoding="utf-8")

    for rule in (
        "deterministic",
        "chronological",
        "derived from append-only input events",
        "call Guard",
        "call Cloud",
        "mutate source events",
        "evaluate execution admissibility",
        "same event stream + same cutoff = same replay state",
    ):
        assert rule in text


def test_governance_replay_state_schema_locks_shape():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == "governance_replay_state.v1"
    for field in (
        "replayed_at",
        "replay_cutoff",
        "source_event_ids",
        "active_authorities",
        "lineage_state",
        "continuity_state",
        "replay_posture",
        "projection_freshness",
        "governance_health",
        "operational_summaries",
    ):
        assert field in schema["required"]
