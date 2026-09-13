from __future__ import annotations

import copy
import json
import sys

from governance_ledger.semantics.diffing import build_semantic_authority_diff
from governance_ledger.semantics.lifecycle_enforcement import (
    SEMANTIC_LIFECYCLE_ENFORCEMENT_PROJECTION_V1,
    build_semantic_lifecycle_enforcement_projection,
)


def test_continuity_change_projects_revalidation_and_unsafe_resumption():
    diff = build_semantic_authority_diff(
        _authority(version="1.0.0", continuity_revalidation=False),
        _authority(version="1.1.0", continuity_revalidation=True, state_snapshot=True),
    )

    projection = build_semantic_lifecycle_enforcement_projection(diff)

    assert projection["schema_version"] == SEMANTIC_LIFECYCLE_ENFORCEMENT_PROJECTION_V1
    assert projection["replay_continuity_projection"]["existing_workflows_need_revalidation"] is True
    assert projection["execution_admissibility_projection"]["projection_posture"] == "changed"
    assert "resumed_workflow_no_longer_admissible" in _unsafe_types(projection)
    assert projection["consequence_chain"][0]["continuity_impact"] == "revalidation_required"


def test_approval_weakening_and_evidence_removal_surface_stale_evidence():
    diff = build_semantic_authority_diff(
        _authority(version="1.0.0", approval_count=2, replay_requirements=["approval_evidence", "decision_trace"]),
        _authority(version="1.1.0", approval_count=1, replay_requirements=["decision_trace"]),
    )

    projection = build_semantic_lifecycle_enforcement_projection(diff)

    assert "independent_approval_requirements_weakened" in _unsafe_types(projection)
    assert "evidence_obligations_removed" in _unsafe_types(projection)
    assert projection["replay_continuity_projection"]["posture"] == "invalidated"
    assert projection["execution_admissibility_projection"]["projection_posture"] == "potentially_weakened"


def test_ai_autonomy_and_execution_boundary_expansion_are_guard_projection_changes():
    diff = build_semantic_authority_diff(
        _authority(version="1.0.0", ai_recommendation_posture="advisory_only", execution_context="local_interactive"),
        _authority(version="1.1.0", ai_recommendation_posture="incident_auto_execute", execution_context="queued_async"),
    )

    projection = build_semantic_lifecycle_enforcement_projection(diff)

    assert "ai_autonomy_scope_widened" in _unsafe_types(projection)
    assert "execution_boundary_expanded" in _unsafe_types(projection)
    assert projection["guard_policy_projection"]["projection_posture"] == "changed"
    assert "Verify AI execution authorization boundary before admissibility." in projection["guard_policy_projection"]["enforcement_changes"]


def test_lifecycle_enforcement_projection_is_deterministic_nondestructive_and_runtime_free(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)
    diff = build_semantic_authority_diff(
        _authority(version="1.0.0", approval_count=1),
        _authority(version="1.1.0", approval_count=2, continuity_revalidation=True),
    )
    before = copy.deepcopy(diff)

    projections = [build_semantic_lifecycle_enforcement_projection(diff) for _ in range(5)]

    assert all(item == projections[0] for item in projections)
    assert diff == before
    assert "does_not_execute_guard" in projections[0]["non_goals"]
    assert "does_not_mutate_registry_state" in projections[0]["non_goals"]


def test_semantic_lifecycle_enforcement_schema_is_canonical():
    schema = json.loads(open("schemas/semantic_lifecycle_enforcement_projection.v1.json", encoding="utf-8").read())

    assert schema["properties"]["schema_version"]["const"] == "semantic_lifecycle_enforcement_projection.v1"
    assert schema["properties"]["replay_continuity_projection"]["properties"]["schema_version"]["const"] == "replay_continuity_projection.v1"
    assert schema["properties"]["execution_admissibility_projection"]["properties"]["schema_version"]["const"] == "execution_admissibility_projection.v1"
    assert schema["properties"]["guard_policy_projection"]["properties"]["schema_version"]["const"] == "guard_policy_projection_change.v1"


def _unsafe_types(projection: dict) -> set[str]:
    return {item["unsafe_type"] for item in projection["what_becomes_unsafe_now"]}


def _authority(
    *,
    version: str,
    approval_count: int = 1,
    continuity_revalidation: bool = False,
    state_snapshot: bool = False,
    replay_requirements: list[str] | None = None,
    ai_recommendation_posture: str = "advisory_only",
    execution_context: str = "local_interactive",
) -> dict:
    return {
        "contract_id": "semantic-policy",
        "contract_version": version,
        "approval_count": approval_count,
        "approval_chain_semantics": {
            "schema_version": "approval_chain_semantics.v1",
            "required_approval_count": approval_count,
            "required_roles": ["governance-operations"],
            "independence_required": approval_count > 1,
            "self_approval_prohibited": True,
            "attestation_required": True,
            "delegation_posture": "not_allowed",
            "ai_recommendation_posture": ai_recommendation_posture,
        },
        "continuity_revalidation": continuity_revalidation,
        "revocation_invalidates_resume": continuity_revalidation,
        "state_snapshot_semantics": {"snapshot_required": True} if state_snapshot else {},
        "execution_context_semantics": {
            "schema_version": "execution_context_semantics.v1",
            "execution_context": execution_context,
            "execution_boundary": "external_worker" if execution_context == "queued_async" else "local_operator",
            "requires_replay_evidence": execution_context == "queued_async",
            "requires_state_snapshot": continuity_revalidation,
            "requires_temporal_validation": True,
            "resume_behavior": "revalidate_on_resume" if continuity_revalidation else "complete_inline",
        },
        "replay_requirements": replay_requirements or ["decision_trace"],
    }
