from __future__ import annotations

import copy
import json
import sys

from governance_ledger.semantics.diffing import (
    SEMANTIC_AUTHORITY_DIFF_V1,
    build_semantic_authority_diff,
)


def test_approval_strengthening_diff_operational_meaning_not_structure():
    previous = _authority(version="2.1.0", approval_count=1)
    current = _authority(version="2.2.0", approval_count=2)

    diff = build_semantic_authority_diff(previous, current)

    change = _change(diff, "approval.required_count")
    assert diff["schema_version"] == SEMANTIC_AUTHORITY_DIFF_V1
    assert change["change_class"] == "approval_strengthened"
    assert change["before"] == 1
    assert change["after"] == 2
    assert "Human approval requirements increased." in diff["operational_impact_narratives"]
    assert "Execution autonomy reduced." in diff["operational_impact_narratives"]


def test_ai_autonomy_expansion_is_breaking_governance_change():
    previous = _authority(
        version="2.1.0",
        ai_recommendation_posture="advisory_only",
    )
    current = _authority(
        version="2.2.0",
        ai_recommendation_posture="incident_auto_execute",
    )

    diff = build_semantic_authority_diff(previous, current)

    change = _change(diff, "ai.autonomy_posture")
    assert change["change_class"] == "relaxed_control"
    assert change["severity"] == "breaking-governance-change"
    assert "AI execution autonomy expanded." in change["operational_impact"]
    assert "Human approval boundary relaxed." in change["operational_impact"]
    assert diff["guard_compatibility_projection"]["compatibility_posture"] == "guard_behavior_changes"
    assert "Verify AI execution authorization boundary before admissibility." in diff["guard_compatibility_projection"]["new_enforcement_obligations"]


def test_capability_added_and_continuity_expansion_emit_guard_obligations():
    previous = _authority(version="2.1.0", capabilities=[])
    current = _authority(
        version="2.2.0",
        continuity_revalidation=True,
        state_snapshot=True,
        capabilities=[
            _capability(
                "resume_ai_workflow",
                action_type="resume_action",
                continuity=True,
                evidence=["replay_evidence"],
            )
        ],
    )

    diff = build_semantic_authority_diff(previous, current)

    classes = {change["change_class"] for change in diff["semantic_changes"]}
    assert "capability_added" in classes
    assert "continuity_change" in classes
    assert "Capability resume_ai_workflow is now governed by this authority." in diff["operational_impact_narratives"]
    assert "Compare governance snapshot hash against active governance posture." in diff["guard_compatibility_projection"]["new_enforcement_obligations"]
    assert "Validate replay_evidence evidence before admissibility." in diff["guard_compatibility_projection"]["new_enforcement_obligations"]


def test_scope_and_delegation_changes_are_governance_meaning():
    previous = _authority(
        version="2.1.0",
        governed_targets=["production_systems"],
        delegation_posture="not_allowed",
    )
    current = _authority(
        version="2.2.0",
        governed_targets=["production_systems", "financial_state"],
        delegation_posture="allowed_with_boundary",
    )

    diff = build_semantic_authority_diff(previous, current)

    scope = _change(diff, "scope.governed_targets")
    delegation = _change(diff, "delegation.posture")
    assert scope["change_class"] == "scope_expansion"
    assert scope["severity"] == "high-impact"
    assert delegation["change_class"] == "delegation_change"
    assert "Delegated authority boundary expanded." in delegation["operational_impact"]


def test_semantic_diff_is_deterministic_nondestructive_and_guard_free(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)
    previous = _authority(version="2.1.0", approval_count=1)
    current = _authority(version="2.2.0", approval_count=2, continuity_revalidation=True)
    before_previous = copy.deepcopy(previous)
    before_current = copy.deepcopy(current)

    diffs = [build_semantic_authority_diff(previous, current) for _ in range(5)]

    assert all(item == diffs[0] for item in diffs)
    assert previous == before_previous
    assert current == before_current
    assert diffs[0]["deterministic_guarantees"][1] == (
        "Does not invoke Guard, Cloud, simulation, runtime evaluation, or admissibility execution."
    )


def test_semantic_authority_diff_schema_is_canonical():
    schema = json.loads(open("schemas/semantic_authority_diff.v1.json", encoding="utf-8").read())

    assert schema["properties"]["schema_version"]["const"] == "semantic_authority_diff.v1"
    assert "approval_strengthened" in schema["properties"]["semantic_changes"]["items"]["properties"]["change_class"]["enum"]
    assert "breaking-governance-change" in schema["properties"]["semantic_changes"]["items"]["properties"]["severity"]["enum"]


def _authority(
    *,
    version: str,
    approval_count: int = 1,
    ai_recommendation_posture: str = "advisory_only",
    continuity_revalidation: bool = False,
    state_snapshot: bool = False,
    governed_targets: list[str] | None = None,
    delegation_posture: str = "not_allowed",
    capabilities: list[dict] | None = None,
) -> dict:
    return {
        "contract_id": "ai-ops-policy",
        "contract_version": version,
        "governed_action": "AI-assisted operational modification",
        "governed_targets": governed_targets or ["production_systems"],
        "governed_operations": ["modify", "resume"],
        "approval_count": approval_count,
        "approval_chain_semantics": {
            "schema_version": "approval_chain_semantics.v1",
            "required_approval_count": approval_count,
            "required_roles": ["operational-governance"],
            "independence_required": approval_count > 1,
            "self_approval_prohibited": True,
            "attestation_required": True,
            "delegation_posture": delegation_posture,
            "ai_recommendation_posture": ai_recommendation_posture,
        },
        "continuity_revalidation": continuity_revalidation,
        "revocation_invalidates_resume": continuity_revalidation,
        "state_snapshot_semantics": {
            "schema_version": "state_posture_snapshot_semantics.v1",
            "snapshot_required": True,
            "snapshot_subject": "active_governance_state",
        }
        if state_snapshot
        else {},
        "capabilities": capabilities or [],
        "replay_requirements": ["decision_trace"],
    }


def _capability(
    capability_id: str,
    *,
    action_type: str,
    continuity: bool = False,
    evidence: list[str] | None = None,
) -> dict:
    return {
        "schema_version": "governance_capability.v1",
        "capability_id": capability_id,
        "action": capability_id.replace("_", " "),
        "action_type": action_type,
        "requirements": [
            {
                "schema_version": "capability_requirement.v1",
                "requirement_type": "continuity_revalidation",
                "summary": "Resumed execution requires current governance posture validation.",
                "fields": {"resume_requires_revalidation": True},
            }
        ],
        "continuity_semantics": {
            "schema_version": "capability_continuity_semantics.v1",
            "revalidation_required": continuity,
            "state_snapshot_semantics": {"snapshot_required": continuity},
        },
        "evidence_requirements": [
            {
                "schema_version": "capability_evidence_requirement.v1",
                "evidence_type": item,
                "summary": f"{item} is required.",
            }
            for item in (evidence or [])
        ],
        "execution_constraints": {},
        "identity_requirements": {},
    }


def _change(diff: dict, semantic_path: str) -> dict:
    return next(change for change in diff["semantic_changes"] if change["semantic_path"] == semantic_path)
