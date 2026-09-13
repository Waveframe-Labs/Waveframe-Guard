from __future__ import annotations

import json
import sys

from governance_ledger.cli import main as governance_cli
from governance_ledger.semantics.preview import build_governance_impact_preview


def test_same_authority_produces_same_preview():
    authority = _authority_contract()

    first = build_governance_impact_preview(authority)
    second = build_governance_impact_preview(authority)

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["schema_version"] == "governance_impact_preview.v1"
    assert first["governance_summary"] == (
        "Corporate treasury transfers are governed by treasury-policy@2.1.0."
    )


def test_preview_changes_deterministically_with_thresholds():
    authority = _authority_contract()
    changed = _authority_contract()
    changed["approval_requirements"]["thresholds"][0]["value"] = 500000

    original_preview = build_governance_impact_preview(authority)
    changed_preview = build_governance_impact_preview(changed)

    assert original_preview != changed_preview
    assert "amount > $250,000" in original_preview["enforcement_behavior"][0]
    assert "amount > $500,000" in changed_preview["enforcement_behavior"][0]


def test_continuity_requirements_produce_lifecycle_implications():
    preview = build_governance_impact_preview(
        {
            **_authority_contract(),
            "continuity_requirements": {
                "revoked_authority_invalidates_resume": True,
                "resume_requires_current_authority": True,
            },
        }
    )

    assert "Revoked authorities invalidate resumed execution continuity." in preview["lifecycle_implications"]
    assert "Resumed executions must remain bound to the current authority identity." in preview["lifecycle_implications"]
    assert _outcomes(preview) >= {"continuity_drift"}


def test_escalation_thresholds_produce_escalation_examples():
    preview = build_governance_impact_preview(_authority_contract())

    assert _outcomes(preview) >= {"allowed_execution", "blocked_execution", "escalation"}
    assert preview["example_governed_outcomes"][2] == {
        "outcome": "escalation",
        "description": "Execution escalates for escalation review when threshold conditions apply.",
    }


def test_execution_context_semantics_appear_in_preview():
    preview = build_governance_impact_preview(
        {
            **_authority_contract(),
            "execution_context_semantics": {
                "schema_version": "execution_context_semantics.v1",
                "execution_context": "queued_async",
                "execution_boundary": "external_worker",
                "requires_replay_evidence": True,
                "requires_state_snapshot": True,
                "requires_temporal_validation": True,
                "resume_behavior": "revalidate_on_resume",
                "continuity_risk_profile": "medium",
                "runtime_enforced_by": "Guard/Cloud",
            },
        }
    )

    assert preview["execution_context"] == {
        "schema_version": "execution_context_semantics.v1",
        "execution_context": "queued_async",
        "summary": "queued async execution context",
        "replay_posture": "Replay-backed continuity required",
        "resume_posture": "Resume revalidation required",
        "runtime_enforced_by": "Guard/Cloud",
    }
    assert "Execution context requires replay-backed continuity evidence." in preview["operational_consequences"]
    assert "Execution may resume later and must revalidate governance posture on resume." in preview["lifecycle_implications"]


def test_preview_does_not_import_or_invoke_guard(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)

    preview = build_governance_impact_preview(_authority_contract())

    assert preview["authority_ref"] == "treasury-policy@2.1.0"


def test_cli_preview_exports_governance_impact_preview(tmp_path, capsys):
    contract_path = tmp_path / "authority.contract.json"
    preview_path = tmp_path / "authority.preview.json"
    contract_path.write_text(
        json.dumps(_authority_contract(), indent=2, sort_keys=True),
        encoding="utf-8",
    )

    exit_code = governance_cli(["preview", str(contract_path), "--output", str(preview_path)])

    captured = capsys.readouterr()
    exported = json.loads(preview_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert exported["schema_version"] == "governance_impact_preview.v1"
    assert exported["authority_ref"] == "treasury-policy@2.1.0"
    assert "Governance Impact Preview" in captured.out


def test_preview_output_is_nondestructive_and_nondeterministic_free():
    authority = _authority_contract()
    before = json.loads(json.dumps(authority, sort_keys=True))

    previews = [build_governance_impact_preview(authority) for _ in range(5)]

    assert authority == before
    assert all(preview == previews[0] for preview in previews)


def _authority_contract() -> dict:
    return {
        "contract_id": "treasury-policy",
        "contract_version": "2.1.0",
        "contract_hash": "sha256:abc123",
        "scope": {"description": "Corporate treasury transfers"},
        "authority_requirements": {
            "required_roles": ["treasury-operator"],
        },
        "approval_requirements": {
            "thresholds": [
                {
                    "field": "amount",
                    "operator": ">",
                    "value": 250000,
                    "requires_role": "escalation review",
                }
            ]
        },
        "artifact_requirements": {
            "required": ["replay", "evidence"],
        },
        "stage_requirements": {
            "allowed_transitions": [
                {"from": "approved", "to": "executed"},
                {"from": "draft", "to": "approved"},
            ]
        },
        "invariants": {},
    }


def _outcomes(preview: dict) -> set[str]:
    return {item["outcome"] for item in preview["example_governed_outcomes"]}
