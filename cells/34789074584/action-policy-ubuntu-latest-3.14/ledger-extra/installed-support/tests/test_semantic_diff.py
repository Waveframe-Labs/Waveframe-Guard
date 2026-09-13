from __future__ import annotations

import json
import sys

from governance_ledger.cli import main as governance_cli
from governance_ledger.schema_versions import (
    AUTHORITY_DIFF_IMPACT_V1,
    GOVERNANCE_IMPACT_PREVIEW_V1,
)
from governance_ledger.semantics.diff import build_authority_diff_impact


def test_threshold_lowering_generates_semantic_escalation_impact():
    old = _authority_contract(threshold=250000, version="2.1.0")
    new = _authority_contract(threshold=100000, version="2.2.0")

    diff = build_authority_diff_impact(old, new)

    assert diff["schema_version"] == AUTHORITY_DIFF_IMPACT_V1
    assert diff["old_authority_ref"] == "treasury-policy@2.1.0"
    assert diff["new_authority_ref"] == "treasury-policy@2.2.0"
    assert diff["changed_governance_rules"][0]["change_type"] == "ESCALATION_THRESHOLD_CHANGED"
    assert diff["changed_governance_rules"][0]["before"]["value"] == 250000
    assert diff["changed_governance_rules"][0]["after"]["value"] == 100000
    assert diff["operational_implications"] == [
        "More executions are expected to enter escalation review."
    ]
    assert diff["lifecycle_continuity_implications"] == [
        "Resumed workflows may require continuity revalidation."
    ]
    assert diff["escalation_impact"] == ["Escalation review coverage expands."]
    assert diff["replay_continuity_implications"] == [
        "Replay bundles spanning this authority change must bind execution state to the exact authority hash."
    ]


def test_threshold_raising_generates_lower_escalation_impact():
    diff = build_authority_diff_impact(
        _authority_contract(threshold=100000),
        _authority_contract(threshold=250000),
    )

    assert diff["operational_implications"] == [
        "Fewer executions are expected to enter escalation review."
    ]
    assert diff["escalation_impact"] == ["Escalation review coverage narrows."]


def test_lifecycle_and_continuity_changes_generate_continuity_impacts():
    old = _authority_contract(
        transitions=[{"from": "draft", "to": "approved"}],
        continuity={"resume_requires_current_authority": False},
    )
    new = _authority_contract(
        transitions=[
            {"from": "draft", "to": "approved"},
            {"from": "approved", "to": "executed"},
        ],
        continuity={"resume_requires_current_authority": True},
    )

    diff = build_authority_diff_impact(old, new)

    change_types = {change["change_type"] for change in diff["changed_governance_rules"]}
    assert change_types == {
        "CONTINUITY_REQUIREMENT_CHANGED",
        "LIFECYCLE_TRANSITION_ADDED",
    }
    assert "Resumed workflows may require continuity revalidation." in diff["lifecycle_continuity_implications"]
    assert (
        "Replay bundles must bind continuity checks to the authority version that governed execution."
        in diff["replay_continuity_implications"]
    )


def test_role_and_artifact_changes_are_semantic_not_structural():
    old = _authority_contract(roles=["treasury-operator"], artifacts=["replay"])
    new = _authority_contract(
        roles=["treasury-operator", "finance-controller"],
        artifacts=["replay", "evidence"],
    )

    diff = build_authority_diff_impact(old, new)

    assert [change["change_type"] for change in diff["changed_governance_rules"]] == [
        "AUTHORITY_ROLE_ADDED",
        "EVIDENCE_ARTIFACT_REQUIRED",
    ]
    assert "Executions may require additional authority evidence before completion." in diff["operational_implications"]
    assert (
        "Executions missing newly required evidence artifacts may be blocked from governed completion."
        in diff["operational_implications"]
    )


def test_authority_diff_is_deterministic_and_nondestructive():
    old = _authority_contract(threshold=250000)
    new = _authority_contract(threshold=100000)
    old_before = json.loads(json.dumps(old, sort_keys=True))
    new_before = json.loads(json.dumps(new, sort_keys=True))

    diffs = [build_authority_diff_impact(old, new) for _ in range(5)]

    assert all(diff == diffs[0] for diff in diffs)
    assert old == old_before
    assert new == new_before


def test_authority_diff_does_not_import_or_invoke_guard(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)

    diff = build_authority_diff_impact(
        _authority_contract(threshold=250000),
        _authority_contract(threshold=100000),
    )

    assert diff["schema_version"] == "authority_diff_impact.v1"


def test_cli_diff_impact_exports_authority_diff(tmp_path, capsys):
    old_path = tmp_path / "old.contract.json"
    new_path = tmp_path / "new.contract.json"
    diff_path = tmp_path / "authority.diff.json"
    old_path.write_text(json.dumps(_authority_contract(threshold=250000)), encoding="utf-8")
    new_path.write_text(json.dumps(_authority_contract(threshold=100000)), encoding="utf-8")

    exit_code = governance_cli(
        [
            "diff-impact",
            "--old",
            str(old_path),
            "--new",
            str(new_path),
            "--output",
            str(diff_path),
        ]
    )

    captured = capsys.readouterr()
    exported = json.loads(diff_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert exported["schema_version"] == "authority_diff_impact.v1"
    assert "Authority Diff Impact" in captured.out


def test_semantic_artifact_versions_are_canonical_schema_consts():
    preview_schema = json.loads(
        open("schemas/governance_impact_preview.v1.json", encoding="utf-8").read()
    )
    diff_schema = json.loads(
        open("schemas/authority_diff_impact.v1.json", encoding="utf-8").read()
    )

    assert preview_schema["properties"]["schema_version"]["const"] == GOVERNANCE_IMPACT_PREVIEW_V1
    assert diff_schema["properties"]["schema_version"]["const"] == AUTHORITY_DIFF_IMPACT_V1


def _authority_contract(
    *,
    threshold: int = 250000,
    version: str = "2.1.0",
    roles: list[str] | None = None,
    artifacts: list[str] | None = None,
    transitions: list[dict[str, str]] | None = None,
    continuity: dict | None = None,
) -> dict:
    return {
        "contract_id": "treasury-policy",
        "contract_version": version,
        "contract_hash": f"sha256:{version}-{threshold}",
        "authority_requirements": {
            "required_roles": roles or ["treasury-operator"],
        },
        "approval_requirements": {
            "thresholds": [
                {
                    "field": "amount",
                    "operator": ">",
                    "value": threshold,
                    "requires_role": "escalation review",
                }
            ]
        },
        "artifact_requirements": {
            "required": artifacts or ["replay", "evidence"],
        },
        "stage_requirements": {
            "allowed_transitions": transitions
            or [
                {"from": "draft", "to": "approved"},
                {"from": "approved", "to": "executed"},
            ]
        },
        "continuity_requirements": continuity
        or {
            "resume_requires_current_authority": True,
        },
    }
