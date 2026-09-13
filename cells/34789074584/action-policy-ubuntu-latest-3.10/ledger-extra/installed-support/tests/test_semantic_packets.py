from __future__ import annotations

import json
import sys
from pathlib import Path

from governance_ledger.cli import main as governance_cli
from governance_ledger.schema_versions import GOVERNANCE_REVIEW_PACKET_V1
from governance_ledger.semantics.diff import build_authority_diff_impact
from governance_ledger.semantics.packets import build_governance_review_packet
from governance_ledger.semantics.preview import build_governance_impact_preview


def test_review_packet_builds_canonical_packet_from_authority_and_preview():
    authority = _authority_contract()
    preview = build_governance_impact_preview(authority)

    packet = build_governance_review_packet(
        authority_contract=authority,
        governance_impact_preview=preview,
    )

    assert packet["schema_version"] == GOVERNANCE_REVIEW_PACKET_V1
    assert packet["packet_id"].startswith("grp_")
    assert packet["authority_ref"] == "finance-policy@0.1.0"
    assert packet["operational_state"] == "review_ready"
    assert packet["protected_resource"] == "Corporate treasury account"
    assert packet["governed_action"] == "transfer"
    assert packet["immutable_inputs"]["authority_hash"] == "sha256:authority-abc"
    assert packet["immutable_inputs"]["preview_hash"].startswith("sha256:")
    assert packet["immutable_inputs"]["diff_hash"] is None
    assert packet["review_context"] == {
        "disposition": None,
        "annotations": [],
    }
    assert packet["non_goals"] == [
        "does_not_change_execution_outcome",
        "does_not_mutate_evidence",
        "does_not_alter_replay",
        "does_not_bypass_guard",
    ]


def test_review_packet_includes_optional_diff_evidence_and_metadata():
    old_authority = _authority_contract(threshold=250000, version="0.1.0")
    new_authority = _authority_contract(threshold=100000, version="0.2.0")
    preview = build_governance_impact_preview(new_authority)
    diff = build_authority_diff_impact(old_authority, new_authority)
    evidence = {
        "evidence_id": "evidence-1",
        "operational_state": "blocked",
        "protected_resource": "wire-transfer-123",
        "governed_action": "treasury_transfer",
        "continuity_signals": ["execution state references prior authority hash"],
        "observed_at": "2026-05-24T12:00:00Z",
    }
    metadata = {
        "disposition": "needs_review",
        "annotations": [
            {"author": "reviewer-b", "text": "second"},
            {"author": "reviewer-a", "text": "first"},
        ],
        "timeline": [
            {
                "event": "review_started",
                "timestamp": "2026-05-24T12:05:00Z",
                "detail": "manual review",
            }
        ],
    }

    packet = build_governance_review_packet(
        authority_contract=new_authority,
        governance_impact_preview=preview,
        authority_diff_impact=diff,
        execution_evidence=evidence,
        review_metadata=metadata,
    )

    assert packet["operational_state"] == "blocked"
    assert packet["protected_resource"] == "wire-transfer-123"
    assert packet["governed_action"] == "treasury_transfer"
    assert packet["immutable_inputs"]["diff_hash"].startswith("sha256:")
    assert "More executions are expected to enter escalation review." in packet["consequence_summary"]
    assert "Escalation review coverage expands." in packet["consequence_summary"]
    assert "execution state references prior authority hash" in packet["continuity_signals"]
    assert packet["review_context"]["disposition"] == "needs_review"
    assert packet["review_context"]["annotations"] == [
        {"author": "reviewer-a", "text": "first"},
        {"author": "reviewer-b", "text": "second"},
    ]
    assert len(packet["timeline"]) == 2


def test_review_packet_is_deterministic_and_nondestructive():
    authority = _authority_contract()
    preview = build_governance_impact_preview(authority)
    metadata = {"annotations": [{"text": "stable"}]}
    authority_before = json.loads(json.dumps(authority, sort_keys=True))
    preview_before = json.loads(json.dumps(preview, sort_keys=True))

    packets = [
        build_governance_review_packet(
            authority_contract=authority,
            governance_impact_preview=preview,
            review_metadata=metadata,
        )
        for _ in range(5)
    ]

    assert all(packet == packets[0] for packet in packets)
    assert authority == authority_before
    assert preview == preview_before


def test_packet_id_changes_when_immutable_preview_changes():
    authority = _authority_contract()
    preview = build_governance_impact_preview(authority)
    changed_preview = {
        **preview,
        "operational_consequences": [
            *preview["operational_consequences"],
            "Additional consequence for review packet hashing.",
        ],
    }

    first = build_governance_review_packet(
        authority_contract=authority,
        governance_impact_preview=preview,
    )
    second = build_governance_review_packet(
        authority_contract=authority,
        governance_impact_preview=changed_preview,
    )

    assert first["immutable_inputs"]["preview_hash"] != second["immutable_inputs"]["preview_hash"]
    assert first["packet_id"] != second["packet_id"]


def test_review_packet_does_not_import_guard_or_cloud(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)
    monkeypatch.setitem(sys.modules, "governance_cloud", None)
    authority = _authority_contract()

    packet = build_governance_review_packet(
        authority_contract=authority,
        governance_impact_preview=build_governance_impact_preview(authority),
    )

    assert packet["schema_version"] == "governance_review_packet.v1"


def test_cli_review_packet_exports_packet(tmp_path, capsys):
    authority = _authority_contract()
    preview = build_governance_impact_preview(authority)
    authority_path = tmp_path / "finance.contract.json"
    preview_path = tmp_path / "finance.preview.json"
    packet_path = tmp_path / "finance.review-packet.json"
    authority_path.write_text(json.dumps(authority), encoding="utf-8")
    preview_path.write_text(json.dumps(preview), encoding="utf-8")

    exit_code = governance_cli(
        [
            "review-packet",
            "--authority",
            str(authority_path),
            "--preview",
            str(preview_path),
            "--output",
            str(packet_path),
        ]
    )

    captured = capsys.readouterr()
    exported = json.loads(packet_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert exported["schema_version"] == "governance_review_packet.v1"
    assert exported["authority_ref"] == "finance-policy@0.1.0"
    assert "Governance Review Packet" in captured.out


def test_review_packet_schema_version_is_canonical_const():
    schema = json.loads(
        Path("schemas/governance_review_packet.v1.json").read_text(encoding="utf-8")
    )

    assert schema["properties"]["schema_version"]["const"] == GOVERNANCE_REVIEW_PACKET_V1


def _authority_contract(*, threshold: int = 250000, version: str = "0.1.0") -> dict:
    return {
        "contract_id": "finance-policy",
        "contract_version": version,
        "contract_hash": "sha256:authority-abc",
        "scope": {
            "description": "Corporate treasury transfers",
            "resource": "Corporate treasury account",
        },
        "governed_actions": ["transfer"],
        "authority_requirements": {
            "required_roles": ["manager"],
        },
        "approval_requirements": {
            "thresholds": [
                {
                    "field": "amount",
                    "operator": ">",
                    "value": threshold,
                    "requires_role": "manager",
                }
            ]
        },
        "artifact_requirements": {
            "required": ["replay", "evidence"],
        },
        "continuity_requirements": {
            "resume_requires_current_authority": True,
        },
    }
