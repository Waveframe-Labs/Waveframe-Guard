from __future__ import annotations

import json
import sys
from pathlib import Path

from governance_ledger.cli import main as governance_cli
from governance_ledger.schema_versions import AUTHORITY_BUNDLE_V1, PUBLICATION_RECEIPT_V1
from governance_ledger.semantics.diff import build_authority_diff_impact
from governance_ledger.semantics.packets import build_governance_review_packet
from governance_ledger.semantics.preview import build_governance_impact_preview
from governance_ledger.semantics.publication import build_authority_bundle, build_publication_receipt


def test_authority_bundle_composes_publishable_governance_object():
    old_authority = _authority_contract(threshold=250000, version="0.1.0")
    authority = _authority_contract(threshold=100000, version="0.2.0")
    manifest = _publication_manifest(authority)
    preview = build_governance_impact_preview(authority)
    diff = build_authority_diff_impact(old_authority, authority)
    packet = build_governance_review_packet(
        authority_contract=authority,
        governance_impact_preview=preview,
        authority_diff_impact=diff,
        execution_evidence={"operational_state": "blocked", "protected_resource": "wire-123"},
    )

    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=manifest,
        governance_impact_preview=preview,
        authority_diff_impact=diff,
        governance_review_packets=[packet],
    )

    assert bundle["schema_version"] == AUTHORITY_BUNDLE_V1
    assert bundle["publication_id"] == "pub_20260524_0001"
    assert bundle["authority_ref"] == "finance-policy@0.2.0"
    assert bundle["contract_hash"] == "sha256:authority-0.2.0-100000"
    assert bundle["authority_contract"] == authority
    assert bundle["semantic_commit_bundle"] is None
    assert bundle["compiled_authority_contract"] is None
    assert bundle["semantic_commit_hash"] is None
    assert bundle["compiled_contract_hash"] is None
    assert bundle["publication_manifest"] == manifest
    assert bundle["governance_impact_preview"] == preview
    assert bundle["authority_diff_impact"] == diff
    assert bundle["governance_review_packets"] == [packet]
    assert bundle["semantic_artifacts"] == [
        {
            "artifact_type": "governance_impact_preview.v1",
            "artifact_hash": bundle["immutable_inputs"]["preview_hash"],
        },
        {
            "artifact_type": "authority_diff_impact.v1",
            "artifact_hash": bundle["immutable_inputs"]["diff_hash"],
        },
    ]
    assert bundle["review_packets"][0]["packet_id"] == packet["packet_id"]
    assert bundle["lineage"]["source_hash"] == "sha256:source"
    assert bundle["provenance"]["published_by"] == "governance-team"
    assert bundle["schema_compatibility"]["compatible"] is True
    assert "The publication includes semantic impact from authority changes." in bundle["publication_meaning"]
    assert "More executions are expected to enter escalation review." in bundle["operational_implications"]
    assert (
        "Replay bundles spanning this authority change must bind execution state to the exact authority hash."
        in bundle["continuity_implications"]
    )
    assert bundle["non_goals"] == [
        "does_not_deploy_authority",
        "does_not_approve_authority",
        "does_not_change_execution_outcome",
        "does_not_mutate_evidence",
        "does_not_alter_replay",
        "does_not_bypass_guard",
        "does_not_call_cloud",
    ]


def test_authority_bundle_supports_optional_diff_and_review_packets():
    authority = _authority_contract()
    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=build_governance_impact_preview(authority),
    )

    assert bundle["authority_diff_impact"] is None
    assert bundle["governance_review_packets"] == []
    assert bundle["review_packets"] == []
    assert bundle["immutable_inputs"]["diff_hash"] is None
    assert bundle["immutable_inputs"]["review_packet_hashes"] == []
    assert bundle["immutable_inputs"]["semantic_commit_hash"] is None
    assert bundle["immutable_inputs"]["compiled_contract_hash"] is None
    assert bundle["schema_compatibility"]["compatible"] is True


def test_authority_bundle_includes_semantic_commit_and_compiled_contract():
    authority = _authority_contract()
    semantic_commit = _semantic_commit_bundle(authority)
    compiled = _compiled_authority_contract(authority, semantic_commit)

    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=build_governance_impact_preview(authority),
        semantic_commit_bundle=semantic_commit,
        compiled_authority_contract=compiled,
    )

    assert bundle["semantic_commit_bundle"] == semantic_commit
    assert bundle["compiled_authority_contract"] == compiled
    assert bundle["semantic_commit_hash"] == semantic_commit["semantic_commit_hash"]
    assert bundle["compiled_contract_hash"] == compiled["contract_hash"]
    assert bundle["immutable_inputs"]["semantic_commit_hash"] == semantic_commit["semantic_commit_hash"]
    assert bundle["immutable_inputs"]["compiled_contract_hash"] == compiled["contract_hash"]
    assert {
        "artifact_type": "semantic_commit_bundle.v1",
        "artifact_hash": semantic_commit["semantic_commit_hash"],
    } in bundle["semantic_artifacts"]
    assert {
        "artifact_type": "compiled_authority_contract.v1",
        "artifact_hash": compiled["contract_hash"],
    } in bundle["semantic_artifacts"]
    assert bundle["schema_compatibility"]["artifacts"]["compiled_authority_contract"] == "compiled_authority_contract.v1"


def test_authority_bundle_derives_publication_id_for_legacy_manifest():
    authority = _authority_contract()
    manifest = _publication_manifest(authority)
    del manifest["publication_id"]
    del manifest["schema_version"]

    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=manifest,
        governance_impact_preview=build_governance_impact_preview(authority),
    )

    assert bundle["publication_id"].startswith("pub_semantic_")
    assert bundle["schema_compatibility"]["artifacts"]["publication_manifest"] == "publication_manifest.v1"


def test_authority_bundle_is_deterministic_and_nondestructive():
    authority = _authority_contract()
    manifest = _publication_manifest(authority)
    preview = build_governance_impact_preview(authority)
    before = json.loads(json.dumps({"authority": authority, "manifest": manifest, "preview": preview}, sort_keys=True))

    bundles = [
        build_authority_bundle(
            authority_contract=authority,
            publication_manifest=manifest,
            governance_impact_preview=preview,
        )
        for _ in range(5)
    ]

    assert all(bundle == bundles[0] for bundle in bundles)
    assert {"authority": authority, "manifest": manifest, "preview": preview} == before


def test_authority_bundle_hashes_change_when_manifest_changes():
    authority = _authority_contract()
    preview = build_governance_impact_preview(authority)
    first = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=preview,
    )
    changed_manifest = _publication_manifest(authority)
    changed_manifest["published_by"] = "another-team"
    second = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=changed_manifest,
        governance_impact_preview=preview,
    )

    assert first["immutable_inputs"]["manifest_hash"] != second["immutable_inputs"]["manifest_hash"]


def test_publication_receipt_binds_bundle_hashes_and_readiness():
    old_authority = _authority_contract(threshold=250000, version="0.1.0")
    authority = _authority_contract(threshold=100000, version="0.2.0")
    preview = build_governance_impact_preview(authority)
    diff = build_authority_diff_impact(old_authority, authority)
    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=preview,
        authority_diff_impact=diff,
    )

    receipt = build_publication_receipt(
        authority_bundle=bundle,
        published_at="2026-05-25T18:00:00Z",
        readiness_confirmations={
            "semantic_diagnostics_reviewed": True,
            "lineage_validated": True,
        },
        publication_notes=[
            {
                "note_type": "operational_change_summary",
                "text": "Escalation threshold lowered for treasury transfers.",
                "created_at": "2026-05-25T17:59:00Z",
            }
        ],
    )

    assert receipt["schema_version"] == PUBLICATION_RECEIPT_V1
    assert receipt["authority_ref"] == "finance-policy@0.2.0"
    assert receipt["bundle_hash"].startswith("sha256:")
    assert receipt["manifest_hash"] == bundle["immutable_inputs"]["manifest_hash"]
    assert receipt["semantic_artifact_hashes"]["governance_impact_preview.v1"] == bundle["immutable_inputs"]["preview_hash"]
    assert receipt["semantic_artifact_hashes"]["authority_diff_impact.v1"] == bundle["immutable_inputs"]["diff_hash"]
    assert receipt["lineage_continuity"]["lineage_complete"] is True
    assert receipt["compatibility_posture"]["compatible"] is True
    assert receipt["readiness_confirmations"]["semantic_diagnostics_reviewed"] is True
    assert receipt["readiness_confirmations"]["continuity_posture_reviewed"] is False
    assert receipt["publication_notes"][0]["note_type"] == "operational_change_summary"
    assert any(
        "lowers escalation thresholds" in warning
        for warning in receipt["semantic_compatibility_warnings"]
    )
    assert receipt["receipt_hash"].startswith("sha256:")


def test_publication_receipt_is_deterministic_for_identical_inputs():
    authority = _authority_contract()
    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=build_governance_impact_preview(authority),
    )

    first = build_publication_receipt(authority_bundle=bundle, published_at="2026-05-25T18:00:00Z")
    second = build_publication_receipt(authority_bundle=bundle, published_at="2026-05-25T18:00:00Z")

    assert first == second


def test_authority_bundle_does_not_import_guard_or_cloud(monkeypatch):
    monkeypatch.setitem(sys.modules, "waveframe_guard", None)
    monkeypatch.setitem(sys.modules, "governance_cloud", None)
    authority = _authority_contract()

    bundle = build_authority_bundle(
        authority_contract=authority,
        publication_manifest=_publication_manifest(authority),
        governance_impact_preview=build_governance_impact_preview(authority),
    )

    assert bundle["schema_version"] == "authority_bundle.v1"


def test_cli_authority_bundle_exports_bundle(tmp_path, capsys):
    authority = _authority_contract()
    manifest = _publication_manifest(authority)
    preview = build_governance_impact_preview(authority)
    authority_path = tmp_path / "authority.contract.json"
    manifest_path = tmp_path / "publication_manifest.json"
    preview_path = tmp_path / "preview.json"
    bundle_path = tmp_path / "authority.bundle.json"
    authority_path.write_text(json.dumps(authority), encoding="utf-8")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    preview_path.write_text(json.dumps(preview), encoding="utf-8")

    exit_code = governance_cli(
        [
            "authority-bundle",
            "--authority",
            str(authority_path),
            "--manifest",
            str(manifest_path),
            "--preview",
            str(preview_path),
            "--output",
            str(bundle_path),
        ]
    )

    captured = capsys.readouterr()
    exported = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert exported["schema_version"] == "authority_bundle.v1"
    assert exported["publication_id"] == "pub_20260524_0001"
    assert "Authority Bundle" in captured.out


def test_authority_bundle_schema_version_is_canonical_const():
    schema = json.loads(Path("schemas/authority_bundle.v1.json").read_text(encoding="utf-8"))

    assert schema["properties"]["schema_version"]["const"] == AUTHORITY_BUNDLE_V1


def _authority_contract(*, threshold: int = 250000, version: str = "0.1.0") -> dict:
    return {
        "schema_version": "authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": version,
        "contract_hash": f"sha256:authority-{version}-{threshold}",
        "scope": {
            "description": "Corporate treasury transfers",
            "resource": "Corporate treasury account",
        },
        "governed_actions": ["transfer"],
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
        "artifact_requirements": {"required": ["replay", "evidence"]},
        "lineage": {
            "schema_version": "governance_authority_lineage.v1",
            "source_hash": "sha256:source",
            "compilation_report_hash": "sha256:report",
            "review_id": "review-finance-policy",
        },
    }


def _semantic_commit_bundle(authority: dict) -> dict:
    return {
        "schema_version": "semantic_commit_bundle.v1",
        "semantic_commit_id": f"semantic-commit-{authority['contract_version']}",
        "semantic_commit_hash": f"sha256:semantic-{authority['contract_version']}".replace(".", ""),
        "committed_semantic_meaning": authority,
    }


def _compiled_authority_contract(authority: dict, semantic_commit: dict) -> dict:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "authority_ref": f"{authority['contract_id']}@{authority['contract_version']}",
        "contract_id": authority["contract_id"],
        "contract_version": authority["contract_version"],
        "compiled_from": {
            "schema_version": "semantic_commit_bundle.v1",
            "semantic_commit_hash": semantic_commit["semantic_commit_hash"],
        },
        "capability_scope": [],
        "replay_obligations": [],
        "continuity_requirements": {},
        "contract_hash": f"sha256:compiled-{authority['contract_version']}".replace(".", ""),
    }


def _publication_manifest(authority: dict) -> dict:
    return {
        "schema_version": "publication_manifest.v1",
        "publication_id": "pub_20260524_0001",
        "published_at": "2026-05-24T12:00:00Z",
        "published_by": "governance-team",
        "contracts": [
            {
                "contract_id": authority["contract_id"],
                "contract_version": authority["contract_version"],
                "contract_hash": authority["contract_hash"],
                "path": "contracts/finance-policy.contract.json",
                "source_hash": "sha256:source",
                "compilation_report_hash": "sha256:report",
            }
        ],
        "reviews": [{"path": "reviews/finance-policy.review.json"}],
        "snapshots": [{"path": "snapshots/snapshot.json"}],
    }
