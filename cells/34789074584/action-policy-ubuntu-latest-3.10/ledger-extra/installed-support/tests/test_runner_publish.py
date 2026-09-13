import json
from pathlib import Path

import pytest

from governance_ledger.publish import approve_review_file, publish_review_file
from governance_ledger.cli import main as governance_cli
from governance_ledger.registry import resolve_authority_ref, update_contract_registry
from governance_ledger.runner import run_policy_directory
from governance_ledger.checks import check_validation_directory, format_check_summary
from governance_ledger.inspect import format_artifact, format_contract_list, list_contracts, show_artifact
from governance_ledger.paths import artifact_path
from governance_ledger.summary import build_pr_summary, format_publish_summary, format_run_summary


def test_run_policy_directory_generates_draft_artifacts_only(tmp_path):
    policies_dir = tmp_path / "policies"
    generated_dir = tmp_path / "generated"
    reviews_dir = tmp_path / "reviews"
    contracts_dir = tmp_path / "contracts"
    policies_dir.mkdir()
    (policies_dir / "finance_policy.txt").write_text(
        "Transfers above $1M require manager approval.\n"
        "Proposer and approver must be separate.\n",
        encoding="utf-8",
    )

    results = run_policy_directory(
        policies_dir,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )

    assert results == [
        {
            "policy": str(policies_dir / "finance_policy.txt"),
            "generated": str(generated_dir / "finance_policy.generated.json"),
            "validation": str(generated_dir / "finance_policy.validation.json"),
            "review": str(reviews_dir / "finance_policy.review.json"),
            "review_id": "review-finance_policy",
            "review_status": "pending",
            "review_created": True,
            "constraint_count": 4,
            "warning_count": 0,
            "ambiguity_count": 0,
        },
    ]
    assert (generated_dir / "finance_policy.generated.json").exists()
    assert (generated_dir / "finance_policy.validation.json").exists()
    assert not contracts_dir.exists()

    review = json.loads((reviews_dir / "finance_policy.review.json").read_text())
    assert review["review_status"] == "pending"


def test_artifact_path_normalizes_windows_separators():
    assert artifact_path("contracts\\finance-policy-0.1.0.contract.json") == (
        "contracts/finance-policy-0.1.0.contract.json"
    )


def test_run_policy_directory_does_not_overwrite_existing_review(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )

    run_policy_directory(
        policies_dir,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )

    review = json.loads(review_path.read_text())
    assert review["review_status"] == "approved"


def test_publish_review_file_requires_approved_review(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"

    with pytest.raises(ValueError, match="approved"):
        publish_review_file(
            review_path,
            generated_dir=generated_dir,
            contracts_dir=contracts_dir,
            reviews_dir=reviews_dir,
            snapshots_dir=snapshots_dir,
        )


def test_approve_then_publish_creates_contract_review_and_snapshot_artifacts(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"

    approved_review = approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
        note="Approved finance governance.",
    )
    result = publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-09T12:30:00Z",
    )

    assert approved_review["review_status"] == "approved"
    assert approved_review["approved_by"] == "governance-team"
    assert approved_review["approved_at"] == "2026-05-09T12:00:00Z"
    assert approved_review["approval_note"] == "Approved finance governance."
    assert Path(result["contract"]).parent == contracts_dir
    assert Path(result["authority_bundle"]).parent == contracts_dir
    assert Path(result["publication_receipt"]).parent == contracts_dir
    assert Path(result["deployed_review"]).parent == reviews_dir
    assert Path(result["manifest"]).parent == contracts_dir
    assert Path(result["registry"]).parent == contracts_dir
    assert Path(result["snapshot"]).parent == snapshots_dir
    assert Path(result["contract"]).name.endswith(".contract.json")

    deployed_review = json.loads(Path(result["deployed_review"]).read_text())
    assert deployed_review["review_status"] == "deployed"
    assert deployed_review["compiled_contract"]["contract_hash"]
    assert deployed_review["deployment"]["environment"] == "production"

    manifest = json.loads(Path(result["manifest"]).read_text())
    assert manifest["published_at"] == "2026-05-09T12:30:00Z"
    assert manifest["contracts"][0]["contract_hash"].startswith("sha256:")
    assert manifest["contracts"][0]["path"] == Path(result["contract"]).as_posix()
    assert "\\" not in manifest["contracts"][0]["path"]
    assert manifest["reviews"][0]["path"] == Path(result["deployed_review"]).as_posix()
    assert "\\" not in manifest["reviews"][0]["path"]
    assert manifest["snapshots"][0]["path"] == Path(result["snapshot"]).as_posix()
    assert "\\" not in manifest["snapshots"][0]["path"]

    registry = json.loads(Path(result["registry"]).read_text())
    authority_bundle = json.loads(Path(result["authority_bundle"]).read_text())
    publication_receipt = json.loads(Path(result["publication_receipt"]).read_text())
    assert registry["contracts"][0]["contract_id"] == "finance-policy"
    assert registry["contracts"][0]["contract_version"] == "0.1.0"
    assert registry["contracts"][0]["authority_ref"] == "finance-policy@0.1.0"
    assert registry["contracts"][0]["contract_ref"] == "finance-policy@0.1.0"
    assert registry["contracts"][0]["contract_hash"] == manifest["contracts"][0]["contract_hash"]
    assert registry["contracts"][0]["path"] == Path(result["contract"]).as_posix()
    assert registry["contracts"][0]["bundle_path"] == Path(result["authority_bundle"]).as_posix()
    assert registry["contracts"][0]["bundle_hash"] == publication_receipt["bundle_hash"]
    assert registry["contracts"][0]["lifecycle_state"] == "active"
    assert registry["contracts"][0]["publication_id"] == "pub_20260509_0001"
    assert registry["contracts"][0]["published_at"] == "2026-05-09T12:30:00Z"
    assert registry["contracts"][0]["published_by"] == "governance-team"
    assert registry["contracts"][0]["source_hash"] == deployed_review["source_hash"]
    assert (
        registry["contracts"][0]["compilation_report_hash"]
        == deployed_review["compilation_report"]["report_hash"]
    )
    assert authority_bundle["schema_version"] == "authority_bundle.v1"
    assert authority_bundle["authority_ref"] == "finance-policy@0.1.0"
    assert authority_bundle["publication_id"] == "pub_20260509_0001"
    assert authority_bundle["contract_hash"] == manifest["contracts"][0]["contract_hash"]
    assert authority_bundle["publication_manifest"] == manifest
    assert publication_receipt["schema_version"] == "publication_receipt.v1"
    assert publication_receipt["authority_ref"] == "finance-policy@0.1.0"
    assert publication_receipt["publication_id"] == "pub_20260509_0001"
    assert publication_receipt["bundle_hash"] == result["authority_bundle_hash"]

    resolved = resolve_authority_ref("finance-policy@0.1.0", contracts_dir=contracts_dir)
    assert resolved == {
        "authority_ref": "finance-policy@0.1.0",
        "lifecycle_state": "active",
        "publication_id": "pub_20260509_0001",
        "contract_hash": manifest["contracts"][0]["contract_hash"],
        "bundle_hash": publication_receipt["bundle_hash"],
        "bundle_path": Path(result["authority_bundle"]).as_posix(),
        "contract_path": Path(result["contract"]).as_posix(),
        "published_at": "2026-05-09T12:30:00Z",
        "published_by": "governance-team",
    }


def test_publish_without_timestamp_records_effective_publication_time(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )

    result = publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
    )

    manifest = json.loads(Path(result["manifest"]).read_text())
    registry = json.loads(Path(result["registry"]).read_text())
    deployed_review = json.loads(Path(result["deployed_review"]).read_text())
    snapshot = json.loads(Path(result["snapshot"]).read_text())

    assert manifest["published_at"] is not None
    assert registry["contracts"][0]["published_at"] == manifest["published_at"]
    assert deployed_review["deployment"]["deployed_at"] == manifest["published_at"]
    assert snapshot["created_at"] == manifest["published_at"]


def test_registry_update_requires_publication_timestamp(tmp_path):
    with pytest.raises(ValueError, match="published_at"):
        update_contract_registry(
            tmp_path / "contracts",
            compiled_contract={
                "contract_id": "finance-policy",
                "contract_version": "0.1.0",
                "contract_hash": "abc123",
            },
            contract_path=tmp_path / "contracts" / "finance-policy-0.1.0.contract.json",
            published_at=None,
            published_by="governance-team",
        )


def test_publish_blocks_generated_policy_schema_errors(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    generated_path = generated_dir / "finance_policy.generated.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )
    generated_path.write_text(
        json.dumps(
            {
                "contract_id": "finance-policy",
                "contract_version": "0.1.0",
                "approvals": {"thresholds": {"transfer_funds": 1_000_000}},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="canonical compiler ingestion schema"):
        publish_review_file(
            review_path,
            generated_dir=generated_dir,
            contracts_dir=contracts_dir,
            reviews_dir=reviews_dir,
            snapshots_dir=snapshots_dir,
            timestamp="2026-05-09T12:30:00Z",
        )


def test_check_validation_directory_fails_on_error_severity(tmp_path):
    generated_dir = tmp_path / "generated"
    generated_dir.mkdir()
    (generated_dir / "policy.validation.json").write_text(
        json.dumps(
            {
                "warnings": [
                    {
                        "type": "ambiguous_authority",
                        "severity": "error",
                        "text": "appropriate manager",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = check_validation_directory(generated_dir)

    assert result["status"] == "failed"
    assert result["publication_status"] == "BLOCKED_ERRORS"
    assert result["policy_count"] == 1
    assert result["warning_count"] == 1
    assert result["error_count"] == 1


def test_check_validation_summary_reports_counts_and_readiness(tmp_path):
    generated_dir = tmp_path / "generated"
    generated_dir.mkdir()
    (generated_dir / "policy.validation.json").write_text(
        json.dumps(
            {
                "warnings": [
                    {
                        "type": "extraction_gap",
                        "severity": "warning",
                        "text": "review quarterly",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = check_validation_directory(generated_dir)
    summary = format_check_summary(result)

    assert result["status"] == "passed"
    assert result["publication_status"] == "READY_FOR_REVIEW"
    assert result["policy_count"] == 1
    assert result["warning_count"] == 1
    assert result["error_count"] == 0
    assert "Governance Validation Summary" in summary
    assert "Policies Processed: 1" in summary
    assert "Warnings: 1" in summary
    assert "Errors: 0" in summary
    assert "READY_FOR_REVIEW" in summary


def test_publish_refuses_to_overwrite_immutable_contract_output(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )
    result = publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-09T12:30:00Z",
    )
    Path(result["contract"]).write_text('{"tampered": true}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="immutable publication output"):
        publish_review_file(
            review_path,
            generated_dir=generated_dir,
            contracts_dir=contracts_dir,
            reviews_dir=reviews_dir,
            snapshots_dir=snapshots_dir,
            timestamp="2026-05-09T12:30:00Z",
        )


def test_publish_rejects_same_authority_ref_with_different_identity(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )
    publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-09T12:30:00Z",
    )
    (policies_dir / "finance_policy.txt").write_text(
        "Transfers above $1M require director approval.\n"
        "Proposer and approver must be separate.\n",
        encoding="utf-8",
    )
    run_policy_directory(
        policies_dir,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T13:00:00Z",
    )

    with pytest.raises(ValueError, match="Refusing to republish finance-policy@0.1.0"):
        publish_review_file(
            review_path,
            generated_dir=generated_dir,
            contracts_dir=contracts_dir,
            reviews_dir=reviews_dir,
            snapshots_dir=snapshots_dir,
            timestamp="2026-05-09T13:30:00Z",
        )


def test_cli_resolve_requires_explicit_versioned_authority_ref(tmp_path, capsys):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )
    publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-09T12:30:00Z",
    )

    exit_code = governance_cli(
        [
            "resolve",
            "finance-policy@0.1.0",
            "--contracts-dir",
            str(contracts_dir),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Authority:     finance-policy@0.1.0" in captured.out
    assert "State:         active" in captured.out
    assert "Publication:   pub_20260509_0001" in captured.out
    assert "Bundle:        " in captured.out

    with pytest.raises(ValueError, match="explicit versioned reference"):
        resolve_authority_ref("finance-policy@latest", contracts_dir=contracts_dir)


def test_list_contracts_and_show_artifact(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    review_path = reviews_dir / "finance_policy.review.json"
    approve_review_file(
        review_path,
        actor="governance-team",
        timestamp="2026-05-09T12:00:00Z",
    )
    result = publish_review_file(
        review_path,
        generated_dir=generated_dir,
        contracts_dir=contracts_dir,
        reviews_dir=reviews_dir,
        snapshots_dir=snapshots_dir,
        timestamp="2026-05-09T12:30:00Z",
    )

    registry = list_contracts(contracts_dir)
    list_summary = format_contract_list(registry)
    artifact = show_artifact(result["contract"])
    artifact_summary = format_artifact(result["contract"], artifact)

    assert registry["contracts"][0]["contract_id"] == "finance-policy"
    assert "Published Contracts" in list_summary
    assert "finance-policy v0.1.0" in list_summary
    assert "sha256:" in list_summary
    assert artifact["contract_id"] == "finance-policy"
    assert "Artifact:" in artifact_summary


def test_format_publish_summary_normalizes_display_paths():
    summary = format_publish_summary(
        {
            "contract": "contracts\\finance-policy-0.1.0.contract.json",
            "deployed_review": "reviews\\finance_policy.deployed.review.json",
            "manifest": "contracts\\finance_policy.publication_manifest.json",
            "registry": "contracts\\index.json",
            "snapshot": "snapshots\\snapshot-98939483f949.json",
        }
    )

    assert "contracts/finance-policy-0.1.0.contract.json" in summary
    assert "reviews/finance_policy.deployed.review.json" in summary
    assert "snapshots/snapshot-98939483f949.json" in summary
    assert "\\" not in summary


def test_format_run_summary_exposes_operational_counts(tmp_path):
    policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir = _draft_policy(tmp_path)
    results = run_policy_directory(
        policies_dir,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )

    summary = format_run_summary(results)

    assert "[Governance Ledger]" in summary
    assert "Policy: finance_policy.txt" in summary
    assert "4 constraints detected" in summary
    assert "0 ambiguity warnings detected" in summary
    assert "pending human approval" in summary
    assert "review-finance_policy preserved" in summary


def test_build_pr_summary_formats_constraints_warnings_and_status():
    review = {
        "source_document": "finance_policy.txt",
        "review_status": "pending",
        "detected_constraints": [
            {
                "type": "required_role",
                "value": "manager",
                "source_text": "require manager approval",
            },
            {
                "type": "approval_threshold",
                "field": "amount",
                "operator": ">",
                "value": 1_000_000,
                "requires_role": "manager",
                "source_text": "above $1M",
            },
            {
                "type": "separation_of_duties",
                "value": True,
                "source_text": "must be separate",
            },
        ],
        "warnings": [
            {
                "type": "ambiguous_authority",
                "severity": "error",
                "text": "appropriate manager",
            },
        ],
    }

    summary = build_pr_summary(review)

    assert "## Governance Review Summary" in summary
    assert "Policy: finance_policy.txt" in summary
    assert "- required_role: manager" in summary
    assert "- threshold: amount > 1000000 requires manager" in summary
    assert "- separation_of_duties" in summary
    assert 'error: ambiguous clause: "appropriate manager"' in summary
    assert "BLOCKED_PENDING_REVIEW" in summary


def test_build_pr_summary_includes_approval_metadata():
    review = {
        "source_document": "finance_policy.txt",
        "review_status": "approved",
        "approved_by": "governance-team",
        "approved_at": "2026-05-09T12:00:00Z",
        "approval_note": "Approved finance governance.",
        "detected_constraints": [],
        "warnings": [],
    }

    summary = build_pr_summary(review)

    assert "Approval Status:" in summary
    assert "APPROVED" in summary
    assert "Approved By:" in summary
    assert "governance-team" in summary
    assert "Approved At:" in summary
    assert "2026-05-09T12:00:00Z" in summary
    assert "Approval Note:" in summary


def _draft_policy(tmp_path):
    policies_dir = tmp_path / "policies"
    generated_dir = tmp_path / "generated"
    reviews_dir = tmp_path / "reviews"
    contracts_dir = tmp_path / "contracts"
    snapshots_dir = tmp_path / "snapshots"
    policies_dir.mkdir()
    (policies_dir / "finance_policy.txt").write_text(
        "Transfers above $1M require manager approval.\n"
        "Proposer and approver must be separate.\n",
        encoding="utf-8",
    )
    run_policy_directory(
        policies_dir,
        generated_dir=generated_dir,
        reviews_dir=reviews_dir,
    )
    return policies_dir, generated_dir, reviews_dir, contracts_dir, snapshots_dir
