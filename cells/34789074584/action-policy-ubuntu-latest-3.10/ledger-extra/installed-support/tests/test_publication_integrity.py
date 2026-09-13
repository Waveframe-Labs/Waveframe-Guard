from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest


from governance_ledger.extract import extract_constraints
from governance_ledger.lifecycle import transition_review_status
from governance_ledger.publish import publish_review_file
from governance_ledger.registry import validate_registry_hash
from governance_ledger.review import build_review_report


def test_publish_commits_authority_transaction_with_registry_integrity(tmp_path):
    paths = _paths(tmp_path)
    review_path = _write_approved_review(
        paths,
        "finance_policy",
        "Transfers above $1000000 require manager approval.",
        timestamp="2026-05-13T12:00:00Z",
    )

    publication = publish_review_file(
        review_path,
        generated_dir=paths["generated"],
        contracts_dir=paths["contracts"],
        reviews_dir=paths["reviews"],
        snapshots_dir=paths["snapshots"],
        timestamp="2026-05-13T12:30:00Z",
    )

    assert publication["publication_status"] == "COMMITTED"
    assert publication["publication_id"] == "pub_20260513_0001"
    assert publication["registry_hash"].startswith("sha256:")

    registry = _read_json(paths["contracts"] / "index.json")
    validate_registry_hash(registry)
    assert registry["registry_hash"] == publication["registry_hash"]
    assert registry["contracts"][0]["authority_ref"] == "finance-policy@0.1.0"
    assert registry["latest"]["finance-policy"]["contract_version"] == "0.1.0"

    manifest = _read_json(Path(publication["manifest"]))
    deployed_review = _read_json(Path(publication["deployed_review"]))
    contract = _read_json(Path(publication["contract"]))
    assert manifest["schema_version"] == "publication_manifest.v1"
    assert manifest["publication_id"] == publication["publication_id"]
    assert deployed_review["publication_id"] == publication["publication_id"]
    assert contract["schema_version"] == "compiled_authority_contract.v1"
    assert contract["lineage"]["schema_version"] == "governance_authority_lineage.v1"
    assert contract["lineage"]["source_hash"] == deployed_review["source_hash"]
    assert contract["lineage"]["compilation_report_hash"] == deployed_review["compilation_report"]["report_hash"]
    assert manifest["contracts"][0]["source_hash"] == deployed_review["source_hash"]
    assert registry["contracts"][0]["source_hash"] == deployed_review["source_hash"]


def test_publish_stamps_lineage_when_installed_compiler_drops_unknown_fields(tmp_path, monkeypatch):
    compiler_module = types.ModuleType("compiler")
    compile_policy_module = types.ModuleType("compiler.compile_policy")

    def compile_policy_without_lineage(policy: dict) -> dict:
        return {
            "contract_id": policy["contract_id"],
            "contract_version": policy["contract_version"],
            "approval_requirements": policy.get("approvals", {}),
            "authority_requirements": policy.get("authority", {}),
            "artifact_requirements": policy.get("artifacts", {}),
            "stage_requirements": policy.get("stages", {}),
            "invariants": {},
            "contract_hash": "compiler-hash-without-lineage",
        }

    compile_policy_module.compile_policy = compile_policy_without_lineage
    monkeypatch.setitem(sys.modules, "compiler", compiler_module)
    monkeypatch.setitem(sys.modules, "compiler.compile_policy", compile_policy_module)

    paths = _paths(tmp_path)
    review_path = _write_approved_review(
        paths,
        "finance_policy",
        "Transfers above $1000000 require manager approval.",
        timestamp="2026-05-13T12:00:00Z",
    )

    publication = publish_review_file(
        review_path,
        generated_dir=paths["generated"],
        contracts_dir=paths["contracts"],
        reviews_dir=paths["reviews"],
        snapshots_dir=paths["snapshots"],
        timestamp="2026-05-13T12:30:00Z",
    )

    contract = _read_json(Path(publication["contract"]))
    manifest = _read_json(Path(publication["manifest"]))
    registry = _read_json(Path(publication["registry"]))
    deployed_review = _read_json(Path(publication["deployed_review"]))

    assert contract["schema_version"] == "compiled_authority_contract.v1"
    assert contract["lineage"]["source_hash"] == deployed_review["source_hash"]
    assert contract["lineage"]["compilation_report_hash"] == deployed_review["compilation_report"]["report_hash"]
    assert contract["contract_hash"] != "compiler-hash-without-lineage"
    assert manifest["contracts"][0]["source_hash"] == deployed_review["source_hash"]
    assert registry["contracts"][0]["source_hash"] == deployed_review["source_hash"]


def test_publish_rolls_back_when_immutable_contract_would_change(tmp_path):
    paths = _paths(tmp_path)
    review_path = _write_approved_review(
        paths,
        "finance_policy",
        "Transfers above $1000000 require manager approval.",
        timestamp="2026-05-13T12:00:00Z",
    )
    first = publish_review_file(
        review_path,
        generated_dir=paths["generated"],
        contracts_dir=paths["contracts"],
        reviews_dir=paths["reviews"],
        snapshots_dir=paths["snapshots"],
        timestamp="2026-05-13T12:30:00Z",
    )

    registry_before = (paths["contracts"] / "index.json").read_text(encoding="utf-8")
    deployed_before = Path(first["deployed_review"]).read_text(encoding="utf-8")
    snapshots_before = sorted(path.name for path in paths["snapshots"].glob("*.json"))

    changed_review_path = _write_approved_review(
        paths,
        "finance_policy",
        "Transfers above $1000000 require director approval.",
        timestamp="2026-05-13T13:00:00Z",
    )

    with pytest.raises(ValueError, match="Refusing to republish finance-policy@0.1.0 with different contract_hash"):
        publish_review_file(
            changed_review_path,
            generated_dir=paths["generated"],
            contracts_dir=paths["contracts"],
            reviews_dir=paths["reviews"],
            snapshots_dir=paths["snapshots"],
            timestamp="2026-05-13T13:30:00Z",
        )

    assert (paths["contracts"] / "index.json").read_text(encoding="utf-8") == registry_before
    assert Path(first["deployed_review"]).read_text(encoding="utf-8") == deployed_before
    assert sorted(path.name for path in paths["snapshots"].glob("*.json")) == snapshots_before
    assert not list(paths["contracts"].glob("*.tmp"))
    assert not list(paths["contracts"].glob("*.bak"))


def _paths(root: Path) -> dict[str, Path]:
    paths = {
        "generated": root / "generated",
        "contracts": root / "contracts",
        "reviews": root / "reviews",
        "snapshots": root / "snapshots",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _write_approved_review(
    paths: dict[str, Path],
    stem: str,
    policy_text: str,
    *,
    timestamp: str,
) -> Path:
    policy = extract_constraints(policy_text)
    review = build_review_report(
        policy_text,
        policy,
        review_id=f"review-{stem}",
        created_at=timestamp,
        source_document=f"{stem}.txt",
    )
    review = transition_review_status(
        review,
        "reviewed",
        actor="governance-team",
        timestamp=timestamp,
    )
    review = transition_review_status(
        review,
        "approved",
        actor="governance-team",
        timestamp=timestamp,
    )
    generated_path = paths["generated"] / f"{stem}.generated.json"
    review_path = paths["reviews"] / f"{stem}.review.json"
    _write_json(generated_path, policy)
    _write_json(review_path, review)
    return review_path


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
