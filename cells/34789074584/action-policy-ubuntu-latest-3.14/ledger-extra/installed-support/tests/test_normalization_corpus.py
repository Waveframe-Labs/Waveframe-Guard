from __future__ import annotations

import json
from pathlib import Path

import pytest


from governance_ledger.extract import extract_constraints
from governance_ledger.review import build_review_report


CORPUS_ROOT = Path(__file__).resolve().parent / "normalization_corpus" / "policies"


def corpus_cases() -> list[Path]:
    return sorted(CORPUS_ROOT.glob("*/*.json"))


@pytest.mark.parametrize("case_path", corpus_cases(), ids=lambda path: str(path.relative_to(CORPUS_ROOT)))
def test_normalization_corpus(case_path: Path):
    case = json.loads(case_path.read_text(encoding="utf-8"))

    policy = extract_constraints(case["policy_text"])
    review = build_review_report(case["policy_text"], policy)

    assert _without_identity(policy) == case["expected_policy"]
    assert [
        statement["classification"]
        for statement in review["normalized_statements"]
    ] == case["expected_classifications"]
    assert review["extraction_coverage"]["coverage_percent"] == case["expected_coverage_percent"]
    assert sorted({warning["type"] for warning in review["warnings"]}) == sorted(
        case["expected_warning_types"]
    )
    assert _publication_gate(review) == case["expected_publication_gate"]


def _without_identity(policy: dict) -> dict:
    return {
        key: value
        for key, value in policy.items()
        if key not in {"contract_id", "contract_version"}
    }


def _publication_gate(review: dict) -> str:
    if any(warning.get("severity") == "error" for warning in review["warnings"]):
        return "BLOCKED"
    return "READY"
