from __future__ import annotations

import pytest

from governance_ledger.extract import extract_constraints
from governance_ledger.review import build_review_report


@pytest.mark.parametrize(
    ("phrase", "operator", "value"),
    [
        ("over $5,000", ">", 5000),
        ("above $1m", ">", 1000000),
        ("greater than 10k", ">", 10000),
        ("at least 1 million", ">=", 1000000),
        ("under $500", "<", 500),
        ("below $5000", "<", 5000),
        ("less than 5K", "<", 5000),
    ],
)
def test_threshold_normalization_matrix(phrase, operator, value):
    text = f"Transfers {phrase} require manager approval."

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert policy.get("authority", {}).get("required_roles", []) == ["manager"]
    assert policy["approvals"]["thresholds"] == [
        {
            "field": "amount",
            "operator": operator,
            "value": value,
            "requires_role": "manager",
        }
    ]
    assert policy["approvals"]["required"] == [
        {
            "role": "manager",
            "condition": {
                "field": "amount",
                "operator": operator,
                "value": value,
            },
        }
    ]
    assert not [
        warning
        for warning in review["warnings"]
        if warning["type"] in {"ambiguous_threshold", "partial_extraction_integrity"}
    ]


def test_missing_role_threshold_is_ambiguous_not_compiler_threshold():
    text = """
    Transfers above $1000000 require approval.
    Requester and approver must be separate.
    """.strip()

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert policy.get("authority", {}).get("required_roles", []) == []
    assert policy.get("approvals", {}).get("thresholds", []) == []
    assert policy.get("authority", {}).get("separation_of_duties") is True
    assert any(
        warning["type"] == "ambiguous_authority"
        and warning["severity"] == "error"
        and "does not name the approving role" in warning["text"]
        for warning in review["warnings"]
    )
    assert review["extraction_coverage"]["coverage_percent"] == 50


def test_subjective_governance_is_not_silently_deterministic():
    text = "Large transfers require manager approval."

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert policy.get("authority", {}).get("required_roles", []) == ["manager"]
    assert policy.get("approvals", {}).get("thresholds", []) == []
    assert any(
        warning["type"] == "ambiguous_threshold"
        and warning["severity"] == "error"
        and "large transfer" in warning["text"].lower()
        for warning in review["warnings"]
    )


def test_low_structural_coverage_blocks_mostly_unparsed_governance():
    text = """
    Transfers over $5,000 require manager approval.
    Invoices should be checked.
    Regional handling is required.
    Exceptions shall be escalated.
    Evidence should be retained.
    """.strip()

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert policy["approvals"]["thresholds"][0]["value"] == 5000
    assert review["extraction_coverage"]["detected_governance_statements"] == 5
    assert review["extraction_coverage"]["deterministically_normalized"] == 2
    assert review["extraction_coverage"]["coverage_percent"] == 40
    assert any(
        warning["type"] == "normalization_coverage"
        and warning["severity"] == "error"
        and "coverage below required threshold" in warning["text"]
        for warning in review["warnings"]
    )


def test_complex_financial_transfer_policy_statement_normalization():
    text = """
    Financial Transfer Approval Policy

    1. Only employees with the Manager role may approve financial transfers.

    2. Any transfer exceeding $10,000 must receive additional approval from a Director before execution.

    3. The employee who creates a transfer request may not be the same employee who approves it.

    4. All transfer approvals must be recorded for audit purposes.

    5. Unauthorized transfer attempts must be blocked and reported to the compliance team.
    """.strip()

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert policy["authority"]["required_roles"] == ["manager", "director"]
    assert policy["authority"]["separation_of_duties"] is True
    assert policy["approvals"]["thresholds"] == [
        {
            "field": "amount",
            "operator": ">",
            "value": 10000,
            "requires_role": "director",
        }
    ]
    assert policy["approvals"]["required"] == [
        {"role": "manager"},
        {
            "role": "director",
            "condition": {
                "field": "amount",
                "operator": ">",
                "value": 10000,
            },
        },
    ]
    assert policy["artifacts"]["required"] == [
        "approval_audit_record",
        "compliance_report",
    ]
    assert review["extraction_coverage"]["coverage_percent"] == 100
    assert [
        statement["classification"]
        for statement in review["normalized_statements"]
    ] == [
        "approval_authority_constraint",
        "conditional_threshold_approval",
        "separation_of_duties_constraint",
        "artifact_requirement",
        "unauthorized_attempt_reporting_requirement",
    ]
    assert not [
        warning
        for warning in review["warnings"]
        if warning["severity"] == "error"
    ]
