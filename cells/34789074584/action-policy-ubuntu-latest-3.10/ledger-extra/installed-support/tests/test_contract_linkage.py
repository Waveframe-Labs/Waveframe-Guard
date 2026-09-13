import pytest

from governance_ledger import (
    attach_compiled_contract,
    review_constraints,
    transition_review_status,
)


def _approved_review():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-001",
        created_at="2026-05-07T20:00:00Z",
    )
    reviewed = transition_review_status(
        review,
        "reviewed",
        actor="governance-team",
        timestamp="2026-05-07T20:10:00Z",
    )
    return transition_review_status(
        reviewed,
        "approved",
        actor="governance-team",
        timestamp="2026-05-07T20:20:00Z",
    )


def test_attach_compiled_contract_requires_approved_review():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-002",
        created_at="2026-05-07T20:00:00Z",
    )

    with pytest.raises(ValueError, match="approved reviews"):
        attach_compiled_contract(
            review,
            {
                "contract_id": "finance-core",
                "contract_version": "1.0.0",
                "contract_hash": "abc123",
            },
        )


def test_attach_compiled_contract_links_only_identity_version_and_hash():
    approved_review = _approved_review()

    linked_review = attach_compiled_contract(
        approved_review,
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "contract_hash": "abc123",
            "approval_requirements": {
                "thresholds": [
                    {
                        "field": "amount",
                        "operator": ">",
                        "value": 1_000_000,
                        "requires_role": "manager",
                    },
                ],
            },
        },
        actor="compiler-service",
        timestamp="2026-05-07T20:30:00Z",
    )

    assert linked_review["review_status"] == "compiled"
    assert linked_review["compiled_contract"] == {
        "contract_id": "finance-core",
        "contract_version": "1.0.0",
        "contract_hash": "abc123",
    }
    assert linked_review["compiled_by"] == "compiler-service"
    assert linked_review["compiled_at"] == "2026-05-07T20:30:00Z"
    assert "approval_requirements" not in linked_review["compiled_contract"]


def test_attach_compiled_contract_uses_lifecycle_transition():
    approved_review = _approved_review()

    linked_review = attach_compiled_contract(
        approved_review,
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "contract_hash": "abc123",
        },
        actor="compiler-service",
        timestamp="2026-05-07T20:30:00Z",
    )

    assert linked_review["lifecycle"][-1] == {
        "from_status": "approved",
        "to_status": "compiled",
        "actor": "compiler-service",
        "timestamp": "2026-05-07T20:30:00Z",
        "note": "Linked compiled contract.",
    }


def test_attach_compiled_contract_returns_new_review_without_mutating_input():
    approved_review = _approved_review()

    linked_review = attach_compiled_contract(
        approved_review,
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "contract_hash": "abc123",
        },
        timestamp="2026-05-07T20:30:00Z",
    )

    assert linked_review is not approved_review
    assert approved_review["review_status"] == "approved"
    assert "compiled_contract" not in approved_review
    assert linked_review["review_status"] == "compiled"


def test_attach_compiled_contract_computes_hash_when_missing():
    approved_review = _approved_review()

    linked_review = attach_compiled_contract(
        approved_review,
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "approval_requirements": {
                "thresholds": [
                    {
                        "field": "amount",
                        "operator": ">",
                        "value": 1_000_000,
                        "requires_role": "manager",
                    },
                ],
            },
        },
        timestamp="2026-05-07T20:30:00Z",
    )

    assert len(linked_review["compiled_contract"]["contract_hash"]) == 64


def test_attach_compiled_contract_requires_contract_identity_fields():
    approved_review = _approved_review()

    with pytest.raises(ValueError, match="contract_id"):
        attach_compiled_contract(
            approved_review,
            {
                "contract_version": "1.0.0",
                "contract_hash": "abc123",
            },
        )
