import pytest

from governance_ledger import review_constraints, transition_review_status
from governance_ledger.lifecycle import (
    ALLOWED_REVIEW_TRANSITIONS,
    VALID_REVIEW_STATUSES,
)


def test_review_status_constants_define_expected_lifecycle():
    assert VALID_REVIEW_STATUSES == {
        "pending",
        "reviewed",
        "approved",
        "rejected",
        "compiled",
        "deployed",
    }
    assert ALLOWED_REVIEW_TRANSITIONS == {
        "pending": {"reviewed", "rejected"},
        "reviewed": {"approved", "rejected"},
        "approved": {"compiled"},
        "compiled": {"deployed"},
        "rejected": set(),
        "deployed": set(),
    }


def test_transitions_review_status_and_appends_lifecycle_entry():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-001",
        created_at="2026-05-07T20:00:00Z",
    )

    updated_review = transition_review_status(
        review,
        "reviewed",
        actor="governance-team",
        timestamp="2026-05-07T20:14:00Z",
        note="Reviewed extracted constraints.",
    )

    assert updated_review["review_status"] == "reviewed"
    assert updated_review["lifecycle"] == [
        {
            "from_status": "pending",
            "to_status": "reviewed",
            "actor": "governance-team",
            "timestamp": "2026-05-07T20:14:00Z",
            "note": "Reviewed extracted constraints.",
        },
    ]


def test_transition_returns_new_review_without_mutating_input():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-002",
        created_at="2026-05-07T20:00:00Z",
    )

    updated_review = transition_review_status(
        review,
        "reviewed",
        timestamp="2026-05-07T20:14:00Z",
    )

    assert updated_review is not review
    assert review["review_status"] == "pending"
    assert "lifecycle" not in review
    assert updated_review["review_status"] == "reviewed"


def test_transition_preserves_existing_lifecycle_entries():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-003",
        created_at="2026-05-07T20:00:00Z",
    )
    reviewed = transition_review_status(
        review,
        "reviewed",
        actor="governance-team",
        timestamp="2026-05-07T20:14:00Z",
    )

    approved = transition_review_status(
        reviewed,
        "approved",
        actor="governance-team",
        timestamp="2026-05-07T20:30:00Z",
        note="Approved for compilation.",
    )

    assert approved["review_status"] == "approved"
    assert approved["lifecycle"] == [
        {
            "from_status": "pending",
            "to_status": "reviewed",
            "actor": "governance-team",
            "timestamp": "2026-05-07T20:14:00Z",
            "note": None,
        },
        {
            "from_status": "reviewed",
            "to_status": "approved",
            "actor": "governance-team",
            "timestamp": "2026-05-07T20:30:00Z",
            "note": "Approved for compilation.",
        },
    ]


def test_rejects_invalid_new_status():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-004",
        created_at="2026-05-07T20:00:00Z",
    )

    with pytest.raises(ValueError, match="Invalid new review status"):
        transition_review_status(review, "archived")


def test_rejects_invalid_current_status():
    review = {
        "review_id": "review-005",
        "review_status": "archived",
    }

    with pytest.raises(ValueError, match="Invalid current review status"):
        transition_review_status(review, "reviewed")


def test_rejects_invalid_transition():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-006",
        created_at="2026-05-07T20:00:00Z",
    )

    with pytest.raises(ValueError, match="Invalid review status transition"):
        transition_review_status(review, "compiled")
