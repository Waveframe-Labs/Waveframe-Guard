from copy import deepcopy

import pytest

from governance_ledger import (
    attach_compiled_contract,
    attach_deployment,
    create_snapshot,
    review_constraints,
    rollback_to_snapshot,
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


def _deployed_review():
    compiled = attach_compiled_contract(
        _approved_review(),
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "contract_hash": "abc123",
        },
        actor="compiler-service",
        timestamp="2026-05-07T20:30:00Z",
    )
    return attach_deployment(
        compiled,
        environment="production",
        runtime="waveframe-guard",
        deployed_by="ops-team",
        enforcement_engine_version="0.12.0",
        timestamp="2026-05-07T21:00:00Z",
    )


def test_rollback_to_snapshot_restores_review_state_and_appends_provenance():
    approved_review = _approved_review()
    snapshot = create_snapshot(
        approved_review,
        created_at="2026-05-07T20:25:00Z",
    )
    current_review = _deployed_review()

    restored_review = rollback_to_snapshot(
        current_review,
        snapshot,
        actor="ops-team",
        timestamp="2026-05-07T22:00:00Z",
        note="restore approved governance",
    )

    assert restored_review["review_status"] == "approved"
    assert "deployment" not in restored_review
    assert restored_review["lifecycle"][:-1] == approved_review["lifecycle"]
    assert restored_review["lifecycle"][-1] == {
        "from_snapshot": snapshot["snapshot_id"],
        "rollback_actor": "ops-team",
        "rollback_reason": "restore approved governance",
        "rolled_back_at": "2026-05-07T22:00:00Z",
    }
    assert restored_review["rollback"] == {
        "from_review_id": "review-001",
        "from_review_status": "deployed",
        "to_snapshot_id": snapshot["snapshot_id"],
        "to_review_id": "review-001",
        "to_review_status": "approved",
        "rollback_actor": "ops-team",
        "rollback_reason": "restore approved governance",
        "rolled_back_at": "2026-05-07T22:00:00Z",
    }


def test_rollback_does_not_mutate_current_review_or_snapshot():
    snapshot = create_snapshot(
        _approved_review(),
        created_at="2026-05-07T20:25:00Z",
    )
    original_snapshot = deepcopy(snapshot)
    current_review = _deployed_review()
    original_current_review = deepcopy(current_review)

    restored_review = rollback_to_snapshot(
        current_review,
        snapshot,
        actor="ops-team",
        timestamp="2026-05-07T22:00:00Z",
    )

    assert restored_review is not current_review
    assert current_review == original_current_review
    assert snapshot == original_snapshot


def test_rollback_rejects_snapshot_with_tampered_review():
    snapshot = create_snapshot(
        _approved_review(),
        created_at="2026-05-07T20:25:00Z",
    )
    snapshot["review"]["review_status"] = "deployed"

    with pytest.raises(ValueError, match="integrity"):
        rollback_to_snapshot(
            _deployed_review(),
            snapshot,
            actor="ops-team",
        )


def test_rollback_rejects_snapshot_with_invalid_snapshot_id():
    snapshot = create_snapshot(
        _approved_review(),
        created_at="2026-05-07T20:25:00Z",
    )
    snapshot["snapshot_id"] = "snapshot-wrong"

    with pytest.raises(ValueError, match="Snapshot ID"):
        rollback_to_snapshot(
            _deployed_review(),
            snapshot,
            actor="ops-team",
        )


def test_rollback_rejects_snapshot_missing_review():
    snapshot = create_snapshot(
        _approved_review(),
        created_at="2026-05-07T20:25:00Z",
    )
    snapshot.pop("review")

    with pytest.raises(ValueError, match="missing review"):
        rollback_to_snapshot(
            _deployed_review(),
            snapshot,
            actor="ops-team",
        )
