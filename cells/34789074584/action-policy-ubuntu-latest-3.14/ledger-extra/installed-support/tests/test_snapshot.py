from governance_ledger import (
    attach_compiled_contract,
    attach_deployment,
    create_snapshot,
    review_constraints,
    transition_review_status,
)


def _deployed_review():
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
    approved = transition_review_status(
        reviewed,
        "approved",
        actor="governance-team",
        timestamp="2026-05-07T20:20:00Z",
    )
    compiled = attach_compiled_contract(
        approved,
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


def test_create_snapshot_freezes_review_state():
    review = _deployed_review()

    snapshot = create_snapshot(
        review,
        created_at="2026-05-07T21:30:00Z",
    )

    assert snapshot["snapshot_id"].startswith("snapshot-")
    assert snapshot["created_at"] == "2026-05-07T21:30:00Z"
    assert snapshot["review_id"] == "review-001"
    assert snapshot["review_status"] == "deployed"
    assert len(snapshot["snapshot_hash"]) == 64
    assert snapshot["review"] == review


def test_snapshot_hash_is_deterministic_for_same_review_state():
    review = _deployed_review()

    first_snapshot = create_snapshot(
        review,
        created_at="2026-05-07T21:30:00Z",
    )
    second_snapshot = create_snapshot(
        review,
        created_at="2026-05-07T22:00:00Z",
    )

    assert first_snapshot["snapshot_hash"] == second_snapshot["snapshot_hash"]
    assert first_snapshot["snapshot_id"] == second_snapshot["snapshot_id"]


def test_snapshot_uses_deep_copied_review():
    review = _deployed_review()

    snapshot = create_snapshot(
        review,
        created_at="2026-05-07T21:30:00Z",
    )
    review["deployment"]["engine_version"] = "0.13.0"

    assert snapshot["review"]["deployment"]["engine_version"] == "0.12.0"
    assert snapshot["review"] is not review


def test_snapshot_hash_changes_when_review_state_changes():
    first_review = _deployed_review()
    second_review = _deployed_review()
    second_review["deployment"]["engine_version"] = "0.13.0"

    first_snapshot = create_snapshot(
        first_review,
        created_at="2026-05-07T21:30:00Z",
    )
    second_snapshot = create_snapshot(
        second_review,
        created_at="2026-05-07T21:30:00Z",
    )

    assert first_snapshot["snapshot_hash"] != second_snapshot["snapshot_hash"]
