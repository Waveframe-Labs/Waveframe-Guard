import pytest

from governance_ledger import (
    attach_compiled_contract,
    attach_deployment,
    review_constraints,
    transition_review_status,
)


def _compiled_review():
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
    return attach_compiled_contract(
        approved,
        {
            "contract_id": "finance-core",
            "contract_version": "1.0.0",
            "contract_hash": "abc123",
        },
        actor="compiler-service",
        timestamp="2026-05-07T20:30:00Z",
    )


def test_attach_deployment_requires_compiled_review():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-002",
        created_at="2026-05-07T20:00:00Z",
    )

    with pytest.raises(ValueError, match="compiled reviews"):
        attach_deployment(
            review,
            environment="production",
            runtime="waveframe-guard",
            deployed_by="ops-team",
            enforcement_engine_version="0.12.0",
        )


def test_attach_deployment_requires_compiled_contract_linkage():
    review = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-003",
        created_at="2026-05-07T20:00:00Z",
        review_status="compiled",
    )

    with pytest.raises(ValueError, match="compiled contract linkage"):
        attach_deployment(
            review,
            environment="production",
            runtime="waveframe-guard",
            deployed_by="ops-team",
            enforcement_engine_version="0.12.0",
        )


def test_attach_deployment_adds_runtime_provenance():
    compiled_review = _compiled_review()

    deployed_review = attach_deployment(
        compiled_review,
        environment="production",
        runtime="waveframe-guard",
        deployed_by="ops-team",
        enforcement_engine_version="0.12.0",
        timestamp="2026-05-07T21:00:00Z",
    )

    assert deployed_review["review_status"] == "deployed"
    assert deployed_review["deployment"] == {
        "environment": "production",
        "runtime": "waveframe-guard",
        "enforcement_engine": "cricore",
        "engine_version": "0.12.0",
        "deployed_by": "ops-team",
        "deployed_at": "2026-05-07T21:00:00Z",
    }


def test_attach_deployment_uses_lifecycle_transition():
    compiled_review = _compiled_review()

    deployed_review = attach_deployment(
        compiled_review,
        environment="production",
        runtime="waveframe-guard",
        deployed_by="ops-team",
        enforcement_engine_version="0.12.0",
        timestamp="2026-05-07T21:00:00Z",
    )

    assert deployed_review["lifecycle"][-1] == {
        "from_status": "compiled",
        "to_status": "deployed",
        "actor": "ops-team",
        "timestamp": "2026-05-07T21:00:00Z",
        "note": "Attached deployment provenance.",
    }


def test_attach_deployment_returns_new_review_without_mutating_input():
    compiled_review = _compiled_review()

    deployed_review = attach_deployment(
        compiled_review,
        environment="production",
        runtime="waveframe-guard",
        deployed_by="ops-team",
        enforcement_engine_version="0.12.0",
        timestamp="2026-05-07T21:00:00Z",
    )

    assert deployed_review is not compiled_review
    assert compiled_review["review_status"] == "compiled"
    assert "deployment" not in compiled_review
    assert deployed_review["review_status"] == "deployed"


def test_attach_deployment_requires_deployment_fields():
    compiled_review = _compiled_review()

    with pytest.raises(ValueError, match="environment"):
        attach_deployment(
            compiled_review,
            environment="",
            runtime="waveframe-guard",
            deployed_by="ops-team",
            enforcement_engine_version="0.12.0",
        )
