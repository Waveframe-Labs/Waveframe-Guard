from governance_ledger import build_review_report, extract_constraints, review_constraints


def test_builds_review_report_with_source_text():
    text = """
    Transfers above $1M require manager approval.
    Proposer and approver must be separate.
    """
    policy = extract_constraints(text)

    report = build_review_report(
        text,
        policy,
        review_id="review-001",
        created_at="2026-05-07T20:14:00Z",
        source_document="finance_policy.txt",
    )

    assert report["review_id"] == "review-001"
    assert report["created_at"] == "2026-05-07T20:14:00Z"
    assert report["source_document"] == "finance_policy.txt"
    assert report["review_status"] == "pending"
    assert report["warnings"] == []
    assert report["detected_constraints"] == [
        {
            "type": "required_role",
            "value": "manager",
            "source_text": "Transfers above $1M require manager approval.",
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
            "type": "required_approval",
            "role": "manager",
            "condition": {
                "field": "amount",
                "operator": ">",
                "value": 1_000_000,
            },
            "source_text": "Transfers above $1M require manager approval.",
        },
        {
            "type": "separation_of_duties",
            "value": True,
            "source_text": "Proposer and approver must be separate.",
        },
    ]
    assert report["compilation_report"]["schema_version"] == "governance_compilation_report.v1"
    assert report["normalization_report"]["schema_version"] == "governance_normalization_report.v1"


def test_review_constraints_extracts_and_reports():
    report = review_constraints(
        "Only compliance may approve transfers.",
        review_id="review-002",
        created_at="2026-05-07T20:15:00Z",
    )

    assert report["review_id"] == "review-002"
    assert report["created_at"] == "2026-05-07T20:15:00Z"
    assert report["source_document"] is None
    assert report["review_status"] == "pending"
    assert report["detected_constraints"] == [
        {
            "type": "required_role",
            "value": "compliance",
            "source_text": "Only compliance may approve transfers.",
        },
        {
            "type": "required_approval",
            "role": "compliance",
            "source_text": "Only compliance may approve transfers.",
        },
    ]
    assert report["warnings"] == []
    assert report["extraction_coverage"]["coverage_percent"] == 100


def test_review_id_is_stable_when_not_supplied():
    text = "Only compliance may approve transfers."
    policy = extract_constraints(text)

    first_report = build_review_report(
        text,
        policy,
        created_at="2026-05-07T20:15:00Z",
    )
    second_report = build_review_report(
        text,
        policy,
        created_at="2026-05-07T20:16:00Z",
    )

    assert first_report["review_id"] == second_report["review_id"]
    assert first_report["review_id"].startswith("review-")
