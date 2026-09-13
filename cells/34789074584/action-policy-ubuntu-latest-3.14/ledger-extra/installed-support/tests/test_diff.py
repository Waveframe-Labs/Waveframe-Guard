from governance_ledger import diff_reviews


def test_diff_reviews_detects_added_removed_and_modified_constraints():
    old_review = {
        "detected_constraints": [
            {
                "type": "required_role",
                "value": "manager",
                "source_text": "require manager approval",
            },
            {
                "type": "separation_of_duties",
                "value": True,
                "source_text": "must be separate",
            },
            {
                "type": "approval_threshold",
                "field": "amount",
                "operator": ">",
                "value": 1_000_000,
                "requires_role": "manager",
                "source_text": "above $1M",
            },
        ],
        "warnings": [],
    }
    new_review = {
        "detected_constraints": [
            {
                "type": "required_role",
                "value": "director",
                "source_text": "require director approval",
            },
            {
                "type": "approval_threshold",
                "field": "amount",
                "operator": ">",
                "value": 2_000_000,
                "requires_role": "manager",
                "source_text": "above $2M",
            },
        ],
        "warnings": [],
    }

    diff = diff_reviews(old_review, new_review)

    assert diff["added_constraints"] == [
        {
            "type": "required_role",
            "value": "director",
            "source_text": "require director approval",
        },
    ]
    assert diff["removed_constraints"] == [
        {
            "type": "required_role",
            "value": "manager",
            "source_text": "require manager approval",
        },
        {
            "type": "separation_of_duties",
            "value": True,
            "source_text": "must be separate",
        },
    ]
    assert diff["modified_constraints"] == [
        {
            "from": {
                "type": "approval_threshold",
                "field": "amount",
                "operator": ">",
                "value": 1_000_000,
                "requires_role": "manager",
                "source_text": "above $1M",
            },
            "to": {
                "type": "approval_threshold",
                "field": "amount",
                "operator": ">",
                "value": 2_000_000,
                "requires_role": "manager",
                "source_text": "above $2M",
            },
        },
    ]


def test_diff_reviews_detects_warning_changes():
    old_review = {
        "detected_constraints": [],
        "warnings": [
            {
                "type": "unsupported_constraint",
                "text": "reasonable approval timing",
            },
        ],
    }
    new_review = {
        "detected_constraints": [],
        "warnings": [
            {
                "type": "ambiguous_authority",
                "text": "appropriate manager",
            },
        ],
    }

    diff = diff_reviews(old_review, new_review)

    assert diff["new_warnings"] == [
        {
            "type": "ambiguous_authority",
            "text": "appropriate manager",
        },
    ]
    assert diff["resolved_warnings"] == [
        {
            "type": "unsupported_constraint",
            "text": "reasonable approval timing",
        },
    ]


def test_diff_reviews_detects_deployment_changes():
    old_review = {
        "detected_constraints": [],
        "warnings": [],
        "deployment": {
            "environment": "production",
            "runtime": "waveframe-guard",
            "enforcement_engine": "cricore",
            "engine_version": "0.12.0",
            "deployed_by": "ops-team",
            "deployed_at": "2026-05-07T21:00:00Z",
        },
    }
    new_review = {
        "detected_constraints": [],
        "warnings": [],
        "deployment": {
            "environment": "production",
            "runtime": "waveframe-guard",
            "enforcement_engine": "cricore",
            "engine_version": "0.13.0",
            "deployed_by": "ops-team",
            "deployed_at": "2026-05-07T22:00:00Z",
        },
    }

    diff = diff_reviews(old_review, new_review)

    assert diff["deployment_changes"] == {
        "engine_version": ["0.12.0", "0.13.0"],
        "deployed_at": ["2026-05-07T21:00:00Z", "2026-05-07T22:00:00Z"],
    }


def test_diff_reviews_returns_empty_sections_when_no_changes():
    review = {
        "detected_constraints": [],
        "warnings": [],
    }

    assert diff_reviews(review, review) == {
        "added_constraints": [],
        "removed_constraints": [],
        "modified_constraints": [],
        "new_warnings": [],
        "resolved_warnings": [],
        "deployment_changes": {},
    }
