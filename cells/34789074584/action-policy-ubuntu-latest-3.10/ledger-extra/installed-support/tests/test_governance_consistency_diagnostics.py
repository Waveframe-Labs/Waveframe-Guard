from __future__ import annotations

from governance_ledger.extract import extract_constraints
from governance_ledger.review import build_review_report
from governance_ledger.validation import validate_authoring


def test_threshold_overlap_emits_compiler_diagnostic():
    text = """
    Transfers up to $10000 require manager approval.
    Transfers above $5000 require director approval.
    """.strip()

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert _codes(review) == {"G102"}
    diagnostic = _diagnostic(review, "G102")
    assert diagnostic["severity"] == "error"
    assert diagnostic["domain"] == "authority_threshold"
    assert diagnostic["blocks_publication"] is True
    assert diagnostic["title"] == "Overlapping approval authority ranges detected"
    assert diagnostic["schema_version"] == "governance_diagnostic.v1"


def test_threshold_gap_emits_compiler_diagnostic():
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "approvals": {
            "thresholds": [
                {"field": "amount", "operator": "<", "value": 5000, "requires_role": "manager"},
                {"field": "amount", "operator": ">", "value": 10000, "requires_role": "director"},
            ]
        },
    }

    validation = validate_authoring("Synthetic threshold policy.", policy)

    assert _codes(validation) == {"G103"}
    diagnostic = _diagnostic(validation, "G103")
    assert diagnostic["severity"] == "warning"
    assert diagnostic["blocks_publication"] is False


def test_lifecycle_cycle_emits_compiler_diagnostic():
    policy = {
        "contract_id": "access-policy",
        "contract_version": "0.1.0",
        "stages": {
            "allowed_transitions": [
                {"from": "draft", "to": "approved"},
                {"from": "approved", "to": "deployed"},
                {"from": "deployed", "to": "draft"},
            ]
        },
    }

    validation = validate_authoring("Synthetic lifecycle policy.", policy)

    assert _codes(validation) == {"G301"}
    assert _diagnostic(validation, "G301")["domain"] == "lifecycle"


def test_artifact_retention_contradiction_emits_compiler_diagnostic():
    text = "Evidence must be retained for 7 years. Evidence must be deleted after 5 years."

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    assert "G401" in _codes(review)


def test_requester_approval_conflicts_with_separation_of_duties():
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "authority": {"separation_of_duties": True},
        "approvals": {"required": [{"role": "requester"}]},
    }

    validation = validate_authoring("Requester cannot approve.", policy)

    assert _codes(validation) == {"G501"}
    assert _diagnostic(validation, "G501")["domain"] == "role_integrity"


def test_duplicate_required_role_is_warning_diagnostic():
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "approvals": {"required": [{"role": "manager"}, {"role": "manager"}]},
    }

    validation = validate_authoring("Synthetic role policy.", policy)

    diagnostic = _diagnostic(validation, "G502")
    assert diagnostic["severity"] == "warning"
    assert diagnostic["blocks_publication"] is False
    assert diagnostic["domain"] == "role_integrity"


def test_cumulative_approval_path_is_info_lint():
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "approvals": {
            "required": [
                {"role": "manager"},
                {
                    "role": "director",
                    "condition": {"field": "amount", "operator": ">", "value": 10000},
                },
            ]
        },
    }

    validation = validate_authoring("Synthetic approval path policy.", policy)

    diagnostic = _diagnostic(validation, "G701")
    assert diagnostic["severity"] == "info"
    assert diagnostic["blocks_publication"] is False
    assert diagnostic["domain"] == "governance_lint"
    assert diagnostic["schema_version"] == "governance_diagnostic.v1"


def test_review_contains_normalization_report_with_statement_trace():
    text = """
    Transfers up to $10000 require manager approval.
    Transfers above $5000 require director approval.
    """.strip()

    policy = extract_constraints(text)
    review = build_review_report(text, policy)

    report = review["normalization_report"]
    assert report["schema_version"] == "governance_normalization_report.v1"
    assert report["coverage"] == review["extraction_coverage"]
    assert report["diagnostic_summary"]["error"] == 1
    assert report["statement_traces"][0]["statement"] == "Transfers up to $10000 require manager approval."
    assert report["statement_traces"][0]["classification"] == "conditional_threshold_approval"
    assert report["statement_traces"][0]["normalized"]
    assert report["diagnostics"][0]["code"] == "G102"

    compilation_report = review["compilation_report"]
    assert compilation_report["schema_version"] == "governance_compilation_report.v1"
    assert compilation_report["authority_ref"] == "finance-policy@0.1.0"
    assert compilation_report["report_hash"].startswith("sha256:")
    assert compilation_report["compiler_summary"]["statement_count"] == 2
    assert compilation_report["compiler_summary"]["blocking_diagnostic_count"] == 1
    assert compilation_report["normalized_statements"] == review["normalized_statements"]


def test_policy_complexity_lint_is_non_fatal_warning():
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "approvals": {
            "required": [
                {"role": "manager"},
                {"role": "director"},
                {"role": "controller"},
                {"role": "compliance"},
            ]
        },
        "artifacts": {"required": ["approval_audit_record", "compliance_report"]},
    }

    validation = validate_authoring("Synthetic complex policy.", policy)

    diagnostic = _diagnostic(validation, "G702")
    assert diagnostic["severity"] == "warning"
    assert diagnostic["blocks_publication"] is False
    assert diagnostic["domain"] == "governance_lint"


def _codes(report: dict) -> set[str]:
    return {
        warning["code"]
        for warning in report["warnings"]
        if warning.get("type") == "compiler_diagnostic"
    }


def _diagnostic(report: dict, code: str) -> dict:
    return next(
        warning
        for warning in report["warnings"]
        if warning.get("type") == "compiler_diagnostic" and warning.get("code") == code
    )
