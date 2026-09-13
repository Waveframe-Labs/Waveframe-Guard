from __future__ import annotations

from governance_ledger.semantics.diagnostics import build_governance_quality_diagnostics


def test_quality_diagnostics_are_advisory_and_deterministic():
    authority = _authority_contract()

    first = build_governance_quality_diagnostics(authority)
    second = build_governance_quality_diagnostics(authority)

    assert first == second
    assert first
    assert {diagnostic["schema_version"] for diagnostic in first} == {"governance_quality_diagnostic.v1"}
    assert {diagnostic["blocks_publication"] for diagnostic in first} == {False}
    assert all("does_not_call_guard" in diagnostic["non_goals"] for diagnostic in first)


def test_missing_escalation_path_emits_quality_diagnostic():
    authority = _authority_contract()
    authority["escalation_requirements"] = {}

    diagnostics = build_governance_quality_diagnostics(authority)

    assert _diagnostic(diagnostics, "GQ001")["title"] == "Missing Escalation Path"


def test_weak_continuity_posture_emits_quality_diagnostic():
    authority = _authority_contract()
    authority["continuity_requirements"]["resume_requires_current_authority"] = False

    diagnostics = build_governance_quality_diagnostics(authority)

    assert _diagnostic(diagnostics, "GQ002")["title"] == "Weak Continuity Posture"


def test_replay_weakness_emits_quality_diagnostic():
    authority = _authority_contract()
    authority["replay_requirements"] = ["approval_evidence"]

    diagnostics = build_governance_quality_diagnostics(authority)

    assert _diagnostic(diagnostics, "GQ003")["title"] == "Replay Weakness"


def test_single_role_approval_model_emits_approval_risk():
    authority = _authority_contract()
    authority["authority_requirements"]["approval_count"] = 1

    diagnostics = build_governance_quality_diagnostics(authority)

    assert _diagnostic(diagnostics, "GQ004")["title"] == "Approval Risk"


def test_missing_supersession_expectation_emits_lifecycle_ambiguity():
    authority = _authority_contract()

    diagnostics = build_governance_quality_diagnostics(authority)

    assert _diagnostic(diagnostics, "GQ005")["title"] == "Lifecycle Ambiguity"


def _diagnostic(diagnostics: list[dict], code: str) -> dict:
    for diagnostic in diagnostics:
        if diagnostic["code"] == code:
            return diagnostic
    raise AssertionError(f"Missing diagnostic {code}: {diagnostics}")


def _authority_contract() -> dict:
    return {
        "schema_version": "authority_contract.v1",
        "contract_id": "treasury-policy",
        "contract_version": "2.1.0",
        "protected_resource": "Corporate Treasury Transfer System",
        "governed_actions": ["transfer funds"],
        "authority_requirements": {
            "required_roles": ["treasury-governance"],
            "approval_count": 2,
        },
        "approval_requirements": {
            "required": [{"role": "treasury-governance"}],
        },
        "escalation_requirements": {
            "threshold": {
                "field": "amount",
                "operator": ">",
                "value": 250000,
            }
        },
        "continuity_requirements": {
            "resume_requires_current_authority": True,
            "revoked_authority_invalidates_resume": True,
        },
        "review_requirements": {
            "approval_count": 2,
        },
        "replay_requirements": [
            "authority_hash",
            "decision_trace",
            "approval_evidence",
        ],
        "stage_requirements": {
            "allowed_transitions": [
                {"from": "draft", "to": "review"},
                {"from": "review", "to": "published"},
            ]
        },
    }
