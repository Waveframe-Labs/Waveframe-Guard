from __future__ import annotations

import json
from pathlib import Path

from governance_ledger.semantics.extraction import build_governance_source, extract_governance_semantics

ROOT = Path(__file__).resolve().parents[1]


POLICY_TEXT = (
    "Corporate Treasury Transfer System transfers above $250,000 require approval by treasury governance. "
    "Approval is valid for 30 days. Resumed workflows must revalidate if authority posture changes, "
    "and revoked authorities invalidate resumed execution. Approval evidence and decision trace are required for replay."
)

AI_OPERATIONS_POLICY = (
    "AI-generated operational recommendations are classified as advisory governance inputs and do not independently authorize execution.\n\n"
    "Any AI-assisted workflow capable of modifying production systems, financial state, customer data, identity posture, or infrastructure configuration must execute through a replay-attested governance boundary.\n\n"
    "Queued or asynchronous AI execution workflows must preserve replay continuity, governance lineage, execution chronology, and governance state snapshots throughout the execution lifecycle.\n\n"
    "Resumed AI workflows must compare the original governance snapshot hash against the active governance posture prior to continuation. If continuity drift exists, execution must pause pending governance review.\n\n"
    "No AI agent may independently approve, attest, supersede, revoke, or publish governance authorities.\n\n"
    "Execution involving external orchestration systems, remote workers, or cloud-managed automation must retain cryptographically linked replay evidence connecting execution actions to the originating governance authority.\n\n"
    "All high-impact AI-assisted operations require independent human approval from both Operational Governance and Security Oversight. The same actor may not satisfy both approval responsibilities.\n\n"
    "Delegated emergency override authority may temporarily authorize AI-assisted remediation actions during declared operational incidents. Emergency delegation expires after 6 hours unless renewed through governance review.\n\n"
    "AI-generated execution recommendations affecting customer-visible systems require attested human acknowledgment prior to execution.\n\n"
    "Governance authorities for autonomous operational systems expire 7 days after publication unless renewed through governance continuity review."
)


def test_governance_source_v1_captures_policy_text_and_stable_hash():
    first = build_governance_source(POLICY_TEXT)
    second = build_governance_source(POLICY_TEXT)

    assert first == second
    assert first["schema_version"] == "governance_source.v1"
    assert first["source_type"] == "policy_text"
    assert first["source_hash"].startswith("sha256:")
    assert first["human_review_required"] is True
    assert first["extraction_mode"] == "deterministic_rules"


def test_semantic_extraction_is_deterministic_and_requires_review():
    first = extract_governance_semantics(POLICY_TEXT)
    second = extract_governance_semantics(POLICY_TEXT)

    assert first == second
    assert first["schema_version"] == "governance_semantic_extraction.v1"
    assert first["extraction_method"] == "deterministic_pattern_pass"
    assert first["confidence_posture"] == "requires_human_review"
    assert first["semantic_provenance"]
    assert "requires operator confirmation before publication" in first["non_goals"]


def test_semantic_extraction_extracts_candidate_authority_anchors():
    extraction = extract_governance_semantics(POLICY_TEXT)
    candidate = extraction["candidate_authority"]

    assert candidate["protected_system"] == "Corporate Treasury Transfer System"
    assert candidate["governed_action"] == "transfer funds"
    assert candidate["approver_role"] == "treasury-governance"
    assert candidate["approval_count"] == 1
    assert candidate["escalation_threshold"] == 250000
    assert candidate["escalation_semantics"] == "Executions above $250,000 require treasury-governance review."
    assert candidate["validity_days"] == 30
    assert candidate["temporal_semantics"]["validity_window"] == "P30D"
    assert candidate["temporal_semantics"]["timestamp_source"] == "unspecified"
    assert candidate["temporal_semantics"]["runtime_enforced_by"] == "Guard/Cloud"
    assert candidate["continuity_revalidation"] is True
    assert candidate["revocation_invalidates_resume"] is True
    assert candidate["state_snapshot_semantics"]["snapshot_required"] is True
    assert candidate["state_snapshot_semantics"]["runtime_enforced_by"] == "Guard/Cloud"
    assert {rule["rule_type"] for rule in extraction["candidate_rules"]} >= {
        "approval_requirement",
        "escalation_threshold",
        "continuity_semantics",
        "required_evidence",
        "temporal_authority_semantics",
        "state_posture_snapshot_semantics",
    }
    provenance = {item["field"]: item for item in extraction["semantic_provenance"]}
    assert provenance["approval_role"]["confidence"] == "high"
    assert provenance["approval_role"]["source_spans"][0]["text"] == "treasury governance"
    assert provenance["validity_window"]["value"] == "P30D"
    assert provenance["validity_window"]["extraction_method"] == "deterministic_pattern"


def test_semantic_extraction_emits_action_level_capabilities():
    extraction = extract_governance_semantics(POLICY_TEXT)
    capabilities = {
        item["capability_id"]: item
        for item in extraction["candidate_capabilities"]
    }

    assert "transfer_funds" in capabilities
    assert "approve_transfer_funds" in capabilities
    assert "resume_transfer_funds" in capabilities
    transfer = capabilities["transfer_funds"]
    resume = capabilities["resume_transfer_funds"]

    assert transfer["schema_version"] == "governance_capability.v1"
    assert {item["requirement_type"] for item in transfer["requirements"]} >= {
        "approval_requirement",
        "escalation_threshold",
        "evidence_requirement",
    }
    assert transfer["continuity_semantics"]["schema_version"] == "capability_continuity_semantics.v1"
    assert transfer["execution_constraints"]["schema_version"] == "capability_execution_constraint.v1"
    assert transfer["identity_requirements"]["schema_version"] == "capability_identity_requirement.v1"
    assert resume["action_type"] == "resume_action"
    assert resume["continuity_semantics"]["revalidation_required"] is True
    assert any(item["evidence_type"] in {"replay", "replay_evidence"} for item in resume["evidence_requirements"])
    assert extraction["candidate_authority"]["capabilities"] == extraction["candidate_capabilities"]


def test_semantic_extraction_emits_delegation_capability_when_policy_delegates_authority():
    extraction = extract_governance_semantics(
        "Payment Workflow transfers above $250,000 require finance approval with delegated authority within boundary."
    )
    capabilities = {item["capability_id"]: item for item in extraction["candidate_capabilities"]}

    assert "delegate_authority" in capabilities
    assert capabilities["delegate_authority"]["action_type"] == "delegation_action"
    assert capabilities["delegate_authority"]["requirements"][0]["fields"]["delegation_posture"] == "allowed_with_boundary"


def test_semantic_extraction_recognizes_ai_operations_policy():
    extraction = extract_governance_semantics(AI_OPERATIONS_POLICY)
    candidate = extraction["candidate_authority"]
    capabilities = {item["capability_id"]: item for item in extraction["candidate_capabilities"]}

    assert candidate["protected_system"] == "Autonomous Operational Systems"
    assert candidate["governed_action"] == "AI-assisted operational modification"
    assert candidate["governed_action_targets"] == [
        "production_systems",
        "financial_state",
        "customer_data",
        "identity_posture",
        "infrastructure_configuration",
    ]
    assert candidate["governed_targets"] == candidate["governed_action_targets"]
    assert set(candidate["governed_operations"]) >= {"modify", "resume", "approve", "delegate"}
    assert {
        "ai_assisted_operational_modification",
        "continuity_sensitive_execution",
        "emergency_delegated_remediation",
        "ai_recommendation_advisory_boundary",
    }.issubset(candidate["mutation_classes"])
    assert candidate["execution_context_semantics"]["execution_context"] == "queued_async"
    assert candidate["execution_context_semantics"]["execution_boundary"] == "external_orchestration_system"
    assert candidate["execution_context_semantics"]["requires_replay_evidence"] is True
    assert candidate["execution_context_semantics"]["requires_state_snapshot"] is True
    assert candidate["state_snapshot_semantics"]["snapshot_subject"] == "original_governance_snapshot_hash"
    assert candidate["state_snapshot_semantics"]["resume_comparison"] == "original_snapshot_hash_must_match_active_governance_posture"
    assert candidate["state_snapshot_semantics"]["drift_behavior"] == "pause_pending_governance_review"
    assert candidate["approval_count"] == 2
    assert candidate["approver_roles"] == ["operational-governance", "security-oversight"]
    assert candidate["approval_chain_semantics"]["required_roles"] == ["operational-governance", "security-oversight"]
    assert candidate["approval_chain_semantics"]["independence_required"] is True
    assert candidate["approval_chain_semantics"]["self_approval_prohibited"] is True
    assert candidate["approval_chain_semantics"]["attestation_required"] is True
    assert candidate["approval_chain_semantics"]["ai_recommendation_posture"] == "advisory_only"
    assert candidate["ai_boundary_semantics"]["recommendation_posture"] == "advisory_only"
    assert candidate["ai_boundary_semantics"]["independent_authorization_prohibited"] is True
    assert set(candidate["ai_boundary_semantics"]["prohibited_authority_actions"]) == {
        "approve",
        "attest",
        "supersede",
        "revoke",
        "publish",
    }
    assert candidate["ai_boundary_semantics"]["human_acknowledgment_required"] is True
    assert candidate["temporal_semantics"]["validity_window"] == "P7D"
    assert candidate["emergency_delegation_semantics"]["validity_window"] == "PT6H"
    assert candidate["emergency_delegation_semantics"]["authorized_action"] == "ai_assisted_remediation"
    assert {
        "ai_assisted_operational_modification",
        "resume_ai_workflow",
        "emergency_delegated_remediation",
        "ai_generated_recommendation",
    }.issubset(capabilities)
    assert "cryptographically_linked_replay_evidence" in {
        item["fields"]["evidence_term"]
        for item in extraction["candidate_rules"]
        if item["rule_type"] == "required_evidence"
    }


def test_semantic_provenance_tracks_confidence_and_source_spans():
    extraction = extract_governance_semantics(
        "No individual may originate and approve the same transfer request."
    )

    provenance = {
        item["field"]: item
        for item in extraction["semantic_provenance"]
    }

    assert provenance["approval_count"]["confidence"] == "high"
    assert provenance["approval_independence"]["value"] is True
    assert provenance["approval_independence"]["confidence"] == "high"
    assert provenance["approval_independence"]["source_spans"][0]["text"] == "originate and approve"


def test_semantic_extraction_emits_timestamp_source_ambiguity_when_missing():
    extraction = extract_governance_semantics(
        "Payment Workflow action: transfer funds. Approval is valid for 30 days."
    )

    candidate = extraction["candidate_authority"]
    ambiguity_types = {item["ambiguity_type"] for item in extraction["ambiguities"]}

    assert candidate["temporal_semantics"]["validity_window"] == "P30D"
    assert candidate["temporal_semantics"]["timestamp_source"] == "unspecified"
    assert "timestamp_source_unspecified" in ambiguity_types


def test_semantic_extraction_captures_timestamp_sources():
    signed = extract_governance_semantics(
        "Payment Workflow action: transfer funds. Approval is valid for 30 days using signed execution timestamp."
    )
    oracle = extract_governance_semantics(
        "Payment Workflow action: transfer funds. Approval is valid for 30 days using signed oracle time."
    )
    block = extract_governance_semantics(
        "Payment Workflow action: transfer funds. Approval is valid for 30 days using block timestamp."
    )
    cloud = extract_governance_semantics(
        "Payment Workflow action: transfer funds. Approval is valid for 30 days using Cloud-attested time."
    )

    assert signed["candidate_authority"]["temporal_semantics"]["timestamp_source"] == "execution_payload"
    assert oracle["candidate_authority"]["temporal_semantics"]["timestamp_source"] == "signed_oracle"
    assert block["candidate_authority"]["temporal_semantics"]["timestamp_source"] == "block_timestamp"
    assert cloud["candidate_authority"]["temporal_semantics"]["timestamp_source"] == "cloud_attested_time"


def test_semantic_extraction_continuity_revalidation_implies_snapshot_semantics():
    extraction = extract_governance_semantics(
        "Payment Workflow must revalidate on resume and compare current policy version before resuming."
    )
    candidate = extraction["candidate_authority"]

    assert candidate["state_snapshot_semantics"] == {
        "schema_version": "state_posture_snapshot_semantics.v1",
        "snapshot_required": True,
        "snapshot_hash_algorithm": "sha256",
        "snapshot_subject": "current_policy_version",
        "resume_comparison": "snapshot_hash_must_match_active_state_hash",
        "drift_result": "continuity_drift_detected",
        "runtime_enforced_by": "Guard/Cloud",
    }


def test_semantic_extraction_revoked_authority_continuity_emits_snapshot_comparison():
    extraction = extract_governance_semantics(
        "Revoked authority invalidates paused workflows and resumed execution requires current governance state."
    )
    candidate = extraction["candidate_authority"]

    assert candidate["revocation_invalidates_resume"] is True
    assert candidate["state_snapshot_semantics"]["snapshot_subject"] == "active_governance_state"
    assert candidate["state_snapshot_semantics"]["resume_comparison"] == "snapshot_hash_must_match_active_state_hash"
    assert candidate["state_snapshot_semantics"]["drift_result"] == "continuity_drift_detected"
    assert candidate["state_snapshot_semantics"]["runtime_enforced_by"] == "Guard/Cloud"


def test_semantic_extraction_policy_change_language_emits_continuity_snapshot_expectation():
    extraction = extract_governance_semantics(
        "If policy changes before execution, resumed workflows require current governance state."
    )
    candidate = extraction["candidate_authority"]

    assert candidate["continuity_revalidation"] is True
    assert candidate["state_snapshot_semantics"]["snapshot_required"] is True
    assert candidate["state_snapshot_semantics"]["snapshot_subject"] == "active_governance_state"


def test_semantic_extraction_expires_after_approval_records_temporal_trigger():
    extraction = extract_governance_semantics(
        "Payment Workflow approval expires after approval using block timestamp."
    )
    temporal = extraction["candidate_authority"]["temporal_semantics"]

    assert temporal["expiration_trigger"] == "approval_completion"
    assert temporal["timestamp_source"] == "block_timestamp"
    assert temporal["runtime_enforced_by"] == "Guard/Cloud"


def test_semantic_extraction_normalizes_execution_context_semantics():
    extraction = extract_governance_semantics(
        "Queued deployment may resume later after approval and requires replay evidence."
    )
    execution_context = extraction["candidate_authority"]["execution_context_semantics"]

    assert execution_context == {
        "schema_version": "execution_context_semantics.v1",
        "execution_context": "queued_async",
        "execution_boundary": "external_worker",
        "requires_replay_evidence": True,
        "requires_state_snapshot": True,
        "requires_temporal_validation": True,
        "resume_behavior": "revalidate_on_resume",
        "continuity_risk_profile": "medium",
        "runtime_enforced_by": "Guard/Cloud",
    }
    assert "execution_context_semantics" in {rule["rule_type"] for rule in extraction["candidate_rules"]}


def test_semantic_extraction_normalizes_identity_and_responsibility_semantics():
    extraction = extract_governance_semantics(
        "Transfers above $250,000 must be approved by finance with dual control and cannot self-approve. "
        "Requires attested operator and human-in-the-loop review."
    )
    candidate = extraction["candidate_authority"]

    assert candidate["governance_actor"] == {
        "schema_version": "governance_actor.v1",
        "actor_id": "finance",
        "actor_type": "team",
        "authority_scope": ["transfer_funds_approval"],
        "delegation_allowed": False,
        "attestation_required": True,
        "identity_continuity_required": False,
    }
    assert candidate["authority_role_binding"]["role_id"] == "finance"
    assert candidate["approval_chain_semantics"]["independence_required"] is True
    assert candidate["approval_chain_semantics"]["self_approval_prohibited"] is True
    assert candidate["approval_chain_semantics"]["attestation_required"] is True
    assert candidate["approval_chain_semantics"]["human_in_loop_required"] is True
    assert {
        "governance_actor",
        "authority_role_binding",
        "approval_chain_semantics",
    }.issubset({rule["rule_type"] for rule in extraction["candidate_rules"]})


def test_semantic_extraction_emits_identity_ambiguities():
    extraction = extract_governance_semantics(
        "Large transfers require independent reviewer approval and delegated authority."
    )

    ambiguity_types = {item["ambiguity_type"] for item in extraction["ambiguities"]}

    assert "approval_independence_ambiguity" in ambiguity_types
    assert "delegation_ambiguity" in ambiguity_types


def test_semantic_extraction_identity_continuity_for_resumed_workflows():
    extraction = extract_governance_semantics(
        "Execution may resume later and the same approver identity must remain valid."
    )

    identity = extraction["candidate_authority"]["identity_continuity_semantics"]

    assert identity == {
        "schema_version": "identity_continuity_semantics.v1",
        "identity_continuity_required": True,
        "resume_identity_check": "actor_or_role_binding_must_remain_valid",
        "identity_revocation_effect": "review_required",
        "runtime_enforced_by": "Guard/Cloud",
    }


def test_semantic_extraction_emits_execution_context_ambiguity_for_vague_deferred_execution():
    extraction = extract_governance_semantics("Approval controls deferred execution after governance review.")

    assert "execution_context_semantics" not in {
        rule["rule_type"] for rule in extraction["candidate_rules"]
    }
    assert "execution_context_ambiguity" in {
        ambiguity["ambiguity_type"] for ambiguity in extraction["ambiguities"]
    }


def test_semantic_extraction_keeps_missing_fields_explicit():
    extraction = extract_governance_semantics("This policy requires appropriate approval for sensitive actions.")

    missing_fields = {item["field"] for item in extraction["missing_information"]}
    assert "protected_system" in missing_fields
    assert "escalation_threshold" in missing_fields
    assert extraction["ambiguities"]


def test_semantic_extraction_schemas_are_canonical():
    source_schema = json.loads((ROOT / "schemas" / "governance_source.v1.json").read_text(encoding="utf-8"))
    extraction_schema = json.loads((ROOT / "schemas" / "governance_semantic_extraction.v1.json").read_text(encoding="utf-8"))
    provenance_schema = json.loads((ROOT / "schemas" / "governance_semantic_provenance.v1.json").read_text(encoding="utf-8"))
    temporal_schema = json.loads((ROOT / "schemas" / "temporal_authority_semantics.v1.json").read_text(encoding="utf-8"))
    snapshot_schema = json.loads((ROOT / "schemas" / "state_posture_snapshot_semantics.v1.json").read_text(encoding="utf-8"))
    execution_context_schema = json.loads((ROOT / "schemas" / "execution_context_semantics.v1.json").read_text(encoding="utf-8"))
    actor_schema = json.loads((ROOT / "schemas" / "governance_actor.v1.json").read_text(encoding="utf-8"))
    role_schema = json.loads((ROOT / "schemas" / "authority_role_binding.v1.json").read_text(encoding="utf-8"))
    approval_chain_schema = json.loads((ROOT / "schemas" / "approval_chain_semantics.v1.json").read_text(encoding="utf-8"))
    identity_schema = json.loads((ROOT / "schemas" / "identity_continuity_semantics.v1.json").read_text(encoding="utf-8"))
    capability_schema = json.loads((ROOT / "schemas" / "governance_capability.v1.json").read_text(encoding="utf-8"))
    capability_requirement_schema = json.loads((ROOT / "schemas" / "capability_requirement.v1.json").read_text(encoding="utf-8"))
    capability_continuity_schema = json.loads((ROOT / "schemas" / "capability_continuity_semantics.v1.json").read_text(encoding="utf-8"))
    capability_evidence_schema = json.loads((ROOT / "schemas" / "capability_evidence_requirement.v1.json").read_text(encoding="utf-8"))
    capability_execution_schema = json.loads((ROOT / "schemas" / "capability_execution_constraint.v1.json").read_text(encoding="utf-8"))
    capability_identity_schema = json.loads((ROOT / "schemas" / "capability_identity_requirement.v1.json").read_text(encoding="utf-8"))

    assert source_schema["properties"]["schema_version"]["const"] == "governance_source.v1"
    assert "source_text" in source_schema["required"]
    assert extraction_schema["properties"]["schema_version"]["const"] == "governance_semantic_extraction.v1"
    assert "candidate_authority" in extraction_schema["required"]
    assert "candidate_capabilities" in extraction_schema["required"]
    assert "semantic_provenance" in extraction_schema["required"]
    assert provenance_schema["properties"]["schema_version"]["const"] == "governance_semantic_provenance.v1"
    assert provenance_schema["properties"]["extraction_method"]["const"] == "deterministic_pattern"
    assert temporal_schema["properties"]["schema_version"]["const"] == "temporal_authority_semantics.v1"
    assert temporal_schema["properties"]["runtime_enforced_by"]["const"] == "Guard/Cloud"
    assert snapshot_schema["properties"]["schema_version"]["const"] == "state_posture_snapshot_semantics.v1"
    assert snapshot_schema["properties"]["runtime_enforced_by"]["const"] == "Guard/Cloud"
    assert execution_context_schema["properties"]["schema_version"]["const"] == "execution_context_semantics.v1"
    assert execution_context_schema["properties"]["runtime_enforced_by"]["const"] == "Guard/Cloud"
    assert actor_schema["properties"]["schema_version"]["const"] == "governance_actor.v1"
    assert role_schema["properties"]["schema_version"]["const"] == "authority_role_binding.v1"
    assert approval_chain_schema["properties"]["schema_version"]["const"] == "approval_chain_semantics.v1"
    assert identity_schema["properties"]["schema_version"]["const"] == "identity_continuity_semantics.v1"
    assert identity_schema["properties"]["runtime_enforced_by"]["const"] == "Guard/Cloud"
    assert capability_schema["properties"]["schema_version"]["const"] == "governance_capability.v1"
    assert capability_requirement_schema["properties"]["schema_version"]["const"] == "capability_requirement.v1"
    assert capability_continuity_schema["properties"]["schema_version"]["const"] == "capability_continuity_semantics.v1"
    assert capability_evidence_schema["properties"]["schema_version"]["const"] == "capability_evidence_requirement.v1"
    assert capability_execution_schema["properties"]["schema_version"]["const"] == "capability_execution_constraint.v1"
    assert capability_identity_schema["properties"]["schema_version"]["const"] == "capability_identity_requirement.v1"
