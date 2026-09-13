from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from governance_ledger.constraint_ir import (
    artifact_hash,
    finalize_constraint_ir,
    finalize_runtime_fact_schema,
    validate_constraint_ir,
    validate_runtime_fact_compatibility,
    validate_runtime_fact_schema,
)
from governance_ledger.customer_policy import (
    _interpret_customer_policy_v0_6_compatibility,
    finalize_customer_policy_authority,
    interpret_customer_policy,
    interpret_customer_policy_text,
)
from governance_ledger.domain_packs import (
    get_builtin_domain_pack,
    list_builtin_domain_packs,
    validate_domain_pack,
)
from governance_ledger.domain_policy import (
    _lower_constraint,
    apply_policy_mapping_decision,
    finalize_domain_policy_authority,
    inspect_policy_mapping_controls,
    interpret_policy_with_domain_pack,
)
from governance_ledger.publication_provenance import (
    canonical_sha256,
    validate_authority_bundle,
    validate_publication_receipt,
)


ROOT = Path(__file__).parents[1]
PACK_ID = "repository-changes"
PACK_VERSION = "1.0.0"
IDENTITIES = {
    "source_policy_id": "repository-policy",
    "source_revision": "revision-1",
    "authority_id": "repository-authority",
    "authority_version": "1.0.0",
}
HUMAN = {
    "approval_id": "approval-1",
    "approved_by": "reviewer",
    "approved_at": "2026-08-30T19:30:00Z",
    "committed_by": "committer",
    "committed_at": "2026-08-30T19:45:00Z",
    "publication_id": "publication-1",
    "published_by": "publisher",
    "published_at": "2026-08-30T20:00:00Z",
}
REPOSITORY_SOURCE = (
    b"Repository changes may be made only by repository maintainers. "
    b"Agents may modify README.md. "
    b"Agents must not modify files under deployment/."
)


def _draft(source: bytes = REPOSITORY_SOURCE) -> dict:
    return interpret_policy_with_domain_pack(
        source,
        domain_pack_id=PACK_ID,
        domain_pack_version=PACK_VERSION,
        **IDENTITIES,
    )


def _decide(
    draft: dict,
    *,
    disposition: str,
    control_id: str | None = None,
    selections: dict | None = None,
    reason_code: str | None = None,
) -> dict:
    statement = next(item for item in draft["source_statements"] if item["classification"] == "pending")
    return apply_policy_mapping_decision(
        draft,
        statement_id=statement["statement_id"],
        disposition=disposition,
        control_id=control_id,
        selections=selections,
        reason_code=reason_code,
        mapper_identity="mapper-1",
        mapped_at="2026-08-30T19:00:00Z",
    )["updated_interpretation"]


def _mapped(source: bytes = b"Engineers should update the readme.") -> dict:
    return _decide(
        _draft(source),
        disposition="enforced",
        control_id="exact-path-access",
        selections={"effect": "allow", "path": "README.md"},
    )


def _final(draft: dict | None = None, **overrides: object) -> dict:
    return finalize_domain_policy_authority(draft or _draft(), **{**HUMAN, **overrides})


def _registry() -> Registry:
    schemas = []
    for path in (ROOT / "schemas").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            schemas.append(schema)
    return Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )


def _schema_validate(value: dict, filename: str) -> None:
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, registry=_registry()).validate(value)


def test_builtin_pack_identity_hash_and_copied_values_are_stable() -> None:
    listed = list_builtin_domain_packs()
    assert len(listed) == 1
    assert (listed[0]["domain_pack_id"], listed[0]["domain_pack_version"]) == (PACK_ID, PACK_VERSION)
    first = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    first["name"] = "tampered"
    second = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    assert second["name"] == "Repository changes"
    assert validate_domain_pack(second)["canonical_hash"] == listed[0]["canonical_hash"]


def test_repository_pack_contains_only_repository_concepts() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    assert pack["supported_actions"] == ["modify"]
    assert pack["resource_kinds"] == ["repository_change", "repository_path"]
    assert pack["subject_kinds"] == ["agent"]
    assert set(pack["role_kinds"]) == {"repository-maintainer", "repository-reviewer", "security-reviewer"}
    assert {item["control_id"] for item in pack["allowed_mapping_controls"]} == {
        "acting-role", "exact-path-access", "prefix-path-access"
    }
    serialized = json.dumps(pack, sort_keys=True).lower()
    for forbidden in ("invoice", "payment", "purchase", "transfer", "financial_request", "request.amount", "approval.count", "usd", "requester", "approver"):
        assert forbidden not in serialized


def test_domain_pack_schema_is_generic_and_does_not_enumerate_emitters() -> None:
    schema = json.loads((ROOT / "schemas/domain_pack.v1.json").read_text(encoding="utf-8"))
    control = schema["properties"]["allowed_mapping_controls"]["items"]
    assert "emitter_id" in control["properties"]
    assert "enum" not in control["properties"]["emitter_id"]
    assert "produces" not in json.dumps(schema)
    assert "repository_path" not in json.dumps(schema)


@pytest.mark.parametrize("field,value,message", [
    ("emitter_id", "uninstalled.emitter.v1", "unavailable emitter"),
    ("format_id", "uninstalled.format.v1", "unavailable format validator"),
])
def test_unknown_emitter_and_format_validator_fail_closed(field: str, value: str, message: str) -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    if field == "emitter_id":
        pack["allowed_mapping_controls"][0][field] = value
    else:
        pack["allowed_mapping_controls"][1]["selection_schema"]["path"][field] = value
    pack["canonical_hash"] = artifact_hash(pack, "canonical_hash")
    with pytest.raises(ValueError, match=message):
        validate_domain_pack(pack)


def test_pack_identity_cannot_reuse_an_installed_compiler_binding() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    pack["domain_pack_id"] = "lookalike-pack"
    pack["canonical_hash"] = artifact_hash(pack, "canonical_hash")
    with pytest.raises(ValueError, match="identity is not bound"):
        validate_domain_pack(pack)


def test_rehashed_builtin_content_cannot_replace_an_installed_immutable_version() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    pack["description"] = "Modified but internally rehashed content."
    pack["canonical_hash"] = artifact_hash(pack, "canonical_hash")
    with pytest.raises(ValueError, match="installed immutable version"):
        validate_domain_pack(pack)


def test_runtime_derivations_are_only_canonical_proposal_pointers() -> None:
    schema = copy.deepcopy(get_builtin_domain_pack(PACK_ID, PACK_VERSION)["runtime_fact_schema"])
    schema["facts"][0]["derivation"] = {"kind": "deterministic_expression", "source": "actor.role"}
    schema["schema_hash"] = artifact_hash(schema, "schema_hash")
    with pytest.raises(ValueError, match="unknown fields|derivation"):
        validate_runtime_fact_schema(schema)


def test_repository_direct_interpretation_is_repeatable() -> None:
    first = _draft()
    assert first == _draft()
    assert first["status"] == {
        "statement_classification_complete": True,
        "pending_statement_count": 0,
        "enforceable_constraint_count": 3,
        "ready_for_finalization": True,
        "publication_ready": False,
    }
    assert {item["action"] for item in first["constraint_ir"]["constraints"]} == {"modify"}


@pytest.mark.parametrize("source", [
    b"Transfers above $1000000 require manager approval.",
    b"Requester and approver must be separate.",
    b"Invoices above $500 require approval.",
])
def test_finance_prose_is_never_directly_compiled_by_repository_pack(source: bytes) -> None:
    draft = _draft(source)
    assert draft["constraint_ir"] is None
    assert draft["source_statements"][0]["classification"] == "pending"
    assert draft["status"]["ready_for_finalization"] is False


def test_every_unmatched_nonempty_statement_is_pending_not_informational() -> None:
    draft = _draft(b"This paragraph is merely descriptive.")
    assert draft["source_statements"][0]["classification"] == "pending"
    assert draft["status"]["pending_statement_count"] == 1


def test_mapping_inspection_has_pack_controls_and_fixed_dispositions() -> None:
    draft = _draft(b"This paragraph needs a decision.")
    controls = inspect_policy_mapping_controls(draft, draft["source_statements"][0]["statement_id"])
    assert {item["control_id"] for item in controls["enforcement_controls"]} == {
        "acting-role", "exact-path-access", "prefix-path-access"
    }
    assert {item["disposition"] for item in controls["disposition_options"]} == {"informational", "unsupported"}


@pytest.mark.parametrize("disposition,reason", [("informational", "descriptive"), ("unsupported", "outside-domain")])
def test_non_enforced_decisions_produce_no_constraint(disposition: str, reason: str) -> None:
    draft = _draft(b"Agents may modify README.md. This clause needs review.")
    before = copy.deepcopy(draft["constraint_ir"])
    decided = _decide(draft, disposition=disposition, reason_code=reason)
    assert decided["constraint_ir"] == before
    decision = decided["statement_decisions"][0]
    assert decision["disposition"] == disposition
    for absent in ("control_id", "selected_subject", "selected_action", "selected_resource", "constraint_id"):
        assert absent not in decision
    assert len(decided["source_to_constraint_mappings"]) == 1


def test_non_enforced_only_policy_still_has_no_enforceable_rules() -> None:
    decided = _decide(_draft(b"Background context."), disposition="informational", reason_code="context-only")
    assert decided["constraint_ir"] is None
    assert decided["status"]["ready_for_finalization"] is False
    with pytest.raises(ValueError, match="explicit human decision"):
        _final(decided)


def test_pending_clause_blocks_finalization() -> None:
    with pytest.raises(ValueError, match="explicit human decision"):
        _final(_draft(b"Agents may modify README.md. Pending prose."))


def test_bounded_enforcement_rejects_arbitrary_rule_injection() -> None:
    draft = _draft(b"Engineers should update the readme.")
    statement_id = draft["source_statements"][0]["statement_id"]
    with pytest.raises(TypeError):
        apply_policy_mapping_decision(
            draft, statement_id=statement_id, disposition="enforced", control_id="exact-path-access",
            selections={"effect": "allow", "path": "README.md"}, mapper_identity="mapper", mapped_at="2026-08-30T19:00:00Z",
            arbitrary_rule={"effect": "allow"},  # type: ignore[call-arg]
        )
    with pytest.raises(ValueError, match="unknown"):
        apply_policy_mapping_decision(
            draft, statement_id=statement_id, disposition="enforced", control_id="exact-path-access",
            selections={"effect": "allow", "path": "README.md", "injected": True}, mapper_identity="mapper", mapped_at="2026-08-30T19:00:00Z",
        )


def test_mapping_decision_is_source_hash_span_pack_and_replay_bound() -> None:
    mapped = _mapped()
    for mutation in ("source_document_hash", "start_byte", "decision_hash"):
        tampered = copy.deepcopy(mapped)
        decision = tampered["statement_decisions"][0]
        decision[mutation] = "sha256:" + "0" * 64 if "hash" in mutation else decision[mutation] + 1
        tampered["draft_hash"] = artifact_hash(tampered, "draft_hash")
        with pytest.raises(ValueError):
            _final(tampered)


def test_direct_and_guided_mapping_produce_equivalent_ir() -> None:
    direct = _draft(b"Agents may modify README.md.")["constraint_ir"]
    mapped = _mapped()["constraint_ir"]
    assert direct == mapped


def test_repository_path_safety_is_pack_validator_scoped() -> None:
    with pytest.raises(ValueError, match="unsafe path"):
        _decide(
            _draft(b"Map this clause."), disposition="enforced", control_id="exact-path-access",
            selections={"effect": "allow", "path": "../secret"},
        )


def test_synthetic_non_repository_resource_has_no_repository_path_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    import governance_ledger.domain_packs as packs_module

    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    pack["domain_pack_id"] = "synthetic-document-fixture"
    pack["resource_kinds"] = ["document_identifier"]
    pack["resource_contracts"] = [{
        "resource_kind": "document_identifier", "permitted_match_modes": ["exact"], "value_type": "string",
        "enum_values": None, "null_allowed": False, "format_id": None, "value_fact_id": "proposal.resource.identifier",
    }]
    runtime = copy.deepcopy(pack["runtime_fact_schema"])
    runtime["facts"] = [item for item in runtime["facts"] if item["fact_id"] != "proposal.resource.path"]
    kind = next(item for item in runtime["facts"] if item["fact_id"] == "proposal.resource.kind")
    kind["enum_values"] = ["document_identifier"]
    runtime["facts"].append({
        "fact_id": "proposal.resource.identifier", "type": "string", "enum_values": None, "canonical_unit": None,
        "required": True, "derivation": {"kind": "proposal_field", "field_path": "/resource/identifier"}, "comparison_operators": ["==", "!="],
    })
    pack["runtime_fact_schema"] = finalize_runtime_fact_schema({key: value for key, value in runtime.items() if key != "schema_hash"})
    trust = copy.deepcopy(packs_module._TRUSTED_COMPILERS)
    key = (pack["grammar_compiler"]["compiler_id"], pack["grammar_compiler"]["compiler_version"])
    trust[key]["domain_packs"].add((pack["domain_pack_id"], pack["domain_pack_version"]))
    monkeypatch.setattr(packs_module, "_TRUSTED_COMPILERS", trust)
    pack["canonical_hash"] = artifact_hash(pack, "canonical_hash")
    validate_domain_pack(pack)
    constraint = {
        "subject": {"kind": "subject_kind", "value": "agent"}, "acting_role": None, "action": "modify",
        "resource": {"kind": "document_identifier", "match": "exact", "value": "invoice:123"}, "effect": "allow", "condition": None,
        "obligations": {"approvals": [], "evidence": [], "separation_of_duties": []}, "exceptions": [],
        "required_runtime_facts": sorted(["actor.subject_kind", "proposal.action", "proposal.resource.kind", "proposal.resource.identifier"]),
    }
    ir = finalize_constraint_ir({
        "schema_version": "constraint_ir.v1",
        "domain_pack": {"domain_pack_id": pack["domain_pack_id"], "domain_pack_version": pack["domain_pack_version"], "domain_pack_hash": pack["canonical_hash"]},
        "runtime_fact_schema_hash": pack["runtime_fact_schema"]["schema_hash"], "constraints": [constraint],
    })
    assert validate_constraint_ir(ir, domain_pack=pack)["valid"] is True


def test_constraint_ir_rejects_unknown_symbols_and_contradictory_effects() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    ir = copy.deepcopy(_draft(b"Agents may modify README.md.")["constraint_ir"])
    ir["constraints"][0]["action"] = "transfer"
    ir = finalize_constraint_ir({key: value for key, value in ir.items() if key != "ir_hash"})
    with pytest.raises(ValueError, match="unknown action"):
        validate_constraint_ir(ir, domain_pack=pack)
    ir = copy.deepcopy(_draft(b"Agents may modify README.md.")["constraint_ir"])
    second = copy.deepcopy(ir["constraints"][0])
    second["effect"] = "deny"
    ir["constraints"].append(second)
    ir = finalize_constraint_ir({key: value for key, value in ir.items() if key != "ir_hash"})
    with pytest.raises(ValueError, match="contradictory"):
        validate_constraint_ir(ir, domain_pack=pack)


def test_explicit_exception_precedence_is_canonical() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    ir = copy.deepcopy(_draft(b"Agents may modify README.md.")["constraint_ir"])
    constraint = ir["constraints"][0]
    constraint["exceptions"] = [{
        "exception_id": "security-reviewer-exception", "effect": "deny",
        "condition": {"kind": "comparison", "operator": "==", "fact": "actor.role", "literal": {"type": "enum", "value": "security-reviewer", "unit": None}},
    }]
    constraint["required_runtime_facts"] = sorted([*constraint["required_runtime_facts"], "actor.role"])
    ir = finalize_constraint_ir({key: value for key, value in ir.items() if key != "ir_hash"})
    assert validate_constraint_ir(ir, domain_pack=pack)["valid"] is True


@pytest.mark.parametrize("advanced_field", ["condition", "approval", "evidence", "separation", "exception"])
def test_advanced_ir_concepts_fail_closed_until_lowering_supports_them(advanced_field: str) -> None:
    constraint = copy.deepcopy(_draft(b"Agents may modify README.md.")["constraint_ir"]["constraints"][0])
    comparison = {
        "kind": "comparison", "operator": "==", "fact": "actor.role",
        "literal": {"type": "enum", "value": "security-reviewer", "unit": None},
    }
    if advanced_field == "condition":
        constraint["condition"] = comparison
    elif advanced_field == "approval":
        constraint["obligations"]["approvals"] = [{"minimum": 1, "role": "repository-reviewer", "evidence_fact": "actor.principal_id"}]
    elif advanced_field == "evidence":
        constraint["obligations"]["evidence"] = [{"evidence_type": "review", "fact": "actor.principal_id"}]
    elif advanced_field == "separation":
        constraint["obligations"]["separation_of_duties"] = [{"roles": ["repository-maintainer", "repository-reviewer"], "principal_facts": ["actor.principal_id", "actor.principal_id"]}]
    else:
        constraint["exceptions"] = [{"exception_id": "exception", "effect": "deny", "condition": comparison}]
    with pytest.raises(ValueError, match="unsupported Constraint IR concept"):
        _lower_constraint(constraint)


def test_missing_runtime_fact_and_type_operator_mismatches_are_actionable() -> None:
    pack = get_builtin_domain_pack(PACK_ID, PACK_VERSION)
    ir = _draft(b"Agents may modify README.md.")["constraint_ir"]
    runtime = copy.deepcopy(pack["runtime_fact_schema"])
    runtime["facts"] = [item for item in runtime["facts"] if item["fact_id"] != "proposal.resource.path"]
    runtime = finalize_runtime_fact_schema({key: value for key, value in runtime.items() if key != "schema_hash"})
    result = validate_runtime_fact_compatibility(ir, runtime, domain_pack=pack)
    assert result["compatible"] is False
    assert "requires proposal.resource.path" in " ".join(item["message"] for item in result["diagnostics"])
    runtime = copy.deepcopy(pack["runtime_fact_schema"])
    fact = next(item for item in runtime["facts"] if item["fact_id"] == "proposal.resource.path")
    fact["type"] = "integer"
    fact["comparison_operators"] = ["=="]
    runtime = finalize_runtime_fact_schema({key: value for key, value in runtime.items() if key != "schema_hash"})
    codes = {item["code"] for item in validate_runtime_fact_compatibility(ir, runtime, domain_pack=pack)["diagnostics"]}
    assert {"runtime_fact_type_mismatch", "runtime_fact_comparison_operators_mismatch"} <= codes


def test_v2_is_one_complete_native_bundle_and_receipt_binds_it() -> None:
    result = _final()
    bundle = result["authority_bundle"]
    receipt = result["publication_receipt"]
    assert bundle["schema_version"] == "authority_bundle.v2"
    assert receipt["schema_version"] == "publication_receipt.v2"
    assert bundle["compiled_authority_contract"]["schema_version"] == "compiled_authority_contract.v2"
    assert "authority_bundle" not in bundle and "publication_receipt" not in bundle
    assert "authority_bundle_v1" not in json.dumps(bundle)
    assert receipt["bundle_hash"] == bundle["bundle_hash"]
    assert validate_authority_bundle(bundle)["provenance_complete"] is True
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True


def test_v2_schemas_validate_complete_artifacts_and_reject_malformed_nested_values() -> None:
    result = _final(_mapped())
    for value, filename in (
        (get_builtin_domain_pack(PACK_ID, PACK_VERSION), "domain_pack.v1.json"),
        (result["authority_bundle"]["constraint_ir"], "constraint_ir.v1.json"),
        (result["authority_bundle"]["runtime_fact_schema"], "runtime_fact_schema.v1.json"),
        (result["compiled_authority_contract"], "compiled_authority_contract.v2.json"),
        (result["authority_bundle"]["statement_decisions"][0], "policy_mapping_decision.v1.json"),
        (result["authority_bundle"], "authority_bundle.v2.json"),
        (result["publication_receipt"], "publication_receipt.v2.json"),
    ):
        _schema_validate(value, filename)
    malformed = copy.deepcopy(result["authority_bundle"])
    malformed["source_statements"][0]["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        _schema_validate(malformed, "authority_bundle.v2.json")
    malformed = copy.deepcopy(result["authority_bundle"])
    malformed["approval_record"].pop("approved_by")
    with pytest.raises(jsonschema.ValidationError):
        _schema_validate(malformed, "authority_bundle.v2.json")


def test_authority_bundle_v2_references_standalone_compiled_contract_v2_schema() -> None:
    schema = json.loads((ROOT / "schemas/authority_bundle.v2.json").read_text(encoding="utf-8"))
    assert schema["properties"]["compiled_authority_contract"] == {
        "$ref": "compiled_authority_contract.v2.json"
    }
    assert "compiledContract" not in schema["$defs"]


def test_v1_shaped_contract_cannot_masquerade_as_v2() -> None:
    sha = "sha256:" + "0" * 64
    contract = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "contract", "contract_version": "1.0.0", "authority_ref": "contract@1.0.0",
        "compiled_from": {"schema_version": "semantic_commit_bundle.v1", "semantic_commit_id": "commit", "semantic_commit_hash": sha, "source_hash": sha, "resolved_interpretation_count": 0},
        "governed_targets": [], "governed_operations": [], "mutation_classes": [], "capability_scope": [],
        "approval_requirements": {}, "continuity_requirements": {}, "replay_obligations": [],
        "lifecycle_requirements": {}, "escalation_requirements": {}, "delegation_requirements": {},
        "identity_bindings": {}, "execution_admissibility_semantics": {},
        "determinism": {"input_schema": "semantic_commit_bundle.v1", "output_schema": "compiled_authority_contract.v1", "same_input_same_output": True, "runtime_enforced_by": "Guard/Cloud"},
        "non_goals": [], "contract_hash": sha,
    }
    _schema_validate(contract, "compiled_authority_contract.v1.json")
    masquerading = copy.deepcopy(contract)
    masquerading["schema_version"] = "compiled_authority_contract.v2"
    with pytest.raises(jsonschema.ValidationError):
        _schema_validate(masquerading, "compiled_authority_contract.v2.json")


def test_v2_shaped_contract_labeled_v1_is_rejected_by_both_contract_schemas() -> None:
    mislabeled = copy.deepcopy(_final()["compiled_authority_contract"])
    mislabeled["schema_version"] = "compiled_authority_contract.v1"
    mislabeled["contract_hash"] = artifact_hash(mislabeled, "contract_hash")
    with pytest.raises(jsonschema.ValidationError):
        _schema_validate(mislabeled, "compiled_authority_contract.v2.json")
    with pytest.raises(jsonschema.ValidationError):
        _schema_validate(mislabeled, "compiled_authority_contract.v1.json")


def test_schema_valid_semantic_tampering_fails_runtime_reconstruction() -> None:
    bundle = copy.deepcopy(_final()["authority_bundle"])
    bundle["compiled_authority_contract"]["target_requirements"]["allow"][0]["value"] = "OTHER.md"
    compiled = bundle["compiled_authority_contract"]
    compiled["contract_hash"] = artifact_hash(compiled, "contract_hash")
    bundle["publication_manifest"]["contracts"][0]["contract_hash"] = compiled["contract_hash"]
    bundle["provenance_bindings"]["compiled_contract_hash"] = compiled["contract_hash"]
    bundle["provenance_bindings"]["publication_manifest_hash"] = canonical_sha256(bundle["publication_manifest"])
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    _schema_validate(bundle, "authority_bundle.v2.json")
    with pytest.raises(ValueError, match="deterministic lowering"):
        validate_authority_bundle(bundle)


def test_receipt_tampering_and_schema_version_mismatch_fail_closed() -> None:
    result = _final()
    receipt = copy.deepcopy(result["publication_receipt"])
    receipt["constraint_ir_hash"] = "sha256:" + "0" * 64
    receipt["receipt_hash"] = artifact_hash(receipt, "receipt_hash")
    with pytest.raises(ValueError, match="constraint_ir_hash"):
        validate_publication_receipt(result["authority_bundle"], receipt)
    with pytest.raises(ValueError, match="versions do not match"):
        validate_publication_receipt(result["authority_bundle"], {"schema_version": "publication_receipt.v1"})


def test_one_byte_source_change_propagates_through_downstream_identities() -> None:
    first = _final(_draft(b"Agents may modify README.md."))
    second = _final(_draft(b"Agents may modify READNE.md."))
    for field in ("source_snapshot_hash", "interpretation_hash", "constraint_ir_hash", "semantic_commit_hash", "compiled_contract_hash", "authority_bundle_hash", "publication_receipt_hash"):
        assert first["canonical_hashes"][field] != second["canonical_hashes"][field]


def test_legacy_v06_api_and_hashes_are_exactly_unchanged() -> None:
    source = (
        b"Repository changes may be made only by repository maintainers.\n"
        b"Agents may modify README.md.\n"
        b"Agents must not modify files under deployment/."
    )
    identities = {"source_policy_id": "repo-change-policy", "source_revision": "revision-2026-08", "authority_id": "repo-change-authority", "authority_version": "6.0.0"}
    public = interpret_customer_policy(source, **identities)
    assert public == _interpret_customer_policy_v0_6_compatibility(source, **identities)
    assert interpret_customer_policy_text(source.decode(), **identities) == public
    assert public["draft_hash"] == "sha256:02a21d437bdb6c029c3bbc8a98d766dbffb696e103154aeb595d76f3af471bec"
    final = finalize_customer_policy_authority(
        public, resolutions=[], approval_id="approval-1", approved_by="reviewer", approved_at="2026-08-29T13:59:00Z",
        committed_by="committer", committed_at="2026-08-29T13:59:30Z", publication_id="publication-1", published_by="publisher", published_at="2026-08-29T14:00:00Z",
    )
    assert final["canonical_hashes"]["authority_bundle_hash"] == "sha256:b1fc5e8a717adc07c0f3f8ec0d6b0b760cfe0bc7a28c3654e3e9366c480c9749"
    assert final["canonical_hashes"]["publication_receipt_hash"] == "sha256:6b5b7a69aebd0ec9d6ffcade311c38d99f85b101aae8a3f119b27b68a2916cb3"


def test_legacy_finance_grammar_remains_available_only_through_v06_api() -> None:
    source = b"Transfers above $1000000 require manager approval. Requester and approver must be separate."
    draft = interpret_customer_policy(source, **IDENTITIES)
    assert [item["rule_type"] for item in draft["proposed_rules"]] == ["approval_threshold", "separation_of_duties"]
    result = finalize_customer_policy_authority(
        draft, resolutions=[], approval_id="approval-1", approved_by="reviewer", approved_at="2026-08-30T19:30:00Z",
        committed_by="committer", committed_at="2026-08-30T19:45:00Z", publication_id="publication-1", published_by="publisher", published_at="2026-08-30T20:00:00Z",
    )
    assert result["canonical_compiler_input"]["approvals"]["thresholds"][0]["value"] == 1000000
    assert result["canonical_compiler_input"]["constraints"] == [{"type": "separation_of_duties", "roles": ["requester", "approver"]}]


def test_released_v1_artifacts_remain_readable() -> None:
    fixture = ROOT / "tests/fixtures/golden_path/contracts/finance-policy-1.0.0.authority-bundle.json"
    bundle = json.loads(fixture.read_text(encoding="utf-8"))
    receipt = json.loads((fixture.parent / "finance-policy-1.0.0.publication-receipt.json").read_text(encoding="utf-8"))
    assert validate_authority_bundle(bundle)["provenance_complete"] is False
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is False


def test_domain_workflow_is_guard_filesystem_and_network_free(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    guard_before = sys.modules.get("waveframe_guard")
    original = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = _final(_mapped())
    finally:
        os.chdir(original)
    assert list(tmp_path.iterdir()) == []
    assert result["status"]["publication_ready"] is True
    assert sys.modules.get("waveframe_guard") is guard_before


def test_base_install_runs_without_guard_in_a_fresh_interpreter() -> None:
    script = """
import sys
from governance_ledger import interpret_policy_with_domain_pack
assert 'waveframe_guard' not in sys.modules
d = interpret_policy_with_domain_pack(b'Agents may modify README.md.', domain_pack_id='repository-changes', domain_pack_version='1.0.0', source_policy_id='p', source_revision='r', authority_id='a', authority_version='1.0.0')
assert d['status']['ready_for_finalization']
assert 'waveframe_guard' not in sys.modules
"""
    completed = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr
