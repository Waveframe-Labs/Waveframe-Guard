from __future__ import annotations

import base64
import json
from pathlib import Path

import jsonschema
import pytest

from governance_ledger.publication_provenance import (
    CUSTOMER_POLICY_PROFILE,
    LEGACY_INCOMPLETE_PROFILE,
    MAX_RESOLUTION_RECORDS,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_STATEMENTS,
    MAX_STATEMENT_MAPPINGS,
    bytes_sha256,
    canonical_json,
    canonical_sha256,
    classify_authority_bundle_provenance,
    resolution_record_id,
    resolution_set_id,
    source_statement_id,
    statement_mapping_id,
    validate_authority_bundle,
    validate_publication_receipt,
)
from governance_ledger.semantics.compiler import (
    build_semantic_commit_bundle,
    compile_semantic_commit_bundle,
)
from governance_ledger.semantics.preview import build_governance_impact_preview
from governance_ledger.semantics.publication import (
    build_authority_bundle,
    build_publication_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests/fixtures/provenance_complete"


def test_valid_provenance_complete_publication_binds_distinct_versions() -> None:
    bundle, receipt = _complete_publication()

    assert validate_authority_bundle(bundle) == {
        "profile": CUSTOMER_POLICY_PROFILE,
        "provenance_complete": True,
    }
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True
    assert bundle["customer_policy_provenance"]["source_policy"]["source_policy_ref"] == "repository-change-policy@rev-17"
    assert bundle["authority_ref"] == "repository-change-authority@6.0.0"
    assert bundle["customer_policy_provenance"]["version_binding"]["relationship"] == "publishes_as"
    assert receipt["provenance_bindings"]["source_policy_ref"] != receipt["provenance_bindings"]["authority_ref"]


@pytest.mark.parametrize(
    "path",
    [
        "provenance_profile",
        "customer_policy_provenance",
        "customer_policy_provenance.profile",
        "customer_policy_provenance.provenance_complete",
        "customer_policy_provenance.source_policy",
        "customer_policy_provenance.source_policy.source_policy_id",
        "customer_policy_provenance.source_policy.source_revision",
        "customer_policy_provenance.source_policy.source_policy_ref",
        "customer_policy_provenance.source_policy.content_encoding",
        "customer_policy_provenance.source_policy.source_bytes_base64",
        "customer_policy_provenance.source_policy.snapshot_hash",
        "customer_policy_provenance.source_statements",
        "customer_policy_provenance.source_statements.0.statement_id",
        "customer_policy_provenance.source_statements.0.start_byte",
        "customer_policy_provenance.source_statements.0.end_byte",
        "customer_policy_provenance.source_statements.0.statement_bytes_base64",
        "customer_policy_provenance.source_statements.0.statement_hash",
        "customer_policy_provenance.source_statements.0.classification",
        "customer_policy_provenance.interpretation",
        "customer_policy_provenance.interpretation.interpretation_id",
        "customer_policy_provenance.interpretation.statement_rule_mappings",
        "customer_policy_provenance.interpretation.mapping_hash",
        "customer_policy_provenance.resolution",
        "customer_policy_provenance.resolution.resolution_id",
        "customer_policy_provenance.resolution.ambiguity_resolutions",
        "customer_policy_provenance.resolution.resolution_hash",
        "customer_policy_provenance.approval_record",
        "customer_policy_provenance.approval_record.approval_id",
        "customer_policy_provenance.approval_record.approved_by",
        "customer_policy_provenance.approval_record.approved_at",
        "customer_policy_provenance.approval_record.approved_semantic_commit_hash",
        "customer_policy_provenance.approval_record.approval_record_hash",
        "customer_policy_provenance.version_binding",
        "customer_policy_provenance.version_binding.source_policy_ref",
        "customer_policy_provenance.version_binding.authority_ref",
        "customer_policy_provenance.version_binding.relationship",
        "customer_policy_provenance.version_binding.binding_hash",
        "semantic_commit_bundle",
        "compiled_authority_contract",
        "immutable_inputs.provenance_profile",
        "immutable_inputs.provenance_complete",
        "immutable_inputs.source_policy_id",
        "immutable_inputs.source_revision",
        "immutable_inputs.source_policy_ref",
        "immutable_inputs.source_snapshot_hash",
        "immutable_inputs.source_statements_hash",
        "immutable_inputs.interpretation_id",
        "immutable_inputs.mapping_hash",
        "immutable_inputs.resolution_id",
        "immutable_inputs.resolution_hash",
        "immutable_inputs.approval_id",
        "immutable_inputs.approval_record_hash",
        "immutable_inputs.semantic_commit_id",
        "immutable_inputs.semantic_commit_hash",
        "immutable_inputs.compiled_contract_id",
        "immutable_inputs.compiled_contract_version",
        "immutable_inputs.compiled_contract_ref",
        "immutable_inputs.compiled_contract_hash",
        "immutable_inputs.authority_id",
        "immutable_inputs.authority_version",
        "immutable_inputs.authority_ref",
        "immutable_inputs.authority_identity_hash",
        "immutable_inputs.version_binding_hash",
    ],
)
def test_complete_profile_rejects_every_missing_required_component(path: str) -> None:
    bundle, _ = _complete_publication()
    _delete_path(bundle, path)

    with pytest.raises(ValueError, match="required|missing|inconsistent|completeness"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize(
    "path",
    [
        "customer_policy_provenance.source_policy.snapshot_hash",
        "customer_policy_provenance.source_statements.0.statement_hash",
        "customer_policy_provenance.interpretation.mapping_hash",
        "customer_policy_provenance.resolution.resolution_hash",
        "customer_policy_provenance.approval_record.approval_record_hash",
        "customer_policy_provenance.version_binding.binding_hash",
        "semantic_commit_bundle.semantic_commit_hash",
        "compiled_authority_contract.contract_hash",
        "immutable_inputs.source_snapshot_hash",
        "immutable_inputs.source_statements_hash",
        "immutable_inputs.mapping_hash",
        "immutable_inputs.resolution_hash",
        "immutable_inputs.approval_record_hash",
        "immutable_inputs.semantic_commit_hash",
        "immutable_inputs.compiled_contract_hash",
        "immutable_inputs.authority_identity_hash",
        "immutable_inputs.version_binding_hash",
    ],
)
def test_complete_profile_rejects_each_individual_hash_mismatch(path: str) -> None:
    bundle, _ = _complete_publication()
    _set_path(bundle, path, "sha256:" + "0" * 64)

    with pytest.raises(ValueError, match="hash|inconsistent"):
        validate_authority_bundle(bundle)


def test_source_byte_tampering_fails_closed() -> None:
    bundle, _ = _complete_publication()
    source = bundle["customer_policy_provenance"]["source_policy"]
    tampered = bytearray(base64.b64decode(source["source_bytes_base64"]))
    tampered[0] ^= 1
    source["source_bytes_base64"] = base64.b64encode(tampered).decode("ascii")

    with pytest.raises(ValueError, match="source snapshot_hash"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize("source_bytes", [b"", b"   \n", b"\xff"])
def test_source_policy_requires_non_empty_utf8_text(source_bytes: bytes) -> None:
    with pytest.raises(ValueError, match="UTF-8 text|non-empty"):
        _complete_publication(source_bytes=source_bytes)


@pytest.mark.parametrize("partition_error", ["omitted", "overlapping", "out_of_order", "duplicate", "out_of_bounds"])
def test_statement_partition_rejects_invalid_spans(partition_error: str) -> None:
    bundle, _ = _complete_publication()
    statements = bundle["customer_policy_provenance"]["source_statements"]
    if partition_error == "omitted":
        del statements[1]
    elif partition_error == "overlapping":
        statements[1]["start_byte"] = statements[0]["end_byte"] - 1
    elif partition_error == "out_of_order":
        statements[0], statements[1] = statements[1], statements[0]
    elif partition_error == "duplicate":
        statements.insert(1, dict(statements[0]))
    else:
        statements[-1]["end_byte"] += 1

    with pytest.raises(ValueError, match="span|overlapping|order|omits"):
        validate_authority_bundle(bundle)


def test_statement_partition_rejects_unclassified_and_multiply_classified_statements() -> None:
    bundle, _ = _complete_publication()
    del bundle["customer_policy_provenance"]["source_statements"][0]["classification"]
    with pytest.raises(ValueError, match="classification|required"):
        validate_authority_bundle(bundle)

    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["source_statements"][0]["classification"] = [
        "enforced",
        "informational",
    ]
    with pytest.raises(ValueError, match="classification"):
        validate_authority_bundle(bundle)


def test_enforced_statement_requires_confirmed_rules() -> None:
    bundle, _ = _complete_publication()
    del bundle["customer_policy_provenance"]["interpretation"]["statement_rule_mappings"][0]

    with pytest.raises(ValueError, match="enforced source statement"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize("classification", ["informational", "unsupported"])
def test_non_enforced_statements_cannot_acquire_rules(classification: str) -> None:
    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["source_statements"][0]["classification"] = classification

    with pytest.raises(ValueError, match="must not acquire enforceable rules"):
        validate_authority_bundle(bundle)


def test_complete_publication_rejects_requires_resolution_state() -> None:
    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["source_statements"][0]["classification"] = "requires_resolution"

    with pytest.raises(ValueError, match="requires_resolution"):
        validate_authority_bundle(bundle)


def test_auditable_resolution_record_is_bound_to_semantic_commit() -> None:
    initial, _ = _complete_publication()
    statement_id = initial["customer_policy_provenance"]["source_statements"][0]["statement_id"]
    record = _resolution_record(statement_id, 1)
    bundle, receipt = _complete_publication(resolution_records=[record])

    assert bundle["semantic_commit_bundle"]["resolved_interpretations"] == [record]
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True


@pytest.mark.parametrize("record_error", ["malformed", "duplicate", "unknown_statement"])
def test_resolution_records_reject_malformed_duplicate_or_unknown_references(record_error: str) -> None:
    initial, _ = _complete_publication()
    statement_id = initial["customer_policy_provenance"]["source_statements"][0]["statement_id"]
    record = _resolution_record(statement_id, 1)
    bundle, _ = _complete_publication(resolution_records=[record])
    records = bundle["customer_policy_provenance"]["resolution"]["ambiguity_resolutions"]
    if record_error == "malformed":
        del records[0]["resolved_by"]
    elif record_error == "duplicate":
        records.append(dict(records[0]))
    else:
        records[0]["statement_ids"] = ["statement-" + "0" * 64]

    with pytest.raises(ValueError, match="required|duplicate|unknown"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize(
    "field",
    [
        "resolution_id",
        "ambiguity_id",
        "statement_ids",
        "selected_decision",
        "resolved_by",
        "resolved_at",
    ],
)
def test_resolution_record_rejects_every_missing_audit_field(field: str) -> None:
    initial, _ = _complete_publication()
    statement_id = initial["customer_policy_provenance"]["source_statements"][0]["statement_id"]
    bundle, _ = _complete_publication(resolution_records=[_resolution_record(statement_id, 1)])
    del bundle["customer_policy_provenance"]["resolution"]["ambiguity_resolutions"][0][field]

    with pytest.raises(ValueError, match="missing|required"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize(
    "field,value",
    [
        ("resolution_id", "resolution-not-a-digest"),
        ("ambiguity_id", ""),
        ("statement_ids", []),
        ("selected_decision", "   "),
        ("resolved_by", ""),
        ("resolved_at", "2026-08-29T13:58:00+00:00"),
    ],
)
def test_resolution_record_rejects_malformed_audit_values(field: str, value: object) -> None:
    initial, _ = _complete_publication()
    statement_id = initial["customer_policy_provenance"]["source_statements"][0]["statement_id"]
    bundle, _ = _complete_publication(resolution_records=[_resolution_record(statement_id, 1)])
    bundle["customer_policy_provenance"]["resolution"]["ambiguity_resolutions"][0][field] = value

    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)


def test_unexplained_or_unbound_version_relationship_fails() -> None:
    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["version_binding"]["relationship"] = ""

    with pytest.raises(ValueError, match="relationship"):
        validate_authority_bundle(bundle)

    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["version_binding"]["authority_ref"] = "repository-change-authority@rev-17"
    with pytest.raises(ValueError, match="version authority_ref"):
        validate_authority_bundle(bundle)


def test_unsupported_version_relationship_fails() -> None:
    bundle, _ = _complete_publication()
    bundle["customer_policy_provenance"]["version_binding"]["relationship"] = "supersedes"

    with pytest.raises(ValueError, match="unsupported version relationship"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize(
    "identity",
    [
        {"source_policy_id": "repository@change-policy"},
        {"source_revision": "rev@17"},
    ],
)
def test_ambiguous_source_policy_identity_is_rejected(identity: dict[str, str]) -> None:
    bundle, _ = _complete_publication()
    source = bundle["customer_policy_provenance"]["source_policy"]
    source.update(identity)

    with pytest.raises(ValueError, match="must not contain @"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize("field", ["source", "statement"])
def test_noncanonical_base64_is_rejected(field: str) -> None:
    bundle, _ = _complete_publication(source_bytes=b"a")
    provenance = bundle["customer_policy_provenance"]
    if field == "source":
        provenance["source_policy"]["source_bytes_base64"] = "YR=="
    else:
        provenance["source_statements"][0]["statement_bytes_base64"] = "YR=="

    with pytest.raises(ValueError, match="canonical base64"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize(
    "limit_name,limit",
    [
        ("source_bytes", MAX_SOURCE_BYTES),
        ("source_statements", MAX_SOURCE_STATEMENTS),
        ("statement_mappings", MAX_STATEMENT_MAPPINGS),
        ("resolution_records", MAX_RESOLUTION_RECORDS),
    ],
)
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_runtime_input_limit_boundaries(limit_name: str, limit: int, offset: int) -> None:
    inputs = _limit_inputs(limit_name, limit + offset)
    bundle_schema = json.loads((ROOT / "schemas/authority_bundle.v1.json").read_text(encoding="utf-8"))
    if offset == 1:
        with pytest.raises(ValueError, match="maximum"):
            _complete_publication(**inputs)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(bundle_schema).validate(
                _schema_above_limit_bundle(limit_name, limit + offset)
            )
    else:
        bundle, receipt = _complete_publication(**inputs)
        jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
        assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True


def test_statement_and_mapping_ids_use_complete_sha256_digests() -> None:
    bundle, _ = _complete_publication()
    provenance = bundle["customer_policy_provenance"]

    assert len(provenance["source_statements"][0]["statement_id"]) == len("statement-") + 64
    assert len(provenance["interpretation"]["statement_rule_mappings"][0]["mapping_id"]) == len("mapping-") + 64


@pytest.mark.parametrize(
    "path,new_value",
    [
        ("customer_policy_provenance.interpretation.statement_rule_mappings.0.rule_ids.0", "rule-role-maintainer-x"),
        ("customer_policy_provenance.resolution.ambiguity_resolutions", [{"ambiguity_id": "a-1", "resolution": "explicit"}]),
        ("customer_policy_provenance.approval_record.approved_by", "mallory@example.com"),
        ("semantic_commit_bundle.committed_semantic_meaning.confirmed_rules.0.effect", "deny"),
        ("compiled_authority_contract.authority_ref", "other@6.0.0"),
        ("publication_meaning", "tampered bundle byte"),
    ],
)
def test_receipt_verification_detects_changed_publication_inputs(path: str, new_value: object) -> None:
    bundle, receipt = _complete_publication()
    _set_path(bundle, path, new_value)

    with pytest.raises(ValueError):
        validate_publication_receipt(bundle, receipt)


@pytest.mark.parametrize(
    "path",
    [
        "provenance_bindings.source_snapshot_hash",
        "provenance_bindings.provenance_profile",
        "provenance_bindings.provenance_complete",
        "provenance_bindings.source_policy_id",
        "provenance_bindings.source_revision",
        "provenance_bindings.source_policy_ref",
        "provenance_bindings.source_statements_hash",
        "provenance_bindings.interpretation_id",
        "provenance_bindings.mapping_hash",
        "provenance_bindings.resolution_id",
        "provenance_bindings.resolution_hash",
        "provenance_bindings.approval_id",
        "provenance_bindings.approval_record_hash",
        "provenance_bindings.semantic_commit_id",
        "provenance_bindings.semantic_commit_hash",
        "provenance_bindings.compiled_contract_id",
        "provenance_bindings.compiled_contract_version",
        "provenance_bindings.compiled_contract_ref",
        "provenance_bindings.compiled_contract_hash",
        "provenance_bindings.authority_id",
        "provenance_bindings.authority_version",
        "provenance_bindings.authority_ref",
        "provenance_bindings.authority_identity_hash",
        "provenance_bindings.version_binding_hash",
        "bundle_hash",
        "semantic_commit_hash",
        "compiled_contract_hash",
        "receipt_id",
        "immutable_inputs.bundle_hash",
        "receipt_hash",
    ],
)
def test_receipt_rejects_each_changed_bound_hash(path: str) -> None:
    bundle, receipt = _complete_publication()
    _set_path(receipt, path, "sha256:" + "0" * 64)

    with pytest.raises(ValueError, match="receipt|inconsistent"):
        validate_publication_receipt(bundle, receipt)


def test_complete_publication_generation_is_deterministic() -> None:
    first_bundle, first_receipt = _complete_publication()
    second_bundle, second_receipt = _complete_publication()

    assert first_bundle == second_bundle
    assert first_receipt == second_receipt
    assert canonical_sha256(first_bundle) == canonical_sha256(second_bundle)
    assert first_receipt["receipt_hash"] == second_receipt["receipt_hash"]
    assert first_bundle["semantic_commit_hash"] == second_bundle["semantic_commit_hash"]
    assert first_bundle["compiled_contract_hash"] == second_bundle["compiled_contract_hash"]


def test_legacy_bundles_are_truthfully_classified_without_inference() -> None:
    legacy = json.loads(
        (ROOT / "tests/fixtures/golden_path/contracts/finance-policy-1.0.0.authority-bundle.json").read_text(
            encoding="utf-8"
        )
    )

    assert "provenance_profile" not in legacy
    assert classify_authority_bundle_provenance(legacy) == LEGACY_INCOMPLETE_PROFILE
    assert validate_authority_bundle(legacy) == {
        "profile": LEGACY_INCOMPLETE_PROFILE,
        "provenance_complete": False,
    }
    legacy_receipt = json.loads(
        (ROOT / "tests/fixtures/golden_path/contracts/finance-policy-1.0.0.publication-receipt.json").read_text(
            encoding="utf-8"
        )
    )
    bundle_schema = json.loads((ROOT / "schemas/authority_bundle.v1.json").read_text(encoding="utf-8"))
    receipt_schema = json.loads((ROOT / "schemas/publication_receipt.v1.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(bundle_schema).validate(legacy)
    jsonschema.Draft202012Validator(receipt_schema).validate(legacy_receipt)


def test_schema_validation_and_canonical_serialization() -> None:
    bundle, receipt = _complete_publication()
    bundle_schema = json.loads((ROOT / "schemas/authority_bundle.v1.json").read_text(encoding="utf-8"))
    receipt_schema = json.loads((ROOT / "schemas/publication_receipt.v1.json").read_text(encoding="utf-8"))
    semantic_schema = json.loads((ROOT / "schemas/semantic_commit_bundle.v1.json").read_text(encoding="utf-8"))

    jsonschema.Draft202012Validator(bundle_schema).validate(bundle)
    jsonschema.Draft202012Validator(receipt_schema).validate(receipt)
    jsonschema.Draft202012Validator(semantic_schema).validate(bundle["semantic_commit_bundle"])
    assert canonical_json({"z": 1, "a": "café"}) == '{"a":"caf\\u00e9","z":1}'
    assert canonical_sha256({"a": 1, "b": 2}) == canonical_sha256({"b": 2, "a": 1})


def _complete_publication(
    *,
    source_bytes: bytes | None = None,
    classifications: list[str] | None = None,
    rule_ids_by_statement: list[list[str]] | None = None,
    confirmed_rules: list[dict] | None = None,
    resolution_records: list[dict] | None = None,
    source_policy_id: str | None = None,
    source_revision: str | None = None,
    version_relationship: str | None = None,
) -> tuple[dict, dict]:
    fixture = json.loads((FIXTURE_ROOT / "publication-inputs.json").read_text(encoding="utf-8"))
    using_fixture_source = source_bytes is None
    if source_bytes is None:
        source_bytes = base64.b64decode(
            (FIXTURE_ROOT / "repository-change-policy.base64").read_text(encoding="ascii").strip(),
            validate=True,
        )
    source_policy_id = source_policy_id or fixture["source_policy"]["source_policy_id"]
    source_revision = source_revision or fixture["source_policy"]["source_revision"]
    source_ref = f"{source_policy_id}@{source_revision}"
    source_hash = bytes_sha256(source_bytes)
    statement_chunks = source_bytes.splitlines(keepends=True) or [source_bytes]
    if classifications is None:
        classifications = (
            fixture["interpretation"]["statement_classifications"]
            if using_fixture_source
            else ["informational"] * len(statement_chunks)
        )
    if rule_ids_by_statement is None:
        rule_ids_by_statement = (
            fixture["interpretation"]["statement_rule_ids"]
            if using_fixture_source
            else [[] for _ in statement_chunks]
        )
    if len(classifications) != len(statement_chunks):
        raise AssertionError("test fixture classifications must match statement chunks")
    if len(rule_ids_by_statement) != len(statement_chunks):
        raise AssertionError("test fixture mappings must match statement chunks")
    source_statements = []
    cursor = 0
    for statement_bytes, classification in zip(statement_chunks, classifications):
        start = cursor
        end = cursor + len(statement_bytes)
        statement_hash = bytes_sha256(statement_bytes)
        source_statements.append(
            {
                "statement_id": source_statement_id(
                    source_policy_id=source_policy_id,
                    source_revision=source_revision,
                    start_byte=start,
                    end_byte=end,
                    statement_hash=statement_hash,
                ),
                "start_byte": start,
                "end_byte": end,
                "statement_bytes_base64": base64.b64encode(statement_bytes).decode("ascii"),
                "statement_hash": statement_hash,
                "classification": classification,
            }
        )
        cursor = end

    mappings = []
    for statement, mapped_rules in zip(source_statements, rule_ids_by_statement):
        if not mapped_rules:
            continue
        statement_ids = [statement["statement_id"]]
        mappings.append(
            {
                "mapping_id": statement_mapping_id(statement_ids, mapped_rules),
                "statement_ids": statement_ids,
                "rule_ids": mapped_rules,
            }
        )
    interpretation = {
        "interpretation_id": fixture["interpretation"]["interpretation_id"],
        "statement_rule_mappings": mappings,
        "mapping_hash": canonical_sha256(mappings),
    }
    resolution_records = (
        fixture["resolution"]["ambiguity_resolutions"]
        if resolution_records is None
        else resolution_records
    )
    resolution = {
        "resolution_id": resolution_set_id(resolution_records),
        "ambiguity_resolutions": resolution_records,
        "resolution_hash": canonical_sha256(resolution_records),
    }
    semantic_bindings = {
        "source_policy_ref": source_ref,
        "source_snapshot_hash": source_hash,
        "source_statements_hash": canonical_sha256(source_statements),
        "interpretation_id": interpretation["interpretation_id"],
        "mapping_hash": interpretation["mapping_hash"],
        "resolution_id": resolution["resolution_id"],
        "resolution_hash": resolution["resolution_hash"],
    }
    reconciliation = {
        "schema_version": "governance_semantic_reconciliation.v1",
        "source_id": source_policy_id,
        "source_hash": source_hash,
        "extraction_id": "extraction-repository-change-001",
        "operator_interpretation_decisions": resolution_records,
        "unresolved_ambiguities": [],
        "semantic_conflicts": [],
        "interpretation_completeness_posture": "complete",
        "final_normalized_semantic_meaning": {
            "contract_id": fixture["authority"]["authority_id"],
            "contract_version": fixture["authority"]["authority_version"],
            "governed_targets": ["README.md", "deployment/"],
            "governed_operations": ["modify"],
            "approver_roles": ["repository-maintainer"],
            "confirmed_rules": (
                fixture["confirmed_rules"]
                if confirmed_rules is None and using_fixture_source
                else (
                    confirmed_rules
                    if confirmed_rules is not None
                    else [
                        {"rule_id": rule_id, "rule_type": "test_rule"}
                        for rule_ids in rule_ids_by_statement
                        for rule_id in rule_ids
                    ]
                )
            ),
        },
    }
    semantic_commit = build_semantic_commit_bundle(
        reconciliation,
        committed_by=fixture["semantic_commit"]["committed_by"],
        committed_at=fixture["semantic_commit"]["committed_at"],
        provenance_bindings=semantic_bindings,
    )
    compiled_contract = compile_semantic_commit_bundle(semantic_commit)
    approval_record = {
        "approval_id": fixture["approval"]["approval_id"],
        "approved_by": fixture["approval"]["approved_by"],
        "approved_at": fixture["approval"]["approved_at"],
        "approved_semantic_commit_hash": semantic_commit["semantic_commit_hash"],
    }
    approval_record["approval_record_hash"] = canonical_sha256(approval_record)
    authority_ref = compiled_contract["authority_ref"]
    version_binding = {
        "source_policy_ref": source_ref,
        "authority_ref": authority_ref,
        "relationship": version_relationship or fixture["version_relationship"],
    }
    version_binding["binding_hash"] = canonical_sha256(version_binding)
    provenance = {
        "profile": CUSTOMER_POLICY_PROFILE,
        "provenance_complete": True,
        "source_policy": {
            "source_policy_id": source_policy_id,
            "source_revision": source_revision,
            "source_policy_ref": source_ref,
            "content_encoding": "base64",
            "source_bytes_base64": base64.b64encode(source_bytes).decode("ascii"),
            "snapshot_hash": source_hash,
        },
        "source_statements": source_statements,
        "interpretation": interpretation,
        "resolution": resolution,
        "approval_record": approval_record,
        "version_binding": version_binding,
    }
    manifest = {
        "schema_version": "publication_manifest.v1",
        "publication_id": fixture["publication"]["publication_id"],
        "published_at": fixture["publication"]["published_at"],
        "published_by": fixture["publication"]["published_by"],
        "contracts": [
            {
                "contract_id": compiled_contract["contract_id"],
                "contract_version": compiled_contract["contract_version"],
                "contract_hash": compiled_contract["contract_hash"],
                "source_hash": source_hash,
                "path": "contracts/repository-change-authority-6.0.0.contract.json",
            }
        ],
        "reviews": [{"path": "reviews/repository-change-policy.review.json"}],
        "snapshots": [{"path": "snapshots/repository-change-policy.json"}],
    }
    bundle = build_authority_bundle(
        authority_contract=compiled_contract,
        publication_manifest=manifest,
        governance_impact_preview=build_governance_impact_preview(compiled_contract),
        semantic_commit_bundle=semantic_commit,
        compiled_authority_contract=compiled_contract,
        customer_policy_provenance=provenance,
    )
    receipt = build_publication_receipt(
        authority_bundle=bundle,
        published_at=manifest["published_at"],
    )
    return bundle, receipt


def _resolution_record(statement_id: str, index: int) -> dict:
    values = {
        "ambiguity_id": f"ambiguity-{index:04d}",
        "statement_ids": [statement_id],
        "selected_decision": f"Selected bounded meaning {index}",
        "resolved_by": "policy-owner@example.com",
        "resolved_at": "2026-08-29T13:58:00Z",
    }
    return {
        "resolution_id": resolution_record_id(**values),
        **values,
    }


def _limit_inputs(limit_name: str, count: int) -> dict:
    if limit_name == "source_bytes":
        return {"source_bytes": b"x" * count}
    if limit_name == "source_statements":
        return {"source_bytes": b"x\n" * count}
    if limit_name == "statement_mappings":
        return {
            "source_bytes": b"x\n" * count,
            "classifications": ["enforced"] * count,
            "rule_ids_by_statement": [[f"rule-{index:04d}"] for index in range(count)],
        }
    if limit_name == "resolution_records":
        source_bytes = b"x"
        statement_hash = bytes_sha256(source_bytes)
        statement_id = source_statement_id(
            source_policy_id="repository-change-policy",
            source_revision="rev-17",
            start_byte=0,
            end_byte=1,
            statement_hash=statement_hash,
        )
        return {
            "source_bytes": source_bytes,
            "resolution_records": [
                _resolution_record(statement_id, index)
                for index in range(count)
            ],
        }
    raise AssertionError(f"unknown test limit: {limit_name}")


def _schema_above_limit_bundle(limit_name: str, count: int) -> dict:
    bundle, _ = _complete_publication()
    provenance = bundle["customer_policy_provenance"]
    if limit_name == "source_bytes":
        provenance["source_policy"]["source_bytes_base64"] = base64.b64encode(
            b"x" * count
        ).decode("ascii")
    elif limit_name == "source_statements":
        provenance["source_statements"] = [
            dict(provenance["source_statements"][0])
            for _ in range(count)
        ]
    elif limit_name == "statement_mappings":
        provenance["interpretation"]["statement_rule_mappings"] = [
            dict(provenance["interpretation"]["statement_rule_mappings"][0])
            for _ in range(count)
        ]
    elif limit_name == "resolution_records":
        statement_id = provenance["source_statements"][0]["statement_id"]
        provenance["resolution"]["ambiguity_resolutions"] = [
            _resolution_record(statement_id, index)
            for index in range(count)
        ]
    else:
        raise AssertionError(f"unknown test limit: {limit_name}")
    return bundle


def _path_parts(path: str) -> list[str | int]:
    return [int(part) if part.isdigit() else part for part in path.split(".")]


def _delete_path(value: dict, path: str) -> None:
    parts = _path_parts(path)
    parent: object = value
    for part in parts[:-1]:
        parent = parent[part]  # type: ignore[index]
    del parent[parts[-1]]  # type: ignore[index]


def _set_path(value: dict, path: str, replacement: object) -> None:
    parts = _path_parts(path)
    parent: object = value
    for part in parts[:-1]:
        parent = parent[part]  # type: ignore[index]
    parent[parts[-1]] = replacement  # type: ignore[index]
