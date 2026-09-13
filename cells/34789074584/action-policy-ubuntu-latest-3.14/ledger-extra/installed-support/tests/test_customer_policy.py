from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import jsonschema

from governance_ledger.customer_policy import (
    finalize_customer_policy_authority,
    interpret_customer_policy,
    interpret_customer_policy_text,
)
from governance_ledger.publication_provenance import (
    CUSTOMER_POLICY_PROFILE,
    MAX_RESOLUTION_RECORDS,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_STATEMENTS,
    MAX_STATEMENT_MAPPINGS,
    canonical_sha256,
    classify_authority_bundle_provenance,
    validate_authority_bundle,
    validate_publication_receipt,
)


GOLDEN_SOURCE = (
    b"Repository changes may be made only by repository maintainers.\n"
    b"Agents may modify README.md.\n"
    b"Agents must not modify files under deployment/."
)
IDENTITIES = {
    "source_policy_id": "repository-change-policy",
    "source_revision": "rev-17",
    "authority_id": "repository-change-authority",
    "authority_version": "6.0.0",
}
HUMAN_INPUTS = {
    "resolutions": [],
    "approval_id": "approval-repository-policy-1",
    "approved_by": "policy-owner@example.com",
    "approved_at": "2026-08-29T13:58:00Z",
    "committed_by": "policy-owner@example.com",
    "committed_at": "2026-08-29T13:59:00Z",
    "publication_id": "publication-repository-policy-1",
    "published_by": "publisher@example.com",
    "published_at": "2026-08-29T14:00:00Z",
}


def _draft(source: bytes = GOLDEN_SOURCE, **identity_overrides: str) -> dict:
    return interpret_customer_policy(source, **{**IDENTITIES, **identity_overrides})


def _final(draft: dict | None = None, **overrides: object) -> dict:
    return finalize_customer_policy_authority(
        draft or _draft(), **{**HUMAN_INPUTS, **overrides}
    )


def _resolution(draft: dict, ambiguity_index: int = 0, option_index: int = 0) -> dict:
    ambiguity = draft["ambiguities"][ambiguity_index]
    return {
        "ambiguity_id": ambiguity["ambiguity_id"],
        "selected_option_id": ambiguity["options"][option_index]["option_id"],
        "resolved_by": "policy-owner@example.com",
        "resolved_at": "2026-08-29T13:57:00Z",
    }


def test_complete_three_sentence_golden_path_needs_only_plain_bytes_and_identities() -> None:
    draft = _draft()
    result = _final(draft)

    assert [item["classification"] for item in draft["source_statements"]] == [
        "enforced", "enforced", "enforced"
    ]
    assert [item["rule_type"] for item in draft["proposed_rules"]] == [
        "required_actor_role", "target", "target"
    ]
    assert all(len(item["rule_id"]) == len("rule-") + 64 for item in draft["proposed_rules"])
    assert all(len(item["statement_id"]) == len("statement-") + 64 for item in draft["source_statements"])
    assert all(len(item["mapping_id"]) == len("mapping-") + 64 for item in draft["statement_rule_mappings"])
    assert result["canonical_compiler_input"] == {
        "contract_id": "repository-change-authority",
        "contract_version": "6.0.0",
        "authority": {"required_roles": ["repository-maintainer"]},
        "targets": {
            "allow": [{"match": "exact", "value": "README.md"}],
            "deny": [{"match": "prefix", "value": "deployment/"}],
        },
    }
    contract = result["compiled_authority_contract"]
    assert contract["authority_requirements"] == {"required_roles": ["repository-maintainer"]}
    assert contract["target_requirements"] == result["canonical_compiler_input"]["targets"]
    meaning = result["semantic_commit_bundle"]["committed_semantic_meaning"]
    assert meaning["required_actor_roles"] == ["repository-maintainer"]
    assert "approver_roles" not in meaning
    assert result["semantic_commit_bundle"]["approved_constraints"]["approval"]["required_roles"] == []
    assert result["status"] == {
        "statement_classification_complete": True,
        "interpretation_complete": True,
        "ready_for_finalization": True,
        "provenance_complete": True,
        "publication_ready": True,
    }
    assert "policy" not in HUMAN_INPUTS and "rules" not in HUMAN_INPUTS


def test_complete_source_to_receipt_chain_and_independent_versions() -> None:
    result = _final()
    bundle = result["authority_bundle"]
    receipt = result["publication_receipt"]
    assert validate_authority_bundle(bundle)["provenance_complete"] is True
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True
    provenance = result["customer_policy_provenance"]
    assert provenance["source_policy"]["source_policy_ref"] == "repository-change-policy@rev-17"
    assert provenance["version_binding"] == {
        "source_policy_ref": "repository-change-policy@rev-17",
        "authority_ref": "repository-change-authority@6.0.0",
        "relationship": "publishes_as",
        "binding_hash": provenance["version_binding"]["binding_hash"],
    }


def test_generated_bundle_and_receipt_validate_schemas_and_canonical_serialization() -> None:
    result = _final()
    root = Path(__file__).resolve().parents[1]
    for artifact_name, schema_name in (
        ("authority_bundle", "authority_bundle.v1.json"),
        ("publication_receipt", "publication_receipt.v1.json"),
    ):
        artifact = result[artifact_name]
        schema = json.loads((root / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(artifact)
        canonical = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
        assert json.loads(canonical) == artifact
        assert canonical_sha256(json.loads(canonical)) == canonical_sha256(artifact)


@pytest.mark.parametrize(
    "source",
    [
        b"Line one.\nLine two.",
        b"Line one.\r\nLine two.\r\n",
        "Caf\u00e9 policy. Agents may modify README.md.".encode(),
        "Cafe\u0301 policy! Agents may modify README.md.".encode(),
        b"Punctuation? Agents may modify README.md!",
    ],
)
def test_exact_bytes_and_complete_contiguous_spans(source: bytes) -> None:
    draft = _draft(source)
    assert base64.b64decode(draft["source_policy"]["source_bytes_base64"]) == source
    cursor = 0
    for statement in draft["source_statements"]:
        assert statement["start_byte"] == cursor
        assert base64.b64decode(statement["statement_bytes_base64"]) == source[
            statement["start_byte"] : statement["end_byte"]
        ]
        cursor = statement["end_byte"]
    assert cursor == len(source)


def test_crlf_lf_trailing_newline_unicode_and_punctuation_are_byte_distinct() -> None:
    values = [
        _draft(b"Information.\n"),
        _draft(b"Information.\r\n"),
        _draft(b"Information."),
        _draft("Informati\u00f3n.".encode()),
        _draft(b"Information!"),
    ]
    assert len({item["source_policy"]["snapshot_hash"] for item in values}) == len(values)
    assert len({item["draft_hash"] for item in values}) == len(values)


def test_string_wrapper_encodes_utf8_without_normalization() -> None:
    text = "Caf\u00e9.\r\nAgents may modify README.md."
    draft = interpret_customer_policy_text(text, **IDENTITIES)
    assert base64.b64decode(draft["source_policy"]["source_bytes_base64"]) == text.encode("utf-8")


@pytest.mark.parametrize("source", [b"", b" \r\n\t", b"\xff"])
def test_source_requires_nonempty_utf8_bytes(source: bytes) -> None:
    with pytest.raises(ValueError, match="UTF-8|non-empty|1 to"):
        _draft(source)


def test_primary_source_input_rejects_text_to_prevent_implicit_encoding() -> None:
    with pytest.raises(TypeError, match="exact bytes"):
        interpret_customer_policy("Agents may modify README.md.", **IDENTITIES)  # type: ignore[arg-type]


def test_deterministic_repeat_generation_and_input_immutability() -> None:
    draft = _draft()
    original_draft = copy.deepcopy(draft)
    human = copy.deepcopy(HUMAN_INPUTS)
    first = finalize_customer_policy_authority(draft, **human)
    second = finalize_customer_policy_authority(draft, **human)
    assert first == second
    assert draft == original_draft
    assert human == HUMAN_INPUTS
    for field in (
        "interpretation_hash", "semantic_commit_hash", "compiled_contract_hash",
        "authority_bundle_hash", "publication_receipt_hash",
    ):
        assert first["canonical_hashes"][field] == second["canonical_hashes"][field]


def test_informational_and_unsupported_only_policy_is_truthful_but_cannot_publish() -> None:
    draft = _draft(b"This policy describes repository work.\nAgents should change docs.")
    assert [item["classification"] for item in draft["source_statements"]] == [
        "informational", "unsupported"
    ]
    assert draft["statement_rule_mappings"] == []
    assert draft["status"] == {
        "statement_classification_complete": True,
        "interpretation_complete": True,
        "requires_resolution_count": 0,
        "unresolved_ambiguity_count": 0,
        "enforceable_rule_count": 0,
        "ready_for_finalization": False,
        "publication_ready": False,
    }
    with pytest.raises(ValueError, match="at least one enforceable confirmed rule"):
        _final(draft)


def test_mixed_supported_and_unsupported_policy_can_publish_without_losing_prose() -> None:
    draft = _draft(
        b"This policy describes repository work. "
        b"Agents should change docs. "
        b"Agents may modify README.md."
    )
    assert [item["classification"] for item in draft["source_statements"]] == [
        "informational", "unsupported", "enforced"
    ]
    assert draft["status"]["ready_for_finalization"] is True
    result = _final(draft)
    assert [item["classification"] for item in result["customer_policy_provenance"]["source_statements"]] == [
        "informational", "unsupported", "enforced"
    ]
    assert len(result["semantic_commit_bundle"]["committed_semantic_meaning"]["confirmed_rules"]) == 1


def test_ambiguous_language_requires_bounded_explicit_resolution() -> None:
    draft = _draft(b"Agents may normally modify README.md.")
    assert draft["source_statements"][0]["classification"] == "requires_resolution"
    assert draft["status"]["statement_classification_complete"] is True
    assert draft["status"]["interpretation_complete"] is False
    assert draft["status"]["ready_for_finalization"] is False
    assert draft["status"]["publication_ready"] is False
    assert {item["statement_outcomes"][0]["classification"] for item in draft["ambiguities"][0]["options"]} == {
        "enforced", "informational", "unsupported"
    }
    enforce = draft["ambiguities"][0]["options"][0]
    assert enforce["enforcement_consequence"] == "Enforce exact allow for README.md."
    with pytest.raises(ValueError, match="resolution for every ambiguity"):
        _final(draft)
    result = _final(draft, resolutions=[_resolution(draft)])
    assert result["customer_policy_provenance"]["source_statements"][0]["classification"] == "enforced"
    confirmed = result["semantic_commit_bundle"]["committed_semantic_meaning"]["confirmed_rules"]
    assert confirmed == [draft["proposed_rules"][0]]
    assert result["canonical_compiler_input"]["targets"] == {
        "allow": [{"match": "exact", "value": "README.md"}],
        "deny": [],
    }
    assert result["compiled_authority_contract"]["target_requirements"] == result["canonical_compiler_input"]["targets"]
    assert result["customer_policy_provenance"]["interpretation"]["statement_rule_mappings"][0]["rule_ids"] == [confirmed[0]["rule_id"]]
    assert validate_publication_receipt(result["authority_bundle"], result["publication_receipt"])["provenance_complete"] is True


def test_resolution_eliminating_every_enforceable_rule_cannot_publish() -> None:
    draft = _draft(b"Agents may normally modify README.md.")
    with pytest.raises(ValueError, match="at least one enforceable confirmed rule"):
        _final(draft, resolutions=[_resolution(draft, option_index=1)])


def test_unsafe_ambiguity_offers_only_non_enforcement_and_cannot_inject_a_rule() -> None:
    draft = _draft(
        b"Agents may modify README.md. Agents may modify an appropriate file."
    )
    ambiguity = draft["ambiguities"][0]
    assert draft["proposed_rules"] == [
        rule for rule in draft["proposed_rules"] if rule["value"] == "README.md"
    ]
    assert {outcome["classification"] for option in ambiguity["options"] for outcome in option["statement_outcomes"]} == {
        "informational", "unsupported"
    }
    assert all(
        not outcome["rule_ids"]
        for option in ambiguity["options"]
        for outcome in option["statement_outcomes"]
    )
    result = _final(draft, resolutions=[_resolution(draft)])
    assert result["canonical_compiler_input"]["targets"] == {
        "allow": [{"match": "exact", "value": "README.md"}],
        "deny": [],
    }


@pytest.mark.parametrize("kind", ["unknown", "duplicate", "malformed", "unknown_option", "bad_time"])
def test_resolution_rejects_unknown_duplicate_malformed_or_unbounded_inputs(kind: str) -> None:
    draft = _draft(b"Agents may normally modify README.md.")
    value = _resolution(draft)
    resolutions = [value]
    if kind == "unknown":
        value["ambiguity_id"] = "ambiguity-" + "0" * 64
    elif kind == "duplicate":
        resolutions.append(copy.deepcopy(value))
    elif kind == "malformed":
        value["free_form_rule"] = {"effect": "allow"}
    elif kind == "unknown_option":
        value["selected_option_id"] = "option-" + "0" * 64
    else:
        value["resolved_at"] = "2026-08-29T13:57:00+00:00"
    with pytest.raises(ValueError):
        _final(draft, resolutions=resolutions)


@pytest.mark.parametrize(
    "target",
    ["/etc/passwd", "C:/work/file", "../secret", "a/../secret", "a//b", "a\\b", "folder/", "a\x00b"],
)
def test_invalid_exact_targets_fail_closed(target: str) -> None:
    with pytest.raises(ValueError, match="target"):
        _draft(f"Agents may modify {target}.".encode())


@pytest.mark.parametrize("prefix", ["deployment", "/deployment/", "../deployment/", "a//b/", "a\\b/"])
def test_invalid_prefix_targets_fail_closed(prefix: str) -> None:
    with pytest.raises(ValueError, match="target|prefix"):
        _draft(f"Agents must not modify files under {prefix}.".encode())


@pytest.mark.parametrize(
    "source",
    [
        b"Agents may modify README.md. Agents must not modify README.md.",
        b"Agents may modify deployment/app.py. Agents must not modify files under deployment/.",
        b"Agents may modify files under src/. Agents must not modify files under src/private/.",
        b"Agents may modify README.md. Agents may modify README.md.",
    ],
)
def test_duplicate_contradictory_and_prefix_overlap_rules_require_resolution(source: bytes) -> None:
    draft = _draft(source)
    assert draft["ambiguities"][0]["ambiguity_type"] == "rule_conflict"
    assert all(item["classification"] == "requires_resolution" for item in draft["source_statements"])
    with pytest.raises(ValueError, match="resolution"):
        _final(draft)
    result = _final(draft, resolutions=[_resolution(draft)])
    assert len(result["semantic_commit_bundle"]["committed_semantic_meaning"]["confirmed_rules"]) == 1


@pytest.mark.parametrize(
    "path,value",
    [
        (("source_policy", "snapshot_hash"), "sha256:" + "0" * 64),
        (("source_statements", 0, "start_byte"), 1),
        (("source_statements", 0, "classification"), "unsupported"),
        (("proposed_rules", 0, "role"), "administrator"),
        (("statement_rule_mappings", 0, "rule_ids", 0), "rule-" + "0" * 64),
        (("version_binding", "authority_ref"), "other@6.0.0"),
        (("authority", "authority_version"), "6.0.1"),
        (("draft_hash",), "sha256:" + "0" * 64),
    ],
)
def test_finalization_reconstructs_and_rejects_modified_draft(path: tuple[object, ...], value: object) -> None:
    draft = _draft()
    target: object = draft
    for part in path[:-1]:
        target = target[part]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    with pytest.raises(ValueError, match="modified|reconstructed"):
        _final(draft)


@pytest.mark.parametrize("field", ["approval_id", "approved_by", "approved_at", "committed_by", "committed_at", "publication_id", "published_by", "published_at"])
def test_all_human_approval_commit_and_publication_inputs_are_explicit_and_valid(field: str) -> None:
    value = "" if not field.endswith("_at") else "2026-08-29T14:00:00+00:00"
    with pytest.raises(ValueError):
        _final(**{field: value})


@pytest.mark.parametrize("field", ["source_policy_id", "source_revision", "authority_id"])
def test_ambiguous_identity_references_are_rejected(field: str) -> None:
    with pytest.raises(ValueError, match="without @"):
        _draft(**{field: "ambiguous@identity"})


def test_authority_version_must_be_canonical_but_need_not_equal_source_revision() -> None:
    with pytest.raises(ValueError, match="semantic version"):
        _draft(authority_version="release-six")
    result = _final(_draft(source_revision="revision-2026-08", authority_version="9.4.1"))
    binding = result["customer_policy_provenance"]["version_binding"]
    assert binding["source_policy_ref"].endswith("@revision-2026-08")
    assert binding["authority_ref"].endswith("@9.4.1")
    assert binding["relationship"] == "publishes_as"


def test_supported_approval_and_separation_of_duties_grammar_projects_to_compiler() -> None:
    source = (
        b"Agents may modify README.md. "
        b"Transfers above $1000000 require manager approval. "
        b"Requester and approver must be separate."
    )
    result = _final(_draft(source))
    compiled = result["compiled_authority_contract"]
    assert compiled["approval_requirements"]["thresholds"] == [
        {"field": "amount", "operator": ">", "value": 1000000, "requires_role": "manager"}
    ]
    assert compiled["invariants"]["separation_of_duties"] == [["requester", "approver"]]


def test_every_rule_category_is_equivalent_across_normalized_commit_compiler_and_contract() -> None:
    source = (
        b"Repository changes may be made only by repository maintainers. "
        b"Agents may modify README.md. "
        b"Agents must not modify files under deployment/. "
        b"Transfers above $1000000 require manager approval. "
        b"Requester and approver must be separate."
    )
    result = _final(_draft(source))
    commit = result["semantic_commit_bundle"]
    meaning = commit["committed_semantic_meaning"]
    compiler_input = result["canonical_compiler_input"]
    compiled = result["compiled_authority_contract"]

    assert meaning["required_actor_roles"] == ["repository-maintainer"]
    assert "approver_roles" not in meaning
    assert meaning["approval_thresholds"] == [
        {"field": "amount", "operator": ">", "value": 1000000, "requires_role": "manager"}
    ]
    assert meaning["separation_of_duties_constraints"] == [["requester", "approver"]]
    assert meaning["target_rules"] == {
        "allow": [{"match": "exact", "value": "README.md"}],
        "deny": [{"match": "prefix", "value": "deployment/"}],
    }
    assert meaning["canonical_compiler_input"] == compiler_input
    assert compiler_input["authority"]["required_roles"] == meaning["required_actor_roles"]
    assert compiler_input["approvals"]["thresholds"] == meaning["approval_thresholds"]
    assert compiler_input["constraints"] == [
        {"type": "separation_of_duties", "roles": ["requester", "approver"]}
    ]
    assert compiler_input["targets"] == meaning["target_rules"]
    assert compiled["authority_requirements"]["required_roles"] == meaning["required_actor_roles"]
    assert compiled["approval_requirements"]["thresholds"] == meaning["approval_thresholds"]
    assert compiled["invariants"]["separation_of_duties"] == meaning["separation_of_duties_constraints"]
    assert compiled["target_requirements"] == meaning["target_rules"]
    assert commit["committed_semantic_meaning"]["confirmed_rules"] == meaning["confirmed_rules"]


@pytest.mark.parametrize(
    "boundary,overrides",
    [
        (
            "resolved_at",
            {"resolution_time": "2026-08-29T13:58:01Z"},
        ),
        (
            "approved_at",
            {
                "approved_at": "2026-08-29T13:59:01Z",
                "committed_at": "2026-08-29T13:59:00Z",
            },
        ),
        (
            "committed_at",
            {
                "committed_at": "2026-08-29T14:00:01Z",
                "published_at": "2026-08-29T14:00:00Z",
            },
        ),
    ],
)
def test_publication_rejects_every_timestamp_inversion(
    boundary: str, overrides: dict[str, str]
) -> None:
    draft = _draft(b"Agents may normally modify README.md.")
    resolution = _resolution(draft)
    final_overrides: dict[str, object] = {}
    if "resolution_time" in overrides:
        resolution["resolved_at"] = overrides["resolution_time"]
    else:
        final_overrides.update(overrides)
    with pytest.raises(ValueError, match=boundary + ".*less than or equal"):
        _final(draft, resolutions=[resolution], **final_overrides)


def test_equal_lifecycle_timestamps_are_valid() -> None:
    timestamp = "2026-08-29T14:00:00Z"
    draft = _draft(b"Agents may normally modify README.md.")
    resolution = _resolution(draft)
    resolution["resolved_at"] = timestamp
    result = _final(
        draft,
        resolutions=[resolution],
        approved_at=timestamp,
        committed_at=timestamp,
        published_at=timestamp,
    )
    assert result["approval_record"]["approved_at"] == timestamp
    assert result["semantic_commit_bundle"]["committed_at"] == timestamp
    assert result["publication_manifest"]["published_at"] == timestamp


def test_resolution_record_order_is_preserved() -> None:
    draft = _draft(
        b"Agents may normally modify README.md. "
        b"Agents may normally modify CONTRIBUTING.md."
    )
    supplied = [_resolution(draft, 1), _resolution(draft, 0)]
    result = _final(draft, resolutions=supplied)
    assert [
        record["ambiguity_id"]
        for record in result["resolution_set"]["ambiguity_resolutions"]
    ] == [record["ambiguity_id"] for record in supplied]


def test_resolved_status_transitions_to_complete_publication() -> None:
    draft = _draft(b"Agents may normally modify README.md.")
    assert draft["status"]["interpretation_complete"] is False
    assert draft["status"]["ready_for_finalization"] is False
    result = _final(draft, resolutions=[_resolution(draft)])
    assert result["validated_interpretation"]["status"] == {
        "statement_classification_complete": True,
        "interpretation_complete": True,
        "requires_resolution_count": 0,
        "unresolved_ambiguity_count": 0,
        "enforceable_rule_count": 1,
        "ready_for_finalization": True,
        "publication_ready": True,
    }


def test_source_byte_change_changes_every_downstream_hash() -> None:
    first = _final(_draft(GOLDEN_SOURCE))
    second = _final(_draft(GOLDEN_SOURCE + b"\n"))
    for field in (
        "interpretation_hash", "semantic_commit_hash", "compiled_contract_hash",
        "authority_bundle_hash", "publication_receipt_hash",
    ):
        assert first["canonical_hashes"][field] != second["canonical_hashes"][field]
    with pytest.raises(ValueError):
        validate_publication_receipt(second["authority_bundle"], first["publication_receipt"])


@pytest.mark.parametrize(
    "location",
    [
        ("customer_policy_provenance", "source_statements", 0, "classification"),
        ("customer_policy_provenance", "interpretation", "statement_rule_mappings", 0, "rule_ids", 0),
        ("customer_policy_provenance", "resolution", "resolution_hash"),
        ("customer_policy_provenance", "approval_record", "approved_by"),
        ("semantic_commit_bundle", "semantic_commit_hash"),
        ("compiled_authority_contract", "contract_hash"),
        ("customer_policy_provenance", "version_binding", "authority_ref"),
        ("publication_id",),
    ],
)
def test_complete_chain_tamper_matrix(location: tuple[object, ...]) -> None:
    result = _final()
    bundle = copy.deepcopy(result["authority_bundle"])
    receipt = result["publication_receipt"]
    target: object = bundle
    for part in location[:-1]:
        target = target[part]  # type: ignore[index]
    leaf = location[-1]
    current = target[leaf]  # type: ignore[index]
    target[leaf] = (current + "-changed") if isinstance(current, str) else "changed"  # type: ignore[index]
    with pytest.raises(ValueError):
        validate_publication_receipt(bundle, receipt)


def test_guard_absent_import_and_execution_in_fresh_interpreter() -> None:
    script = """
import sys
from governance_ledger.customer_policy import interpret_customer_policy
assert 'waveframe_guard' not in sys.modules
d = interpret_customer_policy(b'Agents may modify README.md.', source_policy_id='p', source_revision='r', authority_id='a', authority_version='1.0.0')
assert d['status']['ready_for_finalization']
assert 'waveframe_guard' not in sys.modules
"""
    completed = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr


def test_filesystem_free_use_from_temporary_caller_directory(tmp_path: Path) -> None:
    original = Path.cwd()
    try:
        os.chdir(tmp_path)
        result = _final()
    finally:
        os.chdir(original)
    assert list(tmp_path.iterdir()) == []
    assert result["status"]["publication_ready"] is True


def test_legacy_bundle_classification_remains_provenance_incomplete() -> None:
    fixture = Path(__file__).parent / "fixtures/golden_path/contracts/finance-policy-1.0.0.authority-bundle.json"
    bundle = json.loads(fixture.read_text(encoding="utf-8"))
    assert classify_authority_bundle_provenance(bundle) != CUSTOMER_POLICY_PROFILE
    assert validate_authority_bundle(bundle)["provenance_complete"] is False


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("kind,limit", [
    ("source", MAX_SOURCE_BYTES),
    ("statements", MAX_SOURCE_STATEMENTS),
    ("mappings", MAX_STATEMENT_MAPPINGS),
    ("resolutions", MAX_RESOLUTION_RECORDS),
])
def test_interpreter_limit_boundaries(kind: str, limit: int, offset: int) -> None:
    count = limit + offset
    if kind == "source":
        source = b"x" * count
    elif kind == "statements":
        source = b"Info.\n" * count
    elif kind == "mappings":
        source = b"".join(f"Agents may modify file-{index}.\n".encode() for index in range(count))
    else:
        source = b"".join(f"Agents may normally modify file-{index}.\n".encode() for index in range(count))
    if offset == 1:
        with pytest.raises(ValueError, match="maximum|1 to"):
            _draft(source)
    else:
        draft = _draft(source)
        expected = {
            "source": len(base64.b64decode(draft["source_policy"]["source_bytes_base64"])),
            "statements": len(draft["source_statements"]),
            "mappings": len(draft["statement_rule_mappings"]),
            "resolutions": len(draft["ambiguities"]),
        }[kind]
        assert expected == count
