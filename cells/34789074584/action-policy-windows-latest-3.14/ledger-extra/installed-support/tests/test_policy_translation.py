from __future__ import annotations

import copy
import inspect
import json
import socket
import sys
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from governance_ledger import (
    apply_policy_translation_binding,
    apply_policy_translation_control_confirmation,
    apply_policy_translation_disposition,
    approve_policy_translation_proposal,
    create_policy_translation_proposal,
    create_policy_translation_run,
    create_policy_translation_run_evidence,
    finalize_policy_translation_authority,
    get_policy_translation_capability_catalog,
    inspect_policy_translation_proposal,
    interpret_policy_with_domain_pack,
    render_policy_translation_review,
    resolve_policy_translation_capability_catalog,
    validate_authority_bundle,
    validate_policy_translation_capability_catalog,
    validate_policy_translation_proposal,
    validate_policy_translation_review,
    validate_policy_translation_run_evidence,
    validate_publication_receipt,
)
from governance_ledger.publication_provenance import bytes_sha256, canonical_sha256


ROOT = Path(__file__).parents[1]
NOW = "2026-09-03T12:00:00Z"
FACTS = [
    "actor.subject_kind",
    "proposal.action",
    "proposal.resource.kind",
    "proposal.resource.path",
]


def _run(draft: dict, *, sequence: int = 0, previous: str | None = None,
         provider_class: str = "hosted_model", provider_identifier: str | None = "provider/deployment",
         response: bytes = b'{"untrusted":"candidate"}',
         created_at: str = NOW, completed_at: str = "2026-09-03T12:00:01Z",
         explanation_hash: str | None = None) -> dict:
    return create_policy_translation_run(
        source_policy_ref=draft["source_policy"]["source_policy_ref"],
        source_revision=draft["source_policy"]["source_revision"],
        source_snapshot_hash=draft["source_policy"]["snapshot_hash"],
        provider_class=provider_class,
        provider_identifier=provider_identifier,
        translation_template_version="template-1",
        translation_template_hash=bytes_sha256(b"template"),
        request_configuration_id="request-config-1",
        request_configuration_hash=bytes_sha256(b"configuration"),
        request_hash=bytes_sha256(b'{"source":"policy"}'),
        response_hash=bytes_sha256(response),
        explanation_hash=explanation_hash,
        created_at=created_at,
        completed_at=completed_at,
        sequence_number=sequence,
        previous_run_hash=previous,
    )


def _base(source: bytes) -> dict:
    return interpret_policy_with_domain_pack(
        source,
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
    )


def _path_control(
    path: str, *, source: bytes, clause_start: int, clause_end: int,
    effect: str = "allow", prefix: bool = False,
) -> dict:
    encoded = path.encode("utf-8")
    literal_start = source.find(encoded, clause_start, clause_end)
    if literal_start < 0:
        literal_start = clause_start
    literal_end = literal_start + len(encoded)
    return {
        "control_type": "prefix_path_access" if prefix else "exact_path_access",
        "actor_kind": "autonomous_agent",
        "action": "modify",
        "resource_kind": "repository_path",
        "fact_id": "proposal.resource.path",
        "operator": "starts_with" if prefix else "==",
        "effect": effect,
        "enforcement_point": "waveframe.guard.repository-change.v1",
        "value": {
            "kind": "source_literal",
            "value": path,
            "canonical_value": path,
            "start_byte": literal_start,
            "end_byte": literal_end,
            "literal_hash": bytes_sha256(source[literal_start:literal_end]),
        },
        "required_runtime_facts": FACTS,
    }


def _proposal(
    source: bytes = b"Agents may modify README.md. Policy overview.\n",
) -> dict:
    draft = _base(source)
    clauses = []
    for index, statement in enumerate(draft["source_statements"]):
        if statement["classification"] == "direct":
            mapping = next(item for item in draft["source_to_constraint_mappings"] if item["statement_id"] == statement["statement_id"])
            constraints = {item["constraint_id"]: item for item in draft["constraint_ir"]["constraints"]}
            controls = []
            for constraint_id in mapping["constraint_ids"]:
                constraint = constraints[constraint_id]
                path = constraint["resource"]["value"]
                controls.append(_path_control(
                    path,
                    source=source,
                    clause_start=statement["start_byte"],
                    clause_end=statement["end_byte"],
                    effect=constraint["effect"],
                    prefix=constraint["resource"]["match"] == "prefix",
                ))
            coverage_status = "fully_represented"
        else:
            coverage_status = "informational"
            controls = []
        clauses.append(
            {
                "start_byte": statement["start_byte"],
                "end_byte": statement["end_byte"],
                "coverage_status": coverage_status,
                "candidate_controls": controls,
                "unresolved_binding_ids": [],
                "limitation_code": None,
                "residual_unsupported_spans": [],
            }
        )
    run = _run(draft)
    return create_policy_translation_proposal(
        source,
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
        clauses=clauses,
        organizational_bindings=[],
        translation_runs=[run],
    )


def _confirmed(proposal: dict) -> dict:
    state = None
    for clause in proposal["clauses"]:
        for control in clause["candidate_controls"]:
            state = apply_policy_translation_control_confirmation(
                proposal,
                state,
                clause_id=clause["clause_id"],
                candidate_control_id=control["candidate_control_id"],
                confirmed_by="policy-owner",
                confirmed_at="2026-09-03T12:01:00Z",
            )
        status = clause["coverage_status"]
        state = apply_policy_translation_disposition(
            proposal,
            state,
            clause_id=clause["clause_id"],
            coverage_status=status,
            reason_code=("human-confirmed-complete" if status == "fully_represented" else "context-only"),
            confirmed_by="policy-owner",
            confirmed_at="2026-09-03T12:02:00Z",
        )
    assert state is not None
    return state


def _approved(proposal: dict, confirmation: dict) -> dict:
    return approve_policy_translation_proposal(
        proposal,
        confirmation,
        approved_by="policy-owner",
        approved_at="2026-09-03T12:03:00Z",
    )


def _final(proposal: dict) -> dict:
    confirmation = _confirmed(proposal)
    approval = _approved(proposal, confirmation)
    return finalize_policy_translation_authority(
        proposal,
        confirmation,
        approval,
        committed_by="ledger-committer",
        committed_at="2026-09-03T12:04:00Z",
        publication_id="publication-1",
        published_by="ledger-publisher",
        published_at="2026-09-03T12:05:00Z",
    )


def _restamp_control(control: dict) -> None:
    control["candidate_control_id"] = "candidate-control-" + canonical_sha256(
        {key: value for key, value in control.items() if key != "candidate_control_id"}
    ).removeprefix("sha256:")


def _restamp_proposal(proposal: dict) -> None:
    payload = {
        key: value
        for key, value in proposal.items()
        if key not in {"proposal_id", "proposal_hash"}
    }
    proposal["proposal_hash"] = canonical_sha256(payload)
    proposal["proposal_id"] = "policy-translation-proposal-" + proposal[
        "proposal_hash"
    ].removeprefix("sha256:")


def _schema_validate(value: dict, filename: str) -> None:
    registry = Registry()
    for path in (ROOT / "schemas").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, registry=registry).validate(value)


def test_catalog_is_finite_hashed_and_matches_only_released_runtime_surface() -> None:
    catalog = get_policy_translation_capability_catalog()
    assert catalog["actor_kinds"] == ["autonomous_agent"]
    assert catalog["actions"] == ["modify"]
    assert [item["control_type"] for item in catalog["control_types"]] == [
        "acting_role",
        "exact_path_access",
        "prefix_path_access",
    ]
    assert {
        "push",
        "open_pull_request",
        "merge_pull_request",
        "branch_scope",
        "approval_count_or_threshold",
        "evidence_requirement",
    } <= set(catalog["known_fail_closed_capabilities"])
    assert catalog["domain_pack"]["domain_pack_hash"] == (
        "sha256:4b6ff9a3ebf3b419151fbaa3f899012dca39ff354de8e768da05146ad0c64b80"
    )
    runtime = {item["fact_id"]: item for item in catalog["facts"]}
    assert sorted(runtime) == [
        "actor.role",
        "actor.subject_kind",
        "proposal.action",
        "proposal.resource.kind",
        "proposal.resource.path",
    ]
    assert catalog["operators"] == ["==", "starts_with"]
    assert catalog["effects"] == ["allow", "deny", "require"]
    assert validate_policy_translation_capability_catalog(catalog) == catalog
    assert catalog["catalog_hash"] == canonical_sha256(
        {key: value for key, value in catalog.items() if key != "catalog_hash"}
    )
    _schema_validate(catalog, "policy_translation_capability_catalog.v1.json")


def test_proposal_validation_is_deterministic_but_does_not_claim_semantic_validity() -> None:
    proposal = _proposal()
    first = validate_policy_translation_proposal(proposal)
    second = validate_policy_translation_proposal(copy.deepcopy(proposal))
    assert first == second
    assert first["semantic_validity"] == "not_established"
    assert first["trust_posture"] == "untrusted_authoring_input"
    _schema_validate(proposal, "policy_translation_proposal.v1.json")


@pytest.mark.parametrize("mutation", ["omitted", "duplicated", "overlap", "reordered"])
def test_clause_partition_rejects_omission_duplication_overlap_and_reordering(mutation: str) -> None:
    proposal = _proposal()
    if mutation == "omitted":
        proposal["clauses"].pop()
    elif mutation == "duplicated":
        proposal["clauses"].append(copy.deepcopy(proposal["clauses"][-1]))
    elif mutation == "overlap":
        proposal["clauses"][1]["start_byte"] -= 1
    else:
        proposal["clauses"].reverse()
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="omits|spans|reordered|downgraded"):
        validate_policy_translation_proposal(proposal)


def test_translation_run_tampering_is_detected_even_if_proposal_is_rehashed() -> None:
    proposal = _proposal()
    proposal["translation_runs"][0]["response_hash"] = bytes_sha256(b"tampered")
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="run identity or hash"):
        validate_policy_translation_proposal(proposal)


def test_ordered_multi_run_omission_reordering_duplication_and_substitution_fail_closed() -> None:
    proposal = _proposal()
    draft = _base(b"Agents may modify README.md. Policy overview.\n")
    second = _run(draft, sequence=1, previous=proposal["translation_runs"][0]["run_hash"], response=b"second", created_at="2026-09-03T12:00:01Z", completed_at="2026-09-03T12:00:02Z")
    third = _run(draft, sequence=2, previous=second["run_hash"], response=b"third", created_at="2026-09-03T12:00:02Z", completed_at="2026-09-03T12:00:03Z")
    proposal["translation_runs"].extend([second, third])
    _restamp_proposal(proposal)
    validate_policy_translation_proposal(proposal)

    omitted = copy.deepcopy(proposal)
    omitted["translation_runs"].pop(1)
    _restamp_proposal(omitted)
    with pytest.raises(ValueError, match="missing, reordered, or duplicated|ordering chain"):
        validate_policy_translation_proposal(omitted)

    reordered = copy.deepcopy(proposal)
    reordered["translation_runs"][1:] = reversed(reordered["translation_runs"][1:])
    _restamp_proposal(reordered)
    with pytest.raises(ValueError, match="missing, reordered, or duplicated|ordering chain"):
        validate_policy_translation_proposal(reordered)

    duplicated = copy.deepcopy(proposal)
    duplicated["translation_runs"][2] = copy.deepcopy(duplicated["translation_runs"][1])
    _restamp_proposal(duplicated)
    with pytest.raises(ValueError, match="missing, reordered, or duplicated|duplicated"):
        validate_policy_translation_proposal(duplicated)

    substituted = copy.deepcopy(proposal)
    substituted["translation_runs"][1] = copy.deepcopy(_proposal()["translation_runs"][0])
    _restamp_proposal(substituted)
    with pytest.raises(ValueError, match="missing, reordered, or duplicated|ordering chain"):
        validate_policy_translation_proposal(substituted)


@pytest.mark.parametrize("field", ["source_policy_ref", "source_revision", "source_snapshot_hash", "capability_catalog"])
def test_run_cross_source_revision_and_catalog_binding(field: str) -> None:
    proposal = _proposal()
    run = proposal["translation_runs"][0]
    if field == "capability_catalog":
        run[field] = {**run[field], "catalog_hash": bytes_sha256(b"other-catalog")}
    elif field.endswith("hash"):
        run[field] = bytes_sha256(b"other-source")
    else:
        run[field] = "other"
    core = {key: value for key, value in run.items() if key not in {"run_id", "run_hash"}}
    run["run_id"] = "translation-run-" + canonical_sha256(core).removeprefix("sha256:")
    run["run_hash"] = canonical_sha256({key: value for key, value in run.items() if key != "run_hash"})
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="substituted across|catalog hash is unavailable"):
        validate_policy_translation_proposal(proposal)


@pytest.mark.parametrize("provider_class", ["hosted_model", "local_model"])
def test_model_runs_require_model_or_deployment_identifier(provider_class: str) -> None:
    draft = _base(b"Agents may modify README.md. Policy overview.\n")
    with pytest.raises(ValueError, match="model/deployment identifier"):
        _run(draft, provider_class=provider_class, provider_identifier=None)


def test_raw_run_evidence_is_optional_private_and_independently_deletable() -> None:
    proposal = _proposal()
    run = proposal["translation_runs"][0]
    raw = create_policy_translation_run_evidence(
        run,
        request_bytes=b'{"source":"policy"}',
        response_bytes=b'{"untrusted":"candidate"}',
    )
    assert validate_policy_translation_run_evidence(run, raw) == raw
    _schema_validate(raw, "policy_translation_run_evidence.v1.json")
    with pytest.raises(ValueError, match="response evidence hash"):
        create_policy_translation_run_evidence(
            run,
            request_bytes=b'{"source":"policy"}',
            response_bytes=b"tampered response",
        )
    del raw
    assert validate_policy_translation_proposal(proposal)["valid"] is True
    result = _final(proposal)
    assert validate_authority_bundle(result["authority_bundle"])["provenance_complete"] is True
    assert "request_bytes_base64" not in json.dumps(proposal)


def test_provider_explanation_can_contradict_but_never_controls_review_meaning() -> None:
    source = b"Agents may modify README.md. Policy overview.\n"
    draft = _base(source)
    explanation = "DENY everything and require five reviewers."
    proposal = _proposal(source)
    proposal["translation_runs"] = [
        _run(draft, explanation_hash=bytes_sha256(explanation.encode()))
    ]
    _restamp_proposal(proposal)
    evidence = create_policy_translation_run_evidence(
        proposal["translation_runs"][0],
        request_bytes=b'{"source":"policy"}',
        response_bytes=b'{"untrusted":"candidate"}',
        provider_explanation=explanation,
    )
    review = render_policy_translation_review(proposal)
    rendered = json.dumps(review)
    assert review["clauses"][0]["controls"][0]["operational_explanation"] == "Automated agents may modify README.md."
    assert "DENY everything" not in rendered
    assert "five reviewers" not in rendered
    assert "provider_explanation" not in json.dumps(proposal)
    del evidence
    assert validate_policy_translation_proposal(proposal)["valid"] is True
    assert review["provider_explanations_used"] is False
    assert review == render_policy_translation_review(copy.deepcopy(proposal))
    result = _final(proposal)
    assert validate_authority_bundle(result["authority_bundle"])["provenance_complete"] is True
    assert "provider_explanation" not in json.dumps(result)
    assert validate_policy_translation_review(proposal, None, review) == review
    _schema_validate(review, "policy_translation_review.v1.json")
    tampered = copy.deepcopy(review)
    tampered["clauses"][0]["controls"][0]["operational_explanation"] = "Provider-written contradiction."
    tampered["review_hash"] = canonical_sha256({key: value for key, value in tampered.items() if key != "review_hash"})
    with pytest.raises(ValueError, match="deterministic rendering"):
        validate_policy_translation_review(proposal, None, tampered)
    inspection = inspect_policy_translation_proposal(proposal)
    assert inspection["view_type"] == "policy_translation_inspection"
    assert "schema_version" not in inspection


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("action", "push", "unknown action"),
        ("fact_id", "proposal.branch", "runtime fact"),
        ("operator", ">", "operator"),
        ("enforcement_point", "provider.runtime", "enforcement point"),
    ],
)
def test_unknown_action_fact_operator_and_enforcement_point_fail_closed(
    field: str, value: str, message: str
) -> None:
    proposal = _proposal()
    control = proposal["clauses"][0]["candidate_controls"][0]
    control[field] = value
    _restamp_control(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match=message):
        validate_policy_translation_proposal(proposal)


def test_type_invalid_value_and_unavailable_runtime_fact_fail_closed() -> None:
    proposal = _proposal()
    control = proposal["clauses"][0]["candidate_controls"][0]
    control["value"]["value"] = 7
    _restamp_control(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="non-empty string"):
        validate_policy_translation_proposal(proposal)


@pytest.mark.parametrize(
    ("source", "partial", "expected"),
    [
        (b"Agents may modify README.md.bak.", "README.md", "larger dotted token"),
        (b"Agents may modify files under predeploy/.", "deploy/", "begins inside a larger token"),
    ],
)
def test_partial_token_source_literal_extraction_is_rejected(source: bytes, partial: str, expected: str) -> None:
    proposal = _proposal(source)
    control = proposal["clauses"][0]["candidate_controls"][0]
    start = source.index(partial.encode("utf-8"))
    end = start + len(partial.encode("utf-8"))
    control["value"] = {
        "kind": "source_literal",
        "value": partial,
        "canonical_value": partial,
        "start_byte": start,
        "end_byte": end,
        "literal_hash": bytes_sha256(source[start:end]),
    }
    _restamp_control(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match=expected):
        validate_policy_translation_proposal(proposal)


def test_role_literal_inside_larger_identifier_is_rejected() -> None:
    source = b"Only xrepository maintainers may make repository changes."
    draft = _base(source)
    statement = draft["source_statements"][0]
    literal = "repository maintainers"
    start = source.index(literal.encode())
    control = {
        "control_type": "acting_role", "actor_kind": "autonomous_agent", "action": "modify",
        "resource_kind": "repository_change", "fact_id": "actor.role", "operator": "==",
        "effect": "require", "enforcement_point": "waveframe.guard.repository-change.v1",
        "value": {"kind": "source_literal", "value": literal, "canonical_value": "repository-maintainer", "start_byte": start, "end_byte": start + len(literal), "literal_hash": bytes_sha256(source[start:start + len(literal)])},
        "required_runtime_facts": ["actor.role", "actor.subject_kind", "proposal.action", "proposal.resource.kind"],
    }
    with pytest.raises(ValueError, match="begins inside a larger token"):
        create_policy_translation_proposal(
            source, source_policy_id="repository-policy", source_revision="revision-1",
            authority_id="repository-authority", authority_version="1.0.0",
            clauses=[{"start_byte": statement["start_byte"], "end_byte": statement["end_byte"], "coverage_status": "fully_represented", "candidate_controls": [control], "unresolved_binding_ids": [], "limitation_code": None, "residual_unsupported_spans": []}],
            organizational_bindings=[], translation_runs=[_run(draft)],
        )


@pytest.mark.parametrize("delimiter", ["`", '"'])
def test_quoted_and_backtick_delimited_paths_preserve_exact_literal_spans(delimiter: str) -> None:
    source = f"Agents may modify {delimiter}README.md{delimiter}.".encode()
    proposal = _proposal(source)
    value = proposal["clauses"][0]["candidate_controls"][0]["value"]
    assert source[value["start_byte"]:value["end_byte"]] == f"{delimiter}README.md{delimiter}".encode()
    assert value["canonical_value"] == f"{delimiter}README.md{delimiter}"
    validate_policy_translation_proposal(proposal)


def test_direct_role_surface_literal_is_deterministically_canonicalized() -> None:
    source = b"Repository changes may be made only by repository maintainers."
    draft = _base(source)
    statement = draft["source_statements"][0]
    literal = "repository maintainers"
    start = source.index(literal.encode())
    control = {
        "control_type": "acting_role", "actor_kind": "autonomous_agent", "action": "modify",
        "resource_kind": "repository_change", "fact_id": "actor.role", "operator": "==",
        "effect": "require", "enforcement_point": "waveframe.guard.repository-change.v1",
        "value": {"kind": "source_literal", "value": literal, "canonical_value": "repository-maintainer", "start_byte": start, "end_byte": start + len(literal), "literal_hash": bytes_sha256(source[start:start + len(literal)])},
        "required_runtime_facts": ["actor.role", "actor.subject_kind", "proposal.action", "proposal.resource.kind"],
    }
    proposal = create_policy_translation_proposal(
        source, source_policy_id="repository-policy", source_revision="revision-1",
        authority_id="repository-authority", authority_version="1.0.0",
        clauses=[{"start_byte": statement["start_byte"], "end_byte": statement["end_byte"], "coverage_status": "fully_represented", "candidate_controls": [control], "unresolved_binding_ids": [], "limitation_code": None, "residual_unsupported_spans": []}],
        organizational_bindings=[], translation_runs=[_run(draft)],
    )
    assert validate_policy_translation_proposal(proposal)["valid"] is True
    assert "repository-maintainer" in render_policy_translation_review(proposal)["clauses"][0]["controls"][0]["operational_explanation"]


@pytest.mark.parametrize("mutation", ["operator", "fact", "control"])
def test_catalog_rejects_unreachable_or_inconsistent_advertising(mutation: str) -> None:
    catalog = get_policy_translation_capability_catalog()
    if mutation == "operator":
        catalog["operators"].append("!=")
    elif mutation == "fact":
        extra = copy.deepcopy(catalog["facts"][0])
        extra["fact_id"] = "actor.principal_id"
        catalog["facts"].append(extra)
    else:
        catalog["control_types"][0]["action"] = "push"
    catalog["catalog_hash"] = canonical_sha256({key: value for key, value in catalog.items() if key != "catalog_hash"})
    with pytest.raises(ValueError, match="inconsistent|unreachable|released lowerings"):
        validate_policy_translation_capability_catalog(catalog)

    proposal = _proposal()
    control = proposal["clauses"][0]["candidate_controls"][0]
    control["required_runtime_facts"] = [*FACTS, "proposal.branch"]
    _restamp_control(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="runtime facts"):
        validate_policy_translation_proposal(proposal)


def test_guessed_path_and_provider_resolved_organization_binding_are_rejected() -> None:
    proposal = _proposal()
    control = proposal["clauses"][0]["candidate_controls"][0]
    control["value"]["value"] = "secret/guessed.txt"
    _restamp_control(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="guessed"):
        validate_policy_translation_proposal(proposal)

    proposal = _binding_proposal()
    proposal["organizational_bindings"][0]["status"] = "resolved"
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="cannot present.*resolved"):
        validate_policy_translation_proposal(proposal)


def _binding_proposal() -> dict:
    source = b"Only the designated repository custodians may make repository changes."
    statement = _base(source)["source_statements"][0]
    binding_id = "repository-custodian-role"
    control = {
        "control_type": "acting_role",
        "actor_kind": "autonomous_agent",
        "action": "modify",
        "resource_kind": "repository_change",
        "fact_id": "actor.role",
        "operator": "==",
        "effect": "require",
        "enforcement_point": "waveframe.guard.repository-change.v1",
        "value": {"kind": "organizational_binding", "binding_id": binding_id},
        "required_runtime_facts": [
            "actor.role",
            "actor.subject_kind",
            "proposal.action",
            "proposal.resource.kind",
        ],
    }
    return create_policy_translation_proposal(
        source,
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
        clauses=[
            {
                "start_byte": statement["start_byte"],
                "end_byte": statement["end_byte"],
                "coverage_status": "fully_represented",
                "candidate_controls": [control],
                "unresolved_binding_ids": [binding_id],
                "limitation_code": None,
                "residual_unsupported_spans": [],
            }
        ],
        organizational_bindings=[
            {
                "binding_id": binding_id,
                "binding_type": "repository_role",
                "symbol": "designated repository custodians",
                "question": "Which released repository role represents the custodians?",
                "status": "unresolved",
            }
        ],
        translation_runs=[
            _run(
                _base(source),
                provider_class="guided_deterministic",
                provider_identifier=None,
                response=b"guided candidate",
            )
        ],
    )


def test_bounded_binding_resolution_and_review_then_v2_publication() -> None:
    proposal = _binding_proposal()
    inspection = inspect_policy_translation_proposal(proposal)
    assert inspection["publication_ready"] is False
    assert inspection["unresolved_bindings"][0]["binding_id"] == "repository-custodian-role"
    assert inspection["unresolved_bindings"][0]["question"] == (
        "Which repository role should this policy require?"
    )
    unconfirmed_review = render_policy_translation_review(proposal)
    assert unconfirmed_review["clauses"][0]["controls"][0]["questions"] == [
        "Which repository role should this policy require?"
    ]
    assert "released" not in json.dumps(unconfirmed_review).lower()
    with pytest.raises(ValueError, match="outside the released role"):
        apply_policy_translation_binding(
            proposal,
            None,
            binding_id="repository-custodian-role",
            value="invented-team",
            confirmed_by="owner",
            confirmed_at=NOW,
        )
    state = apply_policy_translation_binding(
        proposal,
        None,
        binding_id="repository-custodian-role",
        value="repository-maintainer",
        confirmed_by="owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
    assert "repository-maintainer" in render_policy_translation_review(proposal, state)[
        "clauses"
    ][0]["controls"][0]["operational_explanation"]
    state = apply_policy_translation_control_confirmation(
        proposal,
        state,
        clause_id=proposal["clauses"][0]["clause_id"],
        candidate_control_id=proposal["clauses"][0]["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
    state = apply_policy_translation_disposition(
        proposal,
        state,
        clause_id=proposal["clauses"][0]["clause_id"],
        coverage_status="fully_represented",
        reason_code="human-confirmed-complete",
        confirmed_by="owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
    approval = _approved(proposal, state)
    _schema_validate(state, "policy_translation_confirmation.v1.json")
    _schema_validate(approval, "policy_translation_approval.v1.json")
    result = finalize_policy_translation_authority(
        proposal,
        state,
        approval,
        committed_by="committer",
        committed_at="2026-09-03T12:04:00Z",
        publication_id="publication-1",
        published_by="publisher",
        published_at="2026-09-03T12:05:00Z",
    )
    assert result["compiled_authority_contract"]["authority_requirements"] == {
        "required_roles": ["repository-maintainer"]
    }
    assert result["proposal_evidence_required_by_guard"] is False


def test_partial_coverage_requires_every_exact_unenforced_acknowledgement() -> None:
    proposal = _proposal()
    first = apply_policy_translation_control_confirmation(
        proposal,
        None,
        clause_id=proposal["clauses"][0]["clause_id"],
        candidate_control_id=proposal["clauses"][0]["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
    first = apply_policy_translation_disposition(
        proposal, first, clause_id=proposal["clauses"][0]["clause_id"],
        coverage_status="fully_represented", reason_code="human-confirmed-complete",
        confirmed_by="owner", confirmed_at="2026-09-03T12:01:00Z",
    )
    with pytest.raises(ValueError, match="inconsistent"):
        apply_policy_translation_disposition(
            proposal,
            first,
            clause_id=proposal["clauses"][1]["clause_id"],
            coverage_status="informational",
            reason_code="context-only",
            acknowledge_unrepresented=True,
            confirmed_by="owner",
            confirmed_at=NOW,
        )
    with pytest.raises(ValueError, match="every source clause"):
        approve_policy_translation_proposal(
            proposal, first, approved_by="owner", approved_at=NOW
        )


def test_unsupported_clause_cannot_silently_become_enforced() -> None:
    proposal = _proposal()
    clause = proposal["clauses"][1]
    # A clause's human decision is bounded to the proposal's exact coverage class.
    _restamp_proposal(proposal)
    validate_policy_translation_proposal(proposal)
    with pytest.raises(ValueError, match="explicitly confirm the reviewed proposal coverage"):
        apply_policy_translation_disposition(
            proposal,
            None,
            clause_id=clause["clause_id"],
            coverage_status="fully_represented",
            reason_code="human-confirmed-complete",
            confirmed_by="owner",
            confirmed_at="2026-09-03T12:01:00Z",
        )


def test_cross_source_and_cross_authority_substitution_fail_closed() -> None:
    proposal = _proposal()
    confirmation = _confirmed(proposal)
    source_substitution = copy.deepcopy(proposal)
    source_substitution["source_policy"]["source_policy_id"] = "other-policy"
    source_substitution["source_policy"]["source_policy_ref"] = "other-policy@revision-1"
    _restamp_proposal(source_substitution)
    with pytest.raises(ValueError, match="substituted across source|clause identity"):
        validate_policy_translation_proposal(source_substitution)

    authority_substitution = copy.deepcopy(proposal)
    authority_substitution["authority"]["authority_id"] = "other-authority"
    authority_substitution["authority"]["authority_ref"] = "other-authority@1.0.0"
    _restamp_proposal(authority_substitution)
    validate_policy_translation_proposal(authority_substitution)
    with pytest.raises(ValueError, match="substituted across"):
        approve_policy_translation_proposal(
            authority_substitution,
            confirmation,
            approved_by="owner",
            approved_at=NOW,
        )


def test_changed_human_confirmation_or_late_confirmation_invalidates_approval() -> None:
    proposal = _proposal()
    confirmation = _confirmed(proposal)
    approval = _approved(proposal, confirmation)
    tampered = copy.deepcopy(confirmation)
    tampered["clause_coverage_decisions"][0]["confirmed_by"] = "different-owner"
    tampered["clause_coverage_decisions"][0]["decision_hash"] = canonical_sha256(
        {
            key: value
            for key, value in tampered["clause_coverage_decisions"][0].items()
            if key != "decision_hash"
        }
    )
    tampered["confirmation_hash"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "confirmation_hash"}
    )
    with pytest.raises(ValueError, match="approval binding is invalid"):
        finalize_policy_translation_authority(
            proposal,
            tampered,
            approval,
            committed_by="committer",
            committed_at="2026-09-03T12:04:00Z",
            publication_id="publication-1",
            published_by="publisher",
            published_at="2026-09-03T12:05:00Z",
        )

    with pytest.raises(ValueError, match="must complete no later|confirmation must precede"):
        approve_policy_translation_proposal(
            proposal,
            confirmation,
            approved_by="owner",
            approved_at="2026-09-03T11:59:00Z",
        )


def test_direct_clause_downgrade_fails_before_approval_even_with_another_enforced_clause() -> None:
    proposal = _proposal(b"Agents may modify README.md. Agents may modify CHANGELOG.md.")
    first = proposal["clauses"][0]
    first["coverage_status"] = "entirely_unsupported"
    _restamp_proposal(proposal)
    # Approval validates the proposal first, so a second truthful enforceable clause
    # cannot conceal the downgrade of deterministic meaning.
    with pytest.raises(ValueError, match="deterministically recognized source clause cannot be downgraded"):
        approve_policy_translation_proposal(
            proposal,
            {"not": "trusted"},
            approved_by="owner",
            approved_at=NOW,
        )


def test_one_clause_can_bind_two_exact_controls_and_requires_two_confirmations() -> None:
    source = b"Agents may modify README.md and CHANGELOG.md."
    proposal = _proposal(source)
    clause = proposal["clauses"][0]
    assert [item["value"]["canonical_value"] for item in clause["candidate_controls"]] == [
        "README.md",
        "CHANGELOG.md",
    ]
    assert render_policy_translation_review(proposal)["clauses"][0]["source_text"] == source.decode()
    state = apply_policy_translation_control_confirmation(
        proposal, None, clause_id=clause["clause_id"],
        candidate_control_id=clause["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="owner", confirmed_at="2026-09-03T12:01:00Z",
    )
    with pytest.raises(ValueError, match="every candidate control"):
        apply_policy_translation_disposition(
            proposal, state, clause_id=clause["clause_id"],
            coverage_status="fully_represented", reason_code="human-confirmed-complete",
            confirmed_by="owner", confirmed_at="2026-09-03T12:02:00Z",
        )
    state = apply_policy_translation_control_confirmation(
        proposal, state, clause_id=clause["clause_id"],
        candidate_control_id=clause["candidate_controls"][1]["candidate_control_id"],
        confirmed_by="owner", confirmed_at="2026-09-03T12:01:30Z",
    )
    state = apply_policy_translation_disposition(
        proposal, state, clause_id=clause["clause_id"],
        coverage_status="fully_represented", reason_code="human-confirmed-complete",
        confirmed_by="owner", confirmed_at="2026-09-03T12:02:00Z",
    )
    assert state["coverage"]["confirmed_control_count"] == 2
    result = finalize_policy_translation_authority(
        proposal, state, _approved(proposal, state), committed_by="committer",
        committed_at="2026-09-03T12:04:00Z", publication_id="publication-1",
        published_by="publisher", published_at="2026-09-03T12:05:00Z",
    )
    assert result["compiled_authority_contract"]["target_requirements"]["allow"] == [
        {"match": "exact", "value": "README.md"},
        {"match": "exact", "value": "CHANGELOG.md"},
    ]


def test_direct_multi_meaning_clause_cannot_claim_full_coverage_with_one_control() -> None:
    proposal = _proposal(b"Agents may modify README.md and CHANGELOG.md.")
    proposal["clauses"][0]["candidate_controls"].pop()
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="completely match deterministic executable semantics"):
        validate_policy_translation_proposal(proposal)


@pytest.mark.parametrize("mutation", ["duplicate", "contradictory"])
def test_duplicate_and_contradictory_controls_are_rejected(mutation: str) -> None:
    proposal = _proposal()
    control = copy.deepcopy(proposal["clauses"][0]["candidate_controls"][0])
    if mutation == "contradictory":
        control["effect"] = "deny"
        _restamp_control(control)
    proposal["clauses"][0]["candidate_controls"].append(control)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="duplicate|contradictory"):
        validate_policy_translation_proposal(proposal)


def test_partial_compound_clause_preserves_residual_meaning_and_acknowledgement() -> None:
    source = b"Agents may modify documentation but must not modify files under crypto/."
    draft = _base(source)
    statement = draft["source_statements"][0]
    control = _path_control(
        "crypto/", source=source, clause_start=statement["start_byte"],
        clause_end=statement["end_byte"], effect="deny", prefix=True,
    )
    residual_start = source.index(b"documentation")
    proposal = create_policy_translation_proposal(
        source, source_policy_id="repository-policy", source_revision="revision-1",
        authority_id="repository-authority", authority_version="1.0.0",
        clauses=[{
            "start_byte": statement["start_byte"], "end_byte": statement["end_byte"],
            "coverage_status": "partially_represented", "candidate_controls": [control],
            "unresolved_binding_ids": [], "limitation_code": "other",
            "residual_unsupported_spans": [{
                "start_byte": residual_start,
                "end_byte": residual_start + len(b"documentation"),
            }],
        }], organizational_bindings=[], translation_runs=[_run(draft)],
    )
    review = render_policy_translation_review(proposal)
    assert review["clauses"][0]["source_text"] == source.decode()
    assert review["clauses"][0]["controls"][0]["operational_explanation"] == (
        "Automated agents are blocked from modifying files under crypto/."
    )
    assert "cannot enforce" in review["clauses"][0]["residual_explanation"]
    state = apply_policy_translation_control_confirmation(
        proposal, None, clause_id=proposal["clauses"][0]["clause_id"],
        candidate_control_id=proposal["clauses"][0]["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="owner", confirmed_at="2026-09-03T12:01:00Z",
    )
    with pytest.raises(ValueError, match="residual-meaning acknowledgement"):
        apply_policy_translation_disposition(
            proposal, state, clause_id=proposal["clauses"][0]["clause_id"],
            coverage_status="partially_represented", reason_code="human-confirmed-partial",
            confirmed_by="owner", confirmed_at="2026-09-03T12:02:00Z",
        )
    state = apply_policy_translation_disposition(
        proposal, state, clause_id=proposal["clauses"][0]["clause_id"],
        coverage_status="partially_represented", reason_code="human-confirmed-partial",
        acknowledge_unrepresented=True, confirmed_by="owner",
        confirmed_at="2026-09-03T12:02:00Z",
    )
    assert state["coverage"]["partially_represented_clause_count"] == 1
    assert state["coverage"]["enforced_clause_count"] == 1
    assert state["coverage"]["unenforced_clause_count"] == 1
    assert state["coverage"]["acknowledged_unrepresented_clause_ids"] == [
        proposal["clauses"][0]["clause_id"]
    ]
    approval = _approved(proposal, state)
    with pytest.raises(ValueError, match="cannot represent enforced and residual unsupported meaning"):
        finalize_policy_translation_authority(
            proposal, state, approval, committed_by="committer",
            committed_at="2026-09-03T12:04:00Z", publication_id="publication-1",
            published_by="publisher", published_at="2026-09-03T12:05:00Z",
        )


def test_catalog_resolution_is_registered_immutable_and_schema_is_extensible() -> None:
    catalog = get_policy_translation_capability_catalog()
    ref = {key: catalog[key] for key in ("catalog_id", "catalog_version", "catalog_hash")}
    assert resolve_policy_translation_capability_catalog(ref) == catalog
    assert "capability_catalog" not in inspect.signature(
        create_policy_translation_run
    ).parameters
    with pytest.raises(ValueError, match="not registered"):
        resolve_policy_translation_capability_catalog({**ref, "catalog_id": "customer.injected"})
    with pytest.raises(ValueError, match="unsupported fields"):
        resolve_policy_translation_capability_catalog({**ref, "control_types": []})

    proposal = _proposal()
    control = proposal["clauses"][0]["candidate_controls"][0]
    control["action"] = "future_action"
    _restamp_control(control)
    _restamp_proposal(proposal)
    _schema_validate(proposal, "policy_translation_proposal.v1.json")
    with pytest.raises(ValueError, match="unknown action"):
        validate_policy_translation_proposal(proposal)


def test_run_chronology_rejects_reversed_overlapping_future_and_post_approval_runs() -> None:
    draft = _base(b"Agents may modify README.md. Policy overview.\n")
    with pytest.raises(ValueError, match="completion precedes creation"):
        _run(draft, created_at="2026-09-03T12:00:02Z", completed_at="2026-09-03T12:00:01Z")

    proposal = _proposal()
    overlapping = _run(
        draft, sequence=1, previous=proposal["translation_runs"][0]["run_hash"],
        created_at="2026-09-03T12:00:00Z", completed_at="2026-09-03T12:00:02Z",
    )
    proposal["translation_runs"].append(overlapping)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="cannot begin before"):
        validate_policy_translation_proposal(proposal)

    proposal = _proposal()
    confirmation = _confirmed(proposal)
    with pytest.raises(ValueError, match="complete no later"):
        approve_policy_translation_proposal(
            proposal, confirmation, approved_by="owner",
            approved_at="2026-09-03T12:00:00Z",
        )
    approval = _approved(proposal, confirmation)
    later = _run(
        draft, sequence=1, previous=proposal["translation_runs"][0]["run_hash"],
        created_at="2026-09-03T12:04:00Z", completed_at="2026-09-03T12:05:00Z",
    )
    proposal["translation_runs"].append(later)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="substituted across proposal|approval binding"):
        finalize_policy_translation_authority(
            proposal, confirmation, approval, committed_by="committer",
            committed_at="2026-09-03T12:06:00Z", publication_id="publication-1",
            published_by="publisher", published_at="2026-09-03T12:07:00Z",
        )


def test_customer_review_explanations_exclude_implementation_identifiers() -> None:
    rendered = render_policy_translation_review(_proposal())
    explanations = " ".join(
        control["operational_explanation"]
        for clause in rendered["clauses"]
        for control in clause["controls"]
    )
    for forbidden in ("capability catalog", "policy_translation", "sha256:", "waveframe.guard", "emitter"):
        assert forbidden not in explanations.lower()


def test_one_byte_source_mutation_changes_every_downstream_normative_identity() -> None:
    first_proposal = _proposal(b"Agents may modify README.md. Policy overview.\n")
    second_proposal = _proposal(b"Agents may modify READNE.md. Policy overview.\n")
    first_confirmation = _confirmed(first_proposal)
    second_confirmation = _confirmed(second_proposal)
    first_approval = _approved(first_proposal, first_confirmation)
    second_approval = _approved(second_proposal, second_confirmation)
    first = finalize_policy_translation_authority(first_proposal, first_confirmation, first_approval, committed_by="ledger-committer", committed_at="2026-09-03T12:04:00Z", publication_id="publication-1", published_by="ledger-publisher", published_at="2026-09-03T12:05:00Z")
    second = finalize_policy_translation_authority(second_proposal, second_confirmation, second_approval, committed_by="ledger-committer", committed_at="2026-09-03T12:04:00Z", publication_id="publication-1", published_by="ledger-publisher", published_at="2026-09-03T12:05:00Z")
    assert first_proposal["source_policy"]["snapshot_hash"] != second_proposal["source_policy"]["snapshot_hash"]
    assert first_proposal["translation_runs"][0]["run_hash"] != second_proposal["translation_runs"][0]["run_hash"]
    assert first_proposal["proposal_hash"] != second_proposal["proposal_hash"]
    assert first_confirmation["confirmation_hash"] != second_confirmation["confirmation_hash"]
    assert first_approval["approval_hash"] != second_approval["approval_hash"]
    for field in (
        "source_snapshot_hash",
        "interpretation_hash",
        "constraint_ir_hash",
        "semantic_commit_hash",
        "compiled_contract_hash",
        "authority_bundle_hash",
        "publication_receipt_hash",
    ):
        assert first["canonical_hashes"][field] != second["canonical_hashes"][field]


def test_v2_publication_independently_validates_without_proposal_evidence() -> None:
    result = _final(_proposal())
    bundle = result["authority_bundle"]
    receipt = result["publication_receipt"]
    assert "translation_runs" not in json.dumps(bundle)
    assert "request_bytes_base64" not in json.dumps(bundle)
    assert "policy_translation_proposal" not in json.dumps(bundle)
    assert validate_authority_bundle(bundle)["provenance_complete"] is True
    assert validate_publication_receipt(bundle, receipt)["provenance_complete"] is True
    assert result["policy_translation_coverage"]["enforced_clause_count"] == 1
    assert result["policy_translation_coverage"]["unenforced_clause_count"] == 1


def test_translation_boundary_is_network_filesystem_guard_and_credentials_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    guard_before = sys.modules.get("waveframe_guard")
    monkeypatch.chdir(tmp_path)
    proposal = _proposal()
    assert validate_policy_translation_proposal(proposal)["valid"] is True
    assert list(tmp_path.iterdir()) == []
    assert sys.modules.get("waveframe_guard") is guard_before


def test_proposal_cannot_masquerade_as_released_runtime_schema() -> None:
    proposal = _proposal()
    for filename, version in (
        ("authority_bundle.v1.json", "authority_bundle.v1"),
        ("authority_bundle.v2.json", "authority_bundle.v2"),
        ("publication_receipt.v1.json", "publication_receipt.v1"),
        ("publication_receipt.v2.json", "publication_receipt.v2"),
    ):
        masquerading = copy.deepcopy(proposal)
        masquerading["schema_version"] = version
        with pytest.raises(jsonschema.ValidationError):
            _schema_validate(masquerading, filename)


def test_guard_0170_cold_verification_binds_v2_publication_to_exact_source(
    tmp_path: Path,
) -> None:
    pytest.importorskip("waveframe_guard")
    from importlib.metadata import version

    from waveframe_guard.authority import load_authority
    from waveframe_guard.authority.adapters import LocalRegistryResolver

    assert version("waveframe-guard") == "0.19.0"
    result = _final(_proposal())
    bundle = result["authority_bundle"]
    receipt = result["publication_receipt"]
    contract = result["compiled_authority_contract"]
    bundle_ref = "contracts/repository-authority-1.0.0.authority-bundle.json"
    receipt_ref = "contracts/repository-authority-1.0.0.publication-receipt.json"
    (tmp_path / "contracts").mkdir()
    (tmp_path / bundle_ref).write_text(json.dumps(bundle), encoding="utf-8")
    (tmp_path / receipt_ref).write_text(json.dumps(receipt), encoding="utf-8")
    registry = {
        "schema_version": "contract_registry.v1",
        "contracts": [
            {
                "contract_id": "repository-authority",
                "contract_version": "1.0.0",
                "authority_ref": "repository-authority@1.0.0",
                "contract_hash": contract["contract_hash"],
                "bundle_path": bundle_ref,
                "bundle_hash": bundle["bundle_hash"],
                "receipt_path": receipt_ref,
                "receipt_hash": receipt["receipt_hash"],
                "publication_id": receipt["publication_id"],
                "published_at": receipt["published_at"],
                "published_by": receipt["published_by"],
                "lifecycle_state": "active",
            }
        ],
    }
    registry["registry_hash"] = canonical_sha256(registry)
    registry_path = tmp_path / "contracts" / "index.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    authority = load_authority(
        "repository-authority@1.0.0",
        resolver=LocalRegistryResolver(registry_path, workspace_root=tmp_path),
    )
    evidence = authority.authority_evidence
    assert evidence is not None
    assert authority.contract["lineage"]["source_hash"] == bundle["source_policy"][
        "snapshot_hash"
    ]
    assert evidence["authority_bundle"]["bundle_hash"] == bundle["bundle_hash"]
    assert evidence["publication_receipt"]["receipt_hash"] == receipt["receipt_hash"]
    assert authority.runtime_integrity_hash
    assert "translation_runs" not in json.dumps(evidence)
    assert "request_bytes_base64" not in json.dumps(evidence)
