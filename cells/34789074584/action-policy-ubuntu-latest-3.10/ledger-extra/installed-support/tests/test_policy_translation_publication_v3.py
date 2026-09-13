from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from governance_ledger import (
    apply_policy_translation_binding,
    apply_policy_translation_control_confirmation,
    apply_policy_translation_disposition,
    create_policy_translation_proposal,
    create_policy_translation_run_evidence,
    finalize_policy_translation_authority_v3,
    inspect_policy_translation_customer_coverage,
    validate_authority_bundle,
    validate_authority_bundle_v3,
    validate_policy_translation_commitment,
    validate_policy_translation_proposal,
    validate_publication_receipt,
)
from governance_ledger.constraint_ir import artifact_hash
from governance_ledger.publication_provenance import canonical_sha256
from tests.test_policy_translation import (
    _approved,
    _base,
    _confirmed,
    _path_control,
    _proposal,
    _restamp_control,
    _restamp_proposal,
    _run,
)


ROOT = Path(__file__).parents[1]


def _publish(proposal: dict, confirmation: dict | None = None) -> dict:
    state = confirmation or _confirmed(proposal)
    approval = _approved(proposal, state)
    return finalize_policy_translation_authority_v3(
        proposal,
        state,
        approval,
        committed_by="ledger-committer",
        committed_at="2026-09-03T12:04:00Z",
        publication_id="publication-1",
        published_by="ledger-publisher",
        published_at="2026-09-03T12:05:00Z",
    )


def _schema_validate(value: dict, filename: str) -> None:
    registry = Registry()
    for path in (ROOT / "schemas").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, registry=registry).validate(value)


def _restamp_commitment_and_bundle(bundle: dict) -> None:
    commitment = bundle["policy_translation_commitment"]
    payload = {
        key: value
        for key, value in commitment.items()
        if key not in {"commitment_id", "commitment_hash"}
    }
    commitment["commitment_hash"] = canonical_sha256(payload)
    commitment["commitment_id"] = "policy-translation-commitment-" + commitment[
        "commitment_hash"
    ].removeprefix("sha256:")
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")


def _partial_proposal() -> dict:
    source = b"Agents may modify documentation but must not modify cryptographic modules."
    draft = _base(source)
    statement = draft["source_statements"][0]
    control = _path_control(
        "crypto/",
        source=source,
        clause_start=statement["start_byte"],
        clause_end=statement["end_byte"],
        effect="deny",
        prefix=True,
    )
    control["value"] = {
        "kind": "organizational_binding",
        "binding_id": "cryptographic-modules-path",
    }
    residual_start = source.index(b"documentation")
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
                "coverage_status": "partially_represented",
                "candidate_controls": [control],
                "unresolved_binding_ids": ["cryptographic-modules-path"],
                "limitation_code": "other",
                "residual_unsupported_spans": [
                    {
                        "start_byte": residual_start,
                        "end_byte": residual_start + len(b"documentation"),
                    }
                ],
            }
        ],
        organizational_bindings=[
            {
                "binding_id": "cryptographic-modules-path",
                "binding_type": "repository_path_prefix",
                "symbol": "cryptographic modules",
                "question": "Which repository path contains cryptographic modules?",
                "status": "unresolved",
            }
        ],
        translation_runs=[_run(draft)],
    )


def _confirm_partial(proposal: dict, *, acknowledge: bool = True) -> dict:
    clause = proposal["clauses"][0]
    state = apply_policy_translation_binding(
        proposal,
        None,
        binding_id="cryptographic-modules-path",
        value="crypto/",
        confirmed_by="policy-owner",
        confirmed_at="2026-09-03T12:00:30Z",
    )
    state = apply_policy_translation_control_confirmation(
        proposal,
        state,
        clause_id=clause["clause_id"],
        candidate_control_id=clause["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="policy-owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
    return apply_policy_translation_disposition(
        proposal,
        state,
        clause_id=clause["clause_id"],
        coverage_status="partially_represented",
        reason_code="human-confirmed-partial",
        acknowledge_unrepresented=acknowledge,
        confirmed_by="policy-owner",
        confirmed_at="2026-09-03T12:02:00Z",
    )


def _direct_unsupported_informational_proposal() -> dict:
    source = b"Agents may modify README.md. Pull requests need approvals. Policy overview."
    draft = _base(source)
    statements = draft["source_statements"]
    direct = statements[0]
    direct_control = _path_control(
        "README.md",
        source=source,
        clause_start=direct["start_byte"],
        clause_end=direct["end_byte"],
    )
    unsupported = statements[1]
    return create_policy_translation_proposal(
        source,
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
        clauses=[
            {
                "start_byte": direct["start_byte"], "end_byte": direct["end_byte"],
                "coverage_status": "fully_represented", "candidate_controls": [direct_control],
                "unresolved_binding_ids": [], "limitation_code": None,
                "residual_unsupported_spans": [],
            },
            {
                "start_byte": unsupported["start_byte"], "end_byte": unsupported["end_byte"],
                "coverage_status": "entirely_unsupported", "candidate_controls": [],
                "unresolved_binding_ids": [], "limitation_code": "pull_request_approval_not_supported",
                "residual_unsupported_spans": [{"start_byte": unsupported["start_byte"], "end_byte": unsupported["end_byte"]}],
            },
            {
                "start_byte": statements[2]["start_byte"], "end_byte": statements[2]["end_byte"],
                "coverage_status": "informational", "candidate_controls": [],
                "unresolved_binding_ids": [], "limitation_code": None,
                "residual_unsupported_spans": [],
            },
        ],
        organizational_bindings=[],
        translation_runs=[_run(draft)],
    )


def test_v3_publishes_two_individually_confirmed_controls_from_one_exact_clause() -> None:
    source = b"Agents may modify README.md and CHANGELOG.md."
    result = _publish(_proposal(source))
    commitment = result["policy_translation_commitment"]

    assert commitment["clauses"][0]["clause_bytes_base64"] == "QWdlbnRzIG1heSBtb2RpZnkgUkVBRE1FLm1kIGFuZCBDSEFOR0VMT0cubWQu"
    assert [item["resolved_value"] for item in commitment["clauses"][0]["controls"]] == [
        "README.md",
        "CHANGELOG.md",
    ]
    assert len({item["human_confirmation"]["confirmation_hash"] for item in commitment["clauses"][0]["controls"]}) == 2
    assert commitment["coverage"] == {
        "total_clause_count": 1, "full_clause_count": 1, "partial_clause_count": 0,
        "waiting_clause_count": 0, "needs_answer_clause_count": 0,
        "needs_connection_clause_count": 0, "unenforced_clause_count": 0,
        "informational_clause_count": 0, "confirmed_control_count": 2,
        "acknowledged_residual_count": 0,
    }
    assert result["compiled_authority_contract"]["schema_version"] == "compiled_authority_contract.v2"


def test_v3_publishes_supported_control_and_acknowledged_residual_as_partial() -> None:
    proposal = _partial_proposal()
    result = _publish(proposal, _confirm_partial(proposal))
    clause = result["policy_translation_commitment"]["clauses"][0]

    assert clause["customer_coverage_state"] == "Partially enforceable"
    assert clause["controls"][0]["customer_explanation"] == (
        "Automated agents are blocked from modifying files under crypto/."
    )
    assert clause["customer_explanation"] == (
        "Waveframe cannot enforce the explicitly identified remaining part of this clause yet."
    )
    assert clause["residuals"][0]["acknowledgment"]["acknowledged_by"] == "policy-owner"
    assert result["policy_translation_commitment"]["coverage"]["partial_clause_count"] == 1
    assert result["policy_translation_commitment"]["coverage"]["acknowledged_residual_count"] == 1


def test_v3_publishes_entirely_unsupported_and_informational_clauses_truthfully() -> None:
    proposal = _direct_unsupported_informational_proposal()
    state = None
    for index, clause in enumerate(proposal["clauses"]):
        if clause["candidate_controls"]:
            state = apply_policy_translation_control_confirmation(
                proposal, state, clause_id=clause["clause_id"],
                candidate_control_id=clause["candidate_controls"][0]["candidate_control_id"],
                confirmed_by="owner", confirmed_at="2026-09-03T12:01:00Z",
            )
        status = clause["coverage_status"]
        state = apply_policy_translation_disposition(
            proposal, state, clause_id=clause["clause_id"], coverage_status=status,
            reason_code={"fully_represented": "human-confirmed-complete", "entirely_unsupported": "not-enforceable", "informational": "context-only"}[status],
            acknowledge_unrepresented=status == "entirely_unsupported",
            confirmed_by="owner", confirmed_at=f"2026-09-03T12:02:0{index}Z",
        )
    assert state is not None
    commitment = _publish(proposal, state)["policy_translation_commitment"]
    assert [item["customer_coverage_state"] for item in commitment["clauses"]] == [
        "Ready to enforce", "Not currently enforceable", "Informational",
    ]
    assert commitment["clauses"][1]["customer_explanation"] == (
        "Waveframe cannot enforce this part yet because pull-request approvals are not currently supported."
    )
    assert commitment["clauses"][2]["customer_explanation"] == (
        "This clause is informational and does not create an enforcement rule."
    )
    assert commitment["coverage"]["unenforced_clause_count"] == 1
    assert commitment["coverage"]["informational_clause_count"] == 1


def test_missing_residual_acknowledgment_and_control_confirmation_fail_before_publication() -> None:
    partial = _partial_proposal()
    with pytest.raises(ValueError, match="residual-meaning acknowledgement"):
        _confirm_partial(partial, acknowledge=False)

    multi = _proposal(b"Agents may modify README.md and CHANGELOG.md.")
    clause = multi["clauses"][0]
    state = apply_policy_translation_control_confirmation(
        multi, None, clause_id=clause["clause_id"],
        candidate_control_id=clause["candidate_controls"][0]["candidate_control_id"],
        confirmed_by="owner", confirmed_at="2026-09-03T12:01:00Z",
    )
    with pytest.raises(ValueError, match="every candidate control"):
        apply_policy_translation_disposition(
            multi, state, clause_id=clause["clause_id"],
            coverage_status="fully_represented", reason_code="human-confirmed-complete",
            confirmed_by="owner", confirmed_at="2026-09-03T12:02:00Z",
        )


@pytest.mark.parametrize("contradictory", [False, True])
def test_duplicate_and_contradictory_controls_never_reach_v3_publication(contradictory: bool) -> None:
    proposal = _proposal()
    duplicate = copy.deepcopy(proposal["clauses"][0]["candidate_controls"][0])
    if contradictory:
        duplicate["effect"] = "deny"
        _restamp_control(duplicate)
    proposal["clauses"][0]["candidate_controls"].append(duplicate)
    _restamp_proposal(proposal)
    with pytest.raises(ValueError, match="duplicate|contradictory"):
        validate_policy_translation_proposal(proposal)


def test_v3_rejects_invalid_publication_chronology() -> None:
    proposal = _proposal()
    state = _confirmed(proposal)
    approval = _approved(proposal, state)
    with pytest.raises(ValueError, match="approved_at must be no later"):
        finalize_policy_translation_authority_v3(
            proposal, state, approval, committed_by="committer",
            committed_at="2026-09-03T12:02:59Z", publication_id="publication-1",
            published_by="publisher", published_at="2026-09-03T12:05:00Z",
        )


@pytest.mark.parametrize("mutation", ["span", "catalog", "coverage", "binding", "hash"])
def test_v3_independent_validation_fails_closed_on_public_provenance_tampering(
    mutation: str,
) -> None:
    if mutation == "binding":
        proposal = _partial_proposal()
        result = _publish(proposal, _confirm_partial(proposal))
    else:
        result = _publish(_proposal())
    bundle = copy.deepcopy(result["authority_bundle"])
    commitment = bundle["policy_translation_commitment"]

    if mutation == "span":
        commitment["clauses"][0]["end_byte"] -= 1
        _restamp_commitment_and_bundle(bundle)
    elif mutation == "catalog":
        commitment["capability_catalog"]["catalog_id"] = "customer.injected"
        _restamp_commitment_and_bundle(bundle)
    elif mutation == "coverage":
        commitment["clauses"][0]["customer_coverage_state"] = "Partially enforceable"
        _restamp_commitment_and_bundle(bundle)
    elif mutation == "binding":
        resolution = commitment["customer_bindings"][0]
        resolution["value"] = "different/"
        resolution["resolution_hash"] = artifact_hash(resolution, "resolution_hash")
        _restamp_commitment_and_bundle(bundle)
    else:
        commitment["commitment_hash"] = "sha256:" + "0" * 64
        bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")

    with pytest.raises(ValueError):
        validate_authority_bundle_v3(bundle)


def test_v3_rejects_post_approval_control_confirmation_even_if_outer_hash_is_restamped() -> None:
    result = _publish(_proposal())
    bundle = copy.deepcopy(result["authority_bundle"])
    control = bundle["policy_translation_commitment"]["clauses"][0]["controls"][0]
    control["human_confirmation"]["confirmed_at"] = "2026-09-03T12:03:01Z"
    control["human_confirmation"]["confirmation_hash"] = artifact_hash(
        control["human_confirmation"], "confirmation_hash"
    )
    _restamp_commitment_and_bundle(bundle)
    with pytest.raises(ValueError, match="no later than approval"):
        validate_authority_bundle_v3(bundle)


def test_private_provider_evidence_can_be_deleted_without_affecting_publication() -> None:
    proposal = _proposal()
    run = proposal["translation_runs"][0]
    evidence = create_policy_translation_run_evidence(
        run,
        request_bytes=b'{"source":"policy"}',
        response_bytes=b'{"untrusted":"candidate"}',
    )
    del evidence
    result = _publish(proposal)
    serialized = json.dumps(result["authority_bundle"], sort_keys=True)
    assert all(term not in serialized for term in ("provider_class", "provider_identifier", "request_hash", "response_hash", "translation_template"))
    assert result["private_translation_evidence_required"] is False
    assert validate_authority_bundle(result["authority_bundle"])["provenance_complete"] is True
    assert validate_publication_receipt(result["authority_bundle"], result["publication_receipt"])["provenance_complete"] is True


def test_one_byte_source_change_propagates_through_every_public_identity() -> None:
    first = _publish(_proposal(b"Agents may modify README.md. Policy overview.\n"))
    second = _publish(_proposal(b"Agents may modify README.md. Policy overview!\n"))
    for key in (
        "source_snapshot_hash", "policy_translation_commitment_hash",
        "semantic_commit_hash", "semantic_commit_bundle_hash", "compiled_contract_hash",
        "authority_bundle_hash", "publication_receipt_hash",
    ):
        assert first["canonical_hashes"][key] != second["canonical_hashes"][key]
    assert first["approval_record"]["approval_id"] != second["approval_record"]["approval_id"]


def test_v3_schemas_are_strict_and_dispatch_rejects_cross_version_masquerading() -> None:
    result = _publish(_proposal())
    _schema_validate(result["policy_translation_commitment"], "policy_translation_commitment.v1.json")
    _schema_validate(result["authority_bundle"], "authority_bundle.v3.json")
    _schema_validate(result["publication_receipt"], "publication_receipt.v3.json")
    validate_authority_bundle_v3(result["authority_bundle"])
    assert validate_policy_translation_commitment(
        result["authority_bundle"]["source_policy"],
        {key: result["authority_bundle"]["authority"][key] for key in ("authority_id", "authority_version", "authority_ref")},
        result["policy_translation_commitment"],
        approved_at=result["approval_record"]["approved_at"],
    )["valid"] is True
    with pytest.raises(ValueError, match="schema versions do not match"):
        validate_publication_receipt(
            result["authority_bundle"],
            {**result["publication_receipt"], "schema_version": "publication_receipt.v2"},
        )


def test_customer_coverage_and_explanations_exclude_implementation_vocabulary() -> None:
    proposal = _proposal()
    pending = inspect_policy_translation_customer_coverage(proposal)
    assert pending["clauses"][0]["customer_coverage_state"] == "Needs an answer"
    result = _publish(proposal)
    explanations = [
        text
        for clause in result["policy_translation_commitment"]["clauses"]
        for text in [
            clause["customer_explanation"],
            *(control["customer_explanation"] for control in clause["controls"]),
        ]
        if text is not None
    ]
    forbidden = ("catalog", "schema", "sha256", "emitter", "guard", "control_type")
    assert all(not any(term in explanation.lower() for term in forbidden) for explanation in explanations)


def test_v3_validation_and_customer_coverage_are_deterministic() -> None:
    proposal = _proposal(b"Agents may modify README.md and CHANGELOG.md.")
    first = _publish(proposal)
    second = _publish(copy.deepcopy(proposal))
    assert first == second
    assert inspect_policy_translation_customer_coverage(proposal) == inspect_policy_translation_customer_coverage(copy.deepcopy(proposal))
    assert canonical_sha256(first["authority_bundle"]) == canonical_sha256(second["authority_bundle"])


def test_guard_0190_loads_native_v3_after_private_evidence_deletion_and_enforces(
    tmp_path: Path,
) -> None:
    pytest.importorskip("waveframe_guard")
    from importlib.metadata import version

    from guard.sdk import Guard, GuardExecutionBlocked
    from waveframe_guard.authority.adapters import LocalRegistryResolver

    assert version("waveframe-guard") == "0.19.0"
    assert version("governance-ledger") == "0.9.0"

    publication = _publish(
        _proposal(b"Agents may modify README.md and CHANGELOG.md.")
    )
    private_evidence = tmp_path / "private-translation-evidence.json"
    private_evidence.write_text(
        '{"provider":"private","request":"private","response":"private"}',
        encoding="utf-8",
    )
    private_evidence.unlink()
    assert not private_evidence.exists()

    public_root = tmp_path / "publication"
    contracts = public_root / "contracts"
    contracts.mkdir(parents=True)
    bundle_ref = "contracts/repository-authority-1.0.0.authority-bundle.json"
    receipt_ref = "contracts/repository-authority-1.0.0.publication-receipt.json"
    bundle = publication["authority_bundle"]
    receipt = publication["publication_receipt"]
    (public_root / bundle_ref).write_text(json.dumps(bundle), encoding="utf-8")
    (public_root / receipt_ref).write_text(json.dumps(receipt), encoding="utf-8")
    registry = {
        "schema_version": "contract_registry.v1",
        "contracts": [
            {
                "authority_ref": "repository-authority@1.0.0",
                "contract_id": "repository-authority",
                "contract_version": "1.0.0",
                "contract_hash": publication["compiled_authority_contract"][
                    "contract_hash"
                ],
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
    registry_path = contracts / "index.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")

    repository = (tmp_path / "repository").resolve()
    (repository / "src").mkdir(parents=True)
    for name in ("README.md", "CHANGELOG.md", "src/unpublished.py"):
        (repository / name).write_bytes(b"original")
    public_before = {str(p): p.read_bytes() for p in public_root.rglob("*.json")}
    guard = Guard.local(
        repository_root=repository,
        workspace=tmp_path / "guard-evidence",
        authority="repository-authority@1.0.0",
        authority_resolver=LocalRegistryResolver(
            registry_path=registry_path,
            workspace_root=public_root,
        ),
        actor_identity={"id": "release-agent", "type": "agent"},
    )
    calls = []
    try:
        @guard.repository_tool(action="modify", target="path", return_result=True,
                               raise_on_block=False)
        def modify(path):
            calls.append("modify")
            return path.write_bytes(b"modified")

        for target, allowed in (("README.md", True), ("CHANGELOG.md", True),
                                ("src/unpublished.py", False)):
            before = len(calls)
            result = modify(target)
            assert result["executed"] is allowed
            assert len(calls) == before + int(allowed)
            assert (repository / target).read_bytes() == (b"modified" if allowed else b"original")
            assert guard.store.replay(result["evaluation"]["run_id"])["matches"]
            assert len(calls) == before + int(allowed), "saved replay must not execute callbacks"
        loaded = guard.boundary_for().loaded_authority
        assert loaded.schema_version == "authority_bundle.v3"
        assert loaded.contract["schema_version"] == "compiled_authority_contract.v2"
        assert loaded.authority_evidence["publication_receipt"]["schema_version"] == "publication_receipt.v3"
        assert calls == ["modify", "modify"]
        assert {str(p): p.read_bytes() for p in public_root.rglob("*.json")} == public_before
    finally:
        guard.close()
