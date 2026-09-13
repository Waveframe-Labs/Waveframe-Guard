"""Acceptance uses the real candidate API; substitutes occur only in rejection tests."""
from __future__ import annotations

import copy
import importlib.metadata
import json
import os
from pathlib import Path
import sys

import pytest

from examples.native_v4_development import POLICIES, build_fixture
from governance_ledger.action_policy import (
    DEV_ENV, compile_verified_action_policy, get_development_capability_catalog,
    lower_action_constraints,
)
from governance_ledger.action_policy_publication import (
    validate_compiled_authority_contract_v3,
)
from governance_ledger.authority_contract import compute_contract_hash
from governance_ledger.constraint_ir import artifact_hash
from governance_ledger.domain_packs import get_builtin_domain_pack, list_builtin_domain_packs
from governance_ledger.policy_translation import (
    _empty_confirmation, apply_policy_translation_disposition,
    approve_policy_translation_proposal, get_policy_translation_capability_catalog,
    render_policy_translation_review, validate_policy_translation_proposal,
    validate_policy_translation_capability_catalog,
)
from governance_ledger.policy_translation_publication import (
    finalize_policy_translation_authority_v3, inspect_policy_translation_customer_coverage,
)
from governance_ledger.publication_provenance import (
    canonical_sha256, validate_authority_bundle, validate_publication_receipt,
)
from test_policy_translation_publication_v3 import _schema_validate

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests/fixtures/action_policy_v4"
CANDIDATE = "ae590dee058d3481e384dea850d5b7d980f533ff"
pytestmark = pytest.mark.skipif(os.environ.get(DEV_ENV) != "1",
    reason="explicit action-policy development opt-in required; see docs/ACTION_POLICY_DEVELOPMENT.md")


@pytest.fixture(scope="module")
def fixtures():
    return {name: build_fixture(name) for name in POLICIES}


def test_candidate_package_provenance():
    from tools.package_provenance import compiler_provenance
    compiler_provenance()


@pytest.mark.parametrize("name", POLICIES)
def test_complete_real_candidate_fixtures_and_reused_schemas(fixtures, name):
    fixture = fixtures[name]
    for artifact, value in fixture.items():
        path = FIXTURES / name / (artifact + (".txt" if artifact == "source" else ".json"))
        recorded = path.read_text(encoding="utf-8")
        assert value == (recorded if artifact == "source" else json.loads(recorded))
    for artifact, schema in {
        "proposal": "policy_translation_proposal.v1.json",
        "confirmation": "policy_translation_confirmation.v1.json",
        "approval": "policy_translation_approval.v1.json",
        "review": "policy_translation_review.v1.json",
        "constraint-ir": "constraint_ir.v1.json",
        "compiled-authority": "compiled_authority_contract.v3.json",
        "authority-bundle": "authority_bundle.v4.json",
        "publication-receipt": "publication_receipt.v4.json",
    }.items():
        _schema_validate(fixture[artifact], schema)
    bundle = fixture["authority-bundle"]
    _schema_validate(bundle["policy_translation_commitment"], "policy_translation_commitment.v1.json")
    _schema_validate(bundle["runtime_fact_schema"], "runtime_fact_schema.v1.json")
    assert validate_authority_bundle(bundle)["valid"]
    assert validate_publication_receipt(bundle, fixture["publication-receipt"])["valid"]
    raw = fixture["compiler-output"]
    assert set(raw) == {"schema_version", "contract_id", "contract_version", "action_requirements", "contract_hash"}
    assert raw["contract_hash"] == compute_contract_hash(raw)
    assert not raw["contract_hash"].startswith("sha256:")
    assert fixture["compiled-authority"]["contract_hash"] != raw["contract_hash"]
    public_json = json.dumps([bundle, fixture["publication-receipt"]])
    assert "provider_identifier" not in public_json
    assert "translation_runs" not in public_json


def test_opt_in_and_immutable_default(fixtures, monkeypatch):
    default = get_policy_translation_capability_catalog()
    assert default["catalog_version"] == "1.0.0" and default["actions"] == ["modify"]
    assert [p["domain_pack_version"] for p in list_builtin_domain_packs()] == ["1.0.0"]
    monkeypatch.delenv(DEV_ENV)
    assert get_policy_translation_capability_catalog() == default
    for call in (get_development_capability_catalog,
                 lambda: get_builtin_domain_pack("repository-changes", "2.0.0"),
                 lambda: validate_authority_bundle(fixtures["modify-only"]["authority-bundle"])):
        with pytest.raises(ValueError, match="explicit"):
            call()


def test_catalog_has_six_distinct_controls_and_bound_fact_identities():
    catalog = get_development_capability_catalog()
    assert len({(c["control_type"], c["action"]) for c in catalog["control_types"]}) == 6
    validate_policy_translation_capability_catalog(catalog)
    _schema_validate(catalog, "policy_translation_capability_catalog.v2.json")
    old = get_builtin_domain_pack("repository-changes", "1.0.0")
    new = get_builtin_domain_pack("repository-changes", "2.0.0")
    _schema_validate(new, "domain_pack.v1.json")
    assert old["canonical_hash"] != new["canonical_hash"]
    assert old["runtime_fact_schema"]["schema_hash"] != new["runtime_fact_schema"]["schema_hash"]
    assert new["runtime_fact_schema"]["schema_version_number"] == "2.0.0"
    catalog["control_types"].pop()
    catalog["catalog_hash"] = artifact_hash(catalog, "catalog_hash")
    with pytest.raises(ValueError):
        validate_policy_translation_capability_catalog(catalog)


def _permits(blocks, action, path, role=None):
    """Test-only semantic oracle; Ledger does not perform runtime authorization."""
    block = blocks.get(action)
    if block is None or (block["required_role"] is not None and role != block["required_role"]):
        return False
    def matches(rule):
        return path == rule["value"] if rule["match"] == "exact" else path.startswith(rule["value"])
    return any(map(matches, block["allow"])) and not any(map(matches, block["deny"]))


def test_independent_actions_roles_default_deny_and_overlap(fixtures):
    mixed = fixtures["mixed"]["compiler-output"]["action_requirements"]
    assert _permits(mixed, "create", "generated/new.md", "repository-maintainer")
    assert not _permits(mixed, "modify", "generated/new.md", "security-reviewer")
    assert _permits(mixed, "modify", "README.md", "security-reviewer")
    assert not _permits(mixed, "create", "README.md", "repository-maintainer")
    assert not _permits(mixed, "create", "generated/new.md", "security-reviewer")
    assert not _permits(mixed, "modify", "unlisted.md", "security-reviewer")
    create = fixtures["create-only"]["compiler-output"]["action_requirements"]
    assert _permits(create, "create", "generated/new.md", "repository-maintainer")
    assert not _permits(create, "create", "generated/private/key", "repository-maintainer")
    assert not _permits(create, "modify", "generated/new.md", "repository-maintainer")
    modify = fixtures["modify-only"]["compiler-output"]["action_requirements"]
    assert not _permits(modify, "create", "docs/new.md", "repository-reviewer")


def test_missing_individual_confirmation_and_action_tampering(fixtures):
    fixture = fixtures["mixed"]
    proposal = copy.deepcopy(fixture["proposal"])
    state = copy.deepcopy(fixture["confirmation"])
    state["control_confirmations"].pop()
    with pytest.raises(ValueError):
        approve_policy_translation_proposal(proposal, state, approved_by="owner", approved_at="2026-09-11T12:03:00Z")
    clause = next(c for c in proposal["clauses"] if len(c["candidate_controls"]) == 2)
    control = clause["candidate_controls"][0]
    control["action"] = "modify"
    control["candidate_control_id"] = "candidate-control-" + canonical_sha256({k:v for k,v in control.items() if k != "candidate_control_id"}).removeprefix("sha256:")
    core = {k:v for k,v in proposal.items() if k not in {"proposal_id", "proposal_hash"}}
    proposal["proposal_hash"] = canonical_sha256(core)
    proposal["proposal_id"] = "policy-translation-proposal-" + proposal["proposal_hash"].removeprefix("sha256:")
    with pytest.raises(ValueError, match="semantics"):
        validate_policy_translation_proposal(proposal)
    clause = fixture["proposal"]["clauses"][2]
    state = _empty_confirmation(fixture["proposal"])
    with pytest.raises(ValueError, match="individual"):
        apply_policy_translation_disposition(fixture["proposal"], state, clause_id=clause["clause_id"],
            coverage_status="fully_represented", reason_code="human-confirmed-complete",
            confirmed_by="owner", confirmed_at="2026-09-11T12:02:00Z")


@pytest.mark.parametrize("text", [
    "Agents may write README.md.", "Agents may change README.md.",
    "Agents with role repository-maintainer may create README.md.",
    "Agents must use role repository-maintainer to create README.md.",
    "Agents may create README.md if approved.",
])
def test_ambiguous_or_path_dependent_role_source_cannot_grant(text):
    with pytest.raises(ValueError, match="unsupported source meaning"):
        build_fixture("unsupported", [(text, [("create", "exact_path_access", "allow", "README.md")])])


@pytest.mark.parametrize("effect", ["deny", "require"])
def test_zero_grant_publication_is_rejected(effect):
    rows = [("Agents must not create README.md.", [("create", "exact_path_access", "deny", "README.md")])]
    if effect == "require":
        rows = [POLICIES["create-only"][0]]
    from governance_ledger.domain_policy import interpret_policy_with_domain_pack
    draft = interpret_policy_with_domain_pack(rows[0][0].encode(), domain_pack_id="repository-changes",
        domain_pack_version="2.0.0", source_policy_id="zero", source_revision="1",
        authority_id="zero", authority_version="2.0.0")
    assert not draft["status"]["ready_for_finalization"]
    with pytest.raises(ValueError, match="at least one path allow"):
        build_fixture("zero", rows)


def test_deny_only_action_never_inherits_other_action_allow():
    rows = [("Agents may modify README.md.", [("modify", "exact_path_access", "allow", "README.md")]),
            ("Agents must not create secret.md.", [("create", "exact_path_access", "deny", "secret.md")])]
    blocks = build_fixture("deny-only-action", rows)["compiler-output"]["action_requirements"]
    assert _permits(blocks, "modify", "README.md")
    assert not _permits(blocks, "create", "README.md")


def test_same_action_contradiction_and_conflicting_roles_reject():
    with pytest.raises(ValueError, match="contradictory"):
        build_fixture("contradictory", [
            ("Agents may create README.md.", [("create", "exact_path_access", "allow", "README.md")]),
            ("Agents must not create README.md.", [("create", "exact_path_access", "deny", "README.md")])])
    with pytest.raises(ValueError, match="conflicting action-wide roles"):
        build_fixture("roles", POLICIES["create-only"] + [
            ("Agents must use role security-reviewer to create repository files.", [("create", "acting_role", "require", "security-reviewer")])])


@pytest.mark.parametrize("mutation", ["schema", "identity", "version", "extra", "hash", "prefixed", "swap", "nested", "legacy"])
def test_compiler_output_substitution_fails_before_authority(fixtures, monkeypatch, mutation):
    import compiler
    policy = fixtures["mixed"]["compiler-input"]
    raw = copy.deepcopy(fixtures["mixed"]["compiler-output"])
    if mutation == "schema": raw["schema_version"] = "compiled_action_contract.v99"
    if mutation == "identity": raw["contract_id"] = "substitution"
    if mutation == "version": raw["contract_version"] = "9.0.0"
    if mutation == "extra": raw["target_requirements"] = {}
    if mutation == "swap": raw["action_requirements"]["create"], raw["action_requirements"]["modify"] = raw["action_requirements"]["modify"], raw["action_requirements"]["create"]
    if mutation == "nested": raw["action_requirements"]["create"]["extra"] = True
    raw["contract_hash"] = compute_contract_hash(raw)
    if mutation == "hash": raw["contract_hash"] = "0" * 64
    if mutation == "prefixed": raw["contract_hash"] = "sha256:" + raw["contract_hash"]
    if mutation == "legacy": raw = {"contract_id": policy["contract_id"], "contract_version": "2.0.0"}
    monkeypatch.setattr(compiler, "compile_action_policy", lambda _: raw)
    with pytest.raises(ValueError):
        compile_verified_action_policy(policy)


def test_missing_compiler_api_never_falls_back(fixtures, monkeypatch):
    import compiler
    monkeypatch.delattr(compiler, "compile_action_policy")
    with pytest.raises(ValueError, match="no legacy fallback"):
        compile_verified_action_policy(fixtures["create-only"]["compiler-input"])


def test_moving_rules_and_rehashing_fails_against_public_commitment(fixtures):
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    contract = bundle["compiled_authority_contract"]
    for value in (contract, contract["compiler_output"]):
        blocks = value["action_requirements"]
        blocks["create"], blocks["modify"] = blocks["modify"], blocks["create"]
    contract["compiler_output"]["contract_hash"] = compute_contract_hash(contract["compiler_output"])
    contract["contract_hash"] = "sha256:" + compute_contract_hash(contract)
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    assert validate_compiled_authority_contract_v3(contract)["valid"]
    with pytest.raises(ValueError, match="substitution"):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize("version", [None, "authority_bundle.v1", "authority_bundle.v2", "authority_bundle.v3", "authority_bundle.v99"])
def test_downgraded_unknown_and_mixed_envelopes_fail(fixtures, version):
    bundle = copy.deepcopy(fixtures["modify-only"]["authority-bundle"])
    if version is None: bundle.pop("schema_version")
    else: bundle["schema_version"] = version
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError): validate_authority_bundle(bundle)
    with pytest.raises(ValueError): validate_publication_receipt(bundle, fixtures["modify-only"]["publication-receipt"])


@pytest.mark.parametrize("version", [None, "publication_receipt.v1", "publication_receipt.v2", "publication_receipt.v3", "publication_receipt.v99"])
def test_receipt_dispatch(fixtures, version):
    receipt = copy.deepcopy(fixtures["modify-only"]["publication-receipt"])
    if version is None: receipt.pop("schema_version")
    else: receipt["schema_version"] = version
    receipt["receipt_hash"] = artifact_hash(receipt, "receipt_hash")
    with pytest.raises(ValueError):
        validate_publication_receipt(fixtures["modify-only"]["authority-bundle"], receipt)


def test_public_verification_needs_neither_provider_nor_compiler(fixtures, monkeypatch):
    monkeypatch.setitem(sys.modules, "compiler", None)
    for fixture in fixtures.values():
        assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]


def test_development_review_and_current_finalizer_gate(fixtures):
    fixture = fixtures["mixed"]
    review = render_policy_translation_review(fixture["proposal"], fixture["confirmation"])
    wording = json.dumps(review)
    for phrase in ("may create", "may modify", "absent action", "matching deny wins", "existing parent", "Roles restrict", "activation are pending"):
        assert phrase in wording
    coverage = inspect_policy_translation_customer_coverage(fixture["proposal"], fixture["confirmation"])
    assert all(c["customer_coverage_state"] == "Not currently enforceable" for c in coverage["clauses"])
    with pytest.raises(ValueError, match="native v4"):
        finalize_policy_translation_authority_v3(fixture["proposal"], fixture["confirmation"], fixture["approval"],
            committed_by="committer", committed_at="2026-09-11T12:04:00Z",
            publication_id="pub", published_by="publisher", published_at="2026-09-11T12:05:00Z")


def test_legacy_contract_substitution_and_explicit_null_versions(fixtures):
    contract = fixtures["modify-only"]["compiled-authority"]
    for schema in ("compiled_authority_contract.v3", "compiled_authority_contract.v99"):
        legacy = {"schema_version": "authority_bundle.v1", "authority_contract": {**contract, "schema_version": schema}}
        with pytest.raises(ValueError, match="legacy compiled contract"):
            validate_authority_bundle(legacy)
    with pytest.raises(ValueError, match="unknown explicit"):
        validate_authority_bundle({"schema_version": None})
    with pytest.raises(ValueError, match="unknown explicit"):
        validate_publication_receipt({}, {"schema_version": None})


def test_published_confirmation_removal_and_identity_substitution(fixtures):
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    bundle["policy_translation_commitment"]["clauses"][2]["controls"][0].pop("human_confirmation")
    commitment = bundle["policy_translation_commitment"]
    commitment["commitment_hash"] = canonical_sha256({k:v for k,v in commitment.items() if k not in {"commitment_id", "commitment_hash"}})
    commitment["commitment_id"] = "policy-translation-commitment-" + commitment["commitment_hash"].removeprefix("sha256:")
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    bundle["authority"]["authority_id"] = "substituted"
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)


def test_changed_source_cannot_reuse_old_confirmation(fixtures):
    old = build_fixture("same-identity", [("Agents may modify README.md.", [("modify", "exact_path_access", "allow", "README.md")])])
    new = build_fixture("same-identity", [("Agents may create README.md.", [("create", "exact_path_access", "allow", "README.md")])])
    with pytest.raises(ValueError):
        approve_policy_translation_proposal(new["proposal"], old["confirmation"],
            approved_by="owner", approved_at="2026-09-11T12:03:00Z")
    assert old["compiler-output"]["contract_hash"] != new["compiler-output"]["contract_hash"]


def test_role_scope_cannot_be_flattened_during_lowering(fixtures):
    constraints = copy.deepcopy(fixtures["create-only"]["constraint-ir"]["constraints"])
    constraints[0]["resource"] = {"kind": "repository_path", "match": "exact", "value": "README.md"}
    with pytest.raises(ValueError, match="path-dependent"):
        lower_action_constraints(fixtures["create-only"]["proposal"]["authority"], constraints)
