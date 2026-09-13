"""Release catalog acceptance must execute with the development opt-in absent."""
import copy
import json
import os
from pathlib import Path
import sys

import pytest

from examples.native_v4_release import POLICIES, build_fixture, build_proposal_fixture
from governance_ledger.action_policy import DEV_ENV, compile_verified_action_policy
from governance_ledger.action_policy_publication import (
    finalize_policy_translation_authority_v4, validate_compiled_authority_contract_v3,
)
from governance_ledger.authority_contract import compute_contract_hash
from governance_ledger.constraint_ir import artifact_hash
from governance_ledger.domain_packs import get_builtin_domain_pack, validate_domain_pack
from governance_ledger.domain_policy import interpret_policy_with_domain_pack
from governance_ledger.policy_translation import (
    apply_policy_translation_control_confirmation, apply_policy_translation_disposition,
    approve_policy_translation_proposal, get_policy_translation_capability_catalog,
    render_policy_translation_review, resolve_policy_translation_capability_catalog,
    validate_policy_translation_capability_catalog, validate_policy_translation_review,
)
from governance_ledger.policy_translation_publication import inspect_policy_translation_customer_coverage
from governance_ledger.publication_provenance import canonical_sha256, validate_authority_bundle, validate_publication_receipt
from test_policy_translation_publication_v3 import _schema_validate

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/action_policy_release_v4"


@pytest.fixture(autouse=True)
def no_development_flag(monkeypatch):
    monkeypatch.delenv(DEV_ENV, raising=False)


@pytest.fixture(scope="module")
def fixtures():
    with pytest.MonkeyPatch.context() as patch:
        patch.delenv(DEV_ENV, raising=False)
        return {name: build_fixture(name) for name in POLICIES}


def finalizer(proposal, confirmation, approval):
    return finalize_policy_translation_authority_v4(proposal, confirmation, approval,
        committed_by="example-release-committer", committed_at="2026-09-12T12:04:00Z",
        publication_id="fresh-release", published_by="example-release-publisher",
        published_at="2026-09-12T12:05:00Z")


def test_explicit_catalog_default_and_exact_identity():
    assert get_policy_translation_capability_catalog()["catalog_version"] == "1.0.0"
    catalog = get_policy_translation_capability_catalog(catalog_version="3.0.0")
    assert catalog["schema_version"] == "policy_translation_capability_catalog.v2"
    assert len({(c["control_type"], c["action"]) for c in catalog["control_types"]}) == 6
    assert catalog["enforcement_points"][0]["enforcement_point_id"] == "waveframe.guard.repository-change.v2"
    assert validate_policy_translation_capability_catalog(catalog) == catalog
    ref = {k: catalog[k] for k in ("catalog_id", "catalog_version", "catalog_hash")}
    assert resolve_policy_translation_capability_catalog(ref) == catalog
    pack = get_builtin_domain_pack("repository-changes", "3.0.0")
    assert pack["runtime_fact_schema"]["schema_version_number"] == "3.0.0"
    assert all("exist" not in f["fact_id"] for f in pack["runtime_fact_schema"]["facts"])
    assert DEV_ENV not in os.environ


@pytest.mark.parametrize("name", POLICIES)
def test_complete_fresh_release_chain_without_flags(fixtures, name):
    fixture = fixtures[name]
    for key, value in fixture.items():
        path = FIXTURES / name / (key + (".txt" if key == "source" else ".json"))
        retained = path.read_text(encoding="utf-8")
        assert value == (retained if key == "source" else json.loads(retained))
    for key, schema in {"proposal": "policy_translation_proposal.v1", "confirmation": "policy_translation_confirmation.v1",
                        "review": "policy_translation_review.v1", "approval": "policy_translation_approval.v1",
                        "constraint-ir": "constraint_ir.v1", "compiled-authority": "compiled_authority_contract.v3",
                        "authority-bundle": "authority_bundle.v4", "publication-receipt": "publication_receipt.v4"}.items():
        _schema_validate(fixture[key], schema + ".json")
    _schema_validate(fixture["authority-bundle"]["policy_translation_commitment"], "policy_translation_commitment.v1.json")
    assert validate_compiled_authority_contract_v3(fixture["compiled-authority"])["valid"]
    assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]
    result = finalizer(fixture["proposal"], fixture["confirmation"], fixture["approval"])
    assert result["result_type"] == "action_policy_publication"
    assert result["status"] == {"publication_ready": True, "runtime_activation_ready": False}
    old = ROOT / "tests/fixtures/action_policy_v4" / name
    assert fixture["source"] == (old / "source.txt").read_text(encoding="utf-8")
    for key, field in (("proposal", "proposal_hash"), ("confirmation", "confirmation_hash"),
                       ("review", "review_hash"), ("approval", "approval_id"),
                       ("publication-receipt", "publication_id")):
        assert fixture[key][field] != json.loads((old / (key + ".json")).read_text())[field]
    assert fixture["proposal"]["authority"]["authority_version"] == "3.0.0"
    assert DEV_ENV not in os.environ


def test_release_review_and_coverage_do_not_claim_runtime_activation(fixtures):
    fixture = fixtures["mixed"]
    text = json.dumps(render_policy_translation_review(fixture["proposal"], fixture["confirmation"]))
    for phrase in ("independent paths", "action-wide roles", "missing matching allow", "matching deny wins",
                   "exclusive creation", "existing parent", "compatible Guard runtime", "mutations outside Guard",
                   "grants no operation", "does not establish deployment"):
        assert phrase in text
    assert "Development validation only" not in text
    coverage = inspect_policy_translation_customer_coverage(fixture["proposal"], fixture["confirmation"])
    assert all(c["customer_coverage_state"] == "Prepared for a compatible Guard runtime" for c in coverage["clauses"])
    assert validate_authority_bundle(fixture["authority-bundle"])["runtime_activation_ready"] is False


@pytest.mark.parametrize("name", POLICIES)
def test_public_validation_does_not_import_compiler(fixtures, monkeypatch, name):
    monkeypatch.setitem(sys.modules, "compiler", None)
    fixture = fixtures[name]
    assert validate_compiled_authority_contract_v3(fixture["compiled-authority"])["valid"]
    assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]
    assert "provider_identifier" not in json.dumps(fixture["authority-bundle"])


@pytest.mark.parametrize("kind", ["catalog", "pack", "compiled", "bundle", "receipt", "compile"])
def test_development_generation_keeps_its_gate(kind):
    folder = ROOT / "tests/fixtures/action_policy_v4/mixed"
    read = lambda key: json.loads((folder / (key + ".json")).read_text())
    calls = {
        "catalog": lambda: get_policy_translation_capability_catalog(catalog_version="2.0.0"),
        "pack": lambda: get_builtin_domain_pack("repository-changes", "2.0.0"),
        "compiled": lambda: validate_compiled_authority_contract_v3(read("compiled-authority")),
        "bundle": lambda: validate_authority_bundle(read("authority-bundle")),
        "receipt": lambda: validate_publication_receipt(read("authority-bundle"), read("publication-receipt")),
        "compile": lambda: compile_verified_action_policy(read("compiler-input")),
    }
    with pytest.raises(ValueError, match="explicit"):
        calls[kind]()


@pytest.mark.parametrize("name", POLICIES)
def test_development_opt_in_still_reproduces_exact_history(monkeypatch, name):
    from examples.native_v4_development import build_fixture as build_development
    monkeypatch.setenv(DEV_ENV, "1")
    fixture = build_development(name)
    for key, value in fixture.items():
        path = ROOT / "tests/fixtures/action_policy_v4" / name / (key + (".txt" if key == "source" else ".json"))
        text = path.read_text(encoding="utf-8")
        assert value == (text if key == "source" else json.loads(text))


@pytest.mark.parametrize("version", ["0.0.0", "3.0.1", "4.0.0", "release", None])
def test_unknown_catalogs_do_not_infer_action_authority(version):
    with pytest.raises(ValueError):
        get_policy_translation_capability_catalog(catalog_version=version)
    with pytest.raises(ValueError):
        get_builtin_domain_pack("repository-changes", version)


@pytest.mark.parametrize("field", ["catalog_id", "catalog_version", "catalog_hash"])
def test_substituted_catalog_references_reject(field):
    catalog = get_policy_translation_capability_catalog(catalog_version="3.0.0")
    ref = {k: catalog[k] for k in ("catalog_id", "catalog_version", "catalog_hash")}
    ref[field] = "substituted"
    with pytest.raises(ValueError):
        resolve_policy_translation_capability_catalog(ref)


@pytest.mark.parametrize("field", ["domain_pack_version", "description", "runtime_fact_schema", "grammar_compiler", "compiler_lowering"])
def test_pack_rehashing_cannot_substitute_registered_identity(field):
    pack = get_builtin_domain_pack("repository-changes", "3.0.0")
    if isinstance(pack[field], str):
        pack[field] = "4.0.0" if field == "domain_pack_version" else "changed"
    else:
        pack[field] = {**pack[field], "substituted": True}
    pack["canonical_hash"] = artifact_hash(pack, "canonical_hash")
    with pytest.raises(ValueError):
        validate_domain_pack(pack)


@pytest.mark.parametrize("kind", ["confirmation", "approval", "review"])
def test_development_decisions_never_approve_release(fixtures, kind):
    fixture = fixtures["mixed"]
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed" / (kind + ".json")).read_text())
    with pytest.raises(ValueError):
        if kind == "confirmation":
            approve_policy_translation_proposal(fixture["proposal"], old, approved_by="new-owner", approved_at="2026-09-12T12:03:00Z")
        elif kind == "review":
            validate_policy_translation_review(fixture["proposal"], fixture["confirmation"], old)
        else:
            finalizer(fixture["proposal"], fixture["confirmation"], old)


@pytest.mark.parametrize("field", ["review_hash", "confirmation_hash", "proposal_hash", "approval_id"])
def test_stale_approval_hashes_reject(fixtures, field):
    fixture = fixtures["mixed"]
    approval = copy.deepcopy(fixture["approval"])
    approval[field] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        finalizer(fixture["proposal"], fixture["confirmation"], approval)


@pytest.mark.parametrize("field", ["domain_pack", "runtime_fact_schema", "compiler_binding", "policy_translation_commitment",
                                  "approval_record", "semantic_commit_bundle"])
def test_mixed_generation_components_reject_even_with_rehashed_outer_bundle(fixtures, field):
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed/authority-bundle.json").read_text())
    bundle[field] = old[field]
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)


@pytest.mark.parametrize("field", ["domain_pack_hash", "runtime_fact_schema_hash", "compiler_binding_hash", "constraint_ir_hash"])
def test_compiled_provenance_substitution_rejects_in_full_chain(fixtures, field):
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    compiled = bundle["compiled_authority_contract"]
    compiled["provenance"][field] = "sha256:" + "0" * 64
    compiled["contract_hash"] = "sha256:" + compute_contract_hash(compiled)
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)
    if field in {"domain_pack_hash", "runtime_fact_schema_hash"}:
        with pytest.raises(ValueError):
            validate_compiled_authority_contract_v3(compiled)


def test_relabeling_development_with_registered_release_hashes_does_not_promote_approval(fixtures):
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed/authority-bundle.json").read_text())
    release = fixtures["mixed"]["authority-bundle"]
    old["domain_pack"] = release["domain_pack"]
    old["runtime_fact_schema"] = release["runtime_fact_schema"]
    old["policy_translation_commitment"]["capability_catalog"] = release["policy_translation_commitment"]["capability_catalog"]
    for key in ("domain_pack_hash", "runtime_fact_schema_hash"):
        old["compiled_authority_contract"]["provenance"][key] = release["compiled_authority_contract"]["provenance"][key]
    old["compiled_authority_contract"]["contract_hash"] = "sha256:" + compute_contract_hash(old["compiled_authority_contract"])
    old["bundle_hash"] = artifact_hash(old, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(old)


@pytest.mark.parametrize("name", POLICIES)
def test_mixed_development_release_receipts_reject(fixtures, name):
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4" / name / "publication-receipt.json").read_text())
    with pytest.raises(ValueError):
        validate_publication_receipt(fixtures[name]["authority-bundle"], old)


@pytest.mark.parametrize("mutation", ["missing-api", "noncallable", "legacy", "shape", "hash", "swap", "role"])
def test_release_compiler_is_fail_closed(fixtures, monkeypatch, mutation):
    import compiler
    policy = fixtures["mixed"]["compiler-input"]
    output = copy.deepcopy(fixtures["mixed"]["compiler-output"])
    if mutation == "missing-api":
        monkeypatch.delattr(compiler, "compile_action_policy")
    elif mutation == "noncallable":
        monkeypatch.setattr(compiler, "compile_action_policy", None)
    else:
        if mutation == "legacy": output = {"contract_id": "legacy"}
        if mutation == "shape": output["extra"] = True
        if mutation == "swap": output["action_requirements"]["create"], output["action_requirements"]["modify"] = output["action_requirements"]["modify"], output["action_requirements"]["create"]
        if mutation == "role": output["action_requirements"]["create"]["required_role"] = None
        output["contract_hash"] = "0" * 64 if mutation == "hash" else compute_contract_hash(output)
        monkeypatch.setattr(compiler, "compile_action_policy", lambda _: output)
    with pytest.raises(ValueError):
        compile_verified_action_policy(policy, catalog_version="3.0.0")


def test_release_action_semantics_match_the_unchanged_compiler_contract(fixtures):
    from test_action_policy_v4 import _permits
    blocks = fixtures["mixed"]["compiler-output"]["action_requirements"]
    assert _permits(blocks, "create", "generated/new.md", "repository-maintainer")
    assert not _permits(blocks, "modify", "generated/new.md", "repository-maintainer")
    assert _permits(blocks, "modify", "README.md", "security-reviewer")
    assert not _permits(blocks, "create", "README.md", "repository-maintainer")
    assert not _permits(blocks, "create", "generated/new.md", "security-reviewer")
    assert not _permits(blocks, "modify", "missing.md", "security-reviewer")
    create = fixtures["create-only"]["compiler-output"]["action_requirements"]
    assert not _permits(create, "create", "generated/private/secret", "repository-maintainer")
    assert not _permits(create, "modify", "generated/new.md", "repository-maintainer")


@pytest.mark.parametrize("source", ["Agents may write README.md.", "Agents may change README.md.",
    "Agents must use role repository-maintainer to create files under generated/.",
    "Agents may create ../secret.", "Agents may delete README.md."])
def test_unrecognized_or_unsupported_language_never_becomes_action_controls(source):
    draft = interpret_policy_with_domain_pack(source.encode(), domain_pack_id="repository-changes", domain_pack_version="3.0.0",
        source_policy_id="unsupported", source_revision="1", authority_id="unsupported", authority_version="3.0.0")
    assert not draft["status"]["ready_for_finalization"]
    assert draft["constraint_ir"] is None


@pytest.mark.parametrize("rows", [[POLICIES["create-only"][0]], [POLICIES["create-only"][2]]])
def test_roles_and_denies_alone_cannot_publish_a_grant(rows):
    with pytest.raises(ValueError, match="at least one path allow"):
        build_fixture("non-grant", rows)


def test_exact_source_reuse_is_allowed_but_changed_bytes_reject(fixtures):
    bundle = copy.deepcopy(fixtures["mixed"]["authority-bundle"])
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed/authority-bundle.json").read_text())
    assert bundle["source_policy"] == old["source_policy"]
    bundle["source_policy"]["source_bytes_base64"] = "c3Vic3RpdHV0ZWQ="
    bundle["bundle_hash"] = artifact_hash(bundle, "bundle_hash")
    with pytest.raises(ValueError):
        validate_authority_bundle(bundle)


def test_existing_authority_version_cannot_be_replaced(fixtures):
    from governance_ledger.registry import validate_registry_identity
    old = json.loads((ROOT / "tests/fixtures/action_policy_v4/mixed/authority-bundle.json").read_text())
    bundle = fixtures["mixed"]["authority-bundle"]
    def entry(value):
        return {"authority_ref": value["authority"]["authority_ref"], "bundle_hash": value["bundle_hash"],
                "contract_hash": value["compiled_authority_contract"]["contract_hash"]}
    registry = {"contracts": [entry(old)]}
    validate_registry_identity(registry, entry(bundle))
    replacement = {**entry(bundle), "authority_ref": old["authority"]["authority_ref"]}
    with pytest.raises(ValueError, match="Refusing to republish"):
        validate_registry_identity(registry, replacement)


def test_unsupported_residuals_require_fresh_explicit_acknowledgment():
    rows = [POLICIES["create-only"][1], ("Agents may write README.md.", [])]
    _, _, proposal = build_proposal_fixture("residual", rows)
    recognized, unsupported = proposal["clauses"]
    state = None
    for control in recognized["candidate_controls"]:
        state = apply_policy_translation_control_confirmation(proposal, state,
            clause_id=recognized["clause_id"], candidate_control_id=control["candidate_control_id"],
            confirmed_by="example-owner", confirmed_at="2026-09-12T12:01:00Z")
    state = apply_policy_translation_disposition(proposal, state, clause_id=recognized["clause_id"],
        coverage_status="fully_represented", reason_code="human-confirmed-complete",
        confirmed_by="example-owner", confirmed_at="2026-09-12T12:02:00Z")
    with pytest.raises(ValueError):
        approve_policy_translation_proposal(proposal, state, approved_by="example-owner", approved_at="2026-09-12T12:03:00Z")
    with pytest.raises(ValueError):
        apply_policy_translation_disposition(proposal, state, clause_id=unsupported["clause_id"],
            coverage_status="entirely_unsupported", reason_code="not-enforceable",
            confirmed_by="example-owner", confirmed_at="2026-09-12T12:02:00Z")
    state = apply_policy_translation_disposition(proposal, state, clause_id=unsupported["clause_id"],
        coverage_status="entirely_unsupported", reason_code="not-enforceable", acknowledge_unrepresented=True,
        confirmed_by="example-owner", confirmed_at="2026-09-12T12:02:00Z")
    approval = approve_policy_translation_proposal(proposal, state, approved_by="example-owner", approved_at="2026-09-12T12:03:00Z")
    result = finalizer(proposal, state, approval)
    commitment = result["authority_bundle"]["policy_translation_commitment"]
    assert commitment["coverage"]["full_clause_count"] == 1
    assert commitment["coverage"]["unenforced_clause_count"] == 1
    assert commitment["coverage"]["acknowledged_residual_count"] == 1
    assert commitment["clauses"][1]["residuals"][0]["acknowledgment"]["acknowledged_by"] == "example-owner"
    assert render_policy_translation_review(proposal, state)["clauses"][1]["residual_explanation"]
    assert result["status"]["runtime_activation_ready"] is False


def test_missing_individual_confirmation_cannot_hide_in_coverage(fixtures):
    fixture = fixtures["mixed"]
    confirmation = copy.deepcopy(fixture["confirmation"])
    confirmation["control_confirmations"].pop()
    confirmation["confirmation_hash"] = artifact_hash(confirmation, "confirmation_hash")
    with pytest.raises(ValueError):
        approve_policy_translation_proposal(fixture["proposal"], confirmation,
            approved_by="example-owner", approved_at="2026-09-12T12:03:00Z")
