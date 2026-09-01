from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest
from governance_ledger import (
    apply_policy_mapping_decision,
    finalize_domain_policy_authority,
    interpret_policy_with_domain_pack,
)

from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority import MemoryAuthorityCache, RuntimeFactError, load_authority
from waveframe_guard.authority.adapters import LocalRegistryResolver, MemoryAuthorityResolver
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.authority.runtime_facts import RepositoryChangesFactProvider


SOURCE = (
    b"Repository changes may be made only by repository-maintainers.\n"
    b"Agents may modify README.md.\n"
    b"Agents must not modify files under deployment/.\n"
    b"Repository policy context."
)
AUTHORITY_REF = "repository-authority@1.0.0"


def _request(path):
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": "repository-change-1",
        "action": "modify",
        "target": path,
        "arguments": {},
        "artifacts": [],
    }


def _tamper_receipt_statement_binding(bundle, receipt):
    receipt["statement_decisions_hash"] = _bad_hash()
    receipt["receipt_hash"] = _canonical_hash(
        {key: value for key, value in receipt.items() if key != "receipt_hash"}
    )


@pytest.fixture(scope="module")
def publication():
    return _publication()


def test_public_ledger_v07_repository_publication_executes_exact_contract_once(
    tmp_path, publication
):
    resolver = _write_publication(tmp_path, publication)
    cache = MemoryAuthorityCache()
    actor = {
        "id": "repo-agent",
        "type": "agent",
        "role": "repository-maintainer",
    }
    actor_before = copy.deepcopy(actor)
    guard = Guard.local(
        workspace=tmp_path / "guard-evidence",
        authority=AUTHORITY_REF,
        authority_resolver=resolver,
        authority_cache=cache,
        actor_identity=actor,
        evaluation_time_source=lambda: "2026-08-31T12:03:00+00:00",
    )
    calls = []

    @guard.tool(action="modify", target="path", return_result=True)
    def write_file(path, metadata=None):
        calls.append(path)
        return path

    metadata = {"unknown": {"allow": False}, "runtime_facts": {"actor.role": "security-reviewer"}}
    metadata_before = copy.deepcopy(metadata)
    allowed = write_file("README.md", metadata)
    assert allowed["executed"] is True
    assert allowed["value"] == "README.md"
    with pytest.raises(GuardExecutionBlocked) as blocked_error:
        write_file("deployment/production.yml", metadata)

    assert calls == ["README.md"]
    assert actor == actor_before
    assert metadata == metadata_before
    assert guard.authorities[AUTHORITY_REF] == publication["compiled_authority_contract"]
    assert guard.authorities[AUTHORITY_REF]["schema_version"] == "compiled_authority_contract.v2"
    assert len(cache) == 1

    allowed_evaluation = allowed["evaluation"]
    blocked_evaluation = blocked_error.value.evaluation
    assert allowed_evaluation["status"] == "admissible"
    assert blocked_evaluation["status"] == "blocked"
    assert allowed_evaluation["runtime_facts"] == {
        "actor.principal_id": "repo-agent",
        "actor.role": "repository-maintainer",
        "actor.subject_kind": "agent",
        "proposal.action": "modify",
        "proposal.resource.kind": "repository_path",
        "proposal.resource.path": "README.md",
    }
    assert allowed_evaluation["execution_attestation"]["mutation_executed"] is True
    assert blocked_evaluation["execution_attestation"]["mutation_executed"] is False
    assert blocked_evaluation["execution_attestation"]["execution_status"] == "blocked"

    records = guard.store.history()
    assert len(records) == 2
    evidence = records[0]["inputs"]["authority_evidence"]
    assert evidence["authority"]["authority_ref"] == AUTHORITY_REF
    assert evidence["authority_bundle"]["bundle_hash"] == publication["authority_bundle"]["bundle_hash"]
    assert evidence["publication_receipt"]["receipt_hash"] == publication["publication_receipt"]["receipt_hash"]
    assert evidence["compiled_contract"]["contract_hash"] == publication["compiled_authority_contract"]["contract_hash"]
    assert evidence["domain_pack"] == {
        "schema_version": "domain_pack.v1",
        **publication["authority_bundle"]["domain_pack"],
    }
    assert evidence["runtime_fact_schema"]["schema_hash"] == publication["authority_bundle"]["runtime_fact_schema"]["schema_hash"]
    assert evidence["runtime_facts"]["canonical_hash"] == allowed_evaluation["runtime_facts_hash"]
    assert evidence["runtime_facts"]["canonical_hash"] == _canonical_hash(
        evidence["runtime_facts"]["facts"]
    )
    assert records[0]["receipt"]["input_hashes"]["authority_evidence_hash"]
    assert records[0]["receipt"]["input_hashes"]["runtime_facts_hash"]
    assert (guard.store.execution_attestation_root / f"{records[0]['run_id']}.json").exists()
    assert (guard.store.execution_attestation_root / f"{records[1]['run_id']}.json").exists()


def test_v2_repeated_evaluation_is_deterministic_and_inputs_are_immutable(tmp_path, publication):
    resolver = _write_publication(tmp_path, publication)
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=resolver,
        actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
        evaluation_time_source=lambda: "2026-08-31T12:03:00+00:00",
    )
    request = _request("README.md")
    before = copy.deepcopy(request)
    boundary = guard.boundary_for()

    first = boundary.evaluate(request, save=False)
    second = boundary.evaluate(request, save=False)

    assert request == before
    assert first == second
    assert first["status"] == "admissible"


def test_v2_repository_maintainer_role_constraint_blocks_other_published_role(
    tmp_path, publication
):
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=_write_publication(tmp_path, publication),
        actor_identity={"id": "reviewer", "type": "agent", "role": "repository-reviewer"},
    )
    calls = []
    with pytest.raises(GuardExecutionBlocked):
        guard.boundary_for().execute(
            lambda: calls.append(True),
            execution_request=_request("README.md"),
        )
    assert calls == []


@pytest.mark.parametrize(
    "case,mutate",
    [
        ("source binding", lambda bundle, receipt: bundle["source_policy"].__setitem__("snapshot_hash", _bad_hash())),
        ("statement binding", lambda bundle, receipt: bundle["source_statements"][0].__setitem__("statement_hash", _bad_hash())),
        ("mapping binding", lambda bundle, receipt: bundle["source_to_constraint_mappings"][0].__setitem__("mapping_id", "modified")),
        ("mapping decision", lambda bundle, receipt: bundle["statement_decisions"][0].__setitem__("reason_code", "descriptive")),
        ("domain-pack identity", lambda bundle, receipt: bundle["domain_pack"].__setitem__("domain_pack_id", "finance")),
        ("domain-pack version", lambda bundle, receipt: bundle["domain_pack"].__setitem__("domain_pack_version", "2.0.0")),
        ("domain-pack hash", lambda bundle, receipt: bundle["domain_pack"].__setitem__("domain_pack_hash", _bad_hash())),
        ("runtime-fact-schema identity", lambda bundle, receipt: bundle["runtime_fact_schema"].__setitem__("schema_id", "modified")),
        ("runtime-fact-schema hash", lambda bundle, receipt: bundle["runtime_fact_schema"].__setitem__("schema_hash", _bad_hash())),
        ("constraint IR", lambda bundle, receipt: bundle["constraint_ir"]["constraints"][0].__setitem__("effect", "deny")),
        ("compiled contract", lambda bundle, receipt: bundle["compiled_authority_contract"]["target_requirements"]["allow"][0].__setitem__("value", "OTHER.md")),
        ("authority identity", lambda bundle, receipt: bundle["authority"].__setitem__("authority_id", "modified-authority")),
        ("authority version", lambda bundle, receipt: bundle["authority"].__setitem__("authority_version", "2.0.0")),
        ("bundle canonical hash", lambda bundle, receipt: bundle.__setitem__("bundle_hash", _bad_hash())),
        ("receipt canonical hash", lambda bundle, receipt: receipt.__setitem__("receipt_hash", _bad_hash())),
        ("receipt statement binding", _tamper_receipt_statement_binding),
    ],
)
def test_modified_v2_publication_chain_fails_before_mutation(
    tmp_path, publication, case, mutate
):
    bundle = copy.deepcopy(publication["authority_bundle"])
    receipt = copy.deepcopy(publication["publication_receipt"])
    mutate(bundle, receipt)
    resolver = _write_artifacts(tmp_path, bundle, receipt, publication=publication)
    calls = []

    with pytest.raises(AuthorityVerificationError):
        guard = Guard.local(
            workspace=tmp_path / "evidence",
            authority=AUTHORITY_REF,
            authority_resolver=resolver,
            actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
        )

        @guard.tool(action="modify", target="path")
        def write_file(path):
            calls.append(path)

        write_file("README.md")

    assert calls == [], case


def test_missing_v2_receipt_fails_before_mutation(tmp_path, publication):
    resolver = _write_artifacts(
        tmp_path,
        publication["authority_bundle"],
        None,
        publication=publication,
    )
    calls = []
    with pytest.raises(AuthorityVerificationError, match="requires a publication receipt"):
        Guard.local(
            workspace=tmp_path / "evidence",
            authority=AUTHORITY_REF,
            authority_resolver=resolver,
        )
    assert calls == []


def test_receipt_for_another_bundle_fails_before_mutation(tmp_path, publication):
    other = _publication(publication_id="publication-2")
    resolver = _write_artifacts(
        tmp_path,
        publication["authority_bundle"],
        other["publication_receipt"],
        publication=publication,
        registry_receipt_hash=other["publication_receipt"]["receipt_hash"],
    )
    with pytest.raises(AuthorityVerificationError):
        Guard.local(workspace=tmp_path / "evidence", authority=AUTHORITY_REF, authority_resolver=resolver)


@pytest.mark.parametrize("claimed_schema", ["authority_bundle.v1", "authority_bundle.v2"])
def test_cross_version_artifacts_are_rejected(tmp_path, publication, claimed_schema):
    if claimed_schema == "authority_bundle.v1":
        bundle = copy.deepcopy(publication["authority_bundle"])
        bundle["schema_version"] = claimed_schema
    else:
        bundle = {
            "schema_version": claimed_schema,
            "authority_ref": AUTHORITY_REF,
            "authority_contract": copy.deepcopy(publication["compiled_authority_contract"]),
            "contract_hash": publication["compiled_authority_contract"]["contract_hash"],
            "bundle_hash": publication["authority_bundle"]["bundle_hash"],
        }
    resolver = _write_artifacts(
        tmp_path,
        bundle,
        publication["publication_receipt"],
        publication=publication,
    )
    with pytest.raises(AuthorityVerificationError):
        Guard.local(workspace=tmp_path / "evidence", authority=AUTHORITY_REF, authority_resolver=resolver)


@pytest.mark.parametrize(
    "actor,proposal,error",
    [
        ({"id": "repo-agent", "type": "agent"}, _request("README.md"), "actor.role"),
        ({"id": "repo-agent", "type": "agent", "role": 7}, _request("README.md"), "incorrect type"),
        ({"id": "repo-agent", "type": "agent", "role": "repository-maintainer"}, {**_request("README.md"), "action": 7}, "incorrect type"),
    ],
)
def test_missing_or_incorrect_runtime_facts_fail_before_callback(
    tmp_path, publication, actor, proposal, error
):
    resolver = _write_publication(tmp_path, publication)
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=resolver,
        actor_identity=actor,
    )
    calls = []
    with pytest.raises(RuntimeFactError, match=error):
        guard.boundary_for().execute(lambda: calls.append(True), execution_request=proposal)
    assert calls == []


def test_unknown_and_extra_proposal_fields_cannot_affect_v2_evaluation(tmp_path, publication):
    resolver = _write_publication(tmp_path, publication)
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=resolver,
        actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
        evaluation_time_source=lambda: "2026-08-31T12:03:00+00:00",
    )
    baseline = guard.boundary_for().evaluate(_request("README.md"), save=False)
    request = {
        **_request("README.md"),
        "runtime_facts": {
            "actor.role": "security-reviewer",
            "proposal.resource.path": "deployment/production.yml",
        },
        "actor": {"role": "security-reviewer"},
        "unknown": {"decision": "blocked"},
    }
    extra = guard.boundary_for().evaluate(request, save=False)
    assert extra["status"] == baseline["status"] == "admissible"
    assert extra["runtime_facts"] == baseline["runtime_facts"]


def test_unsupported_runtime_fact_schema_fails_closed(tmp_path, publication):
    resolver = _write_publication(tmp_path, publication)
    loaded = load_authority(AUTHORITY_REF, resolver=resolver)
    evidence = copy.deepcopy(dict(loaded.authority_evidence))
    evidence["runtime_fact_schema"]["schema_id"] = "unsupported-schema"
    unsupported = replace(loaded, authority_evidence=evidence)
    with pytest.raises(RuntimeFactError, match="unsupported runtime fact schema"):
        RepositoryChangesFactProvider().derive(
            authority=unsupported,
            execution_request=_request("README.md"),
            actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
        )


def test_direct_v2_contract_injection_is_rejected_before_callback(tmp_path, publication):
    guard = Guard.local(
        workspace=tmp_path,
        authorities={AUTHORITY_REF: publication["compiled_authority_contract"]},
        actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
    )
    calls = []
    with pytest.raises(AuthorityVerificationError, match="verified authority bundle"):
        guard.boundary_for(AUTHORITY_REF).execute(
            lambda: calls.append(True),
            execution_request=_request("README.md"),
        )
    assert calls == []


def test_v2_loading_calls_released_public_ledger_validators(tmp_path, publication, monkeypatch):
    import governance_ledger

    calls = {"bundle": 0, "receipt": 0, "facts": 0}
    originals = {
        "bundle": governance_ledger.validate_authority_bundle,
        "receipt": governance_ledger.validate_publication_receipt,
        "facts": governance_ledger.validate_runtime_fact_compatibility,
    }

    def bundle_validator(value):
        calls["bundle"] += 1
        return originals["bundle"](value)

    def receipt_validator(bundle, receipt):
        calls["receipt"] += 1
        return originals["receipt"](bundle, receipt)

    def fact_validator(constraint_ir, runtime_schema, *, domain_pack):
        calls["facts"] += 1
        return originals["facts"](
            constraint_ir,
            runtime_schema,
            domain_pack=domain_pack,
        )

    monkeypatch.setattr(governance_ledger, "validate_authority_bundle", bundle_validator)
    monkeypatch.setattr(governance_ledger, "validate_publication_receipt", receipt_validator)
    monkeypatch.setattr(governance_ledger, "validate_runtime_fact_compatibility", fact_validator)

    load_authority(AUTHORITY_REF, resolver=_write_publication(tmp_path, publication))
    assert calls == {"bundle": 1, "receipt": 1, "facts": 1}


def test_dependency_is_base_ledger_v07_without_guard_extra_or_ai_packages():
    metadata = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    dependencies = metadata["project"]["dependencies"]
    assert "governance-ledger==0.7.0" in dependencies
    assert not any("governance-ledger[guard]" in dependency for dependency in dependencies)
    assert not any(
        token in dependency.lower()
        for dependency in dependencies
        for token in ("openai", "anthropic", "transformers", "ollama", "torch")
    )


def test_contract_hash_mismatch_after_caching_is_rejected(tmp_path, publication):
    resolver = _write_publication(tmp_path, publication)
    cache = MemoryAuthorityCache()
    load_authority(AUTHORITY_REF, resolver=resolver, cache=cache)
    key = (AUTHORITY_REF, publication["authority_bundle"]["bundle_hash"].removeprefix("sha256:"))
    cached = cache._entries[key]
    cached.contract["target_requirements"]["allow"][0]["value"] = "OTHER.md"
    with pytest.raises(AuthorityVerificationError, match="cached contract content mismatch"):
        load_authority(AUTHORITY_REF, resolver=resolver, cache=cache)


def test_cross_authority_cache_substitution_is_rejected(tmp_path, publication):
    resolver = _write_publication(tmp_path, publication)
    loaded = load_authority(AUTHORITY_REF, resolver=resolver)
    substituted = replace(loaded, authority_ref="other-authority@1.0.0")

    class SubstitutionCache:
        def get(self, authority_ref, bundle_hash):
            return substituted

        def put(self, authority):
            raise AssertionError("a substituted cache entry must never be cached")

    with pytest.raises(AuthorityVerificationError, match="cached authority_ref mismatch"):
        load_authority(AUTHORITY_REF, resolver=resolver, cache=SubstitutionCache())


def test_existing_v1_allowed_and_blocked_behavior_is_unchanged(tmp_path):
    authority = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "legacy-repository",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:legacy",
        "authority_requirements": {"required_roles": ["maintainer"]},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
        "target_requirements": {
            "allow": [{"match": "exact", "value": "README.md"}],
            "deny": [{"match": "prefix", "value": "deployment/"}],
        },
    }
    guard = Guard.local(
        workspace=tmp_path,
        authorities={"legacy-repository@1.0.0": authority},
        actor_identity={"id": "agent", "type": "agent", "role": "maintainer"},
    )
    calls = []

    @guard.tool(authority="legacy-repository@1.0.0", target="path")
    def write(path):
        calls.append(path)

    write("README.md")
    with pytest.raises(GuardExecutionBlocked):
        write("deployment/production.yml")
    assert calls == ["README.md"]


def _publication(*, publication_id="publication-1"):
    draft = interpret_policy_with_domain_pack(
        SOURCE,
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        source_policy_id="repository-policy",
        source_revision="rev-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
    )
    pending = next(item for item in draft["source_statements"] if item["classification"] == "pending")
    mapping = apply_policy_mapping_decision(
        draft,
        statement_id=pending["statement_id"],
        disposition="informational",
        mapper_identity="owner@example.com",
        mapped_at="2026-08-31T11:59:00Z",
        reason_code="context-only",
    )
    return finalize_domain_policy_authority(
        mapping["updated_interpretation"],
        approval_id="approval-1",
        approved_by="owner@example.com",
        approved_at="2026-08-31T12:00:00Z",
        committed_by="owner@example.com",
        committed_at="2026-08-31T12:01:00Z",
        publication_id=publication_id,
        published_by="publisher@example.com",
        published_at="2026-08-31T12:02:00Z",
    )


def _write_publication(root: Path, publication):
    return _write_artifacts(
        root,
        publication["authority_bundle"],
        publication["publication_receipt"],
        publication=publication,
    )


def _write_artifacts(
    root: Path,
    bundle,
    receipt,
    *,
    publication,
    registry_receipt_hash=None,
):
    contracts = root / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)
    bundle_path = contracts / "repository-authority-1.0.0.authority-bundle.json"
    receipt_path = contracts / "repository-authority-1.0.0.publication-receipt.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    if receipt is not None:
        receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")
    entry = {
        "authority_ref": AUTHORITY_REF,
        "contract_id": "repository-authority",
        "contract_version": "1.0.0",
        "contract_hash": publication["compiled_authority_contract"]["contract_hash"],
        "bundle_path": "contracts/repository-authority-1.0.0.authority-bundle.json",
        "bundle_hash": publication["authority_bundle"]["bundle_hash"],
        "publication_id": publication["publication_receipt"]["publication_id"],
        "lifecycle_state": "active",
        "published_at": publication["publication_receipt"]["published_at"],
        "published_by": publication["publication_receipt"]["published_by"],
    }
    if receipt is not None:
        entry.update(
            {
                "receipt_path": "contracts/repository-authority-1.0.0.publication-receipt.json",
                "receipt_hash": registry_receipt_hash or publication["publication_receipt"]["receipt_hash"],
            }
        )
    registry = {"schema_version": "contract_registry.v1", "contracts": [entry]}
    registry["registry_hash"] = _canonical_hash(registry)
    registry_path = contracts / "index.json"
    registry_path.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")
    return LocalRegistryResolver(registry_path=registry_path, workspace_root=root)


def _canonical_hash(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _bad_hash():
    return "sha256:" + "0" * 64
