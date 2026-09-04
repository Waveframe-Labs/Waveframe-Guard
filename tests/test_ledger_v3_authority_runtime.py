from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority import MemoryAuthorityCache, RuntimeFactError, load_authority
from waveframe_guard.authority.adapters import LocalRegistryResolver
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.authority.types import Bundle, RegistryEntry
from waveframe_guard.authority.verifier import AuthorityVerifier


AUTHORITY_REF = "repository-authority@1.0.0"
FACTS = [
    "actor.subject_kind",
    "proposal.action",
    "proposal.resource.kind",
    "proposal.resource.path",
]


def _has_ledger_v3() -> bool:
    import governance_ledger

    return hasattr(governance_ledger, "finalize_policy_translation_authority_v3")


@pytest.fixture(scope="module")
def multi_publication():
    if not _has_ledger_v3():
        pytest.skip("Ledger 0.8 v3 publication APIs are not installed")
    return _publication("multi")


@pytest.fixture(scope="module")
def partial_publication():
    if not _has_ledger_v3():
        pytest.skip("Ledger 0.8 v3 publication APIs are not installed")
    return _publication("partial")


def _request(path: str) -> dict:
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": "repository-change-1",
        "action": "modify",
        "target": path,
        "arguments": {},
        "artifacts": [],
    }


def _bytes_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _minimal_v3_bundle(tmp_path: Path) -> Bundle:
    entry = RegistryEntry(
        authority_ref=AUTHORITY_REF,
        contract_id="repository-authority",
        contract_version="1.0.0",
        contract_hash="sha256:" + "1" * 64,
        bundle_path=tmp_path / "bundle.json",
        bundle_hash="sha256:" + "2" * 64,
        receipt_path=tmp_path / "receipt.json",
        receipt_hash="sha256:" + "3" * 64,
        bundle_ref="contracts/bundle.json",
        receipt_ref="contracts/receipt.json",
    )
    return Bundle(
        registry_entry=entry,
        payload={"schema_version": "authority_bundle.v3"},
        bundle_hash=entry.bundle_hash or "",
        bundle_path=entry.bundle_path,
        receipt_payload={"schema_version": "publication_receipt.v3"},
        receipt_hash=entry.receipt_hash,
        receipt_path=entry.receipt_path,
        bundle_ref=entry.bundle_ref,
        receipt_ref=entry.receipt_ref,
    )


def _run(draft: dict) -> dict:
    from governance_ledger import create_policy_translation_run

    source = draft["source_policy"]
    return create_policy_translation_run(
        source_policy_ref=source["source_policy_ref"],
        source_revision=source["source_revision"],
        source_snapshot_hash=source["snapshot_hash"],
        provider_class="hosted_model",
        provider_identifier="private-provider/deployment",
        translation_template_version="template-1",
        translation_template_hash=_bytes_hash(b"private-template"),
        request_configuration_id="request-config-1",
        request_configuration_hash=_bytes_hash(b"private-configuration"),
        request_hash=_bytes_hash(b"private-request"),
        response_hash=_bytes_hash(b"private-response"),
        explanation_hash=_bytes_hash(b"private-explanation"),
        created_at="2026-09-03T12:00:00Z",
        completed_at="2026-09-03T12:00:01Z",
        sequence_number=0,
        previous_run_hash=None,
    )


def _path_control(
    path: str,
    *,
    source: bytes,
    clause_start: int,
    clause_end: int,
    effect: str = "allow",
    prefix: bool = False,
) -> dict:
    encoded = path.encode("utf-8")
    start = source.find(encoded, clause_start, clause_end)
    if start < 0:
        start = clause_start
    end = start + len(encoded)
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
            "start_byte": start,
            "end_byte": end,
            "literal_hash": _bytes_hash(source[start:end]),
        },
        "required_runtime_facts": FACTS,
    }


def _multi_proposal() -> dict:
    from governance_ledger import create_policy_translation_proposal, interpret_policy_with_domain_pack

    source = b"Agents may modify README.md and CHANGELOG.md."
    draft = interpret_policy_with_domain_pack(
        source,
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
    )
    statement = draft["source_statements"][0]
    controls = [
        _path_control(
            path,
            source=source,
            clause_start=statement["start_byte"],
            clause_end=statement["end_byte"],
        )
        for path in ("README.md", "CHANGELOG.md")
    ]
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
                "candidate_controls": controls,
                "unresolved_binding_ids": [],
                "limitation_code": None,
                "residual_unsupported_spans": [],
            }
        ],
        organizational_bindings=[],
        translation_runs=[_run(draft)],
    )


def _partial_proposal() -> dict:
    from governance_ledger import create_policy_translation_proposal, interpret_policy_with_domain_pack

    source = b"Agents may modify documentation but must not modify cryptographic modules."
    draft = interpret_policy_with_domain_pack(
        source,
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
    )
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


def _confirm(proposal: dict) -> dict:
    from governance_ledger import (
        apply_policy_translation_binding,
        apply_policy_translation_control_confirmation,
        apply_policy_translation_disposition,
    )

    state = None
    if proposal["organizational_bindings"]:
        state = apply_policy_translation_binding(
            proposal,
            state,
            binding_id="cryptographic-modules-path",
            value="crypto/",
            confirmed_by="policy-owner",
            confirmed_at="2026-09-03T12:00:30Z",
        )
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
        partial = clause["coverage_status"] == "partially_represented"
        state = apply_policy_translation_disposition(
            proposal,
            state,
            clause_id=clause["clause_id"],
            coverage_status=clause["coverage_status"],
            reason_code="human-confirmed-partial" if partial else "human-confirmed-complete",
            acknowledge_unrepresented=partial,
            confirmed_by="policy-owner",
            confirmed_at="2026-09-03T12:02:00Z",
        )
    assert state is not None
    return state


def _publication(kind: str, *, publication_id: str = "publication-1") -> dict:
    from governance_ledger import (
        approve_policy_translation_proposal,
        finalize_policy_translation_authority_v3,
    )

    proposal = _multi_proposal() if kind == "multi" else _partial_proposal()
    confirmation = _confirm(proposal)
    approval = approve_policy_translation_proposal(
        proposal,
        confirmation,
        approved_by="policy-owner",
        approved_at="2026-09-03T12:03:00Z",
    )
    return finalize_policy_translation_authority_v3(
        proposal,
        confirmation,
        approval,
        committed_by="ledger-committer",
        committed_at="2026-09-03T12:04:00Z",
        publication_id=publication_id,
        published_by="ledger-publisher",
        published_at="2026-09-03T12:05:00Z",
    )


def _write_artifacts(root: Path, publication: dict, *, receipt: dict | None = None):
    bundle = publication["authority_bundle"]
    actual_receipt = publication["publication_receipt"] if receipt is None else receipt
    contracts = root / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)
    bundle_name = "repository-authority-1.0.0.authority-bundle.json"
    receipt_name = "repository-authority-1.0.0.publication-receipt.json"
    (contracts / bundle_name).write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")
    if actual_receipt is not False:
        (contracts / receipt_name).write_text(json.dumps(actual_receipt, sort_keys=True), encoding="utf-8")
    entry = {
        "authority_ref": AUTHORITY_REF,
        "contract_id": "repository-authority",
        "contract_version": "1.0.0",
        "contract_hash": publication["compiled_authority_contract"]["contract_hash"],
        "bundle_path": f"contracts/{bundle_name}",
        "bundle_hash": bundle["bundle_hash"],
        "publication_id": publication["publication_receipt"]["publication_id"],
        "lifecycle_state": "active",
        "published_at": publication["publication_receipt"]["published_at"],
        "published_by": publication["publication_receipt"]["published_by"],
    }
    if actual_receipt is not False:
        entry.update(
            receipt_path=f"contracts/{receipt_name}",
            receipt_hash=actual_receipt["receipt_hash"],
        )
    registry = {"schema_version": "contract_registry.v1", "contracts": [entry]}
    registry["registry_hash"] = _canonical_hash(registry)
    registry_path = contracts / "index.json"
    registry_path.write_text(json.dumps(registry, sort_keys=True), encoding="utf-8")
    return LocalRegistryResolver(registry_path=registry_path, workspace_root=root)


def test_v3_multi_control_publication_loads_and_enforces_both_controls(
    tmp_path, multi_publication
):
    cache = MemoryAuthorityCache()
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=_write_artifacts(tmp_path / "publication", multi_publication),
        authority_cache=cache,
        actor_identity={"id": "agent", "type": "agent"},
    )
    calls = []

    @guard.tool(action="modify", target="path", return_result=True)
    def modify(path):
        calls.append(path)
        return path

    assert modify("README.md")["executed"] is True
    assert modify("CHANGELOG.md")["executed"] is True
    with pytest.raises(GuardExecutionBlocked):
        modify("src/secrets.py")
    assert calls == ["README.md", "CHANGELOG.md"]
    loaded = guard.boundary_for().loaded_authority
    assert loaded.schema_version == "authority_bundle.v3"
    assert loaded.contract["schema_version"] == "compiled_authority_contract.v2"
    assert loaded.authority_evidence["authority_bundle"]["schema_version"] == "authority_bundle.v3"
    assert loaded.authority_evidence["publication_receipt"]["schema_version"] == "publication_receipt.v3"
    assert len(cache) == 1


def test_v3_partial_coverage_enforces_only_control_and_residual_is_not_executable(
    tmp_path, partial_publication
):
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=_write_artifacts(tmp_path / "publication", partial_publication),
        actor_identity={"id": "agent", "type": "agent"},
    )
    boundary = guard.boundary_for()
    assert boundary.evaluate(_request("docs/guide.md"), save=False)["status"] == "admissible"
    assert boundary.evaluate(_request("crypto/key.py"), save=False)["status"] == "blocked"
    commitment = boundary.loaded_authority.authority_bundle["policy_translation_commitment"]
    clause = commitment["clauses"][0]
    assert clause["customer_coverage_state"] == "Partially enforceable"
    assert clause["residuals"][0]["acknowledgment"]["acknowledged_by"] == "policy-owner"
    assert "documentation" not in json.dumps(boundary.compiled_authority)


def test_v3_publication_does_not_require_private_translation_evidence(
    tmp_path, multi_publication
):
    private = tmp_path / "private-translation-evidence.json"
    private.write_text('{"request":"private","response":"private","explanation":"private"}', encoding="utf-8")
    private.unlink()
    public_json = json.dumps(
        {
            "bundle": multi_publication["authority_bundle"],
            "receipt": multi_publication["publication_receipt"],
        }
    )
    assert "private-provider" not in public_json
    assert "private-request" not in public_json
    assert "private-response" not in public_json
    loaded = load_authority(
        AUTHORITY_REF,
        resolver=_write_artifacts(tmp_path / "publication", multi_publication),
    )
    assert loaded.schema_version == "authority_bundle.v3"


def test_v3_requires_receipt(tmp_path, multi_publication):
    resolver = _write_artifacts(tmp_path, multi_publication, receipt=False)
    with pytest.raises(AuthorityVerificationError, match="authority_bundle.v3 requires a publication receipt"):
        load_authority(AUTHORITY_REF, resolver=resolver)


def test_v3_rejects_cross_version_receipt(tmp_path, multi_publication):
    receipt = copy.deepcopy(multi_publication["publication_receipt"])
    receipt["schema_version"] = "publication_receipt.v2"
    receipt["receipt_hash"] = _canonical_hash(
        {key: value for key, value in receipt.items() if key != "receipt_hash"}
    )
    resolver = _write_artifacts(tmp_path, multi_publication, receipt=receipt)
    with pytest.raises(AuthorityVerificationError, match="schema versions do not match"):
        load_authority(AUTHORITY_REF, resolver=resolver)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda bundle: bundle["source_policy"].__setitem__("snapshot_hash", "sha256:" + "0" * 64),
        lambda bundle: bundle["authority"].__setitem__("authority_ref", "other@1.0.0"),
        lambda bundle: bundle["domain_pack"].__setitem__("domain_pack_hash", "sha256:" + "0" * 64),
        lambda bundle: bundle["constraint_ir"].__setitem__("ir_hash", "sha256:" + "0" * 64),
        lambda bundle: bundle["compiled_authority_contract"].__setitem__("contract_hash", "sha256:" + "0" * 64),
        lambda bundle: bundle["publication_manifest"].__setitem__("publication_id", "substituted"),
    ],
)
def test_v3_tampering_and_substitution_fail_before_activation(
    tmp_path, multi_publication, mutation
):
    changed = copy.deepcopy(multi_publication)
    mutation(changed["authority_bundle"])
    resolver = _write_artifacts(tmp_path, changed)
    with pytest.raises(AuthorityVerificationError, match="Ledger rejected the v3 publication chain"):
        load_authority(AUTHORITY_REF, resolver=resolver)


def test_v3_cross_publication_substitution_fails(tmp_path, multi_publication):
    other = _publication("multi", publication_id="publication-2")
    resolver = _write_artifacts(
        tmp_path,
        multi_publication,
        receipt=other["publication_receipt"],
    )
    with pytest.raises(AuthorityVerificationError, match="Ledger rejected the v3 publication chain"):
        load_authority(AUTHORITY_REF, resolver=resolver)


def test_v3_runtime_fact_incompatibility_fails_closed(tmp_path, multi_publication):
    guard = Guard.local(
        workspace=tmp_path / "evidence",
        authority=AUTHORITY_REF,
        authority_resolver=_write_artifacts(tmp_path / "publication", multi_publication),
        actor_identity={"id": "agent", "type": "agent"},
    )
    with pytest.raises(RuntimeFactError):
        guard.boundary_for().evaluate(
            {**_request("README.md"), "runtime_facts": {"proposal.resource.path": 42}},
            save=False,
        )


def test_v3_cache_is_verified_reused_and_drift_rejected(
    tmp_path, multi_publication, monkeypatch
):
    import governance_ledger

    resolver = _write_artifacts(tmp_path, multi_publication)
    cache = MemoryAuthorityCache()
    calls = 0
    original = governance_ledger.validate_authority_bundle

    def counted(bundle):
        nonlocal calls
        calls += 1
        return original(bundle)

    monkeypatch.setattr(governance_ledger, "validate_authority_bundle", counted)
    first = load_authority(AUTHORITY_REF, resolver=resolver, cache=cache)
    second = load_authority(AUTHORITY_REF, resolver=resolver, cache=cache)
    assert first == second
    assert calls == 1

    key = (AUTHORITY_REF, multi_publication["authority_bundle"]["bundle_hash"].removeprefix("sha256:"))
    cache._entries[key].contract["target_requirements"]["allow"][0]["value"] = "OTHER.md"
    with pytest.raises(AuthorityVerificationError, match="cached runtime authority integrity mismatch"):
        load_authority(AUTHORITY_REF, resolver=resolver, cache=cache)
    assert calls == 2


def test_v3_unverified_and_cross_authority_cache_substitution_are_rejected(
    tmp_path, multi_publication
):
    resolver = _write_artifacts(tmp_path, multi_publication)
    loaded = load_authority(AUTHORITY_REF, resolver=resolver)
    with pytest.raises(AuthorityVerificationError, match="v3 authority must complete publication validation"):
        MemoryAuthorityCache().put(replace(loaded, _verification_marker=None))

    substituted = replace(loaded, authority_ref="other-authority@1.0.0")

    class SubstitutionCache:
        def get(self, authority_ref, bundle_hash):
            return substituted

        def put(self, authority):
            raise AssertionError("substituted authority must not be cached")

    with pytest.raises(AuthorityVerificationError, match="cached authority_ref mismatch"):
        load_authority(AUTHORITY_REF, resolver=resolver, cache=SubstitutionCache())


def test_v3_delegates_to_version_dispatched_ledger_validators(
    tmp_path, multi_publication, monkeypatch
):
    import governance_ledger

    calls = {"bundle": 0, "receipt": 0}
    originals = {
        "bundle": governance_ledger.validate_authority_bundle,
        "receipt": governance_ledger.validate_publication_receipt,
    }

    def count(label):
        def invoke(*args, **kwargs):
            calls[label] += 1
            return originals[label](*args, **kwargs)

        return invoke

    monkeypatch.setattr(governance_ledger, "validate_authority_bundle", count("bundle"))
    monkeypatch.setattr(governance_ledger, "validate_publication_receipt", count("receipt"))
    load_authority(AUTHORITY_REF, resolver=_write_artifacts(tmp_path, multi_publication))
    assert calls == {"bundle": 1, "receipt": 1}


def test_v3_incomplete_ledger_result_stops_before_receipt_or_runtime_projection(
    monkeypatch, tmp_path
):
    import governance_ledger

    monkeypatch.setattr(
        governance_ledger,
        "validate_authority_bundle",
        lambda bundle: {
            "schema_version": "authority_bundle.v3",
            "provenance_complete": False,
        },
    )
    monkeypatch.setattr(
        governance_ledger,
        "validate_publication_receipt",
        lambda *args: pytest.fail("receipt validation must not follow an incomplete bundle"),
    )
    with pytest.raises(AuthorityVerificationError, match="provenance-complete authority_bundle.v3"):
        AuthorityVerifier().verify(_minimal_v3_bundle(tmp_path))


def test_v3_with_ledger_07_fails_as_clear_unsupported_version(monkeypatch, tmp_path):
    import governance_ledger

    monkeypatch.setattr(
        governance_ledger,
        "validate_authority_bundle",
        lambda bundle: {"profile": "legacy_incomplete", "provenance_complete": False},
    )
    with pytest.raises(
        AuthorityVerificationError,
        match=r"governance-ledger>=0\.8\.0 is required",
    ):
        AuthorityVerifier().verify(_minimal_v3_bundle(tmp_path))
