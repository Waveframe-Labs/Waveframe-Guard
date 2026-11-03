"""Live containment using immutable artifacts from the Stream #3 reproduction."""
import copy
import json
from pathlib import Path

import pytest

from guard.cognition.admissibility import assess_admissibility
from guard.sdk import Guard, GuardExecutionBlocked, LocalEvaluationStore
from governance_ledger import validate_authority_bundle, validate_publication_receipt
from waveframe_guard.authority import MemoryAuthorityCache, load_authority
from waveframe_guard.authority.adapters import LocalRegistryResolver

FIXTURES = Path(__file__).parent / "fixtures" / "deny_only_v2"


def _read(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _resolver(root, bundle, receipt):
    root.mkdir(parents=True, exist_ok=True)
    for name, payload in [("bundle.json", bundle), ("receipt.json", receipt)]:
        (root / name).write_text(json.dumps(payload), encoding="utf-8")
    contract = bundle["compiled_authority_contract"]
    entry = dict(authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
                 contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
                 bundle_path="bundle.json", bundle_hash=bundle["bundle_hash"], receipt_path="receipt.json",
                 receipt_hash=receipt["receipt_hash"], lifecycle_state="active", publication_id=receipt["publication_id"],
                 published_at=receipt["published_at"], published_by=receipt["published_by"])
    registry = dict(schema_version="contract_registry.v1", contracts=[entry])
    from hashlib import sha256
    registry["registry_hash"] = "sha256:" + sha256(json.dumps(registry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    (root / "index.json").write_text(json.dumps(registry), encoding="utf-8")
    return LocalRegistryResolver(registry_path=root / "index.json", workspace_root=root)


def _request(target):
    return dict(schema_version="normalized_execution_request.v1", request_id="synthetic-request",
                action="modify", target=target, arguments={}, artifacts=[])


MATRIX = _read("historical-matrix.json")


@pytest.mark.parametrize("authority", MATRIX, ids=lambda row: row["producer_stack"]["waveframe-guard"] + "-" + row["case"])
@pytest.mark.parametrize("target", ["README.md", "deployment/prod.yml", "secrets/prod.key"])
def test_33_evaluation_historical_producer_matrix(tmp_path, authority, target):
    bundle, receipt = authority["bundle"], authority["receipt"]
    before = copy.deepcopy(authority)
    validate_authority_bundle(bundle)
    validate_publication_receipt(bundle, receipt)
    resolver = _resolver(tmp_path / "publication", bundle, receipt)
    repo = tmp_path / "repo"
    repo.mkdir()
    path = repo / target
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unchanged")
    guard = Guard.local(workspace=tmp_path / "evidence", repository_root=repo,
                        authority=bundle["compiled_authority_contract"]["authority_ref"], authority_resolver=resolver,
                        actor_identity=dict(id="synthetic-agent", type="agent", role="repository-maintainer"))
    try:
        result = guard.boundary_for().evaluate(_request(target))
        expected = "admissible" if authority["case"] == "allow-and-deny" and target == "README.md" else "blocked"
        assert result["status"] == expected
        assert guard.store.replay(guard.store.history()[0]["run_id"])["matches"]
    finally:
        guard.close()
    assert path.read_bytes() == b"unchanged"
    assert authority == before


@pytest.mark.parametrize("envelope", ["v2", "v3"])
@pytest.mark.parametrize("mode", ["fresh", "resolved", "cached"])
def test_verified_deny_only_cannot_execute_in_any_loading_mode(tmp_path, envelope, mode):
    if envelope == "v2":
        bundle, receipt = _read("bundle.json"), _read("receipt.json")
        denied = "deployment/prod.yml"
    else:
        historical = _read("historical-partial-v3.json")["finalization"]
        bundle, receipt = historical["authority_bundle"], historical["publication_receipt"]
        denied = "crypto/key.txt"
    before = copy.deepcopy((bundle, receipt))
    assert validate_authority_bundle(bundle)["provenance_complete"]
    validate_publication_receipt(bundle, receipt)
    resolver = _resolver(tmp_path / "publication", bundle, receipt)
    cache = MemoryAuthorityCache()
    ref = bundle["compiled_authority_contract"]["authority_ref"]
    if mode in {"resolved", "cached"}:
        load_authority(ref, resolver=resolver, cache=cache if mode == "cached" else None)
    repo = tmp_path / "repo"
    repo.mkdir()
    targets = ["README.md", denied, "secrets/prod.key"]
    for target in targets:
        path = repo / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"unchanged")
    guard = Guard.local(workspace=tmp_path / "evidence", repository_root=repo, authority=ref,
                        authority_resolver=resolver, authority_cache=cache if mode == "cached" else None,
                        actor_identity=dict(id="synthetic-agent", type="agent", role="repository-maintainer"))
    try:
        boundary = guard.boundary_for()
        calls = []
        for target in targets:
            result = boundary.evaluate(_request(target))
            assert result["status"] == "blocked"
            diagnostic = "target_scope_deny" if target == denied else "affirmative_path_grant"
            assert result["violated_constraints"][0]["constraint"] == diagnostic
            if target != denied:
                assert "fresh human approval" in result["rationale"]
            with pytest.raises(GuardExecutionBlocked):
                boundary.execute_repository(lambda path: calls.append(path), execution_request=_request(target))
        assert calls == []
        assert all((repo / target).read_bytes() == b"unchanged" for target in targets)
        # New blocked decisions replay deterministically, with no execution capability.
        assert all(guard.store.replay(record["run_id"])["matches"] for record in guard.store.history())
    finally:
        guard.close()
    assert (bundle, receipt) == before


def test_historical_admission_is_preserved_and_replay_exposes_current_refusal(tmp_path):
    record = _read("historical-evaluation.json")
    assert record["evaluation"]["status"] == "admissible"
    store = LocalEvaluationStore(tmp_path)
    store.history_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    before = store.history_path.read_bytes()
    replay = store.replay(record["run_id"])
    assert replay["matches"] is False
    assert replay["replayed_evaluation"]["status"] == "blocked"
    assert replay["original_outcome_hash"] == record["guard_enforcement_outcome"]["outcome_hash"]
    assert replay["replay_scope"] == "logical_decision_only"
    assert replay["filesystem_state_recreated"] is False
    assert store.history_path.read_bytes() == before


def test_v1_keeps_legacy_default_and_v2_empty_rules_have_actionable_refusal():
    contract = _read("bundle.json")["compiled_authority_contract"]
    for version, status in [("v1", "admissible"), ("v2", "blocked")]:
        candidate = {**contract, "schema_version": "compiled_authority_contract." + version}
        result = assess_admissibility(compiled_authority=candidate, execution_request=_request("secrets/prod.key"),
                                      actor_identity=dict(id="synthetic-agent", type="agent", role="repository-maintainer"))
        assert result["status"] == status
    contract["target_requirements"]["deny"] = []
    result = assess_admissibility(compiled_authority=contract, execution_request=_request("README.md"),
                                  actor_identity=dict(role="repository-maintainer"))
    assert result["violated_constraints"][0]["constraint"] == "affirmative_path_grant"


def test_explicit_allow_deny_precedence_and_role_are_not_relaxed():
    contract = _read("bundle.json")["compiled_authority_contract"]
    contract["target_requirements"]["allow"] = [{"match": "prefix", "value": "deployment/"}]
    for target, role, diagnostic in [("deployment/prod.yml", "repository-maintainer", "target_scope_deny"),
                                     ("secrets/prod.key", "repository-maintainer", "target_scope_allow"),
                                     ("deployment/prod.yml", "outsider", "target_scope_deny")]:
        result = assess_admissibility(compiled_authority=contract, execution_request=_request(target), actor_identity=dict(role=role))
        assert result["status"] == "blocked"
        assert result["violated_constraints"][0]["constraint"] == diagnostic
