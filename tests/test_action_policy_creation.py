"""Real pinned publication intake and Windows/Linux file creation acceptance."""

import copy
from dataclasses import replace
import json
import os

import pytest

from guard.adapters.compiled_authority import intake_compiled_authority, CompiledAuthorityIntakeError
from guard.runtime import evaluate_runtime
from guard.sdk import Guard, GuardExecutionBlocked, RepositoryBoundaryError
from waveframe_guard.authority import MemoryAuthorityCache, load_authority
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.authority.loader import BundleLoader
from waveframe_guard.authority.verifier import AuthorityVerifier
from tools.acceptance.action_policy_creation import resolver, FIXTURES, provenance, run

ENABLED = os.environ.get("WAVEFRAME_GUARD_ACTION_POLICY_DEV") == "1"
development = pytest.mark.skipif(not ENABLED, reason="requires explicit action policy development environment")


def request(path="generated/new.md", action="create"):
    return {"schema_version": "normalized_execution_request.v1", "request_id": "creation-acceptance",
            "action": action, "target": path, "arguments": {}, "artifacts": []}


@pytest.fixture
def runtime(tmp_path):
    instances = []
    (tmp_path / "generated").mkdir()
    (tmp_path / "README.md").write_bytes(b"original")
    def make(kind="create-only", role="repository-maintainer", **kwargs):
        instance = Guard.local(repository_root=tmp_path, workspace=tmp_path / "evidence",
            authority=f"repository-{kind}@2.0.0", authority_resolver=resolver(kind),
            actor_identity={"id": "agent", "type": "agent", "role": role}, **kwargs)
        instances.append(instance)
        return instance
    yield make, tmp_path
    for instance in instances:
        instance.close()


@pytest.mark.parametrize("gate", ["WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"])
def test_default_gate_rejects_native_publication(monkeypatch, gate):
    monkeypatch.delenv(gate, raising=False)
    with pytest.raises(AuthorityVerificationError, match="development"):
        load_authority("repository-create-only@2.0.0", resolver=resolver("create-only"))


def test_standalone_contract_and_caller_verified_flag_rejected():
    contract = json.loads((FIXTURES / "create-only/compiled-authority.json").read_text())
    for kwargs in ({}, {"_verified_v2_authority": True}, {"_verified_runtime_authority": True}):
        with pytest.raises(CompiledAuthorityIntakeError):
            intake_compiled_authority(contract, **kwargs)


@development
def test_exact_dependencies_and_installed_public_api_acceptance():
    assert provenance()
    assert run()["creation"]["repository_operation"]["created"]


@development
@pytest.mark.parametrize("kind,role,action,path,status", [
    ("create-only", "repository-maintainer", "create", "generated/new.md", "admissible"),
    ("create-only", "repository-maintainer", "modify", "generated/new.md", "blocked"),
    ("create-only", "repository-maintainer", "create", "generated/private/key", "blocked"),
    ("create-only", "security-reviewer", "create", "generated/new.md", "blocked"),
    ("create-only", "repository-maintainer", "create", "other.md", "blocked"),
    ("modify-only", "repository-maintainer", "create", "README.md", "blocked"),
    ("mixed", "repository-maintainer", "create", "generated/new.md", "admissible"),
    ("mixed", "repository-maintainer", "modify", "README.md", "blocked"),
    ("mixed", "security-reviewer", "modify", "README.md", "admissible"),
    ("mixed", "security-reviewer", "create", "generated/new.md", "blocked"),
])
def test_action_roles_paths_and_evaluation_only(runtime, kind, role, action, path, status):
    make, root = runtime
    instance = make(kind, role)
    boundary = instance.boundary_for()
    assert boundary.evaluate(request(path, action), save=False)["status"] == status
    assert not (root / "generated/new.md").exists()
    if status == "blocked":
        result = boundary.execute_repository(lambda target: pytest.fail("denied callback invoked"),
            execution_request=request(path, action), operation=action, raise_on_block=False)
        assert not result["executed"]
        assert result["evaluation"]["execution_attestation"]["mutation_executed"] is False


@development
def test_creation_once_expiry_and_modify_separation(runtime):
    make, root = runtime
    instance = make()
    retained = []
    @instance.repository_tool(action="create", target="path", return_result=True)
    def create(path):
        retained.append(path)
        with pytest.raises(RepositoryBoundaryError, match="cannot modify"):
            path.write_bytes(b"wrong operation")
        count = path.create_bytes(b"created")
        with pytest.raises(RepositoryBoundaryError, match="consumed"):
            path.create_bytes(b"twice")
        return count
    result = create("generated/new.md")
    assert result["value"] == 7
    assert (root / "generated/new.md").read_bytes() == b"created"
    with pytest.raises(RepositoryBoundaryError, match="not active"):
        retained[0].create_bytes(b"expired")
    with pytest.raises(RepositoryBoundaryError, match="match"):
        instance.boundary_for().execute_repository(lambda t: None, execution_request=request())


@development
def test_missing_parent_preserves_allowed_decision(runtime):
    make, root = runtime
    with pytest.raises(RepositoryBoundaryError) as error:
        make().boundary_for().execute_repository(lambda t: pytest.fail("callback"),
            execution_request=request("generated/missing/file"), operation="create")
    assert error.value.evaluation["status"] == "admissible"
    assert error.value.evaluation["execution_attestation"]["mutation_executed"] is False
    assert not (root / "generated/missing").exists()


@development
def test_partial_write_failure_is_not_rollback(runtime, monkeypatch):
    import guard.sdk.repository_boundary as filesystem
    make, root = runtime
    instance = make()
    original = filesystem.os.write
    writes = []
    def fail_after_prefix(fd, content):
        if writes:
            raise OSError("simulated disk failure")
        count = original(fd, content[:3])
        writes.append(count)
        return count
    @instance.repository_tool(action="create", target="path")
    def create(path):
        return path.create_bytes(b"private content")
    with monkeypatch.context() as patch:
        patch.setattr(filesystem.os, "write", fail_after_prefix)
        with pytest.raises(OSError) as error:
            create("generated/new.md")
    evaluation = error.value.evaluation
    assert evaluation["status"] == "admissible"
    proof = instance.store.load_execution_attestation(evaluation["run_id"])
    operation = proof["repository_operation"]
    assert operation["created"] and operation["bytes_written"] == 3 and operation["status"] == "failed"
    assert proof["mutation_status"] == "unknown"
    assert (root / "generated/new.md").read_bytes() == b"pri"
    assert "private content" not in json.dumps(instance.store.history())


@development
def test_gate_revocation_contract_and_cache_substitution(runtime, monkeypatch):
    make, root = runtime
    cache = MemoryAuthorityCache()
    instance = make(authority_cache=cache)
    boundary = instance.boundary_for()
    boundary.compiled_authority["action_requirements"]["create"]["required_role"] = None
    with pytest.raises(AuthorityVerificationError):
        boundary.evaluate(request())
    loaded = load_authority("repository-create-only@2.0.0", resolver=resolver("create-only"), cache=cache)
    loaded.authority_bundle["compiled_authority_contract"]["action_requirements"]["create"]["allow"] = []
    cache.put(loaded)
    with pytest.raises(AuthorityVerificationError):
        load_authority(loaded.authority_ref, resolver=resolver("create-only"), cache=cache)
    monkeypatch.delenv("WAVEFRAME_GUARD_ACTION_POLICY_DEV")
    with pytest.raises(AuthorityVerificationError):
        instance.boundary_for().evaluate(request())


@development
@pytest.mark.parametrize("schema", ["authority_bundle.v1", "authority_bundle.v2", "authority_bundle.v3", "authority_bundle.v5"])
def test_downgraded_or_unknown_envelopes_rejected(schema):
    entry = resolver("mixed").resolve("repository-mixed@2.0.0")
    bundle = BundleLoader().load(entry)
    payload = copy.deepcopy(bundle.payload)
    payload["schema_version"] = schema
    with pytest.raises(AuthorityVerificationError):
        AuthorityVerifier().verify(replace(bundle, payload=payload))


@development
def test_replay_revalidates_retained_publication(runtime):
    make, root = runtime
    instance = make()
    @instance.repository_tool(action="create", target="path", return_result=True)
    def create(path):
        return path.create_bytes(b"created")
    result = create("generated/new.md")
    replay = instance.store.replay(result["evaluation"]["run_id"])
    assert replay["matches"] and replay["filesystem_state_recreated"] is False
    assert (root / "generated/new.md").read_bytes() == b"created"


@development
@pytest.mark.parametrize("injected", ["facts", "runtime_facts", "proposal.action", "actor.role"])
def test_injected_facts_rejected(runtime, injected):
    make, root = runtime
    boundary = make().boundary_for()
    actor = {"id": "agent", "type": "agent", "role": "repository-maintainer", injected: "spoof"}
    with pytest.raises(AuthorityVerificationError):
        boundary.evaluate(request(), actor_identity=actor)
    invalid = request()
    invalid[injected] = "spoof"
    with pytest.raises(RepositoryBoundaryError):
        boundary.evaluate(invalid)
    assert not (root / "generated/new.md").exists()


@development
@pytest.mark.parametrize("path", ["../escape", "generated/../escape", "generated/new.md:stream", "generated/NUL",
    "generated/./new.md", "generated/new.md.", "generated\\new.md", "/absolute", "C:/absolute"])
def test_unsupported_creation_paths_fail_closed(runtime, path):
    make, root = runtime
    with pytest.raises(RepositoryBoundaryError):
        make().boundary_for().execute_repository(lambda target: pytest.fail("callback"),
            execution_request=request(path), operation="create")
    assert list((root / "generated").iterdir()) == []


@development
def test_parent_replacement_between_evaluation_and_binding(runtime, monkeypatch):
    make, root = runtime
    boundary = make().boundary_for()
    original = boundary.evaluate
    def substitute(*args, **kwargs):
        result = original(*args, **kwargs)
        (root / "generated").rename(root / "old-parent")
        (root / "generated").mkdir()
        return result
    monkeypatch.setattr(boundary, "evaluate", substitute)
    with pytest.raises((RepositoryBoundaryError, PermissionError)):
        boundary.execute_repository(lambda target: pytest.fail("callback"),
            execution_request=request(), operation="create")
    assert not (root / "generated/new.md").exists()
    assert not (root / "old-parent/new.md").exists()


@development
def test_parent_substitution_inside_callback(runtime):
    make, root = runtime
    instance = make()
    @instance.repository_tool(action="create", target="path")
    def create(path):
        if os.name == "nt":
            with pytest.raises(OSError):
                (root / "generated").rename(root / "old-parent")
            return path.create_bytes(b"locked parent")
        (root / "generated").rename(root / "old-parent")
        (root / "generated").mkdir()
        return path.create_bytes(b"must not write")
    if os.name == "nt":
        create("generated/new.md")
        assert (root / "generated/new.md").read_bytes() == b"locked parent"
    else:
        with pytest.raises(RepositoryBoundaryError):
            create("generated/new.md")
        assert not (root / "generated/new.md").exists()
        assert not (root / "old-parent/new.md").exists()


@development
def test_real_indirection_and_case_alias_rejected(runtime):
    import subprocess
    make, root = runtime
    (root / "outside").mkdir()
    link = root / "generated/link"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(root / "outside")], check=True, capture_output=True)
    else:
        link.symlink_to(root / "outside", target_is_directory=True)
    boundary = make().boundary_for()
    with pytest.raises(RepositoryBoundaryError):
        boundary.execute_repository(lambda t: pytest.fail("callback"),
            execution_request=request("generated/link/file"), operation="create")
    if os.name == "nt":
        with pytest.raises(RepositoryBoundaryError):
            boundary.evaluate(request("Generated/new.md"))
    assert not (root / "outside/file").exists()


@development
def test_escalated_no_callback_or_creation(runtime):
    make, root = runtime
    boundary = make(continuity_state={"requires_revalidation": True}).boundary_for()
    result = boundary.execute_repository(lambda target: pytest.fail("escalated callback"),
        execution_request=request(), operation="create", raise_on_block=False)
    assert result["evaluation"]["status"] == "escalated"
    assert not result["executed"] and not (root / "generated/new.md").exists()


@development
def test_modify_grant_cannot_create_missing_file(runtime):
    make, root = runtime
    instance = make("mixed", "security-reviewer")
    (root / "README.md").unlink()
    with pytest.raises(RepositoryBoundaryError):
        instance.boundary_for().execute_repository(lambda t: t.create_bytes(b"wrong"),
            execution_request=request("README.md", "modify"))
    assert not (root / "README.md").exists()


def test_legacy_contract_cannot_authorize_creation(tmp_path):
    from test_repository_workspace import authority
    instance = Guard.local(repository_root=tmp_path, workspace=tmp_path / "evidence", contract=authority())
    try:
        result = instance.boundary_for().execute_repository(lambda t: pytest.fail("legacy create"),
            execution_request=request("safe/new.md"), operation="create", raise_on_block=False)
        assert result["evaluation"]["status"] == "blocked"
        assert not (tmp_path / "safe").exists()
    finally:
        instance.close()


@development
@pytest.mark.parametrize("change", ["receipt_schema", "contract_action", "contract_field", "pack_hash", "schema_hash"])
def test_malformed_native_publication_rejected(change):
    entry = resolver("mixed").resolve("repository-mixed@2.0.0")
    bundle = BundleLoader().load(entry)
    payload, receipt = copy.deepcopy(bundle.payload), copy.deepcopy(bundle.receipt_payload)
    if change == "receipt_schema":
        receipt["schema_version"] = "publication_receipt.v3"
    elif change == "contract_action":
        payload["compiled_authority_contract"]["action_requirements"]["delete"] = {}
    elif change == "contract_field":
        payload["compiled_authority_contract"]["unrecognized"] = True
    elif change == "pack_hash":
        payload["domain_pack"]["domain_pack_hash"] = "sha256:" + "0" * 64
    else:
        payload["runtime_fact_schema"]["schema_hash"] = "sha256:" + "0" * 64
    with pytest.raises(AuthorityVerificationError):
        AuthorityVerifier().verify(replace(bundle, payload=payload, receipt_payload=receipt))


@development
def test_cache_marker_registry_lifecycle_and_loaded_substitution(runtime):
    from waveframe_guard.authority.runtime_facts import VerifiedRuntimeAuthority
    make, root = runtime
    cache = MemoryAuthorityCache()
    source = resolver("create-only")
    ref = "repository-create-only@2.0.0"
    loaded = load_authority(ref, resolver=source, cache=cache)
    assert load_authority(ref, resolver=source, cache=cache).contract == loaded.contract
    with pytest.raises(AuthorityVerificationError):
        cache.put(replace(loaded, _verification_marker=None))
    with pytest.raises(AuthorityVerificationError):
        VerifiedRuntimeAuthority.from_loaded(replace(loaded, schema_version="authority_bundle.v3"))
    source.entries[ref] = replace(source.entries[ref], lifecycle_state="revoked")
    with pytest.raises(AuthorityVerificationError):
        load_authority(ref, resolver=source, cache=cache)
    boundary = make().boundary_for()
    boundary.loaded_authority.contract["action_requirements"]["create"]["required_role"] = None
    with pytest.raises(AuthorityVerificationError):
        boundary.execute_repository(lambda t: pytest.fail("substituted authority"),
            execution_request=request(), operation="create")


@development
def test_gate_revocation_inside_callback_prevents_creation(runtime, monkeypatch):
    make, root = runtime
    instance = make()
    @instance.repository_tool(action="create", target="path")
    def create(path):
        monkeypatch.delenv("WAVEFRAME_GUARD_ACTION_POLICY_DEV")
        return path.create_bytes(b"must not create")
    with pytest.raises(AuthorityVerificationError):
        create("generated/new.md")
    assert not (root / "generated/new.md").exists()


@development
def test_creation_rejects_cloud_clients(runtime):
    make, root = runtime
    instance = make()
    instance.cloud_runtime_client = object()
    with pytest.raises(AuthorityVerificationError, match="local only"):
        instance.boundary_for()
