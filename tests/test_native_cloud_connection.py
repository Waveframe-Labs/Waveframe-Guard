"""Native intake and reporting faults; connected acceptance uses the real server separately."""
from copy import deepcopy
import json
import os

import pytest
import requests

from waveframe_guard import Guard, RepositoryBoundaryError
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.cloud import CloudAuthorityFetchError, CloudPublicationProtocolError
from guard.runtime.identity import stable_hash
from tools.acceptance.action_policy_creation import FIXTURES, resolver
from test_cloud_publication_resolver import _serve, _rehash


development = pytest.mark.skipif(os.environ.get("WAVEFRAME_GUARD_ACTION_POLICY_DEV") != "1",
                               reason="requires explicit action policy development environment")


def publication(kind="create-only"):
    entry = resolver(kind).resolve(f"repository-{kind}@2.0.0")
    registry = {key: getattr(entry, key) for key in (
        "authority_ref", "contract_id", "contract_version", "contract_hash", "publication_id",
        "bundle_ref", "bundle_hash", "receipt_ref", "receipt_hash", "lifecycle_state", "published_at", "published_by")}
    return _rehash({"schema_version": "cloud_authority_publication.v1", "organization_id": "test-org",
        "authority_ref": entry.authority_ref, "registry_entry": registry,
        "authority_bundle": json.loads(entry.bundle_path.read_text()),
        "publication_receipt": json.loads(entry.receipt_path.read_text())})


class Response:
    def __init__(self, value, status=200):
        self.value, self.status_code = value, status
        self.text = json.dumps(value)

    def json(self):
        return self.value


@pytest.fixture
def connected(tmp_path, monkeypatch):
    state = {"publication_body": json.dumps(publication()).encode()}
    server, url = _serve(state)
    calls, instances = [], []
    def post(url, **kwargs):
        calls.append((url, deepcopy(kwargs["json"])))
        assert kwargs["allow_redirects"] is False
        fault = state.get("preserve_fault" if url.endswith("/preserve") else "report_fault")
        if fault:
            if isinstance(fault, Exception):
                raise fault
            return Response({"error": "rejected"}, fault)
        return Response({"package_id": "package", "receipt_id": "receipt", "sha256": "hash", "timestamp": "now"})
    monkeypatch.setattr(requests, "post", post)
    (tmp_path / "generated").mkdir()
    def make(**kwargs):
        options = dict(authority="repository-create-only@2.0.0", workspace=tmp_path / "evidence",
            repository_root=tmp_path, cloud_url=url, cloud_organization_id="test-org", runtime_id="assigned-runtime",
            runtime_credential="disposable-secret", actor_identity={"id": "actor", "type": "agent", "role": "repository-maintainer"})
        options.update(kwargs)
        instance = Guard.cloud(**options)
        instances.append(instance)
        return instance
    yield make, state, calls, tmp_path
    for instance in instances:
        instance.close()
    server.shutdown()
    server.server_close()


def request(path="generated/new.md"):
    return {"schema_version": "normalized_execution_request.v1", "request_id": "test-native",
            "action": "create", "target": path, "arguments": {}, "artifacts": []}


@development
@pytest.mark.parametrize("case,status,mutation", [
    ("created", "succeeded", True), ("empty", "succeeded", True),
    ("collision", "failed", False), ("partial", "failed", True),
    ("unknown", "failed", None), ("callback-return", "failed", None),
    ("post-validation", "failed", True), ("pre-callback", "not_executed", False),
    ("missing-parent", "not_executed", False), ("blocked", "blocked", False),
])
def test_automatic_reports_use_validated_operation(connected, case, status, mutation):
    make, state, calls, root = connected
    instance = make(execution_context={"surface": "example", "trace": {"value": 1}})
    callbacks = []
    @instance.repository_tool(action="create", target="path", return_result=True, raise_on_block=False)
    def create(path):
        callbacks.append(path)
        if case == "collision":
            (root / "generated/new.md").write_bytes(b"competitor")
        if case == "unknown":
            raise RuntimeError("unconfirmed")
        if case == "callback-return":
            return {"created": True, "bytes_written": 100}
        count = path.create_bytes(b"" if case == "empty" else b"content")
        if case == "partial":
            raise RuntimeError("after mutation")
        if case == "post-validation":
            def fail():
                raise RepositoryBoundaryError("post validation")
            path._validate = fail
        return count
    if case == "pre-callback":
        original = instance.cloud_preservation_client.preserve
        def preserve(package):
            result = original(package)
            # Confirmed namespace configuration refusal after the saved decision.
            instance._repository_workspace._binding_id = "changed"
            return result
        instance.cloud_preservation_client.preserve = preserve
    target = "other.md" if case == "blocked" else "generated/missing/new.md" if case == "missing-parent" else "generated/new.md"
    try:
        result = create(target)
        evaluation = result["evaluation"]
    except (RepositoryBoundaryError, RuntimeError) as exc:
        evaluation = exc.evaluation
    assert len(callbacks) == (0 if case in {"blocked", "missing-parent", "pre-callback"} else 1)
    saved = instance.store.load_run(evaluation["run_id"])
    proof = instance.store.load_execution_attestation(evaluation["run_id"])
    reports = [body for url, body in calls if url.endswith("/attestations")]
    assert len(reports) == 1, evaluation.get("cloud_runtime_attestation")
    assert reports[0]["execution_status"] == status
    assert reports[0].get("mutation_executed") is mutation
    if mutation is None:
        assert "mutation_executed" not in reports[0]
    assert reports[0]["runtime_id"] == "assigned-runtime"
    assert reports[0]["event_id"] == saved["run_id"]
    context = saved["inputs"]["runtime_evidence"]["execution_context"]
    assert context["runtime_id"] == "assigned-runtime" and context["organization_id"] == "test-org"
    assert context["trace"] == {"value": 1}
    assert saved["receipt"]["input_hashes"]["execution_context_hash"] == stable_hash(context)
    pair = saved["inputs"]["authority_publication"]
    assert pair == {"bundle": publication()["authority_bundle"], "receipt": publication()["publication_receipt"]}
    submitted = [body for url, body in calls if url.endswith("/preserve")]
    assert len(submitted) == 1
    assert "cloud_preservation" not in submitted[0]["saved_evaluation"]
    if case in {"partial", "collision", "post-validation"}:
        assert proof["mutation_executed"] is None  # Historical local proof is unchanged.


@development
@pytest.mark.parametrize("field,value", [("runtime_id", "other"), ("organization_id", "other"), ("runtime_id", None)])
@pytest.mark.parametrize("boundary", ["configuration", "boundary", "call"])
def test_identity_overrides_fail_before_saved_run(connected, field, value, boundary):
    make, state, calls, root = connected
    with pytest.raises(AuthorityVerificationError, match="conflicts"):
        if boundary == "configuration":
            make(execution_context={field: value})
        else:
            instance = make()
            if boundary == "boundary":
                instance.boundary_for(execution_context={field: value})
            else:
                instance.boundary_for().execute_repository(lambda t: pytest.fail("callback"),
                    execution_request=request(), operation="create", execution_context={field: value})
    assert not any(url.endswith(("/preserve", "/attestations")) for url, _ in calls)


@development
@pytest.mark.parametrize("endpoint", ["preserve", "report"])
@pytest.mark.parametrize("fault", [403, 503, 307, requests.Timeout("uncertain"), RuntimeError("secret must not escape")])
@pytest.mark.parametrize("raises", [False, True])
def test_reporting_failure_never_repeats_mutation(connected, endpoint, fault, raises):
    make, state, calls, root = connected
    instance = make()
    state[endpoint + "_fault"] = fault
    count = []
    @instance.repository_tool(action="create", target="path", return_result=True)
    def create(path):
        count.append(1)
        path.create_bytes(b"once")
        if raises:
            raise RuntimeError("operation failed after mutation")
    if raises:
        with pytest.raises(RuntimeError) as caught:
            create("generated/new.md")
        evaluation = caught.value.evaluation
    else:
        evaluation = create("generated/new.md")["evaluation"]
    assert count == [1] and (root / "generated/new.md").read_bytes() == b"once"
    assert evaluation["status"] == "admissible"
    key = "cloud_preservation" if endpoint == "preserve" else "cloud_runtime_attestation"
    assert evaluation[key]["ok"] is False
    assert sum(url.endswith("/preserve") for url, _ in calls) == 1
    assert sum(url.endswith("/attestations") for url, _ in calls) == 1
    if endpoint == "preserve":
        assert not instance.store.load_run(evaluation["run_id"]).get("cloud_preservation")
        if isinstance(fault, requests.Timeout):
            assert evaluation[key]["ambiguous"]


@pytest.mark.parametrize("gate", ["WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"])
def test_native_cloud_gate_off(connected, monkeypatch, gate):
    make, state, calls, root = connected
    monkeypatch.delenv(gate, raising=False)
    with pytest.raises(AuthorityVerificationError, match="development"):
        make()
    assert calls == []


@development
@pytest.mark.parametrize("change", ["tenant", "authority", "bundle", "receipt", "mixed", "downgrade", "registry",
                                    "revoked", "superseded", "reference", "provenance"])
def test_native_intake_rejects_tampering_even_with_outer_hashes(connected, change):
    make, state, calls, root = connected
    payload = publication()
    if change == "tenant": payload["organization_id"] = "other"
    elif change == "authority": payload["authority_ref"] = "wrong@2.0.0"
    elif change == "bundle": payload["authority_bundle"]["compiled_authority_contract"]["action_requirements"]["create"]["required_role"] = None
    elif change == "receipt": payload["publication_receipt"]["publication_id"] = "wrong"
    elif change == "mixed": payload["publication_receipt"] = publication("mixed")["publication_receipt"]
    elif change == "downgrade":
        payload["authority_bundle"]["schema_version"] = "authority_bundle.v3"
        payload["publication_receipt"]["schema_version"] = "publication_receipt.v3"
    elif change == "registry": payload["registry_entry"]["bundle_hash"] = "sha256:" + "0" * 64
    elif change in {"revoked", "superseded"}: payload["registry_entry"]["lifecycle_state"] = change
    elif change == "reference": payload["registry_entry"]["bundle_ref"] = "../escape.json"
    elif change == "provenance": payload["authority_bundle"].pop("approval_record")
    state["publication_body"] = json.dumps(_rehash(payload)).encode()
    with pytest.raises((AuthorityVerificationError, CloudPublicationProtocolError, CloudAuthorityFetchError)):
        make()
    assert calls == []
    assert not any(item["path"].startswith("/v1/contracts/") for item in state["requests"])


@development
def test_no_terminal_report_and_malformed_request(connected):
    make, state, calls, root = connected
    instance = make()
    evaluation = instance.boundary_for().evaluate(request())
    assert evaluation["run_id"] and "cloud_runtime_attestation" not in evaluation
    assert not any(url.endswith("/attestations") for url, _ in calls)
    before = len(calls)
    with pytest.raises(RepositoryBoundaryError):
        instance.boundary_for().execute_repository(lambda t: None, execution_request={"action": "create"}, operation="create")
    assert len(calls) == before


@development
def test_required_dependency_api_and_warm_identity_rejection(connected, monkeypatch):
    import governance_ledger
    make, state, calls, root = connected
    instance = make()
    boundary = instance.boundary_for()
    instance.cloud_runtime_client.runtime_id = "substituted"
    with pytest.raises(AuthorityVerificationError, match="identity"):
        boundary.evaluate(request())
    monkeypatch.delattr(governance_ledger, "validate_authority_bundle")
    with pytest.raises(AuthorityVerificationError):
        make()


@development
@pytest.mark.parametrize("change", ["bundle", "receipt", "revoked", "gate"])
def test_native_cloud_cache_revalidates_resolution(connected, monkeypatch, change):
    from waveframe_guard.authority import MemoryAuthorityCache, load_authority
    from waveframe_guard.cloud import CloudAuthorityClient, CloudAuthorityResolver
    make, state, calls, root = connected
    instance = make()
    client = CloudAuthorityClient(instance.cloud_runtime_client.base_url,
                                  organization_id="test-org", api_key="disposable-secret")
    cache = MemoryAuthorityCache()
    with CloudAuthorityResolver(client) as source:
        load_authority(instance.default_authority_ref, resolver=source, cache=cache)
        payload = publication()
        if change == "bundle": payload["authority_bundle"]["approval_record"]["approved_by"] = "tampered"
        if change == "receipt": payload["publication_receipt"]["publication_id"] = "tampered"
        if change == "revoked": payload["registry_entry"]["lifecycle_state"] = "revoked"
        if change == "gate": monkeypatch.delenv("WAVEFRAME_LEDGER_ACTION_POLICY_DEV")
        state["publication_body"] = json.dumps(_rehash(payload)).encode()
        with pytest.raises(AuthorityVerificationError):
            load_authority(instance.default_authority_ref, resolver=source, cache=cache)


@development
def test_generic_boundary_cannot_ignore_identity_override(connected):
    make, state, calls, root = connected
    instance = make()
    with pytest.raises(AuthorityVerificationError, match="conflicts"):
        instance.boundary_for().execute(lambda: pytest.fail("callback"), execution_request=request(),
                                       execution_context={"runtime_id": "wrong"})
    assert not any(url.endswith("/preserve") for url, _ in calls)


@development
def test_matching_per_call_identity_and_other_context_are_saved(connected):
    make, state, calls, root = connected
    instance = make()
    result = instance.boundary_for().execute_repository(lambda path: path.create_bytes(b""), operation="create",
        execution_request=request(), execution_context={"runtime_id": "assigned-runtime", "organization_id": "test-org", "trace": "call"})
    assert result["cloud_runtime_attestation"]["ok"]
    saved = instance.store.load_run(result["evaluation"]["run_id"])
    assert saved["inputs"]["runtime_evidence"]["execution_context"]["trace"] == "call"
