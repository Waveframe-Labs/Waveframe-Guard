from __future__ import annotations

import json
import hashlib
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.sdk import (
    CLOUD_PRESERVATION_METADATA_V1,
    ENFORCEMENT_RECEIPT_V1,
    SAVED_EVALUATION_V1,
    Guard,
    GuardExecutionBlocked,
    GuardRuntimeBoundary,
    LocalEvaluationStore,
    agent_runner_adapter,
    http_middleware_adapter,
    python_callable_adapter,
    queue_job_adapter,
    webhook_enforcement_adapter,
)
from waveframe_guard.authority.adapters import MemoryAuthorityResolver
from waveframe_guard.authority.cache import MemoryAuthorityCache
from waveframe_guard.authority.loader import BundleLoader
from waveframe_guard.authority.types import RegistryEntry


EVALUATION_TIME = "2026-06-03T22:30:00+00:00"


def test_python_callable_adapter_blocks_before_execution():
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        evaluation_time_source=lambda: EVALUATION_TIME,
    )
    calls = []

    def transfer():
        calls.append("executed")

    with pytest.raises(GuardExecutionBlocked) as exc:
        python_callable_adapter(boundary, transfer, execution_request=_request(amount=12500))

    assert calls == []
    assert exc.value.outcome["schema_version"] == "guard_enforcement_outcome.v1"
    assert exc.value.outcome["status"] == "blocked"


def test_guard_sdk_import_path_can_construct_authority_backed_guard():
    from guard.sdk import Guard as SdkGuard

    guard = SdkGuard.local(authority="finance-policy@1.0.0")

    assert guard.default_authority_ref == "finance-policy@1.0.0"
    assert guard.resolve_authority("finance-policy@1.0.0")["schema_version"] == COMPILED_AUTHORITY_CONTRACT_V1


def test_runtime_boundary_executes_callable_when_admissible():
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    result = boundary.execute(
        lambda amount: amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )

    assert result["executed"] is True
    assert result["value"] == 501
    assert result["outcome"]["status"] == "admissible"


def test_decorator_flow_uses_supplied_normalized_request_builder():
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    @boundary.decorator(lambda amount: _request(amount=amount))
    def transfer(amount):
        return {"transferred": amount}

    assert transfer(500) == {"transferred": 500}


def test_guard_local_protect_emits_inspector_discoverable_artifacts(tmp_path):
    mutation_log = []
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    @guard.protect(authority="finance-policy@1.0.0")
    def wire_transfer(execution_request):
        mutation_log.append(execution_request["arguments"]["amount"])
        return {"wire_sent": execution_request["arguments"]["amount"]}

    with pytest.raises(GuardExecutionBlocked):
        wire_transfer(_request(amount=12500))

    history = guard.store.history()
    run_id = history[0]["run_id"]

    assert mutation_log == []
    assert history[0]["guard_enforcement_outcome"]["status"] == "blocked"
    assert (tmp_path / ".guard-local" / "receipts" / f"{run_id}.json").exists()
    assert (tmp_path / ".guard-local" / "manifests" / f"{run_id}.json").exists()
    assert guard.store.replay(run_id)["matches"] is True
    assert (tmp_path / ".guard-local" / "replays" / f"{run_id}.json").exists()


def test_guard_local_protect_requires_normalized_request_boundary(tmp_path):
    guard = Guard.local(
        workspace=tmp_path,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    @guard.protect(authority="finance-policy@1.0.0")
    def wire_transfer(raw_request):
        return raw_request

    with pytest.raises(ValueError, match="normalized_execution_request.v1"):
        wire_transfer({"amount": 500})


def test_guard_local_accepts_published_authority_ref_without_repeating_authority(tmp_path):
    calls = []
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authority="finance-policy@1.0.0",
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    @guard.protect()
    def wire_transfer(execution_request):
        calls.append(execution_request["arguments"]["amount"])
        return {"wire_sent": execution_request["arguments"]["amount"]}

    result = wire_transfer(_request(amount=500))

    assert result == {"wire_sent": 500}
    assert calls == [500]


def test_guard_local_accepts_injected_authority_resolver(tmp_path):
    registry_entry = _memory_registry_entry(tmp_path)
    resolver = MemoryAuthorityResolver({"finance-policy@1.2.0": registry_entry})
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authority="finance-policy@1.2.0",
        authority_resolver=resolver,
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    result = guard.boundary_for().execute(
        lambda amount: amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )

    assert result["executed"] is True
    assert result["value"] == 501
    assert result["outcome"]["authority_ref"] == "finance-policy@1.2.0"


def test_guard_local_accepts_authority_cache_without_changing_enforcement(tmp_path, monkeypatch):
    registry_entry = _memory_registry_entry(tmp_path)
    resolver = MemoryAuthorityResolver({"finance-policy@1.2.0": registry_entry})
    cache = MemoryAuthorityCache()
    load_calls = []
    original_load = BundleLoader.load

    def counted_load(self, entry):
        load_calls.append(entry.authority_ref)
        return original_load(self, entry)

    monkeypatch.setattr(BundleLoader, "load", counted_load)

    first = Guard.local(
        workspace=tmp_path / "first" / ".guard-local",
        authority="finance-policy@1.2.0",
        authority_resolver=resolver,
        authority_cache=cache,
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )
    second = Guard.local(
        workspace=tmp_path / "second" / ".guard-local",
        authority="finance-policy@1.2.0",
        authority_resolver=resolver,
        authority_cache=cache,
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    result = second.boundary_for().execute(
        lambda amount: amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )

    assert first.default_authority_ref == second.default_authority_ref == "finance-policy@1.2.0"
    assert load_calls == ["finance-policy@1.2.0"]
    assert result["executed"] is True
    assert result["value"] == 501


def test_guard_local_legacy_contract_input_normalizes_to_default_authority(tmp_path):
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        contract=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    result = guard.boundary_for().execute(
        lambda amount: amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )

    assert result["executed"] is True
    assert result["outcome"]["authority_ref"] == "finance-policy@1.0.0"


def test_guard_local_rejects_authority_and_contract_together(tmp_path):
    with pytest.raises(ValueError, match="mutually exclusive"):
        Guard.local(
            workspace=tmp_path / ".guard-local",
            authority="finance-policy@1.0.0",
            contract=_authority(),
        )


def test_guard_local_rejects_authority_resolver_without_authority(tmp_path):
    registry_entry = _memory_registry_entry(tmp_path)

    with pytest.raises(ValueError, match="authority_resolver requires authority"):
        Guard.local(
            workspace=tmp_path / ".guard-local",
            authority_resolver=MemoryAuthorityResolver([registry_entry]),
        )


def test_guard_local_deduplicates_identical_authority_source_content(tmp_path):
    contract = _authority()
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        contract=contract,
        authorities={"finance-policy@1.0.0": dict(contract)},
    )

    assert guard.resolve_authority("finance-policy@1.0.0") == contract


def test_guard_local_rejects_same_ref_different_authority_source_content(tmp_path):
    contract = _authority()
    conflicting = {
        **contract,
        "authority_requirements": {"required_roles": ["director"]},
    }

    with pytest.raises(ValueError, match="conflicting authority source"):
        Guard.local(
            workspace=tmp_path / ".guard-local",
            contract=contract,
            authorities={"finance-policy@1.0.0": conflicting},
        )


def test_guard_local_can_preserve_saved_evaluation_after_local_decision(tmp_path):
    workspace = tmp_path / ".guard-local"
    cloud_api_key = "wf_cloud_secret_not_evidence"
    state = {"workspace": workspace}
    server, preserve_to = _serve_preservation_app(state)
    guard = Guard.local(
        workspace=workspace,
        preserve_to=preserve_to,
        cloud_organization_id="org-finance",
        cloud_api_key=cloud_api_key,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    try:
        result = guard.boundary_for("finance-policy@1.0.0").execute(
            lambda amount: amount + 1,
            execution_request=_request(amount=500),
            args=(500,),
        )
    finally:
        server.shutdown()
        server.server_close()

    history = guard.store.history()
    run_id = history[0]["run_id"]
    cloud_metadata = history[0]["cloud_preservation"]

    assert result["executed"] is True
    assert result["cloud_preservation"]["ok"] is True
    assert result["cloud_preservation"]["package_id"] == "pkg_guard_123"
    assert result["cloud_preservation"]["receipt_id"] == "rcpt_guard_123"
    assert result["cloud_preservation"]["sha256"] == "sha256:guard-package"
    assert result["cloud_preservation"]["timestamp"] == "2026-07-13T00:00:00+00:00"
    assert cloud_metadata == {
        "schema_version": CLOUD_PRESERVATION_METADATA_V1,
        "status": "preserved",
        "package_id": "pkg_guard_123",
        "receipt_id": "rcpt_guard_123",
        "sha256": "sha256:guard-package",
        "timestamp": "2026-07-13T00:00:00+00:00",
        "receipt": {
            "package_id": "pkg_guard_123",
            "receipt_id": "rcpt_guard_123",
            "sha256": "sha256:guard-package",
            "timestamp": "2026-07-13T00:00:00+00:00",
            "status": "preserved",
        },
    }
    assert state["path"] == "/v1/preserve"
    assert state["organization_id"] == "org-finance"
    assert state["api_key"] == cloud_api_key
    assert state["payload"]["schema_version"] == "guard_cloud_preservation_package.v1"
    assert state["payload"]["run_id"] == run_id
    assert state["payload"]["saved_evaluation"]["schema_version"] == SAVED_EVALUATION_V1
    assert state["payload"]["saved_evaluation"]["run_id"] == run_id
    assert state["payload"]["receipt"] == history[0]["receipt"]
    assert state["payload"]["artifact_manifest"] == history[0]["artifact_manifest"]
    assert state["payload"]["replay_result"]["matches"] is True
    assert state["local_artifacts_existed_before_preserve"] == {
        "history": True,
        "receipt": True,
        "manifest": True,
        "replay": True,
    }
    assert (workspace / "receipts" / f"{run_id}.json").exists()
    assert (workspace / "manifests" / f"{run_id}.json").exists()
    assert (workspace / "replays" / f"{run_id}.json").exists()
    assert cloud_api_key not in json.dumps(state["payload"], sort_keys=True)
    for artifact_path in workspace.rglob("*"):
        if artifact_path.is_file():
            assert cloud_api_key not in artifact_path.read_text(encoding="utf-8")


def test_guard_local_reads_cloud_credentials_from_environment(tmp_path, monkeypatch):
    state = {}
    server, preserve_to = _serve_preservation_app(state)
    monkeypatch.setenv("WAVEFRAME_CLOUD_ORGANIZATION_ID", "org-environment")
    monkeypatch.setenv("WAVEFRAME_CLOUD_API_KEY", "wf_environment_secret")
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        preserve_to=preserve_to,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    try:
        result = guard.boundary_for("finance-policy@1.0.0").execute(
            lambda amount: amount + 1,
            execution_request=_request(amount=500),
            args=(500,),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result["cloud_preservation"]["ok"] is True
    assert state["organization_id"] == "org-environment"
    assert state["api_key"] == "wf_environment_secret"
    assert "wf_environment_secret" not in json.dumps(state["payload"], sort_keys=True)


def test_guard_local_omits_cloud_preservation_when_not_configured(tmp_path, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Cloud preservation should not run without preserve_to")

    monkeypatch.setattr("waveframe_guard.cloud.client.requests.post", fail_if_called)
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    result = guard.boundary_for("finance-policy@1.0.0").execute(
        lambda amount: amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )

    assert result["executed"] is True
    assert "cloud_preservation" not in result["evaluation"]
    assert guard.store.history()[0]["schema_version"] == SAVED_EVALUATION_V1


def test_guard_local_cloud_preservation_failure_does_not_change_enforcement(tmp_path):
    state = {
        "status": "503 Service Unavailable",
        "body": b'{"error":"cloud offline"}',
    }
    server, preserve_to = _serve_preservation_app(state)
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        preserve_to=preserve_to,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    try:
        result = guard.boundary_for("finance-policy@1.0.0").execute(
            lambda amount: amount + 1,
            execution_request=_request(amount=500),
            args=(500,),
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result["executed"] is True
    assert result["outcome"]["status"] == "admissible"
    assert result["cloud_preservation"]["ok"] is False
    assert result["cloud_preservation"]["error_type"] == "http_error"
    assert guard.store.history()[0]["schema_version"] == SAVED_EVALUATION_V1
    assert "cloud_preservation" not in guard.store.history()[0]


def test_local_persistence_saves_receipt_and_replays_deterministically(tmp_path):
    store = LocalEvaluationStore(tmp_path / "guard-runs")
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
        store=store,
    )

    evaluation = boundary.evaluate(_request(amount=500))
    history = store.history()
    run_id = history[0]["run_id"]
    replay = store.replay(run_id)

    assert evaluation["status"] == "admissible"
    assert history[0]["schema_version"] == SAVED_EVALUATION_V1
    assert history[0]["receipt"]["schema_version"] == ENFORCEMENT_RECEIPT_V1
    assert (tmp_path / "guard-runs" / "receipts" / f"{run_id}.json").exists()
    assert replay["matches"] is True
    assert replay["replayed_outcome_hash"] == history[0]["guard_enforcement_outcome"]["outcome_hash"]


def test_http_webhook_queue_and_agent_adapters_share_boundary():
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )
    handled = []

    http = http_middleware_adapter(
        boundary,
        request_loader=lambda request: request["execution_request"],
        call_next=lambda request: handled.append(("http", request["id"])),
    )
    webhook = webhook_enforcement_adapter(
        boundary,
        request_loader=lambda payload: payload["execution_request"],
        handler=lambda payload: handled.append(("webhook", payload["id"])),
    )
    queue = queue_job_adapter(
        boundary,
        request_loader=lambda job: job["execution_request"],
        handler=lambda job: handled.append(("queue", job["id"])),
    )
    agent = agent_runner_adapter(
        boundary,
        request_loader=lambda step: step["execution_request"],
        runner=lambda step: handled.append(("agent", step["id"])),
    )

    for name, adapter in [
        ("http", http),
        ("webhook", webhook),
        ("queue", queue),
        ("agent", agent),
    ]:
        adapter({"id": name, "execution_request": _request(amount=500)})

    assert handled == [
        ("http", "http"),
        ("webhook", "webhook"),
        ("queue", "queue"),
        ("agent", "agent"),
    ]


def _authority():
    return {
        "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:contract",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {"required": [{"role": "manager"}]},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }


def _request(*, amount):
    return {
        "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
        "request_id": f"exec-{amount}",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


def _memory_registry_entry(tmp_path: Path) -> RegistryEntry:
    contract = _authority()
    contract["contract_version"] = "1.2.0"
    contract["contract_hash"] = _contract_hash(contract)
    bundle = {
        "schema_version": "authority_bundle.v1",
        "publication_id": "pub_memory",
        "authority_ref": "finance-policy@1.2.0",
        "contract_hash": f"sha256:{contract['contract_hash']}",
        "semantic_commit_hash": None,
        "compiled_contract_hash": None,
        "authority_contract": contract,
        "semantic_commit_bundle": None,
        "compiled_authority_contract": None,
        "publication_manifest": {"publication_id": "pub_memory"},
        "governance_impact_preview": {},
        "authority_diff_impact": None,
        "governance_review_packets": [],
        "semantic_artifacts": [],
        "review_packets": [],
        "lineage": {},
        "provenance": {},
        "schema_compatibility": {},
        "publication_meaning": "Published finance-policy@1.2.0.",
        "operational_implications": [],
        "continuity_implications": [],
        "immutable_inputs": {"authority_hash": f"sha256:{contract['contract_hash']}"},
        "non_goals": [],
    }
    bundle_path = tmp_path / "finance-policy-1.2.0.authority-bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return RegistryEntry(
        authority_ref="finance-policy@1.2.0",
        contract_id="finance-policy",
        contract_version="1.2.0",
        contract_hash=f"sha256:{contract['contract_hash']}",
        bundle_path=bundle_path,
        bundle_hash=f"sha256:{_canonical_hash(bundle)}",
        lifecycle_state="active",
    )


def _contract_hash(contract):
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    return _canonical_hash(canonical_contract)


def _canonical_hash(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _serve_preservation_app(state):
    server = make_server("127.0.0.1", 0, _preservation_app(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _preservation_app(state):
    def app(environ, start_response):
        state["method"] = environ["REQUEST_METHOD"]
        state["path"] = environ["PATH_INFO"]
        state["organization_id"] = environ.get("HTTP_X_ORGANIZATION_ID")
        state["api_key"] = environ.get("HTTP_X_API_KEY")

        if state.get("status"):
            start_response(state["status"], [("Content-Type", "application/json")])
            return [state.get("body", b'{"error":"unavailable"}')]

        length = int(environ.get("CONTENT_LENGTH") or "0")
        body = environ["wsgi.input"].read(length)
        state["payload"] = json.loads(body.decode("utf-8"))
        workspace = state.get("workspace")
        if workspace is not None:
            run_id = state["payload"]["run_id"]
            state["local_artifacts_existed_before_preserve"] = {
                "history": (workspace / "evaluation-history.jsonl").exists(),
                "receipt": (workspace / "receipts" / f"{run_id}.json").exists(),
                "manifest": (workspace / "manifests" / f"{run_id}.json").exists(),
                "replay": (workspace / "replays" / f"{run_id}.json").exists(),
            }
        start_response("200 OK", [("Content-Type", "application/json")])
        return [
            json.dumps(
                {
                    "package_id": "pkg_guard_123",
                    "receipt_id": "rcpt_guard_123",
                    "sha256": "sha256:guard-package",
                    "timestamp": "2026-07-13T00:00:00+00:00",
                    "receipt": {
                        "package_id": "pkg_guard_123",
                        "receipt_id": "rcpt_guard_123",
                        "sha256": "sha256:guard-package",
                        "timestamp": "2026-07-13T00:00:00+00:00",
                        "status": "preserved",
                    },
                },
                sort_keys=True,
            ).encode("utf-8")
        ]

    return app
