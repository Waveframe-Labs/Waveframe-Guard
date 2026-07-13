from __future__ import annotations

import json
import threading
from wsgiref.simple_server import make_server

import pytest

from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.sdk import (
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


def test_guard_local_can_preserve_saved_evaluation_after_local_decision(tmp_path):
    state = {}
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

    history = guard.store.history()
    run_id = history[0]["run_id"]

    assert result["executed"] is True
    assert result["cloud_preservation"]["ok"] is True
    assert result["cloud_preservation"]["package_id"] == "pkg_guard_123"
    assert state["path"] == "/v1/preserve"
    assert state["payload"]["schema_version"] == SAVED_EVALUATION_V1
    assert state["payload"]["run_id"] == run_id
    assert (tmp_path / ".guard-local" / "receipts" / f"{run_id}.json").exists()


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


def _serve_preservation_app(state):
    server = make_server("127.0.0.1", 0, _preservation_app(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _preservation_app(state):
    def app(environ, start_response):
        state["method"] = environ["REQUEST_METHOD"]
        state["path"] = environ["PATH_INFO"]

        if state.get("status"):
            start_response(state["status"], [("Content-Type", "application/json")])
            return [state.get("body", b'{"error":"unavailable"}')]

        length = int(environ.get("CONTENT_LENGTH") or "0")
        body = environ["wsgi.input"].read(length)
        state["payload"] = json.loads(body.decode("utf-8"))
        start_response("200 OK", [("Content-Type", "application/json")])
        return [
            json.dumps(
                {
                    "package_id": "pkg_guard_123",
                    "receipt": {
                        "package_id": "pkg_guard_123",
                        "status": "preserved",
                    },
                },
                sort_keys=True,
            ).encode("utf-8")
        ]

    return app
