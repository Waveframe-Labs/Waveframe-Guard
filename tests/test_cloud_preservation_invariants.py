from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest
import requests

from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.runtime.identity import stable_hash
from guard.sdk import (
    CLOUD_PRESERVATION_METADATA_V1,
    ConflictingCloudPreservationError,
    Guard,
    GuardRuntimeBoundary,
    LocalEvaluationStore,
)


EVALUATION_TIME = "2026-06-03T22:30:00+00:00"
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_local_only_path_has_no_cloud_client_or_preserved_status(tmp_path, monkeypatch):
    def fail_if_network_called(*args, **kwargs):
        raise AssertionError("local-only Guard must not call Cloud")

    monkeypatch.setattr("waveframe_guard.cloud.client.requests.post", fail_if_network_called)
    baseline = _run_allowed(tmp_path / "baseline")
    local_only = _run_allowed(tmp_path / "local-only", preserve_to=None)
    record = local_only["guard"].store.history()[0]

    assert local_only["guard"].cloud_preservation_client is None
    assert local_only["result"]["cloud_preservation"] is None
    assert "cloud_preservation" not in local_only["result"]["evaluation"]
    assert "cloud_preservation" not in record
    assert _artifact_names(tmp_path / "local-only") == {
        "history": True,
        "receipt": True,
        "manifest": True,
        "replay": False,
    }
    assert local_only["result"]["outcome"]["outcome_hash"] == baseline["result"]["outcome"]["outcome_hash"]
    assert record["guard_enforcement_outcome"]["outcome_hash"] == baseline["record"]["guard_enforcement_outcome"]["outcome_hash"]


@pytest.mark.parametrize(
    ("role", "amount", "expected_executed", "expected_status"),
    [
        ("employee", 12_500, False, "blocked"),
        ("manager", 500, True, "admissible"),
    ],
)
def test_successful_preservation_for_blocked_and_allowed_results(
    tmp_path,
    role,
    amount,
    expected_executed,
    expected_status,
):
    workspace = tmp_path / f"guard-{role}"
    state = {"workspace": workspace}
    server, preserve_to = _serve_preservation_app(state)
    calls = []
    guard = Guard.local(
        workspace=workspace,
        preserve_to=preserve_to,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": f"{role}-1", "type": "human", "role": role},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}] if role == "manager" else [],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )

    try:
        result = guard.boundary_for("finance-policy@1.0.0").execute(
            lambda amount: calls.append(amount) or amount + 1,
            execution_request=_request(amount=amount),
            args=(amount,),
            raise_on_block=False,
        )
    finally:
        server.shutdown()
        server.server_close()

    record = guard.store.history()[0]
    assert state["call_count"] == 1
    assert state["payload"]["schema_version"] == "guard_cloud_preservation_package.v1"
    assert set(state["payload"]) >= {
        "saved_evaluation",
        "receipt",
        "artifact_manifest",
        "replay_result",
    }
    assert state["payload"]["saved_evaluation"]["run_id"] == record["run_id"]
    saved_evaluation = dict(state["payload"]["saved_evaluation"])
    record_hash = saved_evaluation.pop("record_hash")
    assert record_hash == stable_hash(saved_evaluation)
    assert state["payload"]["receipt"] == record["receipt"]
    assert state["payload"]["artifact_manifest"] == record["artifact_manifest"]
    assert state["payload"]["replay_result"]["matches"] is True
    assert state["local_artifacts_existed_before_preserve"] == {
        "history": True,
        "receipt": True,
        "manifest": True,
        "replay": True,
    }
    assert record["cloud_preservation"]["schema_version"] == CLOUD_PRESERVATION_METADATA_V1
    assert record["cloud_preservation"]["package_id"] == "pkg_guard_123"
    assert record["cloud_preservation"]["receipt_id"] == "rcpt_guard_123"
    assert result["outcome"]["status"] == expected_status
    assert result["executed"] is expected_executed
    assert calls == ([amount] if expected_executed else [])


@pytest.mark.parametrize(
    ("failure_name", "server_state", "request_exception", "expected_error_type"),
    [
        ("timeout", None, requests.Timeout("timed out"), "timeout"),
        ("request_error", None, requests.ConnectionError("connection failed"), "request_error"),
        ("http_4xx", {"status": "400 Bad Request", "body": b'{"error":"bad"}'}, None, "http_error"),
        ("http_5xx", {"status": "503 Service Unavailable", "body": b'{"error":"down"}'}, None, "http_error"),
        ("invalid_json", {"body": b"not-json"}, None, "invalid_json"),
        ("wrong_shape", {"body": b'["not", "an", "object"]'}, None, "invalid_response"),
        ("missing_identifiers", {"body": b'{"package_id":"pkg_only"}'}, None, "invalid_response"),
    ],
)
def test_cloud_failure_isolation_for_allowed_execution(
    tmp_path,
    monkeypatch,
    failure_name,
    server_state,
    request_exception,
    expected_error_type,
):
    baseline = _run_allowed(tmp_path / f"baseline-{failure_name}")
    if request_exception is not None:
        preserve_to = "http://cloud.example"

        def raise_request_exception(*args, **kwargs):
            raise request_exception

        monkeypatch.setattr("waveframe_guard.cloud.client.requests.post", raise_request_exception)
        server = None
    else:
        server_state = server_state or {}
        server_state["workspace"] = tmp_path / f"failure-{failure_name}"
        server, preserve_to = _serve_preservation_app(server_state)

    try:
        failed = _run_allowed(
            tmp_path / f"failure-{failure_name}",
            preserve_to=preserve_to,
        )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    result = failed["result"]
    record = failed["record"]
    assert result["cloud_preservation"]["ok"] is False
    assert result["cloud_preservation"]["error_type"] == expected_error_type
    assert result["evaluation"]["status"] == baseline["result"]["evaluation"]["status"]
    assert result["outcome"]["status"] == baseline["result"]["outcome"]["status"]
    assert result["executed"] == baseline["result"]["executed"]
    assert result["value"] == baseline["result"]["value"]
    assert result["evaluation"]["rationale"] == baseline["result"]["evaluation"]["rationale"]
    assert result["outcome"]["outcome_hash"] == baseline["result"]["outcome"]["outcome_hash"]
    assert "cloud_preservation" not in record
    assert _artifact_names(tmp_path / f"failure-{failure_name}") == {
        "history": True,
        "receipt": True,
        "manifest": True,
        "replay": True,
    }
    assert failed["guard"].store.replay(record["run_id"])["matches"] is True


def test_preservation_timeout_does_not_duplicate_local_evidence_or_allowed_callback(tmp_path, monkeypatch):
    attempts = []

    def timeout(*args, **kwargs):
        attempts.append((args, kwargs))
        raise requests.Timeout("response was not received")

    monkeypatch.setattr("waveframe_guard.cloud.client.requests.post", timeout)
    failed = _run_allowed(
        tmp_path / "timeout",
        preserve_to="http://cloud.example",
        preservation_timeout_seconds=0.1,
    )

    assert len(attempts) == 1
    assert failed["calls"] == [500]
    assert failed["result"]["cloud_preservation"]["ambiguous"] is True
    assert len(failed["guard"].store.history()) == 1
    assert "cloud_preservation" not in failed["record"]
    assert failed["guard"].store.replay(failed["record"]["run_id"])["matches"] is True


def test_preservation_timeout_does_not_execute_blocked_callback(tmp_path, monkeypatch):
    attempts = []
    calls = []

    def timeout(*args, **kwargs):
        attempts.append((args, kwargs))
        raise requests.Timeout("response was not received")

    monkeypatch.setattr("waveframe_guard.cloud.client.requests.post", timeout)
    guard = Guard.local(
        workspace=tmp_path / "blocked-timeout",
        preserve_to="http://cloud.example",
        preservation_timeout_seconds=0.1,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        evaluation_time_source=lambda: EVALUATION_TIME,
    )
    result = guard.boundary_for("finance-policy@1.0.0").execute(
        lambda amount: calls.append(amount),
        execution_request=_request(amount=12_500),
        args=(12_500,),
        raise_on_block=False,
    )

    assert len(attempts) == 1
    assert calls == []
    assert result["executed"] is False
    assert result["evaluation"]["status"] == "blocked"
    assert result["cloud_preservation"]["ambiguous"] is True


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "10"])
def test_guard_rejects_invalid_preservation_timeout_configuration(tmp_path, timeout):
    with pytest.raises(ValueError, match="preservation_timeout_seconds must be a positive finite number"):
        Guard.local(
            workspace=tmp_path,
            authorities={"finance-policy@1.0.0": _authority()},
            preservation_timeout_seconds=timeout,
        )


def test_guard_preservation_timeout_configuration_is_backward_compatible(tmp_path):
    legacy = Guard.local(
        workspace=tmp_path / "legacy",
        authorities={"finance-policy@1.0.0": _authority()},
    )
    configured = Guard.local(
        workspace=tmp_path / "configured",
        preserve_to="http://cloud.example",
        preservation_timeout_seconds=12.5,
        authorities={"finance-policy@1.0.0": _authority()},
    )

    assert legacy.preservation_timeout_seconds == 10.0
    assert configured.cloud_preservation_client.timeout_seconds == 12.5


def test_append_cloud_preservation_preserves_history_integrity(tmp_path):
    store = LocalEvaluationStore(tmp_path / "guard-runs")
    first = _save_direct(store, amount=500)
    second = _save_direct(store, amount=750)
    original_records = deepcopy(store.history())
    metadata = _cloud_metadata()

    updated = store.append_cloud_preservation(
        first["run_id"],
        metadata,
        record_hash=first["record_hash"],
    )
    records = store.history()
    updated_without_hash = {key: value for key, value in updated.items() if key != "record_hash"}

    assert [record["run_id"] for record in records] == [
        first["run_id"],
        second["run_id"],
    ]
    assert len(records) == 2
    assert records[1] == original_records[1]
    assert records[0]["cloud_preservation"]["package_id"] == metadata["package_id"]
    assert updated["record_hash"] == stable_hash(updated_without_hash)
    assert records[0]["receipt"] == original_records[0]["receipt"]
    assert records[0]["artifact_manifest"] == original_records[0]["artifact_manifest"]
    assert store.load_run(first["run_id"])["cloud_preservation"]["receipt_id"] == metadata["receipt_id"]
    assert store.replay(first["run_id"])["matches"] is True
    assert (tmp_path / "guard-runs" / "receipts" / f"{first['run_id']}.json").exists()
    assert (tmp_path / "guard-runs" / "manifests" / f"{first['run_id']}.json").exists()
    assert (tmp_path / "guard-runs" / "replays" / f"{first['run_id']}.json").exists()


def test_append_cloud_preservation_history_safety_rules(tmp_path):
    store = LocalEvaluationStore(tmp_path / "guard-runs")
    first = _save_direct(store, amount=500)
    second = _save_direct(store, amount=750)
    metadata = _cloud_metadata()

    with pytest.raises(FileNotFoundError):
        store.append_cloud_preservation("missing-run", metadata)

    once = store.append_cloud_preservation(first["run_id"], metadata)
    twice = store.append_cloud_preservation(first["run_id"], metadata)
    records = store.history()
    assert once["cloud_preservation"] == twice["cloud_preservation"]
    assert [record["run_id"] for record in records] == [
        first["run_id"],
        second["run_id"],
    ]
    assert len(records) == 2

    conflicting = {
        **metadata,
        "receipt_id": "rcpt_conflict",
    }
    with pytest.raises(ConflictingCloudPreservationError):
        store.append_cloud_preservation(first["run_id"], conflicting)
    assert store.history()[0]["cloud_preservation"]["receipt_id"] == metadata["receipt_id"]


def test_cloud_preservation_is_post_decision_annotation_not_receipt_claim(tmp_path):
    preserved = _run_allowed_with_successful_preservation(tmp_path / "annotation")
    record = preserved["guard"].store.history()[0]

    assert "cloud_preservation" in record
    assert "cloud_preservation" not in record["receipt"]
    assert "cloud_preservation" not in record["artifact_manifest"]
    assert record["artifact_manifest"]["persisted_artifacts"]["receipt"] == record["receipt"]["receipt_hash"]
    assert preserved["guard"].store.replay(record["run_id"])["matches"] is True


def test_cloud_preservation_annotation_semantics_are_documented():
    source = (REPO_ROOT / "docs" / "architecture" / "LOCAL_CLOUD_LIFECYCLE_BOUNDARY.md").read_text(
        encoding="utf-8"
    )
    normalized = " ".join(source.split())

    assert "Cloud preservation is post-decision evidence durability" in source
    assert "Cloud preservation metadata is a later durability annotation" in source
    assert "It is not proof that the protected business mutation completed" in normalized


def _run_allowed(workspace, *, preserve_to=None, preservation_timeout_seconds=10.0):
    calls = []
    guard = Guard.local(
        workspace=workspace,
        preserve_to=preserve_to,
        preservation_timeout_seconds=preservation_timeout_seconds,
        authorities={"finance-policy@1.0.0": _authority()},
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
    )
    result = guard.boundary_for("finance-policy@1.0.0").execute(
        lambda amount: calls.append(amount) or amount + 1,
        execution_request=_request(amount=500),
        args=(500,),
    )
    return {
        "guard": guard,
        "result": result,
        "record": guard.store.history()[0],
        "calls": calls,
    }


def _run_allowed_with_successful_preservation(workspace):
    state = {"workspace": workspace}
    server, preserve_to = _serve_preservation_app(state)
    try:
        return _run_allowed(workspace, preserve_to=preserve_to)
    finally:
        server.shutdown()
        server.server_close()


def _save_direct(store, *, amount):
    boundary = GuardRuntimeBoundary(
        compiled_authority=_authority(),
        actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
        approvals=[{"role": "manager", "approved_by": "manager-approval"}],
        evaluation_time_source=lambda: EVALUATION_TIME,
        store=store,
    )
    boundary.evaluate(_request(amount=amount))
    return store.history()[-1]


def _artifact_names(workspace):
    history = LocalEvaluationStore(workspace).history()
    run_id = history[0]["run_id"]
    return {
        "history": (workspace / "evaluation-history.jsonl").exists(),
        "receipt": (workspace / "receipts" / f"{run_id}.json").exists(),
        "manifest": (workspace / "manifests" / f"{run_id}.json").exists(),
        "replay": (workspace / "replays" / f"{run_id}.json").exists(),
    }


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


def _cloud_metadata():
    return {
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


def _serve_preservation_app(state):
    server = make_server("127.0.0.1", 0, _preservation_app(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _preservation_app(state):
    def app(environ, start_response):
        state["call_count"] = state.get("call_count", 0) + 1
        state["method"] = environ["REQUEST_METHOD"]
        state["path"] = environ["PATH_INFO"]
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
        return [state.get("body", json.dumps(_cloud_response()).encode("utf-8"))]

    return app


def _cloud_response():
    return {
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
