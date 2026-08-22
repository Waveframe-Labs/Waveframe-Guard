from __future__ import annotations

import requests

from waveframe_guard.cloud import CloudRuntimeClient


class _Response:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"status": "ok"}
        self.text = text

    def json(self):
        return self._payload


def _client():
    return CloudRuntimeClient(
        "https://cloud.waveframelabs.com",
        organization_id="acme",
        api_key="wf_runtime_secret",
        runtime_id="support-agent",
        environment="production",
        authority_ref="support-policy@2.1.0",
        runtime_version="guard-0.15.0",
    )


def test_cloud_runtime_client_connects_with_registration_and_heartbeat(monkeypatch):
    requests_seen = []

    def post(url, **kwargs):
        requests_seen.append((url, kwargs))
        return _Response(payload={"accepted": True})

    monkeypatch.setattr(requests, "post", post)

    result = _client().connect()

    assert result.ok is True
    assert result.registration.ok is True
    assert result.heartbeat.ok is True
    registration_url, registration = requests_seen[0]
    heartbeat_url, heartbeat = requests_seen[1]
    assert registration_url.endswith("/v1/runtimes/register")
    assert registration["headers"] == {
        "X-Organization-ID": "acme",
        "X-API-Key": "wf_runtime_secret",
    }
    assert registration["json"]["runtime_id"] == "support-agent"
    assert registration["json"]["authority_refs"] == ["support-policy@2.1.0"]
    assert "runtime_result_attestation" in registration["json"]["capabilities"]
    assert heartbeat_url.endswith("/v1/runtimes/support-agent/heartbeats")
    assert heartbeat["json"]["status"] == "online"
    assert heartbeat["json"]["environment"] == "production"


def test_cloud_runtime_client_attests_post_execution_result(monkeypatch):
    request = {}

    def post(url, **kwargs):
        request.update(url=url, **kwargs)
        return _Response(payload={"attestation_id": "attest-123"})

    monkeypatch.setattr(requests, "post", post)

    result = _client().attest(
        event_id="guard_run_123",
        compiled_contract_hash="sha256:contract",
        runtime_decision="ALLOWED",
        execution_status="succeeded",
        execution_result_summary="write_file callback completed exactly once.",
        mutation_executed=True,
    )

    assert result.ok is True
    assert request["url"].endswith("/v1/runtime/attestations")
    assert request["json"] == {
        "schema_version": "runtime_execution_attestation.v1",
        "event_id": "guard_run_123",
        "runtime_id": "support-agent",
        "authority_ref": "support-policy@2.1.0",
        "compiled_contract_hash": "sha256:contract",
        "runtime_decision": "ALLOWED",
        "execution_status": "succeeded",
        "execution_result_summary": "write_file callback completed exactly once.",
        "mutation_executed": True,
    }


def test_cloud_runtime_reporting_failure_is_structured_and_redacted(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.RequestException("rejected wf_runtime_secret")

    monkeypatch.setattr(requests, "post", fail)

    result = _client().heartbeat()

    assert result.ok is False
    assert result.error_type == "request_error"
    assert result.error == "rejected [REDACTED]"


def test_cloud_runtime_connect_does_not_heartbeat_after_registration_failure(monkeypatch):
    calls = []

    def post(url, **kwargs):
        calls.append(url)
        return _Response(status_code=403, text="forbidden")

    monkeypatch.setattr(requests, "post", post)

    result = _client().connect()

    assert result.ok is False
    assert result.registration.error_type == "http_error"
    assert result.registration.response == {"status": "ok"}
    assert result.heartbeat is None
    assert len(calls) == 1
