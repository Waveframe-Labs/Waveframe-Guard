from __future__ import annotations

import hashlib
import json
import threading
import time
from wsgiref.simple_server import make_server

import pytest
import requests

from waveframe_guard.cloud import (
    CloudAuthorityClient,
    CloudAuthorityFetchError,
    CloudPreservationClient,
)


def serve_preservation_app(state):
    server = make_server("127.0.0.1", 0, _preservation_app(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _preservation_app(state):
    def app(environ, start_response):
        state["call_count"] = state.get("call_count", 0) + 1
        state["method"] = environ["REQUEST_METHOD"]
        state["path"] = environ["PATH_INFO"]
        state["authorization"] = environ.get("HTTP_AUTHORIZATION")
        state["organization_id"] = environ.get("HTTP_X_ORGANIZATION_ID")
        state["api_key"] = environ.get("HTTP_X_API_KEY")

        if state.get("status"):
            start_response(state["status"], [("Content-Type", "application/json")])
            return [state.get("body", b'{"error":"unavailable"}')]

        length = int(environ.get("CONTENT_LENGTH") or "0")
        body = environ["wsgi.input"].read(length)
        state["payload"] = json.loads(body.decode("utf-8"))
        if state.get("delay_seconds"):
            time.sleep(state["delay_seconds"])
        start_response(state.get("success_status", "200 OK"), [("Content-Type", "application/json")])
        return [
            json.dumps(
                {
                    "package_id": "pkg_123",
                    "receipt_id": "rcpt_123",
                    "sha256": "sha256:preserved",
                    "timestamp": "2026-07-13T00:00:00+00:00",
                    "receipt": {
                        "receipt_id": "rcpt_123",
                        "package_id": "pkg_123",
                        "sha256": "sha256:preserved",
                        "timestamp": "2026-07-13T00:00:00+00:00",
                        "status": "preserved",
                    },
                },
                sort_keys=True,
            ).encode("utf-8")
        ]

    return app


def serve_authority_app(state):
    server = make_server("127.0.0.1", 0, _authority_app(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _authority_app(state):
    def app(environ, start_response):
        state["method"] = environ["REQUEST_METHOD"]
        state["path"] = environ["PATH_INFO"]
        state["organization_id"] = environ.get("HTTP_X_ORGANIZATION_ID")
        state["api_key"] = environ.get("HTTP_X_API_KEY")
        start_response(state.get("status", "200 OK"), [("Content-Type", "application/json")])
        return [state.get("body", json.dumps(_compiled_authority()).encode("utf-8"))]

    return app


def _compiled_authority():
    contract = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "repository-change-policy",
        "contract_version": "1.0.0",
        "authority_requirements": {"required_roles": ["repository-maintainer"]},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    contract["contract_hash"] = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    return contract


def _preservation_response():
    return {
        "package_id": "pkg_123",
        "receipt_id": "rcpt_123",
        "sha256": "sha256:preserved",
        "timestamp": "2026-07-13T00:00:00+00:00",
    }


class _response:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def test_cloud_preservation_client_posts_to_preserve_and_parses_receipt():
    state = {}
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url).preserve(
            {
                "event_id": "evt_123",
                "decision": "ALLOWED",
            }
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is True
    assert result.package_id == "pkg_123"
    assert result.receipt_id == "rcpt_123"
    assert result.sha256 == "sha256:preserved"
    assert result.timestamp == "2026-07-13T00:00:00+00:00"
    assert result.receipt == {
        "receipt_id": "rcpt_123",
        "package_id": "pkg_123",
        "sha256": "sha256:preserved",
        "timestamp": "2026-07-13T00:00:00+00:00",
        "status": "preserved",
    }
    assert result.status_code == 200
    assert state["method"] == "POST"
    assert state["path"] == "/v1/preserve"
    assert state["payload"] == {
        "event_id": "evt_123",
        "decision": "ALLOWED",
    }
    assert state["authorization"] is None
    assert state["organization_id"] is None
    assert state["api_key"] is None


def test_cloud_preservation_default_timeout_is_ten_seconds():
    assert CloudPreservationClient("http://cloud.example").timeout_seconds == 10.0


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "10"])
def test_cloud_preservation_timeout_requires_positive_finite_number(timeout):
    with pytest.raises(ValueError, match="preservation_timeout_seconds must be a positive finite number"):
        CloudPreservationClient("http://cloud.example", timeout_seconds=timeout)


def test_cloud_preservation_accepts_delayed_created_response_with_configured_timeout():
    state = {"delay_seconds": 2.05, "success_status": "201 Created"}
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url, timeout_seconds=3.0).preserve(
            {"event_id": "evt_123"}
        )
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is True
    assert result.status_code == 201
    assert state["call_count"] == 1


def test_cloud_preservation_client_sends_organization_credentials_as_headers():
    state = {}
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(
            base_url,
            organization_id="org-finance",
            api_key="wf_cloud_secret",
        ).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is True
    assert state["organization_id"] == "org-finance"
    assert state["api_key"] == "wf_cloud_secret"
    assert "wf_cloud_secret" not in json.dumps(state["payload"], sort_keys=True)


def test_cloud_preservation_client_requires_complete_credentials():
    for options in (
        {"organization_id": "org-finance"},
        {"api_key": "wf_cloud_secret"},
    ):
        try:
            CloudPreservationClient("http://cloud.example", **options)
        except ValueError as exc:
            assert str(exc) == "organization_id and api_key must be configured together"
            assert "wf_cloud_secret" not in str(exc)
        else:
            raise AssertionError("incomplete Cloud credentials must be rejected")


def test_cloud_preservation_client_returns_http_failure_result():
    state = {
        "status": "503 Service Unavailable",
        "body": b'{"error":"cloud offline"}',
    }
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is False
    assert result.status_code == 503
    assert result.error_type == "http_error"
    assert "cloud offline" in result.error
    assert result.response == {"error": "cloud offline"}


def test_cloud_preservation_client_redacts_secret_from_http_failure_response():
    secret = "wf_cloud_secret"
    state = {
        "status": "400 Bad Request",
        "body": json.dumps(
            {
                "error": f"rejected {secret}",
                "api_key": secret,
            }
        ).encode("utf-8"),
    }
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(
            base_url,
            organization_id="org-finance",
            api_key=secret,
        ).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.response == {
        "error": "rejected [REDACTED]",
        "api_key": "[REDACTED]",
    }
    assert secret not in result.error
    assert secret not in json.dumps(result.response)


def test_cloud_preservation_client_returns_timeout_failure_result(monkeypatch):
    calls = []

    def raise_timeout(*args, **kwargs):
        calls.append((args, kwargs))
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(requests, "post", raise_timeout)

    result = CloudPreservationClient("http://cloud.example").preserve({"event_id": "evt_123"})

    assert result.ok is False
    assert result.error_type == "timeout"
    assert result.ambiguous is True
    assert result.error == (
        "Cloud evidence preservation was not confirmed; the local Guard decision "
        "remains authoritative. Do not blindly retry because Cloud may already have committed it."
    )
    assert len(calls) == 1


def test_timeout_after_commit_can_be_reconciled_without_retrying_or_mutating_package(monkeypatch):
    package = {"event_id": "evt_123", "decision": "BLOCKED"}
    original_package = dict(package)
    committed = {}
    post_calls = []

    def timeout_after_commit(url, **kwargs):
        post_calls.append({"url": url, "json": dict(kwargs["json"]), "headers": kwargs["headers"], "timeout": kwargs["timeout"]})
        committed["payload"] = dict(kwargs["json"])
        committed["package_id"] = "pkg_after_commit"
        canonical = json.dumps(committed["payload"], sort_keys=True, separators=(",", ":"))
        committed["sha256"] = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
        raise requests.Timeout("response was not received")

    def retrieve(url, *, headers):
        assert url.endswith("/v1/package/pkg_after_commit")
        assert headers == {"X-Organization-ID": "org-finance", "X-API-Key": "wf_cloud_secret"}
        return _response(
            {
                "package_id": "pkg_after_commit",
                "integrity_status": "verified",
                "sha256": committed["sha256"],
                "evidence": committed["payload"],
            }
        )

    monkeypatch.setattr(requests, "post", timeout_after_commit)
    monkeypatch.setattr(requests, "get", retrieve)

    result = CloudPreservationClient(
        "http://cloud.example",
        timeout_seconds=0.1,
        organization_id="org-finance",
        api_key="wf_cloud_secret",
    ).preserve(package)
    recovered = requests.get(
        "http://cloud.example/v1/package/pkg_after_commit",
        headers={"X-Organization-ID": "org-finance", "X-API-Key": "wf_cloud_secret"},
    ).json()

    assert result.ok is False
    assert result.ambiguous is True
    assert len(post_calls) == 1
    assert package == original_package
    assert recovered["integrity_status"] == "verified"
    assert recovered["evidence"] == original_package
    canonical = json.dumps(original_package, sort_keys=True, separators=(",", ":"))
    assert recovered["sha256"] == f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def test_preservation_timeout_does_not_change_authority_or_runtime_timeouts(monkeypatch):
    post_calls = []
    get_calls = []

    def post(url, **kwargs):
        post_calls.append((url, kwargs["timeout"]))
        return _response(_preservation_response() if url.endswith("/v1/preserve") else {"ok": True})

    def get(url, **kwargs):
        get_calls.append((url, kwargs["timeout"]))
        return _response(_compiled_authority())

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setattr(requests, "get", get)

    CloudPreservationClient("http://cloud.example", timeout_seconds=7.5).preserve({"event_id": "evt_123"})
    CloudAuthorityClient(
        "http://cloud.example", organization_id="org", api_key="key"
    ).fetch("repository-change-policy@1.0.0")
    from waveframe_guard.cloud import CloudRuntimeClient

    CloudRuntimeClient(
        "http://cloud.example",
        organization_id="org",
        api_key="key",
        runtime_id="runtime",
        environment="test",
        authority_ref="repository-change-policy@1.0.0",
        runtime_version="guard-test",
    ).heartbeat()

    assert get_calls == [("http://cloud.example/v1/contracts/repository-change-policy/1.0.0", 5.0)]
    assert post_calls == [
        ("http://cloud.example/v1/preserve", 7.5),
        ("http://cloud.example/v1/runtimes/runtime/heartbeats", 5.0),
    ]


def test_cloud_preservation_client_redacts_api_key_from_transport_errors(monkeypatch):
    secret = "wf_cloud_secret"

    def raise_failure(*args, **kwargs):
        raise requests.RequestException(f"transport rejected {secret}")

    monkeypatch.setattr(requests, "post", raise_failure)
    result = CloudPreservationClient(
        "http://cloud.example",
        organization_id="org-finance",
        api_key=secret,
    ).preserve({"event_id": "evt_123"})

    assert result.ok is False
    assert result.error == "transport rejected [REDACTED]"
    assert secret not in result.error


def test_cloud_preservation_client_returns_invalid_json_failure_result():
    state = {
        "status": "200 OK",
        "body": b"not-json",
    }
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is False
    assert result.status_code == 200
    assert result.error_type == "invalid_json"


def test_cloud_preservation_client_rejects_missing_required_receipt_fields():
    state = {
        "status": "200 OK",
        "body": b'{"package_id":"pkg_123"}',
    }
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is False
    assert result.status_code == 200
    assert result.error_type == "invalid_response"
    assert "receipt_id" in result.error
    assert "sha256" in result.error
    assert "timestamp" in result.error


def test_cloud_preservation_client_rejects_wrongly_typed_required_receipt_fields():
    state = {
        "status": "200 OK",
        "body": b'{"package_id":"pkg_123","receipt_id":42,"sha256":"sha256:preserved","timestamp":"2026-07-13T00:00:00+00:00"}',
    }
    server, base_url = serve_preservation_app(state)

    try:
        result = CloudPreservationClient(base_url).preserve({"event_id": "evt_123"})
    finally:
        server.shutdown()
        server.server_close()

    assert result.ok is False
    assert result.status_code == 200
    assert result.error_type == "invalid_response"
    assert "receipt_id" in result.error


def test_cloud_authority_client_fetches_exact_published_contract_with_runtime_headers():
    state = {}
    server, base_url = serve_authority_app(state)

    try:
        contract = CloudAuthorityClient(
            base_url,
            organization_id="waveframe-labs",
            api_key="wf_runtime_secret",
        ).fetch("repository-change-policy@1.0.0")
    finally:
        server.shutdown()
        server.server_close()

    assert contract == _compiled_authority()
    assert state == {
        "method": "GET",
        "path": "/v1/contracts/repository-change-policy/1.0.0",
        "organization_id": "waveframe-labs",
        "api_key": "wf_runtime_secret",
    }


def test_cloud_authority_client_fails_closed_on_contract_hash_mismatch():
    contract = _compiled_authority()
    contract["authority_requirements"] = {"required_roles": ["attacker"]}
    state = {"body": json.dumps(contract).encode("utf-8")}
    server, base_url = serve_authority_app(state)

    try:
        with pytest.raises(CloudAuthorityFetchError, match="integrity check"):
            CloudAuthorityClient(
                base_url,
                organization_id="waveframe-labs",
                api_key="wf_runtime_secret",
            ).fetch("repository-change-policy@1.0.0")
    finally:
        server.shutdown()
        server.server_close()


def test_cloud_authority_client_redacts_runtime_secret_from_http_failures():
    secret = "wf_runtime_secret"
    state = {
        "status": "403 Forbidden",
        "body": f'{{"error":"rejected {secret}"}}'.encode("utf-8"),
    }
    server, base_url = serve_authority_app(state)

    try:
        with pytest.raises(CloudAuthorityFetchError) as exc_info:
            CloudAuthorityClient(
                base_url,
                organization_id="waveframe-labs",
                api_key=secret,
            ).fetch("repository-change-policy@1.0.0")
    finally:
        server.shutdown()
        server.server_close()

    assert secret not in str(exc_info.value)
    assert "[REDACTED]" in str(exc_info.value)
