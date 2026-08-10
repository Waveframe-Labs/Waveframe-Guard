from __future__ import annotations

import hashlib
import json
import threading
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
        start_response("200 OK", [("Content-Type", "application/json")])
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
    def raise_timeout(*args, **kwargs):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(requests, "post", raise_timeout)

    result = CloudPreservationClient("http://cloud.example").preserve({"event_id": "evt_123"})

    assert result.ok is False
    assert result.error_type == "timeout"
    assert "timed out" in result.error


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
