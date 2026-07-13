from __future__ import annotations

import json
import threading
from wsgiref.simple_server import make_server

import requests

from waveframe_guard.cloud import CloudPreservationClient


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


def test_cloud_preservation_client_returns_timeout_failure_result(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise requests.Timeout("request timed out")

    monkeypatch.setattr(requests, "post", raise_timeout)

    result = CloudPreservationClient("http://cloud.example").preserve({"event_id": "evt_123"})

    assert result.ok is False
    assert result.error_type == "timeout"
    assert "timed out" in result.error


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
