# ---
# title: "Waveframe Guard External Agent Quickstart Regression Tests"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.15.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest

from waveframe_guard.quickstarts.external_agent import (
    QuickstartSettings,
    build_guard,
    run_quickstart,
)
from waveframe_guard.cloud import (
    CloudPreservationResult,
    CloudRuntimeConnectionResult,
    CloudRuntimeOperationResult,
)
from guard.sdk import Guard
from tools.acceptance.external_agent_clean_machine import _run


def test_external_agent_quickstart_allows_blocks_and_mutates_exactly_once(tmp_path, capsys):
    settings = QuickstartSettings(
        cloud_url="https://cloud.waveframelabs.com",
        organization_id="acme",
        api_key="wf_runtime_secret",
        runtime_id="budget-agent-runtime",
        environment="development",
        actor_id="budget-agent",
        actor_role="allocator",
        authority_ref="budget-quickstart@1.0.0",
    )
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authorities={settings.authority_ref: _threshold_authority()},
        actor_identity={
            "id": settings.actor_id,
            "type": "agent",
            "role": settings.actor_role,
        },
    )
    preservation_client = _configure_successful_cloud_reporting(guard)

    summary = run_quickstart(guard, settings)
    output = capsys.readouterr().out

    assert summary == {
        "runtime_id": "budget-agent-runtime",
        "actor_id": "budget-agent",
        "authority_ref": "budget-quickstart@1.0.0",
        "allowed_decision": "allowed",
        "blocked_decision": "blocked",
        "mutation_count": 1,
        "exactly_once": True,
        "allowed_package_id": "pkg-1",
        "allowed_receipt_id": "receipt-1",
        "allowed_proof_sha256": "sha256:package-1",
        "blocked_package_id": "pkg-2",
        "blocked_receipt_id": "receipt-2",
        "blocked_proof_sha256": "sha256:package-2",
    }
    assert "allowed_decision=allowed" in output
    assert "blocked_decision=blocked" in output
    assert "mutation_count=1" in output
    assert "allowed_package_id=pkg-1" in output
    assert "allowed_receipt_id=receipt-1" in output
    assert "blocked_package_id=pkg-2" in output
    assert "blocked_receipt_id=receipt-2" in output
    assert len(guard.store.history()) == 2
    assert len(preservation_client.payloads) == 2


def test_external_agent_quickstart_fails_on_allowed_preservation_and_redacts_secret(
    tmp_path,
):
    settings, guard = _local_quickstart(tmp_path)
    secret = settings.api_key
    client = _configure_successful_cloud_reporting(
        guard,
        preservation_results=[
            CloudPreservationResult(
                ok=False,
                status_code=400,
                error=f'{{"error":"rejected {secret}"}}',
                error_type="http_error",
            ),
            _preservation_success(2),
        ],
    )

    with pytest.raises(RuntimeError) as exc_info:
        run_quickstart(guard, settings)

    message = str(exc_info.value)
    assert "Cloud preservation failed for the allowed 500-unit action" in message
    assert "HTTP status: 400" in message
    assert "error_type: http_error" in message
    assert 'Cloud error: {"error":"rejected [REDACTED]"}' in message
    assert secret not in message
    assert len(client.payloads) == 2
    assert [record["evaluation"]["status"] for record in guard.store.history()] == [
        "admissible",
        "blocked",
    ]


def test_external_agent_quickstart_fails_on_blocked_preservation(tmp_path):
    settings, guard = _local_quickstart(tmp_path)
    client = _configure_successful_cloud_reporting(
        guard,
        preservation_results=[
            _preservation_success(1),
            CloudPreservationResult(
                ok=False,
                status_code=503,
                error='{"error":"preservation unavailable"}',
                error_type="http_error",
            ),
        ],
    )

    with pytest.raises(RuntimeError) as exc_info:
        run_quickstart(guard, settings)

    message = str(exc_info.value)
    assert "Cloud preservation failed for the blocked 12,500-unit action" in message
    assert "HTTP status: 503" in message
    assert "error_type: http_error" in message
    assert "preservation unavailable" in message
    assert len(client.payloads) == 2


def test_external_agent_quickstart_rejects_malformed_successful_preservation(tmp_path):
    settings, guard = _local_quickstart(tmp_path)
    _configure_successful_cloud_reporting(
        guard,
        preservation_results=[
            CloudPreservationResult(
                ok=True,
                package_id="pkg-1",
                status_code=201,
                response={"package_id": "pkg-1"},
            ),
            _preservation_success(2),
        ],
    )

    with pytest.raises(RuntimeError) as exc_info:
        run_quickstart(guard, settings)

    message = str(exc_info.value)
    assert "HTTP status: 201" in message
    assert "error_type: invalid_response" in message
    assert "receipt_id, sha256, timestamp" in message


def test_external_agent_quickstart_requires_explicit_customer_configuration(monkeypatch):
    for name in (
        "WAVEFRAME_CLOUD_URL",
        "WAVEFRAME_CLOUD_ORGANIZATION_ID",
        "WAVEFRAME_CLOUD_API_KEY",
        "WAVEFRAME_RUNTIME_ID",
        "WAVEFRAME_ACTOR_ID",
        "WAVEFRAME_ACTOR_ROLE",
        "WAVEFRAME_AUTHORITY_REF",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="WAVEFRAME_CLOUD_URL"):
        QuickstartSettings.from_environment()


def test_external_agent_quickstart_reports_actionable_incompatible_authority_diagnostics(
    tmp_path,
):
    settings = QuickstartSettings(
        cloud_url="https://cloud.waveframelabs.com",
        organization_id="acme",
        api_key="wf_runtime_secret",
        runtime_id="budget-agent-runtime",
        environment="development",
        actor_id="budget-agent",
        actor_role="allocator",
        authority_ref="repository-change-policy@1.0.0",
    )
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authorities={settings.authority_ref: _repository_change_authority()},
        actor_identity={
            "id": settings.actor_id,
            "type": "agent",
            "role": settings.actor_role,
        },
    )
    _configure_successful_cloud_reporting(guard)

    with pytest.raises(RuntimeError) as exc_info:
        run_quickstart(guard, settings)

    message = str(exc_info.value)
    assert "expected decision: allowed" in message
    assert "observed execution_state: blocked" in message
    assert "Guard rationale: actor role is not authorized by compiled authority" in message
    assert "violated constraints:" in message
    assert "repository-maintainer" in message
    assert "required evidence: []" in message


def test_external_agent_module_invocation_has_no_runpy_warning():
    environment = os.environ.copy()
    for name in (
        "WAVEFRAME_CLOUD_URL",
        "WAVEFRAME_CLOUD_ORGANIZATION_ID",
        "WAVEFRAME_CLOUD_API_KEY",
        "WAVEFRAME_RUNTIME_ID",
        "WAVEFRAME_ACTOR_ID",
        "WAVEFRAME_ACTOR_ROLE",
        "WAVEFRAME_AUTHORITY_REF",
    ):
        environment.pop(name, None)

    completed = subprocess.run(
        [sys.executable, "-m", "waveframe_guard.quickstarts.external_agent"],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "RuntimeWarning" not in completed.stderr
    assert "Missing required environment variable: WAVEFRAME_CLOUD_URL" in completed.stderr


def test_quickstart_package_exports_are_lazy_and_preserved():
    code = """
import sys
import waveframe_guard.quickstarts as quickstarts

assert "waveframe_guard.quickstarts.external_agent" not in sys.modules
assert quickstarts.__all__ == [
    "QuickstartSettings",
    "build_guard",
    "main",
    "run_quickstart",
]
assert quickstarts.QuickstartSettings.__name__ == "QuickstartSettings"
assert "waveframe_guard.quickstarts.external_agent" in sys.modules
assert callable(quickstarts.build_guard)
assert callable(quickstarts.main)
assert callable(quickstarts.run_quickstart)
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_acceptance_runner_surfaces_captured_child_output(tmp_path, capsys):
    command = [
        sys.executable,
        "-c",
        (
            "import sys; "
            "print('captured child stdout'); "
            "print('captured child stderr', file=sys.stderr); "
            "raise SystemExit(7)"
        ),
    ]

    with pytest.raises(SystemExit) as exc_info:
        _run(command, cwd=tmp_path, capture_output=True)

    captured = capsys.readouterr()
    assert exc_info.value.code == 7
    assert "captured child stdout" in captured.out
    assert "captured child stderr" in captured.err


def test_external_agent_quickstart_reports_both_decisions_and_identities_to_cloud(
    tmp_path,
    monkeypatch,
):
    state = {"requests": [], "preservation_count": 0}
    server, cloud_url = _serve_cloud_boundary(state)
    settings = QuickstartSettings(
        cloud_url=cloud_url,
        organization_id="acme",
        api_key="wf_runtime_secret",
        runtime_id="budget-agent-runtime",
        environment="development",
        actor_id="budget-agent",
        actor_role="allocator",
        authority_ref="budget-quickstart@1.0.0",
    )
    monkeypatch.chdir(tmp_path)

    try:
        guard = build_guard(settings)
        summary = run_quickstart(guard, settings)
    finally:
        server.shutdown()
        server.server_close()

    assert summary["allowed_decision"] == "allowed"
    assert summary["blocked_decision"] == "blocked"
    assert summary["allowed_package_id"] == "pkg-1"
    assert summary["allowed_receipt_id"] == "receipt-1"
    assert summary["blocked_package_id"] == "pkg-2"
    assert summary["blocked_receipt_id"] == "receipt-2"
    paths = [request["path"] for request in state["requests"]]
    assert paths.count("/v1/contracts/budget-quickstart/1.0.0") == 1
    assert paths.count("/v1/runtimes/register") == 1
    assert paths.count("/v1/runtimes/budget-agent-runtime/heartbeats") == 1
    assert paths.count("/v1/preserve") == 2
    assert paths.count("/v1/runtime/attestations") == 2

    registration = next(
        request["payload"]
        for request in state["requests"]
        if request["path"] == "/v1/runtimes/register"
    )
    heartbeat = next(
        request["payload"]
        for request in state["requests"]
        if request["path"] == "/v1/runtimes/budget-agent-runtime/heartbeats"
    )
    assert registration["environment"] == "development"
    assert registration["environment_id"] == "development"
    assert heartbeat["environment"] == "development"
    assert heartbeat["environment_id"] == "development"

    preserved = [
        request["payload"]
        for request in state["requests"]
        if request["path"] == "/v1/preserve"
    ]
    assert {
        package["saved_evaluation"]["guard_enforcement_outcome"]["execution_state"]
        for package in preserved
    } == {"allowed", "blocked"}
    assert {
        package["saved_evaluation"]["inputs"]["runtime_evidence"]["actor_identity"]["id"]
        for package in preserved
    } == {"budget-agent"}
    assert {
        package["saved_evaluation"]["guard_enforcement_outcome"]["authority_ref"]
        for package in preserved
    } == {"budget-quickstart@1.0.0"}

    attestations = [
        request["payload"]
        for request in state["requests"]
        if request["path"] == "/v1/runtime/attestations"
    ]
    assert {attestation["runtime_id"] for attestation in attestations} == {
        "budget-agent-runtime"
    }
    assert {attestation["authority_ref"] for attestation in attestations} == {
        "budget-quickstart@1.0.0"
    }
    assert {
        (attestation["runtime_decision"], attestation["mutation_executed"])
        for attestation in attestations
    } == {("ALLOWED", True), ("BLOCKED", False)}


def _threshold_authority():
    authority = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "budget-quickstart",
        "contract_version": "1.0.0",
        "authority_requirements": {"required_roles": ["allocator"]},
        "approval_requirements": {
            "thresholds": [
                {
                    "field": "amount",
                    "operator": ">=",
                    "value": 10_000,
                    "requires_role": "finance-approver",
                }
            ]
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    canonical = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    authority["contract_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return authority


def _local_quickstart(tmp_path):
    settings = QuickstartSettings(
        cloud_url="https://cloud.waveframelabs.com",
        organization_id="acme",
        api_key="wf_runtime_secret",
        runtime_id="budget-agent-runtime",
        environment="development",
        actor_id="budget-agent",
        actor_role="allocator",
        authority_ref="budget-quickstart@1.0.0",
    )
    guard = Guard.local(
        workspace=tmp_path / ".guard-local",
        authorities={settings.authority_ref: _threshold_authority()},
        actor_identity={
            "id": settings.actor_id,
            "type": "agent",
            "role": settings.actor_role,
        },
    )
    return settings, guard


def _configure_successful_cloud_reporting(guard, preservation_results=None):
    client = _SequencedPreservationClient(
        preservation_results
        or [_preservation_success(1), _preservation_success(2)]
    )
    guard.cloud_preservation_client = client
    guard.cloud_runtime_client = _SuccessfulRuntimeClient()
    registration = CloudRuntimeOperationResult(ok=True, response={"accepted": True}, status_code=201)
    heartbeat = CloudRuntimeOperationResult(ok=True, response={"accepted": True}, status_code=202)
    guard.runtime_connection = CloudRuntimeConnectionResult(
        ok=True,
        registration=registration,
        heartbeat=heartbeat,
    )
    return client


def _preservation_success(index):
    return CloudPreservationResult(
        ok=True,
        package_id=f"pkg-{index}",
        receipt_id=f"receipt-{index}",
        sha256=f"sha256:package-{index}",
        timestamp=f"2026-08-08T00:00:0{index}+00:00",
        receipt={"receipt_id": f"receipt-{index}"},
        response={"package_id": f"pkg-{index}"},
        status_code=201,
    )


class _SequencedPreservationClient:
    def __init__(self, results):
        self.results = list(results)
        self.payloads = []

    def preserve(self, payload):
        self.payloads.append(payload)
        return self.results.pop(0)


class _SuccessfulRuntimeClient:
    def __init__(self):
        self.attestations = []

    def attest(self, **payload):
        self.attestations.append(payload)
        return CloudRuntimeOperationResult(
            ok=True,
            response={"attestation_id": f"attest-{len(self.attestations)}"},
            status_code=201,
        )


def _repository_change_authority():
    authority = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "repository-change-policy",
        "contract_version": "1.0.0",
        "authority_requirements": {"required_roles": ["repository-maintainer"]},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    canonical = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    authority["contract_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return authority


def _serve_cloud_boundary(state):
    authority = _threshold_authority()

    def app(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length) if length else b""
        payload = json.loads(body) if body else None
        request = {
            "method": environ["REQUEST_METHOD"],
            "path": environ["PATH_INFO"],
            "organization_id": environ.get("HTTP_X_ORGANIZATION_ID"),
            "api_key": environ.get("HTTP_X_API_KEY"),
            "payload": payload,
        }
        state["requests"].append(request)

        if request["path"] == "/v1/contracts/budget-quickstart/1.0.0":
            response = authority
        elif request["path"] == "/v1/preserve":
            state["preservation_count"] += 1
            index = state["preservation_count"]
            response = {
                "package_id": f"pkg-{index}",
                "receipt_id": f"receipt-{index}",
                "sha256": f"sha256:package-{index}",
                "timestamp": f"2026-08-08T00:00:0{index}+00:00",
            }
        else:
            response = {"accepted": True}

        encoded = json.dumps(response).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(encoded))),
            ],
        )
        return [encoded]

    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"
