# ---
# title: "Waveframe Guard External Agent Quickstart Regression Tests"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.14.0-dev"
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
    }
    assert "allowed_decision=allowed" in output
    assert "blocked_decision=blocked" in output
    assert "mutation_count=1" in output
    assert len(guard.store.history()) == 2


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
    paths = [request["path"] for request in state["requests"]]
    assert paths.count("/v1/contracts/budget-quickstart/1.0.0") == 1
    assert paths.count("/v1/runtimes/register") == 1
    assert paths.count("/v1/runtimes/budget-agent-runtime/heartbeats") == 1
    assert paths.count("/v1/preserve") == 2
    assert paths.count("/v1/runtime/attestations") == 2

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
