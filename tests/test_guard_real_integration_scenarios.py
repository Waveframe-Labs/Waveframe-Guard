from __future__ import annotations

from examples.e2e_agent_execution_boundary import run_demo as run_agent_demo
from examples.e2e_fastapi_runtime_protection import run_demo as run_fastapi_demo
from examples.e2e_queue_worker_protection import run_demo as run_queue_demo


def test_fastapi_runtime_protection_blocks_before_mutation(tmp_path):
    result = run_fastapi_demo(tmp_path / "fastapi")

    assert result["demo"] == "fastapi_runtime_protection"
    assert result["request"]["schema_version"] == "normalized_execution_request.v1"
    assert result["decision"] == "blocked"
    assert result["mutation_executed"] is False
    assert result["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert result["replay_reference"]["matches"] is True


def test_agent_execution_boundary_blocks_unsafe_tool_action(tmp_path):
    result = run_agent_demo(tmp_path / "agent")

    assert result["demo"] == "agent_execution_boundary"
    assert result["agent_proposal"]["tool"] == "payments.transfer"
    assert result["normalized_execution_request"]["schema_version"] == "normalized_execution_request.v1"
    assert result["decision"] == "blocked"
    assert result["agent_action_executed"] is False
    assert result["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert result["replay_reference"]["matches"] is True


def test_queue_worker_protection_escalates_before_deferred_job(tmp_path):
    result = run_queue_demo(tmp_path / "queue")

    assert result["demo"] == "queue_worker_protection"
    assert result["job"]["normalized_execution_request"]["schema_version"] == "normalized_execution_request.v1"
    assert result["decision"] == "escalated"
    assert result["job_processed"] is False
    assert result["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert result["replay_reference"]["matches"] is True
