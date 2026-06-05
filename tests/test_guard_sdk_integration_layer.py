from __future__ import annotations

import pytest

from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.sdk import (
    ENFORCEMENT_RECEIPT_V1,
    SAVED_EVALUATION_V1,
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
