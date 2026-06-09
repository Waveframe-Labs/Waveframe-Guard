from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard.sdk import GuardRuntimeBoundary, LocalEvaluationStore, agent_runner_adapter


def run_demo(store_root: str | Path | None = None) -> dict[str, Any]:
    temporary = TemporaryDirectory() if store_root is None else None
    root = Path(store_root or temporary.name)
    executed_steps = []
    guard = GuardRuntimeBoundary(
        compiled_authority=_compiled_authority(),
        actor_identity={"id": "agent-1", "type": "agent", "role": "agent"},
        approvals=[],
        store=LocalEvaluationStore(root),
        evaluation_time_source=lambda: "2026-06-03T22:30:00+00:00",
    )

    def run_agent_step(step: dict[str, Any]) -> dict[str, Any]:
        executed_steps.append(step["id"])
        return {"executed": step["id"]}

    guarded_runner = agent_runner_adapter(
        guard,
        request_loader=lambda step: step["normalized_execution_request"],
        runner=run_agent_step,
    )
    proposal = _agent_proposal()
    try:
        guarded_runner(proposal)
        blocked = False
    except Exception as exc:
        blocked = True
        outcome = exc.outcome
    saved = LocalEvaluationStore(root).history()[-1]
    replay = LocalEvaluationStore(root).replay(saved["run_id"])
    if temporary is not None:
        temporary.cleanup()
    return {
        "demo": "agent_execution_boundary",
        "agent_proposal": proposal["proposal"],
        "normalized_execution_request": proposal["normalized_execution_request"],
        "decision": outcome["status"] if blocked else "admissible",
        "agent_action_executed": bool(executed_steps),
        "receipt": saved["receipt"],
        "replay_reference": {
            "run_id": saved["run_id"],
            "matches": replay["matches"],
        },
    }


def _compiled_authority() -> dict[str, Any]:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "agent-tool-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:agent-demo",
        "authority_requirements": {"required_roles": ["agent"]},
        "approval_requirements": {
            "required": [
                {
                    "role": "human-supervisor",
                    "condition": {"field": "amount", "operator": ">", "value": 0},
                }
            ]
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }


def _agent_proposal() -> dict[str, Any]:
    return {
        "id": "agent-step-1",
        "proposal": {
            "intent": "send external payment",
            "tool": "payments.transfer",
            "amount": 2500,
        },
        "normalized_execution_request": {
            "schema_version": "normalized_execution_request.v1",
            "request_id": "agent-step-1",
            "action": "tool_call",
            "target": "payments.transfer",
            "arguments": {"amount": 2500, "destination": "external_vendor"},
            "artifacts": [],
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_demo(".guard-demo/agent"), indent=2, sort_keys=True))
