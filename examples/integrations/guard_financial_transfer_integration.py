from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard.sdk import Guard, GuardExecutionBlocked


def run_integration(workspace: str | Path = ".guard-local") -> dict[str, Any]:
    mutation_log: list[dict[str, Any]] = []
    guard = Guard.local(
        workspace=workspace,
        authorities={"finance-policy@1.0.0": compiled_finance_authority()},
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        execution_context={"surface": "production_transfer_service", "boundary": "before_mutation"},
        evaluation_time_source=lambda: "2026-06-07T12:00:00+00:00",
    )

    @guard.protect(authority="finance-policy@1.0.0")
    def wire_transfer(execution_request: dict[str, Any]) -> dict[str, Any]:
        mutation_log.append(
            {
                "mutation": "wire_transfer",
                "amount": execution_request["arguments"]["amount"],
            }
        )
        return {"wire_sent": execution_request["arguments"]["amount"]}

    request = normalized_wire_transfer(amount=12500)
    try:
        result = wire_transfer(request)
        state = "allowed"
    except GuardExecutionBlocked as exc:
        result = exc.outcome
        state = "blocked"

    saved = guard.store.history()[-1]
    replay = guard.store.replay(saved["run_id"])
    return {
        "integration": "financial_transfer_runtime_boundary",
        "execution_state": state,
        "mutation_executed": bool(mutation_log),
        "run_id": saved["run_id"],
        "receipt_path": str(Path(workspace) / "receipts" / f"{saved['run_id']}.json"),
        "manifest_path": str(Path(workspace) / "manifests" / f"{saved['run_id']}.json"),
        "replay_record_path": str(Path(workspace) / "replays" / f"{saved['run_id']}.json"),
        "replay_matches": replay["matches"],
        "result": result,
    }


def compiled_finance_authority() -> dict[str, Any]:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:finance-transfer-compiled-authority",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {
            "required": [
                {"role": "manager"},
                {"role": "director", "condition": {"field": "amount", "operator": ">", "value": 10000}},
            ]
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {"separation_of_duties": True},
    }


def normalized_wire_transfer(*, amount: int) -> dict[str, Any]:
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": f"wire-transfer-{amount}",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


if __name__ == "__main__":
    print(json.dumps(run_integration(), indent=2, sort_keys=True))
