from __future__ import annotations

from tempfile import TemporaryDirectory
from pathlib import Path
from typing import Any

from guard.sdk import GuardRuntimeBoundary, LocalEvaluationStore


def run_demo(store_root: str | Path | None = None) -> dict[str, Any]:
    temporary = TemporaryDirectory() if store_root is None else None
    root = Path(store_root or temporary.name)
    mutation_log = []
    guard = GuardRuntimeBoundary(
        compiled_authority=_compiled_authority(),
        actor_identity={"id": "employee-1", "type": "human", "role": "employee"},
        approvals=[],
        store=LocalEvaluationStore(root),
        evaluation_time_source=lambda: "2026-06-03T22:30:00+00:00",
    )

    def wire_transfer(amount: int) -> dict[str, Any]:
        mutation_log.append({"wire_sent": amount})
        return {"wire_sent": amount}

    request = _normalized_request(amount=12500)
    result = guard.execute(
        wire_transfer,
        execution_request=request,
        args=(12500,),
        raise_on_block=False,
        execution_context={"surface": "fastapi_route", "route": "POST /wire"},
    )
    saved = LocalEvaluationStore(root).history()[-1]
    replay = LocalEvaluationStore(root).replay(saved["run_id"])
    if temporary is not None:
        temporary.cleanup()
    return {
        "demo": "fastapi_runtime_protection",
        "request": request,
        "decision": result["outcome"]["status"],
        "mutation_executed": bool(mutation_log),
        "receipt": saved["receipt"],
        "replay_reference": {
            "run_id": saved["run_id"],
            "matches": replay["matches"],
        },
    }


def create_app():
    from fastapi import FastAPI

    app = FastAPI()

    @app.post("/wire")
    def wire_transfer_route(payload: dict[str, Any]) -> dict[str, Any]:
        return run_demo()["receipt"]

    return app


def _compiled_authority() -> dict[str, Any]:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:fastapi-demo",
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


def _normalized_request(*, amount: int) -> dict[str, Any]:
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": "wire-transfer-demo",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_demo(".guard-demo/fastapi"), indent=2, sort_keys=True))
