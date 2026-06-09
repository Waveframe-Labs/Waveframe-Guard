from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard.sdk import GuardRuntimeBoundary, LocalEvaluationStore, queue_job_adapter


def run_demo(store_root: str | Path | None = None) -> dict[str, Any]:
    temporary = TemporaryDirectory() if store_root is None else None
    root = Path(store_root or temporary.name)
    processed_jobs = []
    guard = GuardRuntimeBoundary(
        compiled_authority=_compiled_authority(),
        actor_identity={"id": "worker-1", "type": "service", "role": "worker"},
        approvals=[],
        replay_posture={"required": True, "obligations": [{"obligation": "link_replay"}]},
        store=LocalEvaluationStore(root),
        evaluation_time_source=lambda: "2026-06-03T22:30:00+00:00",
    )

    def process_job(job: dict[str, Any]) -> dict[str, Any]:
        processed_jobs.append(job["id"])
        return {"processed": job["id"]}

    guarded_worker = queue_job_adapter(
        guard,
        request_loader=lambda job: job["normalized_execution_request"],
        handler=process_job,
    )
    job = _job()
    try:
        guarded_worker(job)
        outcome_status = "admissible"
    except Exception as exc:
        outcome_status = exc.outcome["status"]
    saved = LocalEvaluationStore(root).history()[-1]
    replay = LocalEvaluationStore(root).replay(saved["run_id"])
    if temporary is not None:
        temporary.cleanup()
    return {
        "demo": "queue_worker_protection",
        "job": job,
        "decision": outcome_status,
        "job_processed": bool(processed_jobs),
        "receipt": saved["receipt"],
        "replay_reference": {
            "run_id": saved["run_id"],
            "matches": replay["matches"],
        },
    }


def _compiled_authority() -> dict[str, Any]:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "queue-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:queue-demo",
        "authority_requirements": {"required_roles": ["worker"]},
        "approval_requirements": {"required": []},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }


def _job() -> dict[str, Any]:
    return {
        "id": "nightly-settlement-1",
        "normalized_execution_request": {
            "schema_version": "normalized_execution_request.v1",
            "request_id": "nightly-settlement-1",
            "action": "settle",
            "target": "batch_payments",
            "arguments": {"amount": 8500},
            "artifacts": [],
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_demo(".guard-demo/queue"), indent=2, sort_keys=True))
