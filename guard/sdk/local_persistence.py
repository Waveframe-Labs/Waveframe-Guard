from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guard.runtime import evaluate_runtime
from guard.runtime.builders import GUARD_ENFORCEMENT_OUTCOME_V1, validate_guard_enforcement_outcome
from guard.runtime.identity import stable_hash, stable_id


SAVED_EVALUATION_V1 = "guard_saved_evaluation.v1"
ENFORCEMENT_RECEIPT_V1 = "guard_enforcement_receipt.v1"


class LocalEvaluationStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.history_path = self.root / "evaluation-history.jsonl"
        self.receipt_root = self.root / "receipts"

    def save_evaluation(
        self,
        *,
        inputs: dict[str, Any],
        evaluation: dict[str, Any],
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self.root.mkdir(parents=True, exist_ok=True)
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        outcome = validate_guard_enforcement_outcome(evaluation["enforcement_outcome"])
        receipt = build_enforcement_receipt(
            inputs=inputs,
            evaluation=evaluation,
            recorded_at=recorded_at or _evaluation_timestamp(evaluation),
        )
        record = {
            "schema_version": SAVED_EVALUATION_V1,
            "run_id": receipt["run_id"],
            "recorded_at": receipt["recorded_at"],
            "inputs": inputs,
            "evaluation": evaluation,
            "guard_enforcement_outcome": outcome,
            "receipt": receipt,
        }
        record["record_hash"] = stable_hash(record)
        with self.history_path.open("a", encoding="utf-8") as history:
            history.write(json.dumps(record, sort_keys=True) + "\n")
        self.export_receipt(receipt)
        return record

    def history(self) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        return [
            json.loads(line)
            for line in self.history_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def load_run(self, run_id: str) -> dict[str, Any]:
        for record in reversed(self.history()):
            if record["run_id"] == run_id:
                return record
        raise FileNotFoundError(f"saved Guard evaluation not found: {run_id}")

    def replay(self, run_id: str) -> dict[str, Any]:
        record = self.load_run(run_id)
        inputs = record["inputs"]
        runtime_evidence = inputs["runtime_evidence"]
        replayed = evaluate_runtime(
            compiled_authority=inputs["compiled_authority"],
            execution_request=inputs["execution_request"],
            actor_identity=runtime_evidence["actor_identity"],
            continuity_state=inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot")),
            replay_posture=runtime_evidence.get("replay_evidence"),
            evidence_posture={
                "approvals": runtime_evidence.get("approvals", []),
                "execution_context": runtime_evidence.get("execution_context", {}),
            },
            evaluation_time=runtime_evidence["timestamp_source"]["timestamp"],
            start_sequence=_start_sequence(record["evaluation"]),
        )
        return {
            "schema_version": "guard_replay_result.v1",
            "run_id": run_id,
            "matches": replayed["enforcement_outcome"]["outcome_hash"]
            == record["guard_enforcement_outcome"]["outcome_hash"],
            "original_outcome_hash": record["guard_enforcement_outcome"]["outcome_hash"],
            "replayed_outcome_hash": replayed["enforcement_outcome"]["outcome_hash"],
            "replayed_evaluation": replayed,
        }

    def export_receipt(self, receipt: dict[str, Any]) -> Path:
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        path = self.receipt_root / f"{receipt['run_id']}.json"
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path


def build_enforcement_receipt(
    *,
    inputs: dict[str, Any],
    evaluation: dict[str, Any],
    recorded_at: str,
) -> dict[str, Any]:
    outcome = validate_guard_enforcement_outcome(evaluation["enforcement_outcome"])
    run_basis = {
        "authority_ref": outcome["authority_ref"],
        "outcome_hash": outcome["outcome_hash"],
        "execution_request": inputs["execution_request"],
        "runtime_evidence": inputs["runtime_evidence"],
    }
    receipt = {
        "schema_version": ENFORCEMENT_RECEIPT_V1,
        "run_id": stable_id("guard_run", run_basis),
        "recorded_at": recorded_at,
        "authority_ref": outcome["authority_ref"],
        "outcome_status": outcome["status"],
        "outcome_id": outcome["outcome_id"],
        "outcome_hash": outcome["outcome_hash"],
        "evaluation_trace_hash": evaluation["evaluation_trace"]["trace_hash"],
        "chronology_event_ids": [event["event_id"] for event in evaluation["telemetry_events"]],
    }
    receipt["receipt_hash"] = stable_hash(receipt)
    return receipt


def _evaluation_timestamp(evaluation: dict[str, Any]) -> str:
    events = evaluation.get("telemetry_events") or []
    if events:
        return events[0]["timestamp"]
    return evaluation.get("runtime_evidence", {}).get("timestamp_source", {}).get("timestamp", "")


def _start_sequence(evaluation: dict[str, Any]) -> int:
    events = evaluation.get("telemetry_events") or []
    if not events:
        return 1
    return int(events[0]["sequence"])
