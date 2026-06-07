from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guard.runtime import evaluate_runtime
from guard.runtime.builders import GUARD_ENFORCEMENT_OUTCOME_V1, validate_guard_enforcement_outcome
from guard.runtime.identity import stable_hash, stable_id


SAVED_EVALUATION_V1 = "guard_saved_evaluation.v1"
ENFORCEMENT_RECEIPT_V1 = "guard_enforcement_receipt.v1"
GUARD_ARTIFACT_MANIFEST_V1 = "guard_artifact_manifest.v1"


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
        artifact_manifest = build_artifact_manifest(
            inputs=inputs,
            evaluation=evaluation,
            receipt=receipt,
        )
        record = {
            "schema_version": SAVED_EVALUATION_V1,
            "run_id": receipt["run_id"],
            "recorded_at": receipt["recorded_at"],
            "inputs": inputs,
            "evaluation": evaluation,
            "guard_enforcement_outcome": outcome,
            "receipt": receipt,
            "artifact_manifest": artifact_manifest,
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
    input_hashes = _input_hashes(inputs)
    replay_basis = _replay_basis(inputs, evaluation)
    chronology_hash = stable_hash(evaluation["telemetry_events"])
    lineage_basis = _lineage_continuity_basis(
        inputs=inputs,
        evaluation=evaluation,
        input_hashes=input_hashes,
        chronology_hash=chronology_hash,
    )
    run_basis = {
        "authority_ref": outcome["authority_ref"],
        "contract_hash": inputs["compiled_authority"].get("contract_hash"),
        "outcome_hash": outcome["outcome_hash"],
        "execution_request_hash": input_hashes["execution_request_hash"],
        "runtime_evidence_hash": input_hashes["runtime_evidence_hash"],
        "continuity_posture_hash": input_hashes["continuity_posture_hash"],
        "replay_basis_hash": stable_hash(replay_basis),
    }
    receipt = {
        "schema_version": ENFORCEMENT_RECEIPT_V1,
        "run_id": stable_id("guard_run", run_basis),
        "recorded_at": recorded_at,
        "authority_ref": outcome["authority_ref"],
        "contract_hash": inputs["compiled_authority"].get("contract_hash"),
        "outcome_status": outcome["status"],
        "outcome_id": outcome["outcome_id"],
        "outcome_hash": outcome["outcome_hash"],
        "evaluation_trace_hash": evaluation["evaluation_trace"]["trace_hash"],
        "chronology_event_ids": [event["event_id"] for event in evaluation["telemetry_events"]],
        "chronology_hash": chronology_hash,
        "input_hashes": input_hashes,
        "deterministic_identity_hash": stable_hash(run_basis),
        "replay_basis_hash": stable_hash(replay_basis),
        "lineage_continuity_hash": stable_hash(lineage_basis),
    }
    receipt["receipt_hash"] = stable_hash(receipt)
    return receipt


def build_artifact_manifest(
    *,
    inputs: dict[str, Any],
    evaluation: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    persisted_artifacts = {
        "inputs": stable_hash(inputs),
        "evaluation": stable_hash(evaluation),
        "guard_enforcement_outcome": stable_hash(evaluation["enforcement_outcome"]),
        "receipt": receipt["receipt_hash"],
    }
    replay_basis = _replay_basis(inputs, evaluation)
    manifest = {
        "schema_version": GUARD_ARTIFACT_MANIFEST_V1,
        "persisted_artifacts": persisted_artifacts,
        "hashed_inputs": receipt["input_hashes"],
        "deterministic_identity_hash": receipt["deterministic_identity_hash"],
        "replay_basis_hash": receipt["replay_basis_hash"],
        "lineage_continuity_hash": receipt["lineage_continuity_hash"],
        "replayable": True,
        "replay_basis_fields": sorted(replay_basis.keys()),
        "lineage_continuity_fields": [
            "authority_ref",
            "contract_hash",
            "execution_request_hash",
            "runtime_evidence_hash",
            "continuity_posture_hash",
            "replay_posture_hash",
            "outcome_hash",
            "evaluation_trace_hash",
            "chronology_hash",
        ],
    }
    manifest["manifest_hash"] = stable_hash(manifest)
    return manifest


def _input_hashes(inputs: dict[str, Any]) -> dict[str, str]:
    runtime_evidence = inputs["runtime_evidence"]
    return {
        "compiled_authority_hash": stable_hash(inputs["compiled_authority"]),
        "execution_request_hash": stable_hash(inputs["execution_request"]),
        "runtime_evidence_hash": stable_hash(runtime_evidence),
        "continuity_posture_hash": stable_hash(
            inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot", {}))
        ),
        "replay_posture_hash": stable_hash(runtime_evidence.get("replay_evidence", {})),
        "actor_identity_hash": stable_hash(runtime_evidence.get("actor_identity", {})),
        "approval_evidence_hash": stable_hash(runtime_evidence.get("approvals", [])),
        "execution_context_hash": stable_hash(runtime_evidence.get("execution_context", {})),
        "timestamp_source_hash": stable_hash(runtime_evidence.get("timestamp_source", {})),
    }


def _replay_basis(inputs: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    runtime_evidence = inputs["runtime_evidence"]
    return {
        "compiled_authority": inputs["compiled_authority"],
        "execution_request": inputs["execution_request"],
        "actor_identity": runtime_evidence["actor_identity"],
        "continuity_state": inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot", {})),
        "replay_posture": runtime_evidence.get("replay_evidence", {}),
        "evidence_posture": {
            "approvals": runtime_evidence.get("approvals", []),
            "execution_context": runtime_evidence.get("execution_context", {}),
        },
        "evaluation_time": runtime_evidence["timestamp_source"]["timestamp"],
        "start_sequence": _start_sequence(evaluation),
    }


def _lineage_continuity_basis(
    *,
    inputs: dict[str, Any],
    evaluation: dict[str, Any],
    input_hashes: dict[str, str],
    chronology_hash: str,
) -> dict[str, Any]:
    outcome = evaluation["enforcement_outcome"]
    return {
        "authority_ref": outcome["authority_ref"],
        "contract_hash": inputs["compiled_authority"].get("contract_hash"),
        "execution_request_hash": input_hashes["execution_request_hash"],
        "runtime_evidence_hash": input_hashes["runtime_evidence_hash"],
        "continuity_posture_hash": input_hashes["continuity_posture_hash"],
        "replay_posture_hash": input_hashes["replay_posture_hash"],
        "outcome_hash": outcome["outcome_hash"],
        "evaluation_trace_hash": evaluation["evaluation_trace"]["trace_hash"],
        "chronology_hash": chronology_hash,
    }


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
