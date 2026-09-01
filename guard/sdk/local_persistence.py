from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from guard.runtime import evaluate_runtime
from guard.runtime.builders import GUARD_ENFORCEMENT_OUTCOME_V1, validate_guard_enforcement_outcome
from guard.runtime.identity import stable_hash, stable_id


SAVED_EVALUATION_V1 = "guard_saved_evaluation.v1"
ENFORCEMENT_RECEIPT_V1 = "guard_enforcement_receipt.v1"
GUARD_ARTIFACT_MANIFEST_V1 = "guard_artifact_manifest.v1"
GUARD_REPLAY_RECORD_V1 = "guard_replay_record.v1"
GUARD_REPLAY_RESULT_V1 = "guard_replay_result.v1"
CLOUD_PRESERVATION_METADATA_V1 = "guard_cloud_preservation_metadata.v1"
GUARD_EXECUTION_ATTESTATION_V1 = "guard_execution_attestation.v1"

REPLAY_MISMATCH_CLASSES = {
    "contract_drift",
    "evidence_mutation",
    "chronology_mutation",
    "continuity_mismatch",
    "request_mismatch",
    "manifest_integrity_failure",
}


class GuardArtifactError(ValueError):
    error_class = "artifact_error"


class UnsupportedArtifactSchemaError(GuardArtifactError):
    error_class = "unsupported_schema_version"


class UnreadableReceiptError(GuardArtifactError):
    error_class = "unreadable_receipt"


class ConflictingCloudPreservationError(GuardArtifactError):
    error_class = "conflicting_cloud_preservation"


class LocalEvaluationStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.history_path = self.root / "evaluation-history.jsonl"
        self.receipt_root = self.root / "receipts"
        self.manifest_root = self.root / "manifests"
        self.replay_root = self.root / "replays"
        self.execution_attestation_root = self.root / "execution-attestations"

    def save_evaluation(
        self,
        *,
        inputs: dict[str, Any],
        evaluation: dict[str, Any],
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self.root.mkdir(parents=True, exist_ok=True)
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        self.manifest_root.mkdir(parents=True, exist_ok=True)
        self.replay_root.mkdir(parents=True, exist_ok=True)
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
            "inputs": deepcopy(inputs),
            "evaluation": deepcopy(evaluation),
            "guard_enforcement_outcome": deepcopy(outcome),
            "receipt": deepcopy(receipt),
            "artifact_manifest": deepcopy(artifact_manifest),
        }
        record["record_hash"] = stable_hash(record)
        with self.history_path.open("a", encoding="utf-8") as history:
            history.write(json.dumps(record, sort_keys=True) + "\n")
        self.export_receipt(receipt)
        self.export_manifest(artifact_manifest)
        return record

    def append_cloud_preservation(
        self,
        run_id: str,
        metadata: dict[str, Any],
        *,
        record_hash: str | None = None,
    ) -> dict[str, Any]:
        records = self.history()
        updated_record = None
        for record in reversed(records):
            if record["run_id"] != run_id:
                continue
            if record_hash is not None and record.get("record_hash") != record_hash:
                continue
            incoming = {
                "schema_version": CLOUD_PRESERVATION_METADATA_V1,
                **metadata,
            }
            if "cloud_preservation" in record:
                _validate_cloud_preservation_update(
                    existing=record.get("cloud_preservation"),
                    incoming=incoming,
                )
            record["cloud_preservation"] = incoming
            record.pop("record_hash", None)
            record["record_hash"] = stable_hash(record)
            updated_record = record
            break

        if updated_record is None:
            raise FileNotFoundError(f"saved Guard evaluation not found: {run_id}")

        self.root.mkdir(parents=True, exist_ok=True)
        with self.history_path.open("w", encoding="utf-8") as history:
            for record in records:
                history.write(json.dumps(record, sort_keys=True) + "\n")
        return updated_record

    def history(self) -> list[dict[str, Any]]:
        return self.history_with_errors()["records"]

    def history_with_errors(self) -> dict[str, Any]:
        if not self.history_path.exists():
            return {"records": [], "errors": []}
        records = []
        errors = []
        for line_number, line in enumerate(self.history_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if record.get("schema_version") != SAVED_EVALUATION_V1:
                    raise UnsupportedArtifactSchemaError(
                        f"unsupported saved evaluation schema: {record.get('schema_version')}"
                    )
                records.append(record)
            except json.JSONDecodeError as exc:
                errors.append(
                    {
                        "error_class": "unreadable_receipt",
                        "line": line_number,
                        "message": f"unreadable saved evaluation record: {exc.msg}",
                    }
                )
            except GuardArtifactError as exc:
                errors.append(
                    {
                        "error_class": exc.error_class,
                        "line": line_number,
                        "message": str(exc),
                    }
                )
        return {"records": records, "errors": errors}

    def load_run(self, run_id: str) -> dict[str, Any]:
        for record in reversed(self.history()):
            if record["run_id"] == run_id:
                return record
        raise FileNotFoundError(f"saved Guard evaluation not found: {run_id}")

    def replay(self, run_id: str) -> dict[str, Any]:
        record = self.load_run(run_id)
        if record.get("schema_version") != SAVED_EVALUATION_V1:
            raise UnsupportedArtifactSchemaError(f"unsupported saved evaluation schema: {record.get('schema_version')}")
        inputs = record["inputs"]
        runtime_evidence = inputs["runtime_evidence"]
        original_reasons = _artifact_replay_failure_reasons(record)
        replayed = evaluate_runtime(
            compiled_authority=inputs["compiled_authority"],
            execution_request=inputs.get("evaluated_execution_request", inputs["execution_request"]),
            actor_identity=runtime_evidence["actor_identity"],
            continuity_state=inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot")),
            replay_posture=runtime_evidence.get("replay_evidence"),
            evidence_posture={
                "approvals": runtime_evidence.get("approvals", []),
                "execution_context": runtime_evidence.get("execution_context", {}),
                "runtime_dependencies": runtime_evidence.get("runtime_dependencies", []),
            },
            evaluation_time=runtime_evidence["timestamp_source"]["timestamp"],
            start_sequence=_start_sequence(record["evaluation"]),
            _verified_v2_authority=(
                inputs["compiled_authority"].get("schema_version")
                == "compiled_authority_contract.v2"
            ),
        )
        outcome_matches = (
            replayed["enforcement_outcome"]["outcome_hash"]
            == record["guard_enforcement_outcome"]["outcome_hash"]
        )
        replay_reasons = original_reasons + _replayed_output_failure_reasons(record, replayed)
        mismatch_classes = sorted({reason["class"] for reason in replay_reasons})
        replay_result = {
            "schema_version": GUARD_REPLAY_RESULT_V1,
            "run_id": run_id,
            "matches": outcome_matches and not replay_reasons,
            "outcome_matches": outcome_matches,
            "mismatch_classes": mismatch_classes,
            "replay_failure_reasons": replay_reasons,
            "original_outcome_hash": record["guard_enforcement_outcome"]["outcome_hash"],
            "replayed_outcome_hash": replayed["enforcement_outcome"]["outcome_hash"],
            "replayed_evaluation": replayed,
        }
        self.export_replay_record(replay_result)
        return replay_result

    def export_receipt(self, receipt: dict[str, Any]) -> Path:
        self.receipt_root.mkdir(parents=True, exist_ok=True)
        path = self.receipt_root / f"{receipt['run_id']}.json"
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def export_manifest(self, manifest: dict[str, Any]) -> Path:
        self.manifest_root.mkdir(parents=True, exist_ok=True)
        run_id = manifest["run_id"]
        path = self.manifest_root / f"{run_id}.json"
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def export_replay_record(self, replay_result: dict[str, Any]) -> Path:
        self.replay_root.mkdir(parents=True, exist_ok=True)
        record = {
            "schema_version": GUARD_REPLAY_RECORD_V1,
            "run_id": replay_result["run_id"],
            "matches": replay_result["matches"],
            "mismatch_classes": replay_result["mismatch_classes"],
            "replay_failure_reasons": replay_result["replay_failure_reasons"],
            "original_outcome_hash": replay_result["original_outcome_hash"],
            "replayed_outcome_hash": replay_result["replayed_outcome_hash"],
        }
        record["replay_record_hash"] = stable_hash(record)
        path = self.replay_root / f"{replay_result['run_id']}.json"
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def export_execution_attestation(self, attestation: dict[str, Any]) -> Path:
        if attestation.get("schema_version") != GUARD_EXECUTION_ATTESTATION_V1:
            raise UnsupportedArtifactSchemaError(
                f"unsupported execution attestation schema: {attestation.get('schema_version')}"
            )
        self.execution_attestation_root.mkdir(parents=True, exist_ok=True)
        path = self.execution_attestation_root / f"{attestation['run_id']}.json"
        path.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    if "authority_evidence_hash" in input_hashes:
        run_basis["authority_evidence_hash"] = input_hashes["authority_evidence_hash"]
        run_basis["runtime_facts_hash"] = input_hashes["runtime_facts_hash"]
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
        "run_id": receipt["run_id"],
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
            "runtime_dependencies_hash",
        ],
    }
    if "authority_evidence_hash" in receipt["input_hashes"]:
        manifest["lineage_continuity_fields"].extend(
            ["authority_evidence_hash", "runtime_facts_hash"]
        )
    manifest["manifest_hash"] = stable_hash(manifest)
    return manifest


def _artifact_replay_failure_reasons(record: dict[str, Any]) -> list[dict[str, Any]]:
    reasons = []
    inputs = record.get("inputs", {})
    evaluation = record.get("evaluation", {})
    receipt = record.get("receipt", {})
    manifest = record.get("artifact_manifest", {})
    if not manifest:
        reasons.append(_reason("manifest_integrity_failure", "artifact_manifest", "present", "missing", "Invalid manifest."))
        return reasons
    if manifest.get("schema_version") != GUARD_ARTIFACT_MANIFEST_V1:
        reasons.append(
            _reason(
                "manifest_integrity_failure",
                "artifact_manifest.schema_version",
                GUARD_ARTIFACT_MANIFEST_V1,
                manifest.get("schema_version"),
                "Unsupported schema version.",
                error_class="unsupported_schema_version",
            )
        )
    if not manifest.get("replayable") or not manifest.get("replay_basis_hash"):
        reasons.append(
            _reason(
                "manifest_integrity_failure",
                "artifact_manifest.replay_basis_hash",
                "present",
                manifest.get("replay_basis_hash") or "missing",
                "Missing replay basis.",
                error_class="missing_replay_basis",
            )
        )
    _compare_hash(reasons, "manifest_integrity_failure", "artifact_manifest.manifest_hash", manifest.get("manifest_hash"), stable_hash(_without_hash(manifest, "manifest_hash")), "Invalid manifest.")
    _compare_hash(reasons, "manifest_integrity_failure", "receipt.receipt_hash", receipt.get("receipt_hash"), stable_hash(_without_hash(receipt, "receipt_hash")), "Unreadable receipt.", error_class="unreadable_receipt")
    current_input_hashes = _input_hashes(inputs)
    recorded_input_hashes = receipt.get("input_hashes", {})
    _compare_hash(reasons, "contract_drift", "compiled_authority", recorded_input_hashes.get("compiled_authority_hash"), current_input_hashes.get("compiled_authority_hash"), "Compiled authority changed after receipt emission.")
    _compare_hash(reasons, "request_mismatch", "execution_request", recorded_input_hashes.get("execution_request_hash"), current_input_hashes.get("execution_request_hash"), "Execution request changed after receipt emission.")
    _compare_hash(reasons, "evidence_mutation", "runtime_evidence", recorded_input_hashes.get("runtime_evidence_hash"), current_input_hashes.get("runtime_evidence_hash"), "Runtime evidence changed after receipt emission.")
    _compare_hash(reasons, "evidence_mutation", "actor_identity", recorded_input_hashes.get("actor_identity_hash"), current_input_hashes.get("actor_identity_hash"), "Actor identity changed after receipt emission.")
    _compare_hash(reasons, "evidence_mutation", "approvals", recorded_input_hashes.get("approval_evidence_hash"), current_input_hashes.get("approval_evidence_hash"), "Approval evidence changed after receipt emission.")
    _compare_hash(reasons, "evidence_mutation", "timestamp_source", recorded_input_hashes.get("timestamp_source_hash"), current_input_hashes.get("timestamp_source_hash"), "Timestamp source changed after receipt emission.")
    _compare_hash(reasons, "evidence_mutation", "runtime_dependencies", recorded_input_hashes.get("runtime_dependencies_hash"), current_input_hashes.get("runtime_dependencies_hash"), "Runtime dependencies changed after receipt emission.")
    if "authority_evidence_hash" in recorded_input_hashes:
        _compare_hash(reasons, "contract_drift", "authority_evidence", recorded_input_hashes.get("authority_evidence_hash"), current_input_hashes.get("authority_evidence_hash"), "Verified authority evidence changed after receipt emission.")
        _compare_hash(reasons, "evidence_mutation", "runtime_facts", recorded_input_hashes.get("runtime_facts_hash"), current_input_hashes.get("runtime_facts_hash"), "Derived runtime facts changed after receipt emission.")
        _compare_hash(reasons, "request_mismatch", "evaluated_execution_request", recorded_input_hashes.get("evaluated_execution_request_hash"), current_input_hashes.get("evaluated_execution_request_hash"), "Fact-projected execution request changed after receipt emission.")
    _compare_hash(reasons, "continuity_mismatch", "continuity_posture", recorded_input_hashes.get("continuity_posture_hash"), current_input_hashes.get("continuity_posture_hash"), "Lineage continuity changed after receipt emission.")
    _compare_hash(reasons, "chronology_mutation", "chronology", receipt.get("chronology_hash"), stable_hash(evaluation.get("telemetry_events", [])), "Generated execution chronology changed after receipt emission.")
    _compare_hash(reasons, "chronology_mutation", "chronology_event_ids", stable_hash(receipt.get("chronology_event_ids", [])), stable_hash([event.get("event_id") for event in evaluation.get("telemetry_events", [])]), "Chronology event identity changed after receipt emission.")
    persisted = manifest.get("persisted_artifacts", {})
    _compare_hash(reasons, "manifest_integrity_failure", "persisted_artifacts.inputs", persisted.get("inputs"), stable_hash(inputs), "Hash mismatch.")
    _compare_hash(reasons, "manifest_integrity_failure", "persisted_artifacts.evaluation", persisted.get("evaluation"), stable_hash(evaluation), "Hash mismatch.")
    _compare_hash(reasons, "manifest_integrity_failure", "persisted_artifacts.guard_enforcement_outcome", persisted.get("guard_enforcement_outcome"), stable_hash(record.get("guard_enforcement_outcome", {})), "Hash mismatch.")
    _compare_hash(reasons, "manifest_integrity_failure", "persisted_artifacts.receipt", persisted.get("receipt"), receipt.get("receipt_hash"), "Hash mismatch.")
    return _dedupe_reasons(reasons)


def _replayed_output_failure_reasons(record: dict[str, Any], replayed: dict[str, Any]) -> list[dict[str, Any]]:
    reasons = []
    receipt = record["receipt"]
    _compare_hash(
        reasons,
        "chronology_mutation",
        "replayed_chronology",
        receipt.get("chronology_hash"),
        stable_hash(replayed.get("telemetry_events", [])),
        "Replayed chronology does not match the Guard Receipt.",
    )
    _compare_hash(
        reasons,
        "chronology_mutation",
        "replayed_chronology_event_ids",
        stable_hash(receipt.get("chronology_event_ids", [])),
        stable_hash([event.get("event_id") for event in replayed.get("telemetry_events", [])]),
        "Replayed event identity does not match the Guard Receipt.",
    )
    return _dedupe_reasons(reasons)


def _compare_hash(
    reasons: list[dict[str, Any]],
    reason_class: str,
    field: str,
    expected: Any,
    observed: Any,
    message: str,
    *,
    error_class: str | None = None,
) -> None:
    if expected != observed:
        reasons.append(_reason(reason_class, field, expected, observed, message, error_class=error_class))


def _reason(
    reason_class: str,
    field: str,
    expected: Any,
    observed: Any,
    message: str,
    *,
    error_class: str | None = None,
) -> dict[str, Any]:
    if reason_class not in REPLAY_MISMATCH_CLASSES:
        reason_class = "manifest_integrity_failure"
    reason = {
        "class": reason_class,
        "field": field,
        "expected": expected,
        "observed": observed,
        "message": message,
    }
    if error_class:
        reason["error_class"] = error_class
    return reason


def _dedupe_reasons(reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for reason in reasons:
        key = (reason["class"], reason["field"], str(reason.get("expected")), str(reason.get("observed")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(reason)
    return deduped


def _validate_cloud_preservation_update(
    *,
    existing: dict[str, Any] | None,
    incoming: dict[str, Any],
) -> None:
    if existing is None:
        return
    identity_fields = ["package_id", "receipt_id", "sha256", "timestamp"]
    for field in identity_fields:
        if existing.get(field) != incoming.get(field):
            raise ConflictingCloudPreservationError(
                f"conflicting Cloud preservation metadata for {field}"
            )


def _without_hash(payload: dict[str, Any], hash_key: str) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != hash_key}


def _input_hashes(inputs: dict[str, Any]) -> dict[str, str]:
    runtime_evidence = inputs["runtime_evidence"]
    hashes = {
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
        "runtime_dependencies_hash": stable_hash(runtime_evidence.get("runtime_dependencies", [])),
    }
    if "authority_evidence" in inputs:
        hashes["authority_evidence_hash"] = stable_hash(inputs["authority_evidence"])
        hashes["runtime_facts_hash"] = stable_hash(inputs.get("runtime_facts", {}))
        hashes["evaluated_execution_request_hash"] = stable_hash(
            inputs.get("evaluated_execution_request", {})
        )
    return hashes


def _replay_basis(inputs: dict[str, Any], evaluation: dict[str, Any]) -> dict[str, Any]:
    runtime_evidence = inputs["runtime_evidence"]
    basis = {
        "compiled_authority": inputs["compiled_authority"],
        "execution_request": inputs["execution_request"],
        "actor_identity": runtime_evidence["actor_identity"],
        "continuity_state": inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot", {})),
        "replay_posture": runtime_evidence.get("replay_evidence", {}),
        "evidence_posture": {
            "approvals": runtime_evidence.get("approvals", []),
            "execution_context": runtime_evidence.get("execution_context", {}),
            "runtime_dependencies": runtime_evidence.get("runtime_dependencies", []),
        },
        "evaluation_time": runtime_evidence["timestamp_source"]["timestamp"],
        "start_sequence": _start_sequence(evaluation),
    }
    if "authority_evidence" in inputs:
        basis["authority_evidence"] = inputs["authority_evidence"]
        basis["runtime_facts"] = inputs.get("runtime_facts", {})
        basis["evaluated_execution_request"] = inputs.get("evaluated_execution_request", {})
    return basis


def _lineage_continuity_basis(
    *,
    inputs: dict[str, Any],
    evaluation: dict[str, Any],
    input_hashes: dict[str, str],
    chronology_hash: str,
) -> dict[str, Any]:
    outcome = evaluation["enforcement_outcome"]
    basis = {
        "authority_ref": outcome["authority_ref"],
        "contract_hash": inputs["compiled_authority"].get("contract_hash"),
        "execution_request_hash": input_hashes["execution_request_hash"],
        "runtime_evidence_hash": input_hashes["runtime_evidence_hash"],
        "continuity_posture_hash": input_hashes["continuity_posture_hash"],
        "replay_posture_hash": input_hashes["replay_posture_hash"],
        "runtime_dependencies_hash": input_hashes["runtime_dependencies_hash"],
        "outcome_hash": outcome["outcome_hash"],
        "evaluation_trace_hash": evaluation["evaluation_trace"]["trace_hash"],
        "chronology_hash": chronology_hash,
    }
    if "authority_evidence_hash" in input_hashes:
        basis["authority_evidence_hash"] = input_hashes["authority_evidence_hash"]
        basis["runtime_facts_hash"] = input_hashes["runtime_facts_hash"]
    return basis


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
