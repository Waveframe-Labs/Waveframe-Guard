from __future__ import annotations

import json
from copy import deepcopy

from guard.runtime.identity import stable_hash
from guard.sdk.local_persistence import (
    ENFORCEMENT_RECEIPT_V1,
    GUARD_ARTIFACT_MANIFEST_V1,
    SAVED_EVALUATION_V1,
    LocalEvaluationStore,
)
from server import local_api


def test_saved_evaluation_defines_persisted_artifact_semantics(tmp_path):
    evaluation = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(evaluation, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    record = local_api.load_saved_runtime_evaluation(run_id, store_root=tmp_path)["saved_run"]
    full_record = LocalEvaluationStore(tmp_path).load_run(run_id)
    receipt = full_record["receipt"]
    manifest = full_record["artifact_manifest"]

    assert full_record["schema_version"] == SAVED_EVALUATION_V1
    assert receipt["schema_version"] == ENFORCEMENT_RECEIPT_V1
    assert manifest["schema_version"] == GUARD_ARTIFACT_MANIFEST_V1
    assert record["receipt"] == receipt

    assert full_record["inputs"] == evaluation["inputs"]
    assert full_record["evaluation"] == evaluation["evaluation"]
    assert full_record["guard_enforcement_outcome"] == evaluation["guard_enforcement_outcome"]
    assert manifest["persisted_artifacts"] == {
        "inputs": stable_hash(full_record["inputs"]),
        "evaluation": stable_hash(full_record["evaluation"]),
        "guard_enforcement_outcome": stable_hash(full_record["guard_enforcement_outcome"]),
        "receipt": receipt["receipt_hash"],
    }


def test_receipt_hashes_inputs_replay_identity_and_lineage_continuity(tmp_path):
    response = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    record = LocalEvaluationStore(tmp_path).load_run(saved["saved_run"]["run_id"])
    receipt = record["receipt"]
    inputs = record["inputs"]
    evaluation = record["evaluation"]
    runtime_evidence = inputs["runtime_evidence"]

    assert receipt["input_hashes"]["compiled_authority_hash"] == stable_hash(inputs["compiled_authority"])
    assert receipt["input_hashes"]["execution_request_hash"] == stable_hash(inputs["execution_request"])
    assert receipt["input_hashes"]["runtime_evidence_hash"] == stable_hash(runtime_evidence)
    assert receipt["input_hashes"]["continuity_posture_hash"] == stable_hash(inputs["continuity_posture"])
    assert receipt["input_hashes"]["replay_posture_hash"] == stable_hash(runtime_evidence["replay_evidence"])
    assert receipt["chronology_hash"] == stable_hash(evaluation["telemetry_events"])

    replay_basis = {
        "compiled_authority": inputs["compiled_authority"],
        "execution_request": inputs["execution_request"],
        "actor_identity": runtime_evidence["actor_identity"],
        "continuity_state": inputs["continuity_posture"],
        "replay_posture": runtime_evidence["replay_evidence"],
        "evidence_posture": {
            "approvals": runtime_evidence["approvals"],
            "execution_context": runtime_evidence["execution_context"],
        },
        "evaluation_time": runtime_evidence["timestamp_source"]["timestamp"],
        "start_sequence": evaluation["telemetry_events"][0]["sequence"],
    }
    assert receipt["replay_basis_hash"] == stable_hash(replay_basis)

    identity_basis = {
        "authority_ref": receipt["authority_ref"],
        "contract_hash": inputs["compiled_authority"]["contract_hash"],
        "outcome_hash": receipt["outcome_hash"],
        "execution_request_hash": receipt["input_hashes"]["execution_request_hash"],
        "runtime_evidence_hash": receipt["input_hashes"]["runtime_evidence_hash"],
        "continuity_posture_hash": receipt["input_hashes"]["continuity_posture_hash"],
        "replay_basis_hash": receipt["replay_basis_hash"],
    }
    assert receipt["deterministic_identity_hash"] == stable_hash(identity_basis)

    lineage_basis = {
        "authority_ref": receipt["authority_ref"],
        "contract_hash": inputs["compiled_authority"]["contract_hash"],
        "execution_request_hash": receipt["input_hashes"]["execution_request_hash"],
        "runtime_evidence_hash": receipt["input_hashes"]["runtime_evidence_hash"],
        "continuity_posture_hash": receipt["input_hashes"]["continuity_posture_hash"],
        "replay_posture_hash": receipt["input_hashes"]["replay_posture_hash"],
        "outcome_hash": receipt["outcome_hash"],
        "evaluation_trace_hash": receipt["evaluation_trace_hash"],
        "chronology_hash": receipt["chronology_hash"],
    }
    assert receipt["lineage_continuity_hash"] == stable_hash(lineage_basis)


def test_deterministic_identity_changes_when_replayable_inputs_change(tmp_path):
    response = local_api.evaluate_runtime_request()
    changed = deepcopy(response)
    changed["inputs"]["runtime_evidence"]["actor_identity"] = {
        **changed["inputs"]["runtime_evidence"]["actor_identity"],
        "id": "employee-2",
    }

    first = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    second = local_api.save_runtime_evaluation(
        local_api.evaluate_runtime_request(changed["inputs"]),
        store_root=tmp_path,
    )

    first_record = LocalEvaluationStore(tmp_path).load_run(first["saved_run"]["run_id"])
    second_record = LocalEvaluationStore(tmp_path).load_run(second["saved_run"]["run_id"])

    assert first_record["run_id"] != second_record["run_id"]
    assert (
        first_record["receipt"]["deterministic_identity_hash"]
        != second_record["receipt"]["deterministic_identity_hash"]
    )
    assert first_record["receipt"]["lineage_continuity_hash"] != second_record["receipt"]["lineage_continuity_hash"]


def test_replayable_artifacts_verify_against_original_outcome(tmp_path):
    response = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    record = LocalEvaluationStore(tmp_path).load_run(run_id)
    replay = local_api.replay_runtime_evaluation(run_id, store_root=tmp_path)

    assert record["artifact_manifest"]["replayable"] is True
    assert replay["replay"]["matches"] is True
    assert replay["replay"]["original_outcome_hash"] == record["receipt"]["outcome_hash"]
    assert replay["replay"]["replayed_outcome_hash"] == record["receipt"]["outcome_hash"]


def test_local_workspace_persists_receipts_manifests_and_replay_records(tmp_path):
    response = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    replay = local_api.replay_runtime_evaluation(run_id, store_root=tmp_path)

    assert (tmp_path / "evaluation-history.jsonl").exists()
    assert (tmp_path / "receipts" / f"{run_id}.json").exists()
    assert (tmp_path / "manifests" / f"{run_id}.json").exists()
    assert (tmp_path / "replays" / f"{run_id}.json").exists()
    assert replay["replay"]["schema_version"] == "guard_replay_result.v1"
    assert replay["replay"]["mismatch_classes"] == []
    assert replay["replay"]["replay_failure_reasons"] == []


def test_replay_reports_contract_drift(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["inputs"]["compiled_authority"]["contract_hash"] = "sha256:drifted"
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "contract_drift" in replay["mismatch_classes"]


def test_replay_reports_request_mismatch(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["inputs"]["execution_request"]["arguments"]["amount"] = 999
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "request_mismatch" in replay["mismatch_classes"]


def test_replay_reports_evidence_mutation(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["inputs"]["runtime_evidence"]["approvals"].append(
        {"role": "director", "approved_by": "director-9"}
    )
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "evidence_mutation" in replay["mismatch_classes"]


def test_replay_reports_chronology_mutation(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["evaluation"]["telemetry_events"][0]["event_id"] = "guard_event_mutated"
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "chronology_mutation" in replay["mismatch_classes"]


def test_replay_reports_continuity_mismatch(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["inputs"]["continuity_posture"] = {"requires_revalidation": True, "reason": "drift"}
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "continuity_mismatch" in replay["mismatch_classes"]


def test_replay_reports_manifest_integrity_failure(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["artifact_manifest"]["manifest_hash"] = "sha256:corrupt"
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "manifest_integrity_failure" in replay["mismatch_classes"]


def test_replay_reports_missing_replay_basis_and_unsupported_manifest_schema(tmp_path):
    run_id, record = _saved_record(tmp_path)
    record["artifact_manifest"]["schema_version"] = "guard_artifact_manifest.v0"
    record["artifact_manifest"].pop("replay_basis_hash")
    _rewrite_history(tmp_path, record)

    replay = LocalEvaluationStore(tmp_path).replay(run_id)

    assert replay["matches"] is False
    assert "manifest_integrity_failure" in replay["mismatch_classes"]
    assert {reason.get("error_class") for reason in replay["replay_failure_reasons"]} >= {
        "missing_replay_basis",
        "unsupported_schema_version",
    }


def _saved_record(tmp_path):
    response = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    return run_id, LocalEvaluationStore(tmp_path).load_run(run_id)


def _rewrite_history(tmp_path, record):
    (tmp_path / "evaluation-history.jsonl").write_text(
        json.dumps(record, sort_keys=True) + "\n",
        encoding="utf-8",
    )
