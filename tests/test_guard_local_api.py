from __future__ import annotations

from server import local_api


def test_local_api_loads_runtime_inputs_and_evaluates_real_guard_output():
    response = local_api.evaluate_runtime_request()

    assert response["inputs"]["compiled_authority"]["schema_version"] == "compiled_authority_contract.v1"
    assert response["inputs"]["execution_request"]["schema_version"] == "normalized_execution_request.v1"
    assert response["inputs"]["runtime_evidence"]["schema_version"] == "guard_runtime_evidence_model.v1"
    assert response["inputs"]["continuity_posture"] == response["inputs"]["runtime_evidence"]["continuity_snapshot"]
    assert response["guard_enforcement_outcome"]["schema_version"] == "guard_enforcement_outcome.v1"
    assert response["evaluation"]["status"] == "blocked"
    assert response["chronology"] == local_api.reconstruct_chronology(response["evaluation"]["telemetry_events"])
    assert response["evaluation_events"] == response["evaluation"]["telemetry_events"]


def test_local_api_keeps_evaluation_events_scoped_to_current_evaluation():
    first = local_api.evaluate_runtime_request()
    second = local_api.evaluate_runtime_request()

    assert first["evaluation_events"][0]["sequence"] == 1
    assert second["evaluation_events"][0]["sequence"] == 1
    assert "telemetry_stream" not in first
    assert "telemetry_stream" not in second


def test_local_api_accepts_posted_runtime_ingestion_payload():
    payload = local_api.load_runtime_inputs()
    payload["runtime_evidence"]["actor_identity"]["role"] = "manager"
    payload["runtime_evidence"]["approvals"].append(
        {"role": "director", "approved_by": "director-1"}
    )
    payload["runtime_evidence"]["replay_evidence"] = {}
    payload["runtime_evidence"]["continuity_snapshot"] = {}
    payload["continuity_posture"] = {}

    response = local_api.evaluate_runtime_request(payload)

    assert response["evaluation"]["status"] == "admissible"
    assert response["guard_enforcement_outcome"]["status"] == "admissible"
    assert response["evaluation"]["required_evidence"] == []
    assert response["evaluation"]["continuity_requirements"] == []


def test_local_api_saves_replays_and_exports_local_receipts(tmp_path):
    response = local_api.evaluate_runtime_request()

    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    replayed = local_api.replay_runtime_evaluation(run_id, store_root=tmp_path)
    exported = local_api.export_runtime_receipt(response)

    assert saved["saved_run"]["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert (tmp_path / "receipts" / f"{run_id}.json").exists()
    assert replayed["replay"]["matches"] is True
    assert replayed["guard_enforcement_outcome"]["schema_version"] == "guard_enforcement_outcome.v1"
    assert exported["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"


def test_local_api_lists_and_loads_local_evaluation_history(tmp_path):
    response = local_api.evaluate_runtime_request()
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]

    history = local_api.runtime_history(store_root=tmp_path)
    loaded = local_api.load_saved_runtime_evaluation(run_id, store_root=tmp_path)

    assert history["schema_version"] == "guard_local_evaluation_history.v1"
    assert history["evaluations"][0]["run_id"] == run_id
    assert history["evaluations"][0]["status"] == "blocked"
    assert history["evaluations"][0]["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert loaded["saved_run"]["run_id"] == run_id
    assert loaded["guard_enforcement_outcome"]["schema_version"] == "guard_enforcement_outcome.v1"
