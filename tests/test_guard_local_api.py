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


def test_local_api_exposes_named_sample_input_sets():
    blocked = local_api.load_runtime_inputs("blocked-transfer")
    allowed = local_api.load_runtime_inputs("allowed-transfer")
    escalated = local_api.load_runtime_inputs("escalated-queued-job")
    deferred = local_api.load_runtime_inputs("deferred-release-expired-approval")
    empty = local_api.load_runtime_inputs("empty")

    assert blocked["sample_label"] == "Blocked transfer example"
    assert allowed["sample_label"] == "Allowed transfer example"
    assert escalated["sample_label"] == "Escalated queued job example"
    assert deferred["sample_label"] == "Expired approval release block"
    assert deferred["deferred_release"]["schema_version"] == "guard_deferred_release_plan.v1"
    assert empty["sample_label"] == "Empty input set"
    assert empty["compiled_authority"] == {}
    assert empty["execution_request"] == {}
    assert empty["runtime_evidence"] == {}

    assert local_api.evaluate_runtime_request(blocked)["evaluation"]["status"] == "blocked"
    assert local_api.evaluate_runtime_request(allowed)["evaluation"]["status"] == "admissible"
    assert local_api.evaluate_runtime_request(escalated)["evaluation"]["status"] == "escalated"
    assert local_api.evaluate_runtime_request(deferred)["evaluation"]["status"] == "admissible"


def test_local_api_runs_deferred_release_expired_approval_demo(tmp_path):
    demo = local_api.run_deferred_release_demo(
        local_api.load_runtime_inputs("deferred-release-expired-approval"),
        store_root=tmp_path,
    )

    deferred = demo["deferred_release"]
    lease = deferred["continuation_lease"]
    release = deferred["release_validation"]

    assert demo["evaluation"]["status"] == "admissible"
    assert demo["guard_enforcement_outcome"]["status"] == "admissible"
    assert deferred["schema_version"] == "guard_deferred_release_demo.v1"
    assert lease["schema_version"] == "guard_continuation_lease.v1"
    assert release["schema_version"] == "guard_release_validation.v1"
    assert release["outcome"] == "dependency_expired"
    assert release["release_blocked"] is True
    assert deferred["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert [event["event_type"] for event in deferred["release_chronology"]] == [
        "evaluation_admissible",
        "continuation_lease_issued",
        "runtime_dependency_expired",
        "continuation_invalidated",
        "release_blocked",
    ]
    assert (tmp_path / "receipts" / f"{deferred['saved_run']['run_id']}.json").exists()
    assert (tmp_path / "continuation-leases" / f"{lease['continuation_id']}.json").exists()
    assert (tmp_path / "release-validations" / f"{release['release_validation_id']}.json").exists()
    dashboard = local_api.persistent_runtime_dashboard(store_root=tmp_path)
    assert dashboard["schema_version"] == "guard_persistent_runtime_dashboard.v1"
    assert dashboard["summary"]["blocked_releases"] == 1
    exported = local_api.export_persistent_runtime_state(store_root=tmp_path)
    assert exported["schema_version"] == "guard_persistent_runtime_export.v1"
    assert exported["tables"]["release_queue"][0]["state"] == "release_blocked"


def test_local_api_saves_replays_and_exports_local_receipts(tmp_path):
    response = local_api.evaluate_runtime_request()

    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)
    run_id = saved["saved_run"]["run_id"]
    replayed = local_api.replay_runtime_evaluation(run_id, store_root=tmp_path)
    exported = local_api.export_runtime_receipt(response)

    assert saved["saved_run"]["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert saved["saved_run"]["artifact_manifest"]["schema_version"] == "guard_artifact_manifest.v1"
    assert (tmp_path / "receipts" / f"{run_id}.json").exists()
    assert (tmp_path / "manifests" / f"{run_id}.json").exists()
    assert (tmp_path / "replays" / f"{run_id}.json").exists()
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
    assert history["workspace_root"] == str(tmp_path.resolve())
    assert history["artifact_errors"] == []
    assert history["evaluations"][0]["run_id"] == run_id
    assert history["evaluations"][0]["status"] == "blocked"
    assert history["evaluations"][0]["receipt"]["schema_version"] == "guard_enforcement_receipt.v1"
    assert history["evaluations"][0]["artifact_manifest_hash"].startswith("sha256:")
    assert loaded["saved_run"]["run_id"] == run_id
    assert loaded["artifact_manifest"]["schema_version"] == "guard_artifact_manifest.v1"
    assert loaded["guard_enforcement_outcome"]["schema_version"] == "guard_enforcement_outcome.v1"


def test_local_api_reports_corrupt_history_as_operational_artifact_error(tmp_path):
    (tmp_path / "evaluation-history.jsonl").write_text("{not-json\n", encoding="utf-8")

    history = local_api.runtime_history(store_root=tmp_path)

    assert history["evaluations"] == []
    assert history["artifact_errors"][0]["error_class"] == "unreadable_receipt"
