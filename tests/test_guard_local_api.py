from __future__ import annotations

from server import local_api


def test_local_api_loads_runtime_inputs_and_evaluates_real_guard_output():
    local_api.TELEMETRY_LOG.clear()

    response = local_api.evaluate_runtime_request()

    assert response["inputs"]["compiled_authority"]["schema_version"] == "compiled_authority_contract.v1"
    assert response["inputs"]["execution_request"]["schema_version"] == "normalized_execution_request.v1"
    assert response["inputs"]["runtime_evidence"]["schema_version"] == "guard_runtime_evidence_model.v1"
    assert response["guard_enforcement_outcome"]["schema_version"] == "guard_enforcement_outcome.v1"
    assert response["evaluation"]["status"] == "blocked"
    assert response["chronology"] == local_api.reconstruct_chronology(response["evaluation"]["telemetry_events"])
    assert len(response["telemetry_appended"]) == len(response["evaluation"]["telemetry_events"])
    assert local_api.TELEMETRY_LOG == response["telemetry_stream"]


def test_local_api_appends_telemetry_across_runtime_evaluations():
    local_api.TELEMETRY_LOG.clear()

    first = local_api.evaluate_runtime_request()
    second = local_api.evaluate_runtime_request()

    assert first["telemetry_appended"][0]["sequence"] == 1
    assert second["telemetry_appended"][0]["sequence"] == len(first["telemetry_appended"]) + 1
    assert len(local_api.TELEMETRY_LOG) == (
        len(first["telemetry_appended"]) + len(second["telemetry_appended"])
    )


def test_local_api_accepts_posted_runtime_ingestion_payload():
    local_api.TELEMETRY_LOG.clear()
    payload = local_api.load_runtime_inputs()
    payload["runtime_evidence"]["actor_identity"]["role"] = "manager"
    payload["runtime_evidence"]["approvals"].append(
        {"role": "director", "approved_by": "director-1"}
    )
    payload["runtime_evidence"]["replay_evidence"] = {}
    payload["runtime_evidence"]["continuity_snapshot"] = {}

    response = local_api.evaluate_runtime_request(payload)

    assert response["evaluation"]["status"] == "admissible"
    assert response["guard_enforcement_outcome"]["status"] == "admissible"
    assert response["evaluation"]["required_evidence"] == []
    assert response["evaluation"]["continuity_requirements"] == []
