from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from guard.enforcement.chronology import build_release_chronology
from guard.runtime import evaluate_runtime
from guard.runtime.continuation import build_continuation_lease, validate_continuation
from guard.runtime.organization import PersistentOrganizationalRuntime, default_organization_context
from guard.sdk.local_persistence import (
    build_enforcement_receipt,
    LocalEvaluationStore,
)


LOCAL_EVALUATION_HISTORY_V1 = "guard_local_evaluation_history.v1"
DEFAULT_STORE_ROOT = ".guard-local"


def load_runtime_inputs(sample: str = "blocked-transfer") -> dict[str, Any]:
    samples = _sample_inputs()
    if sample not in samples:
        raise ValueError(f"unknown Guard runtime sample input set: {sample}")
    return deepcopy(samples[sample])


def evaluate_runtime_request(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    inputs = deepcopy(payload) if payload is not None else load_runtime_inputs()
    runtime_evidence = inputs["runtime_evidence"]
    evaluation = evaluate_runtime(
        compiled_authority=inputs["compiled_authority"],
        execution_request=inputs["execution_request"],
        actor_identity=runtime_evidence["actor_identity"],
        continuity_state=inputs.get("continuity_posture", runtime_evidence.get("continuity_snapshot", {})),
        replay_posture=runtime_evidence.get("replay_evidence", {}),
        evidence_posture={
            "approvals": runtime_evidence.get("approvals", []),
            "execution_context": runtime_evidence.get("execution_context", {}),
            "runtime_dependencies": runtime_evidence.get("runtime_dependencies", []),
        },
        evaluation_time=runtime_evidence["timestamp_source"]["timestamp"],
    )
    return {
        "schema_version": "guard_runtime_evaluation_response.v1",
        "inputs": inputs,
        "evaluation": evaluation,
        "guard_enforcement_outcome": evaluation["enforcement_outcome"],
        "chronology": reconstruct_chronology(evaluation["telemetry_events"]),
        "evaluation_events": list(evaluation["telemetry_events"]),
    }


def reconstruct_chronology(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return list(events)


def save_runtime_evaluation(
    evaluated: dict[str, Any],
    *,
    store_root: str | Path = DEFAULT_STORE_ROOT,
) -> dict[str, Any]:
    record = LocalEvaluationStore(store_root).save_evaluation(
        inputs=evaluated["inputs"],
        evaluation=evaluated["evaluation"],
    )
    return {
        "schema_version": "guard_saved_runtime_evaluation_response.v1",
        "saved_run": record,
    }


def replay_runtime_evaluation(
    run_id: str,
    *,
    store_root: str | Path = DEFAULT_STORE_ROOT,
) -> dict[str, Any]:
    replay = LocalEvaluationStore(store_root).replay(run_id)
    return {
        "schema_version": "guard_runtime_replay_response.v1",
        "replay": replay,
        "guard_enforcement_outcome": replay["replayed_evaluation"]["enforcement_outcome"],
    }


def export_runtime_receipt(evaluated: dict[str, Any]) -> dict[str, Any]:
    receipt = build_enforcement_receipt(
        inputs=evaluated["inputs"],
        evaluation=evaluated["evaluation"],
        recorded_at=_evaluation_time(evaluated),
    )
    return {
        "schema_version": "guard_runtime_receipt_export.v1",
        "receipt": receipt,
    }


def runtime_history(*, store_root: str | Path = DEFAULT_STORE_ROOT) -> dict[str, Any]:
    store = LocalEvaluationStore(store_root)
    history = store.history_with_errors()
    return {
        "schema_version": LOCAL_EVALUATION_HISTORY_V1,
        "workspace_root": str(Path(store_root).resolve()),
        "artifact_errors": history["errors"],
        "evaluations": [_history_summary(record) for record in history["records"]],
    }


def load_saved_runtime_evaluation(
    run_id: str,
    *,
    store_root: str | Path = DEFAULT_STORE_ROOT,
) -> dict[str, Any]:
    record = LocalEvaluationStore(store_root).load_run(run_id)
    return {
        "schema_version": "guard_loaded_runtime_evaluation.v1",
        "saved_run": record,
        "artifact_manifest": record["artifact_manifest"],
        "guard_enforcement_outcome": record["guard_enforcement_outcome"],
    }


def run_deferred_release_demo(
    payload: dict[str, Any] | None = None,
    *,
    store_root: str | Path = DEFAULT_STORE_ROOT,
) -> dict[str, Any]:
    evaluated = evaluate_runtime_request(payload or load_runtime_inputs("deferred-release-expired-approval"))
    saved = save_runtime_evaluation(evaluated, store_root=store_root)["saved_run"]
    inputs = evaluated["inputs"]
    evidence = inputs["runtime_evidence"]
    dependency = evidence["runtime_dependencies"][0]
    lease = build_continuation_lease(
        execution_id=inputs["execution_request"]["request_id"],
        authority_ref=evaluated["guard_enforcement_outcome"]["authority_ref"],
        issued_at=evidence["timestamp_source"]["timestamp"],
        admissible_until=dependency["valid_until"],
        runtime_dependencies=evidence["runtime_dependencies"],
        continuation_status=evaluated["evaluation"]["continuation_status"],
    )
    release = validate_continuation(
        lease,
        runtime_state={"timestamp": "2026-06-26T13:30:00+00:00"},
    )
    chronology = build_release_chronology(
        authority_ref=lease["authority_ref"],
        timestamp=evidence["timestamp_source"]["timestamp"],
        continuation_lease=lease,
        release_validation=release,
    )
    deferred = {
        "schema_version": "guard_deferred_release_demo.v1",
        "evaluation": evaluated["evaluation"],
        "saved_run": saved,
        "receipt": saved["receipt"],
        "continuation_lease": lease,
        "release_validation": release,
        "release_chronology": chronology,
    }
    _export_deferred_release_artifacts(store_root, lease, release)
    PersistentOrganizationalRuntime(store_root).record_evaluation(
        evaluated,
        receipt=saved["receipt"],
        context=default_organization_context(),
    )
    PersistentOrganizationalRuntime(store_root).record_deferred_release(
        deferred,
        context=default_organization_context(),
    )
    return {
        **evaluated,
        "deferred_release": deferred,
    }


def persistent_runtime_dashboard(*, store_root: str | Path = DEFAULT_STORE_ROOT) -> dict[str, Any]:
    return PersistentOrganizationalRuntime(store_root).dashboard(default_organization_context())


def export_persistent_runtime_state(*, store_root: str | Path = DEFAULT_STORE_ROOT) -> dict[str, Any]:
    return PersistentOrganizationalRuntime(store_root).export_state(default_organization_context())


def import_persistent_runtime_state(
    artifact: dict[str, Any],
    *,
    store_root: str | Path = DEFAULT_STORE_ROOT,
) -> dict[str, Any]:
    return PersistentOrganizationalRuntime(store_root).import_state(artifact)


def cleanup_local_runtime_state(*, store_root: str | Path = DEFAULT_STORE_ROOT) -> dict[str, Any]:
    return PersistentOrganizationalRuntime(store_root, initialize=False).cleanup_dev_state()


def _history_summary(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": record["run_id"],
        "recorded_at": record["recorded_at"],
        "status": record["guard_enforcement_outcome"]["status"],
        "receipt": record["receipt"],
        "artifact_manifest_hash": record["artifact_manifest"]["manifest_hash"],
    }


def _evaluation_time(evaluated: dict[str, Any]) -> str:
    events = evaluated.get("evaluation", {}).get("telemetry_events") or []
    if events:
        return events[0]["timestamp"]
    return evaluated["inputs"]["runtime_evidence"]["timestamp_source"]["timestamp"]


def _export_deferred_release_artifacts(
    store_root: str | Path,
    lease: dict[str, Any],
    release: dict[str, Any],
) -> None:
    root = Path(store_root)
    lease_root = root / "continuation-leases"
    validation_root = root / "release-validations"
    lease_root.mkdir(parents=True, exist_ok=True)
    validation_root.mkdir(parents=True, exist_ok=True)
    (lease_root / f"{lease['continuation_id']}.json").write_text(
        json.dumps(lease, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (validation_root / f"{release['release_validation_id']}.json").write_text(
        json.dumps(release, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sample_inputs() -> dict[str, dict[str, Any]]:
    authority = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:finance-policy-1.0.0",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {
            "required": [
                {
                    "role": "director",
                    "condition": {"field": "amount", "operator": ">=", "value": 10000},
                }
            ]
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {"separation_of_duties": True},
    }
    base = {
        "sample_label": "Blocked transfer example",
        "compiled_authority": authority,
        "execution_request": {
            "schema_version": "normalized_execution_request.v1",
            "request_id": "exec-blocked-transfer",
            "action": "transfer_funds",
            "target": "finance.wire_transfer",
            "arguments": {"amount": 25000, "currency": "USD"},
            "artifacts": [],
        },
        "runtime_evidence": {
            "schema_version": "guard_runtime_evidence_model.v1",
            "actor_identity": {
                "id": "manager-1",
                "role": "manager",
                "team": "finance",
                "clearance": "standard",
                "status": "active",
            },
            "approvals": [],
            "replay_evidence": {},
            "continuity_snapshot": {},
            "timestamp_source": {
                "source": "fixture",
                "timestamp": "2026-06-26T12:00:00+00:00",
            },
            "execution_context": {"environment": "local"},
            "runtime_dependencies": [],
        },
        "continuity_posture": {},
    }
    allowed = deepcopy(base)
    allowed["sample_label"] = "Allowed transfer example"
    allowed["execution_request"]["request_id"] = "exec-allowed-transfer"
    allowed["runtime_evidence"]["approvals"] = [
        {"role": "director", "approved_by": "director-1"}
    ]

    escalated = deepcopy(allowed)
    escalated["sample_label"] = "Escalated queued job example"
    escalated["execution_request"]["request_id"] = "exec-escalated-queued-job"
    escalated["runtime_evidence"]["replay_evidence"] = {"required": True}

    deferred = deepcopy(allowed)
    deferred["sample_label"] = "Expired approval release block"
    deferred["execution_request"]["request_id"] = "exec-deferred-release"
    deferred["runtime_evidence"]["actor_identity"]["id"] = "manager-2"
    deferred["runtime_evidence"]["runtime_dependencies"] = [
        {
            "dependency_type": "approval",
            "dependency_id": "director-approval-1",
            "dependency_hash": "sha256:approval-director-1",
            "current_hash": "sha256:approval-director-1",
            "valid_until": "2026-06-26T13:00:00+00:00",
            "linked_at": "2026-06-26T12:00:00+00:00",
            "status": "valid",
        }
    ]
    deferred["deferred_release"] = {
        "schema_version": "guard_deferred_release_plan.v1",
        "release_after": "2026-06-26T13:30:00+00:00",
    }

    return {
        "blocked-transfer": base,
        "allowed-transfer": allowed,
        "escalated-queued-job": escalated,
        "deferred-release-expired-approval": deferred,
        "empty": {
            "sample_label": "Empty input set",
            "compiled_authority": {},
            "execution_request": {},
            "runtime_evidence": {},
            "continuity_posture": {},
        },
    }
