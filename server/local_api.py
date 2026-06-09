from __future__ import annotations

import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui"
INPUT_ROOT = Path(__file__).resolve().parent / "runtime_inputs"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard import build_continuation_lease, evaluate_runtime, validate_continuation
from guard.enforcement import build_release_chronology
from guard.sdk.local_persistence import GuardArtifactError, LocalEvaluationStore, build_enforcement_receipt
from guard.runtime.evidence import validate_runtime_evidence_model
from guard.runtime.organization import PersistentOrganizationalRuntime, default_organization_context

LOCAL_WORKSPACE_ROOT = REPO_ROOT / ".guard-local"


def load_runtime_inputs(sample: str = "blocked-transfer") -> dict[str, Any]:
    runtime_evidence = _read_json(INPUT_ROOT / "runtime_evidence.json")
    base = {
        "compiled_authority": _read_json(INPUT_ROOT / "compiled_authority.json"),
        "execution_request": _read_json(INPUT_ROOT / "normalized_execution_request.json"),
        "runtime_evidence": runtime_evidence,
        "continuity_posture": runtime_evidence.get("continuity_snapshot", {}),
        "sample_label": "Blocked transfer example",
    }
    return _sample_inputs(base, sample)


def evaluate_runtime_request(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or load_runtime_inputs()
    compiled_authority = payload.get("compiled_authority")
    execution_request = payload.get("execution_request")
    runtime_evidence = validate_runtime_evidence_model(payload.get("runtime_evidence"))
    timestamp = runtime_evidence["timestamp_source"].get("timestamp") or _now()
    continuity_state = payload.get("continuity_posture")
    if continuity_state is None:
        continuity_state = runtime_evidence["continuity_snapshot"]

    result = evaluate_runtime(
        compiled_authority=compiled_authority,
        execution_request=execution_request,
        actor_identity=runtime_evidence["actor_identity"],
        continuity_state=continuity_state,
        replay_posture=runtime_evidence["replay_evidence"],
        evidence_posture={
            "approvals": runtime_evidence["approvals"],
            "execution_context": runtime_evidence["execution_context"],
            "runtime_dependencies": runtime_evidence.get("runtime_dependencies", []),
        },
        evaluation_time=timestamp,
        start_sequence=1,
    )
    return {
        "inputs": {
            "compiled_authority": compiled_authority,
            "execution_request": execution_request,
            "runtime_evidence": runtime_evidence,
            "continuity_posture": continuity_state,
        },
        "evaluation": result,
        "guard_enforcement_outcome": result["enforcement_outcome"],
        "chronology": reconstruct_chronology(result["telemetry_events"]),
        "evaluation_events": result["telemetry_events"],
    }


def save_runtime_evaluation(payload: dict[str, Any], *, store_root: Path | None = None) -> dict[str, Any]:
    evaluated = _coerce_evaluated_payload(payload)
    root = store_root or LOCAL_WORKSPACE_ROOT
    store = LocalEvaluationStore(root)
    record = store.save_evaluation(
        inputs=evaluated["inputs"],
        evaluation=evaluated["evaluation"],
    )
    PersistentOrganizationalRuntime(root).record_evaluation(
        evaluated,
        receipt=record["receipt"],
        context=_organization_context(evaluated.get("inputs", {})),
    )
    return {
        "saved_run": {
            "run_id": record["run_id"],
            "record_hash": record["record_hash"],
            "receipt": record["receipt"],
            "artifact_manifest": record["artifact_manifest"],
        }
    }


def run_deferred_release_demo(
    payload: dict[str, Any] | None = None,
    *,
    store_root: Path | None = None,
) -> dict[str, Any]:
    inputs = payload or load_runtime_inputs("deferred-release-expired-approval")
    evaluated = evaluate_runtime_request(inputs)
    store_root = store_root or LOCAL_WORKSPACE_ROOT
    saved = save_runtime_evaluation(evaluated, store_root=store_root)
    evaluation = evaluated["evaluation"]
    request = evaluated["inputs"]["execution_request"]
    evidence = evaluated["inputs"]["runtime_evidence"]
    authority_ref = evaluation["enforcement_outcome"]["authority_ref"]
    issued_at = evidence["timestamp_source"]["timestamp"]
    release_plan = inputs.get("deferred_release", {})
    release_time = release_plan.get("release_time") or "2026-06-03T22:32:00+00:00"
    lease = build_continuation_lease(
        execution_id=request["request_id"],
        authority_ref=authority_ref,
        issued_at=issued_at,
        admissible_until=release_plan.get("admissible_until") or "2026-06-03T22:35:00+00:00",
        runtime_dependencies=evaluation["runtime_dependency_posture"]["dependencies"],
        continuation_status=evaluation["continuation_status"],
    )
    release_validation = validate_continuation(
        lease,
        release_time=release_time,
    )
    release_chronology = build_release_chronology(
        authority_ref=authority_ref,
        timestamp=issued_at,
        continuation_lease=lease,
        release_validation=release_validation,
    )
    _write_local_artifact(store_root, "continuation-leases", f"{lease['continuation_id']}.json", lease)
    _write_local_artifact(
        store_root,
        "release-validations",
        f"{release_validation['release_validation_id']}.json",
        {
            "release_validation": release_validation,
            "release_chronology": release_chronology,
        },
    )
    org_runtime = PersistentOrganizationalRuntime(store_root)
    context = _organization_context(inputs)
    org_runtime.record_deferred_release(
        {
            "continuation_lease": lease,
            "release_validation": release_validation,
            "saved_run": saved["saved_run"],
        },
        context=context,
    )
    return {
        **evaluated,
        "sample_label": "Expired approval release block",
        "deferred_release": {
            "schema_version": "guard_deferred_release_demo.v1",
            "admissible_at": issued_at,
            "release_attempted_at": release_time,
            "continuation_lease": lease,
            "release_validation": release_validation,
            "release_chronology": release_chronology,
            "saved_run": saved["saved_run"],
            "receipt": saved["saved_run"]["receipt"],
            "persistent_runtime_dashboard": org_runtime.dashboard(context),
        },
    }


def replay_runtime_evaluation(run_id: str, *, store_root: Path | None = None) -> dict[str, Any]:
    store = LocalEvaluationStore(store_root or LOCAL_WORKSPACE_ROOT)
    replay = store.replay(run_id)
    evaluation = replay["replayed_evaluation"]
    return {
        "replay": replay,
        "evaluation": evaluation,
        "guard_enforcement_outcome": evaluation["enforcement_outcome"],
        "chronology": reconstruct_chronology(evaluation["telemetry_events"]),
        "evaluation_events": evaluation["telemetry_events"],
        "inputs": store.load_run(run_id)["inputs"],
    }


def load_saved_runtime_evaluation(run_id: str, *, store_root: Path | None = None) -> dict[str, Any]:
    store = LocalEvaluationStore(store_root or LOCAL_WORKSPACE_ROOT)
    record = store.load_run(run_id)
    evaluation = record["evaluation"]
    return {
        "saved_run": {
            "run_id": record["run_id"],
            "record_hash": record["record_hash"],
            "recorded_at": record["recorded_at"],
            "receipt": record["receipt"],
            "artifact_manifest": record["artifact_manifest"],
        },
        "artifact_manifest": record["artifact_manifest"],
        "evaluation": evaluation,
        "guard_enforcement_outcome": evaluation["enforcement_outcome"],
        "chronology": reconstruct_chronology(evaluation["telemetry_events"]),
        "evaluation_events": evaluation["telemetry_events"],
        "inputs": record["inputs"],
    }


def runtime_history(*, store_root: Path | None = None, limit: int = 20) -> dict[str, Any]:
    store = LocalEvaluationStore(store_root or LOCAL_WORKSPACE_ROOT)
    history = store.history_with_errors()
    records = list(reversed(history["records"]))[:limit]
    return {
        "schema_version": "guard_local_evaluation_history.v1",
        "workspace_root": str((store_root or LOCAL_WORKSPACE_ROOT).resolve()),
        "artifact_errors": history["errors"],
        "evaluations": [
            {
                "run_id": record["run_id"],
                "recorded_at": record["recorded_at"],
                "record_hash": record["record_hash"],
                "request_id": record["inputs"]["execution_request"].get("request_id"),
                "action": record["inputs"]["execution_request"].get("action"),
                "target": record["inputs"]["execution_request"].get("target"),
                "authority_ref": record["guard_enforcement_outcome"]["authority_ref"],
                "status": record["guard_enforcement_outcome"]["status"],
                "rationale": record["guard_enforcement_outcome"]["rationale"],
                "receipt": record["receipt"],
                "artifact_manifest_hash": record.get("artifact_manifest", {}).get("manifest_hash", "missing"),
            }
            for record in records
        ],
    }


def persistent_runtime_dashboard(
    *,
    store_root: Path | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = store_root or LOCAL_WORKSPACE_ROOT
    return PersistentOrganizationalRuntime(root).dashboard(context or default_organization_context())


def export_persistent_runtime_state(
    *,
    store_root: Path | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = store_root or LOCAL_WORKSPACE_ROOT
    return PersistentOrganizationalRuntime(root).export_state(context or default_organization_context())


def import_persistent_runtime_state(
    payload: dict[str, Any],
    *,
    store_root: Path | None = None,
) -> dict[str, Any]:
    root = store_root or LOCAL_WORKSPACE_ROOT
    return PersistentOrganizationalRuntime(root).import_state(payload)


def recover_persistent_runtime_state(*, store_root: Path | None = None) -> dict[str, Any]:
    root = store_root or LOCAL_WORKSPACE_ROOT
    return PersistentOrganizationalRuntime(root).recover_if_corrupt()


def cleanup_local_runtime_state(*, store_root: Path | None = None) -> dict[str, Any]:
    root = store_root or LOCAL_WORKSPACE_ROOT
    return PersistentOrganizationalRuntime(root, initialize=False).cleanup_dev_state()


def export_runtime_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    evaluated = _coerce_evaluated_payload(payload)
    return {
        "receipt": build_enforcement_receipt(
            inputs=evaluated["inputs"],
            evaluation=evaluated["evaluation"],
            recorded_at=_now(),
        )
    }


def reconstruct_chronology(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": event["sequence"],
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "authority_ref": event["authority_ref"],
            "details": event.get("details", {}),
            "event_hash": event["event_hash"],
        }
        for event in sorted(events, key=lambda item: item["sequence"])
    ]


class GuardLocalRequestHandler(BaseHTTPRequestHandler):
    server_version = "WaveframeGuardLocal/0.1"

    def do_GET(self) -> None:
        if self._handle_api_get():
            return
        self._send_static()

    def do_POST(self) -> None:
        path = _request_path(self.path)
        if path not in {
            "/api/runtime/evaluate",
            "/api/runtime/save",
            "/api/runtime/replay",
            "/api/runtime/load_run",
            "/api/runtime/export_receipt",
            "/api/runtime/deferred_release_demo",
            "/api/runtime/import_org_state",
            "/api/runtime/recover_org_state",
            "/api/runtime/cleanup_local_state",
        }:
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            body = self._read_body()
            if path == "/api/runtime/evaluate":
                self._send_json(evaluate_runtime_request(body))
            elif path == "/api/runtime/save":
                self._send_json(save_runtime_evaluation(body))
            elif path == "/api/runtime/replay":
                self._send_json(replay_runtime_evaluation(body["run_id"]))
            elif path == "/api/runtime/load_run":
                self._send_json(load_saved_runtime_evaluation(body["run_id"]))
            elif path == "/api/runtime/export_receipt":
                self._send_json(export_runtime_receipt(body))
            elif path == "/api/runtime/deferred_release_demo":
                self._send_json(run_deferred_release_demo(body or None))
            elif path == "/api/runtime/import_org_state":
                self._send_json(import_persistent_runtime_state(body))
            elif path == "/api/runtime/recover_org_state":
                self._send_json(recover_persistent_runtime_state())
            elif path == "/api/runtime/cleanup_local_state":
                self._send_json(cleanup_local_runtime_state())
        except Exception as exc:
            self._send_error(exc)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _send_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, exc: Exception) -> None:
        error_class = exc.error_class if isinstance(exc, GuardArtifactError) else exc.__class__.__name__
        self._send_json(
            {
                "error": exc.__class__.__name__,
                "error_class": error_class,
                "message": str(exc),
            },
            status=HTTPStatus.BAD_REQUEST,
        )

    def _handle_api_get(self) -> bool:
        api_body = self._api_get_body()
        if api_body is None:
            return False
        self._send_json(api_body)
        return True

    def _api_get_body(self) -> dict[str, Any] | None:
        path = _request_path(self.path)
        if path == "/api/runtime/inputs":
            sample = _query_param(self.path, "sample", "blocked-transfer")
            return load_runtime_inputs(sample)
        if path == "/api/runtime/evaluate":
            return evaluate_runtime_request()
        if path == "/api/runtime/history":
            return runtime_history()
        if path == "/api/runtime/org_dashboard":
            return persistent_runtime_dashboard()
        if path == "/api/runtime/export_org_state":
            return export_persistent_runtime_state()
        if path.startswith("/api"):
            return {"error": "unknown api route", "path": path}
        return None

    def _send_static(self) -> None:
        path = _request_path(self.path)
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        static_path = (UI_ROOT / relative).resolve()
        if not _is_relative_to(static_path, UI_ROOT) or not static_path.is_file():
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        body = static_path.read_bytes()
        content_type = mimetypes.guess_type(static_path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def run(host: str = "127.0.0.1", port: int = 4173) -> None:
    server = ThreadingHTTPServer((host, port), GuardLocalRequestHandler)
    print(f"Serving Guard UI and local runtime API on http://{host}:{server.server_port}/")
    server.serve_forever()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _coerce_evaluated_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if "evaluation" in payload and "inputs" in payload:
        return payload
    return evaluate_runtime_request(payload)


def _request_path(raw_path: str) -> str:
    return unquote(urlparse(raw_path).path).rstrip("/")


def _query_param(raw_path: str, name: str, default: str) -> str:
    values = parse_qs(urlparse(raw_path).query).get(name)
    return values[0] if values else default


def _sample_inputs(base: dict[str, Any], sample: str) -> dict[str, Any]:
    payload = deepcopy(base)
    if sample == "empty":
        return {
            "compiled_authority": {},
            "execution_request": {},
            "runtime_evidence": {},
            "continuity_posture": {},
            "sample_label": "Empty input set",
        }
    if sample == "allowed-transfer":
        payload["execution_request"] = {
            **payload["execution_request"],
            "request_id": "exec-allowed-transfer",
            "arguments": {"amount": 500},
        }
        payload["runtime_evidence"] = {
            **payload["runtime_evidence"],
            "actor_identity": {
                "id": "manager-2",
                "type": "human",
                "role": "manager",
            },
            "approvals": [
                {
                    "role": "manager",
                    "approved_by": "manager-1",
                }
            ],
            "replay_evidence": {},
            "continuity_snapshot": {},
            "execution_context": {
                "surface": "sdk",
                "environment": "local",
                "latency_ms": 9,
            },
        }
        payload["continuity_posture"] = {}
        payload["sample_label"] = "Allowed transfer example"
        return payload
    if sample == "escalated-queued-job":
        payload["execution_request"] = {
            "schema_version": "normalized_execution_request.v1",
            "request_id": "exec-queued-job",
            "action": "settle_batch",
            "target": "queue:wire-settlement",
            "arguments": {
                "batch_id": "batch-042",
                "amount": 900,
            },
            "artifacts": [],
        }
        payload["runtime_evidence"] = {
            **payload["runtime_evidence"],
            "actor_identity": {
                "id": "worker-1",
                "type": "service",
                "role": "manager",
            },
            "approvals": [
                {
                    "role": "manager",
                    "approved_by": "manager-1",
                }
            ],
            "replay_evidence": {
                "required": True,
                "obligations": [
                    {
                        "obligation": "attach_worker_replay",
                        "rationale": "queued execution requires replay evidence before release",
                    }
                ],
            },
            "continuity_snapshot": {},
            "execution_context": {
                "surface": "queue",
                "environment": "local",
                "latency_ms": 21,
            },
        }
        payload["continuity_posture"] = {}
        payload["sample_label"] = "Escalated queued job example"
        return payload
    if sample == "deferred-release-expired-approval":
        payload["execution_request"] = {
            **payload["execution_request"],
            "request_id": "exec-deferred-release-transfer",
            "arguments": {"amount": 500},
        }
        payload["runtime_evidence"] = {
            **payload["runtime_evidence"],
            "actor_identity": {
                "id": "manager-2",
                "type": "human",
                "role": "manager",
            },
            "approvals": [
                {
                    "role": "manager",
                    "approved_by": "manager-1",
                }
            ],
            "replay_evidence": {},
            "continuity_snapshot": {},
            "timestamp_source": {
                "source": "caller_supplied",
                "timestamp": "2026-06-03T22:00:00+00:00",
            },
            "execution_context": {
                "surface": "sdk",
                "environment": "local",
                "latency_ms": 10,
            },
            "runtime_dependencies": [
                {
                    "schema_version": "guard_runtime_dependency.v1",
                    "dependency_type": "approval",
                    "dependency_id": "director-approval-1",
                    "dependency_hash": "sha256:director-approval",
                    "current_hash": "sha256:director-approval",
                    "linked_at": "2026-06-03T22:00:00+00:00",
                    "valid_until": "2026-06-03T22:30:00+00:00",
                    "status": "valid",
                }
            ],
        }
        payload["continuity_posture"] = {}
        payload["deferred_release"] = {
            "schema_version": "guard_deferred_release_plan.v1",
            "admissible_until": "2026-06-03T22:35:00+00:00",
            "release_time": "2026-06-03T22:32:00+00:00",
            "expected_outcome": "dependency_expired",
        }
        payload["sample_label"] = "Expired approval release block"
        return payload
    return payload


def _organization_context(payload: dict[str, Any] | None) -> dict[str, str]:
    context = default_organization_context()
    if payload:
        context.update(payload.get("organization_context") or {})
        runtime_evidence = payload.get("runtime_evidence") or {}
        execution_context = runtime_evidence.get("execution_context") or {}
        if execution_context.get("environment"):
            context["environment"] = execution_context["environment"]
    return context


def _write_local_artifact(root: Path, folder: str, filename: str, payload: dict[str, Any]) -> Path:
    path = root / folder / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    run()
