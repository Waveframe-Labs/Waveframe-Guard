from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import mimetypes
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui"
INPUT_ROOT = Path(__file__).resolve().parent / "runtime_inputs"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard import evaluate_runtime
from guard.runtime.evidence import validate_runtime_evidence_model

TELEMETRY_LOG: list[dict[str, Any]] = []


def load_runtime_inputs() -> dict[str, Any]:
    return {
        "compiled_authority": _read_json(INPUT_ROOT / "compiled_authority.json"),
        "execution_request": _read_json(INPUT_ROOT / "normalized_execution_request.json"),
        "runtime_evidence": _read_json(INPUT_ROOT / "runtime_evidence.json"),
    }


def evaluate_runtime_request(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or load_runtime_inputs()
    compiled_authority = payload.get("compiled_authority")
    execution_request = payload.get("execution_request")
    runtime_evidence = validate_runtime_evidence_model(payload.get("runtime_evidence"))
    timestamp = runtime_evidence["timestamp_source"].get("timestamp") or _now()

    result = evaluate_runtime(
        compiled_authority=compiled_authority,
        execution_request=execution_request,
        actor_identity=runtime_evidence["actor_identity"],
        continuity_state=runtime_evidence["continuity_snapshot"],
        replay_posture=runtime_evidence["replay_evidence"],
        evidence_posture={
            "approvals": runtime_evidence["approvals"],
            "execution_context": runtime_evidence["execution_context"],
        },
        evaluation_time=timestamp,
        start_sequence=len(TELEMETRY_LOG) + 1,
    )
    appended = append_telemetry(result["telemetry_events"], outcome=result["enforcement_outcome"])
    return {
        "inputs": {
            "compiled_authority": compiled_authority,
            "execution_request": execution_request,
            "runtime_evidence": runtime_evidence,
        },
        "evaluation": result,
        "guard_enforcement_outcome": result["enforcement_outcome"],
        "chronology": reconstruct_chronology(result["telemetry_events"]),
        "telemetry_appended": appended,
        "telemetry_stream": TELEMETRY_LOG,
    }


def append_telemetry(events: list[dict[str, Any]], *, outcome: dict[str, Any]) -> list[dict[str, Any]]:
    appended = []
    received_at = _now()
    for event in events:
        telemetry_event = {
            "received_at": received_at,
            "outcome_id": outcome["outcome_id"],
            "outcome_status": outcome["status"],
            **event,
        }
        TELEMETRY_LOG.append(telemetry_event)
        appended.append(telemetry_event)
    return appended


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
        if path != "/api/runtime/evaluate":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            self._send_json(evaluate_runtime_request(self._read_body()))
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
        self._send_json(
            {
                "error": exc.__class__.__name__,
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
            return load_runtime_inputs()
        if path == "/api/runtime/evaluate":
            return evaluate_runtime_request()
        if path == "/api/runtime/telemetry":
            return {"telemetry_stream": TELEMETRY_LOG}
        if path == "/api/runtime/chronology":
            return {"chronology": reconstruct_chronology(TELEMETRY_LOG)}
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
        self.end_headers()
        self.wfile.write(body)


def run(host: str = "127.0.0.1", port: int = 4173) -> None:
    server = ThreadingHTTPServer((host, port), GuardLocalRequestHandler)
    print(f"Serving Guard UI and local runtime API on http://{host}:{server.server_port}/")
    server.serve_forever()


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _request_path(raw_path: str) -> str:
    return unquote(urlparse(raw_path).path).rstrip("/")


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
