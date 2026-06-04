from __future__ import annotations

from typing import Any


def telemetry_stream(chronology: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "sequence": event["sequence"],
            "timestamp": event["timestamp"],
            "authority_ref": event["authority_ref"],
            "event_hash": event["event_hash"],
        }
        for event in chronology
    ]
