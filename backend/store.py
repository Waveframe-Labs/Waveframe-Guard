from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from .models import EventRecord


class EventStore:
    def __init__(self, db_path: str = "waveframe_guard.db") -> None:
        self.db_path = db_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    policy TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def insert_event(self, event: EventRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events (
                    event_id,
                    timestamp,
                    actor,
                    action_type,
                    action_json,
                    context_json,
                    allowed,
                    reason,
                    policy
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.actor,
                    event.action_type,
                    json.dumps(event.action),
                    json.dumps(event.context),
                    1 if event.allowed else 0,
                    event.reason,
                    event.policy,
                ),
            )
            conn.commit()

    def list_events(self, limit: int = 100) -> list[EventRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM events
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [self._row_to_event(row) for row in rows]

    def get_event(self, event_id: str) -> Optional[EventRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_event(row)

    def _row_to_event(self, row: sqlite3.Row) -> EventRecord:
        return EventRecord(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            actor=row["actor"],
            action_type=row["action_type"],
            action=json.loads(row["action_json"]),
            context=json.loads(row["context_json"]),
            allowed=bool(row["allowed"]),
            reason=row["reason"],
            policy=row["policy"],
        )