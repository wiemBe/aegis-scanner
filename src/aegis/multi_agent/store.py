"""SQLite adapter using the existing Aegis database for agent runs and typed events."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from aegis.multi_agent.contracts import AgentAuditEvent, RunEvaluation


class MultiAgentStore:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        path = Path(self.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS agent_runs (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_events_run_sequence
                    ON agent_events(run_id, sequence);
                """
            )

    def save(self, evaluation: RunEvaluation) -> None:
        payload = evaluation.model_dump_json()
        run = evaluation.run
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT state, payload FROM agent_runs WHERE run_id = ?", (run.run_id,)
            ).fetchone()
            if (
                existing is not None
                and existing["state"] in {"COMPLETED", "FAILED", "CANCELLED"}
                and existing["payload"] != payload
            ):
                raise ValueError("TERMINAL_RUN_IMMUTABLE")
            connection.execute(
                """INSERT INTO agent_runs(run_id, state, created_at, payload) VALUES (?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET state=excluded.state, payload=excluded.payload""",
                (run.run_id, run.state.value, run.created_at.isoformat(), payload),
            )
            for event in evaluation.audit_events:
                connection.execute(
                    """INSERT OR IGNORE INTO agent_events(event_id, run_id, created_at, payload)
                    VALUES (?, ?, ?, ?)""",
                    (
                        event.event_id,
                        event.run_id,
                        event.created_at.isoformat(),
                        event.model_dump_json(),
                    ),
                )

    def get(self, run_id: str) -> RunEvaluation | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM agent_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return RunEvaluation.model_validate_json(row["payload"]) if row else None

    def list_recent(self, limit: int = 25) -> list[RunEvaluation]:
        bounded = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM agent_runs ORDER BY created_at DESC LIMIT ?", (bounded,)
            ).fetchall()
        return [RunEvaluation.model_validate_json(row["payload"]) for row in rows]

    def events(self, run_id: str) -> list[AgentAuditEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM agent_events WHERE run_id = ? ORDER BY sequence", (run_id,)
            ).fetchall()
        return [AgentAuditEvent.model_validate_json(row["payload"]) for row in rows]
