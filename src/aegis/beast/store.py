from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.beast.contracts import BeastLease, BeastRun


class BeastStore:
    """Append-only audit plus current lease/run projections.

    Audit rows have a hash chain.  SQLite is still not claimed to be an immutable external audit
    store, but shell processes have neither a mount nor a network route to this database.
    """

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS beast_leases (
                    lease_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS beast_runs (
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS beast_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details TEXT NOT NULL,
                    previous_digest TEXT NOT NULL,
                    digest TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_beast_audit_run
                    ON beast_audit(run_id, sequence);
                CREATE TABLE IF NOT EXISTS beast_target_blocks (
                    target_ref TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    blocked_at TEXT NOT NULL,
                    run_id TEXT NOT NULL
                );
                """
            )

    def save_lease(self, lease: BeastLease) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO beast_leases (lease_id, payload) VALUES (?, ?) "
                "ON CONFLICT(lease_id) DO UPDATE SET payload=excluded.payload",
                (lease.lease_id, lease.model_dump_json()),
            )

    def get_lease(self, lease_id: str) -> BeastLease | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM beast_leases WHERE lease_id = ?", (lease_id,)
            ).fetchone()
        return BeastLease.model_validate_json(row["payload"]) if row else None

    def save_run(self, run: BeastRun) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO beast_runs (run_id, created_at, payload) VALUES (?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET payload=excluded.payload",
                (run.run_id, run.created_at.isoformat(), run.model_dump_json()),
            )

    def get_run(self, run_id: str) -> BeastRun | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM beast_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return BeastRun.model_validate_json(row["payload"]) if row else None

    def list_runs(self, limit: int = 50) -> list[BeastRun]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM beast_runs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [BeastRun.model_validate_json(row["payload"]) for row in rows]

    def active_runs(self) -> list[BeastRun]:
        return [
            run
            for run in self.list_runs(100)
            if run.state.value in {"QUEUED", "RUNNING"}
        ]

    def block_target(self, target_ref: str, reason: str, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO beast_target_blocks (target_ref, reason, blocked_at, run_id) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(target_ref) DO UPDATE SET "
                "reason=excluded.reason, blocked_at=excluded.blocked_at, run_id=excluded.run_id",
                (target_ref, reason, datetime.now(UTC).isoformat(), run_id),
            )

    def target_block(self, target_ref: str) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT reason, blocked_at, run_id FROM beast_target_blocks WHERE target_ref=?",
                (target_ref,),
            ).fetchone()
        if row is None:
            return None
        return {
            "reason": str(row["reason"]),
            "blocked_at": str(row["blocked_at"]),
            "run_id": str(row["run_id"]),
        }

    def clear_target_block(self, target_ref: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM beast_target_blocks WHERE target_ref=?", (target_ref,))

    def audit(
        self,
        run_id: str,
        event_type: str,
        actor_type: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        created_at = datetime.now(UTC).isoformat()
        safe_details = details or {}
        encoded = json.dumps(safe_details, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            previous = connection.execute(
                "SELECT digest FROM beast_audit ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_digest = str(previous["digest"]) if previous else "0" * 64
            digest = hashlib.sha256(
                f"{previous_digest}\n{run_id}\n{event_type}\n{actor_type}\n{created_at}\n{encoded}".encode()
            ).hexdigest()
            cursor = connection.execute(
                "INSERT INTO beast_audit "
                "(run_id,event_type,actor_type,created_at,details,previous_digest,digest) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    run_id,
                    event_type,
                    actor_type,
                    created_at,
                    encoded,
                    previous_digest,
                    digest,
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("BEAST_AUDIT_SEQUENCE_NOT_ASSIGNED")
            sequence = cursor.lastrowid
        return {
            "sequence": sequence,
            "event_id": f"beast-evt-{sequence:012d}",
            "run_id": run_id,
            "event_type": event_type,
            "actor_type": actor_type,
            "timestamp": created_at,
            "details": safe_details,
            "previous_digest": previous_digest,
            "digest": digest,
        }

    def events(self, run_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        bounded = max(1, min(limit, 1000))
        with self._connect() as connection:
            if run_id:
                rows = connection.execute(
                    "SELECT * FROM beast_audit WHERE run_id=? ORDER BY sequence LIMIT ?",
                    (run_id, bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM beast_audit ORDER BY sequence DESC LIMIT ?", (bounded,)
                ).fetchall()[::-1]
        return [
            {
                "sequence": int(row["sequence"]),
                "event_id": f"beast-evt-{int(row['sequence']):012d}",
                "run_id": str(row["run_id"]),
                "event_type": str(row["event_type"]),
                "actor_type": str(row["actor_type"]),
                "timestamp": str(row["created_at"]),
                "details": json.loads(row["details"]),
                "previous_digest": str(row["previous_digest"]),
                "digest": str(row["digest"]),
            }
            for row in rows
        ]
