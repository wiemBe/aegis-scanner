import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.audit import actor_for_event, redacted_evidence_ref, stable_event_id
from aegis.models import ScanResult, ScanStatus
from aegis.verifier import DeterministicVerifier


class ScanStore:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        path = Path(self.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_scan_id_id
                    ON audit_events(scan_id, id);
                CREATE TABLE IF NOT EXISTS audit_access_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    route TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
            if "details" not in columns:
                connection.execute(
                    "ALTER TABLE audit_events ADD COLUMN details TEXT NOT NULL DEFAULT '{}'"
                )
            # Background jobs do not survive process restart; never leave a stale running scan.
            rows = connection.execute(
                "SELECT payload FROM scans WHERE status IN ('QUEUED', 'RUNNING')"
            ).fetchall()
        for row in rows:
            result = ScanResult.model_validate_json(row["payload"])
            result.findings = DeterministicVerifier().verify(
                result.hypotheses, result.evidence, result.variant, scan_id=result.id
            )
            result.status = ScanStatus.FAIL if result.findings else ScanStatus.INCOMPLETE
            result.stop_reason = "PROCESS_RESTART"
            result.completed_at = datetime.now(UTC)
            self.save(result)
            self.add_audit(result.id, "PROCESS_RESTART")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def save(self, result: ScanResult) -> None:
        payload = result.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (id, status, created_at, payload) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET status=excluded.status, payload=excluded.payload
                """,
                (result.id, result.status.value, result.created_at.isoformat(), payload),
            )

    def add_audit(self, scan_id: str, event: str, details: dict[str, Any] | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_events (scan_id, event, details) VALUES (?, ?, ?)",
                (scan_id, event, json.dumps(details or {})),
            )

    def get(self, scan_id: str) -> ScanResult | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return ScanResult.model_validate_json(row["payload"]) if row else None

    def list_recent(self, limit: int = 25) -> list[ScanResult]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [ScanResult.model_validate_json(row["payload"]) for row in rows]

    def list_all(self, limit: int = 500) -> list[ScanResult]:
        bounded = max(1, min(limit, 500))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM scans ORDER BY created_at DESC, id DESC LIMIT ?", (bounded,)
            ).fetchall()
        return [ScanResult.model_validate_json(row["payload"]) for row in rows]

    def raw_audit_events(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 100,
        scan_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return persisted rows in stable global sequence order for console projection."""

        bounded = max(1, min(limit, 200))
        with self._connect() as connection:
            if scan_id is None:
                rows = connection.execute(
                    "SELECT ae.id, ae.scan_id, ae.event, ae.created_at, ae.details, "
                    "(SELECT MAX(prev.id) FROM audit_events prev "
                    "WHERE prev.scan_id = ae.scan_id AND prev.id < ae.id) AS parent_id, "
                    "(SELECT MIN(child.id) FROM audit_events child "
                    "WHERE child.scan_id = ae.scan_id AND child.id > ae.id) AS child_id "
                    "FROM audit_events ae WHERE ae.id > ? ORDER BY ae.id ASC LIMIT ?",
                    (max(0, after_sequence), bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT ae.id, ae.scan_id, ae.event, ae.created_at, ae.details, "
                    "(SELECT MAX(prev.id) FROM audit_events prev "
                    "WHERE prev.scan_id = ae.scan_id AND prev.id < ae.id) AS parent_id, "
                    "(SELECT MIN(child.id) FROM audit_events child "
                    "WHERE child.scan_id = ae.scan_id AND child.id > ae.id) AS child_id "
                    "FROM audit_events ae WHERE ae.id > ? AND ae.scan_id = ? "
                    "ORDER BY ae.id ASC LIMIT ?",
                    (max(0, after_sequence), scan_id, bounded),
                ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            try:
                details = json.loads(row["details"])
            except (json.JSONDecodeError, TypeError):
                details = {}
            evidence_ref = (
                redacted_evidence_ref(details, str(row["scan_id"]))
                if row["event"] == "OBSERVATION"
                else None
            )
            records.append(
                {
                    "id": int(row["id"]),
                    "scan_id": str(row["scan_id"]),
                    "event": str(row["event"]),
                    "created_at": str(row["created_at"]),
                    "details": details,
                    "evidence_ref": evidence_ref,
                    "parent_id": int(row["parent_id"]) if row["parent_id"] else None,
                    "child_id": int(row["child_id"]) if row["child_id"] else None,
                }
            )
        return records

    def audit_access(self, request_id: str, route: str, outcome: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_access_log (request_id, route, outcome) VALUES (?, ?, ?)",
                (request_id[:64], route[:120], outcome[:32]),
            )

    def audit(self, scan_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, event, created_at, details FROM audit_events "
                "WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
            scan_rows = connection.execute("SELECT payload FROM scans").fetchall()

        scan_payloads: list[dict[str, Any]] = []
        for row in scan_rows:
            try:
                payload = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(payload, dict):
                scan_payloads.append(payload)

        current = next((item for item in scan_payloads if item.get("id") == scan_id), {})
        finding_ids = [
            str(item["id"])
            for item in current.get("findings", [])
            if isinstance(item, dict) and item.get("id")
        ]
        retest_of_scan_id = current.get("retest_of")
        linked_retest_scan_ids = sorted(
            str(item["id"])
            for item in scan_payloads
            if item.get("retest_of") == scan_id and item.get("id")
        )

        records: list[dict[str, Any]] = []
        for row in rows:
            details = json.loads(row["details"])
            event = str(row["event"])
            evidence_ref = (
                redacted_evidence_ref(details, scan_id) if event == "OBSERVATION" else None
            )
            records.append(
                {
                    "id": row["id"],
                    "event_id": stable_event_id(scan_id, row["id"]),
                    "scan_id": scan_id,
                    "event": event,
                    "actor_type": actor_for_event(event),
                    "timestamp": row["created_at"],
                    "created_at": row["created_at"],
                    "links": {
                        "scan_id": scan_id,
                        "finding_ids": finding_ids,
                        "retest_of_scan_id": retest_of_scan_id,
                        "linked_retest_scan_ids": linked_retest_scan_ids,
                    },
                    "evidence_ref": evidence_ref,
                    "details": details,
                }
            )
        return records
