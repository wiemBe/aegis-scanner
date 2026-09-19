import sqlite3
from pathlib import Path

from aegis.models import ScanResult, ScanStatus
from aegis.storage import ScanStore


def test_legacy_audit_migration_preserves_history_and_marks_interrupted(tmp_path: Path) -> None:
    path = str(tmp_path / "legacy.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "scan_id TEXT, event TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute("INSERT INTO audit_events (scan_id, event) VALUES ('old', 'LEGACY_EVENT')")
    store = ScanStore(path)
    store.initialize()
    store.save(
        ScanResult(
            id="old",
            target_name="lab",
            target_base_url="http://lab-api:8001",
            status=ScanStatus.RUNNING,
            planner="DEMO_HEURISTIC",
        )
    )
    store.initialize()
    result = store.get("old")
    assert result and result.status == ScanStatus.INCOMPLETE
    assert result.stop_reason == "PROCESS_RESTART"
    assert store.audit("old")[0]["event"] == "LEGACY_EVENT"
    assert store.audit("old")[0]["details"] == {}


def test_audit_projection_has_stable_ids_actors_links_and_safe_evidence(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "audit.db"))
    store.initialize()
    store.save(
        ScanResult(
            id="scan-aaaaaaaaaaaa",
            target_name="lab",
            target_base_url="http://lab-api:8001",
            status=ScanStatus.FAIL,
            planner="LOCAL_LLM",
        )
    )
    store.add_audit(
        "scan-aaaaaaaaaaaa",
        "OBSERVATION",
        {
            "name": "request-1",
            "method": "GET",
            "path": "/api/v1/accounts/B-200",
            "credential_profile": "user_a",
            "status_code": 200,
            "response_excerpt": {"sensitive": "omitted from projection"},
            "error": "raw exception prose",
        },
    )

    event = store.audit("scan-aaaaaaaaaaaa")[0]
    assert event["event_id"] == "scan-aaaaaaaaaaaa:1"
    assert event["scan_id"] == "scan-aaaaaaaaaaaa"
    assert event["timestamp"]
    assert event["actor_type"] == "CONTROLLER"
    assert event["links"]["scan_id"] == "scan-aaaaaaaaaaaa"
    assert event["evidence_ref"] == {
        "evidence_id": "scan-aaaaaaaaaaaa:request-1",
        "name": "request-1",
        "method": "GET",
        "path": "/api/v1/accounts/B-200",
        "credential_profile": "user_a",
        "status_code": 200,
        "has_error": True,
    }
