import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

import aegis.main as main_module
from aegis.models import Finding, ScanResult, ScanStatus
from aegis.operator import ActorType, Engine, project_event, safe_metadata
from aegis.screenshots import PNG_MAGIC, ScreenshotMetadata, ScreenshotStore
from aegis.storage import ScanStore


def _scan(scan_id: str = "scan-aaaaaaaaaaaa") -> ScanResult:
    return ScanResult(
        id=scan_id,
        target_name="Synthetic Bank API",
        target_base_url="http://lab-api:8001",
        status=ScanStatus.FAIL,
        planner="LOCAL_LLM",
        model="qwen3:8b",
    )


def test_event_projection_is_typed_ordered_checksummed_and_redacted() -> None:
    scan = _scan()
    row = {
        "id": 7,
        "scan_id": scan.id,
        "event": "CANDIDATE_GENERATED",
        "created_at": "2026-09-18 19:00:00",
        "details": {
            "stage": "discovery",
            "authorization": "Bearer secret",
            "reasoning_content": "hidden",
            "response_body": {"account_balance": 99},
        },
        "evidence_ref": None,
    }
    event = project_event(row, scan, parent_event_id="evt-000000000006")
    assert event.event_id == "evt-000000000007"
    assert event.sequence == 7
    assert event.actor_type == ActorType.AI_PLANNER
    assert event.engine == Engine.AEGIS_NATIVE
    assert event.parent_event_id == "evt-000000000006"
    assert event.metadata == {"stage": "discovery"}
    assert len(event.integrity["digest"]) == 64
    assert "secret" not in event.model_dump_json().lower()
    assert "balance" not in event.model_dump_json().lower()


def test_safe_metadata_rejects_nested_sensitive_fields_and_bounds_lists() -> None:
    projected = safe_metadata(
        {
            "limits": {"requests": 8, "token": "secret", "cookie": "bad"},
            "path": "/api/v1/accounts/B-200",
            "traceback": "raw stack",
            "requests": list(range(30)),
        }
    )
    assert projected["limits"] == {"requests": 8}
    assert projected["path"] == "/api/v1/accounts/B-200"
    assert len(projected["requests"]) == 12
    assert "traceback" not in projected


def test_global_audit_pagination_and_stable_order(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "audit.db"))
    store.initialize()
    scan = _scan()
    store.save(scan)
    store.add_audit(scan.id, "SCAN_CREATED", {"planner": "LOCAL_LLM"})
    store.add_audit(scan.id, "PREFLIGHT", {"stage": "discovery"})
    store.add_audit(scan.id, "CANDIDATE_GENERATED", {"stage": "discovery"})
    first = store.raw_audit_events(limit=2)
    second = store.raw_audit_events(after_sequence=first[-1]["id"], limit=2)
    assert [row["id"] for row in first] == sorted(row["id"] for row in first)
    assert len(first) == 2
    assert first[0]["child_id"] == first[1]["id"]
    assert first[1]["parent_id"] == first[0]["id"]
    assert [row["event"] for row in second] == ["CANDIDATE_GENERATED"]
    assert second[0]["parent_id"] == first[1]["id"]


@pytest.mark.asyncio
async def test_audit_api_filters_and_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "api.db"))
    store.initialize()
    scan = _scan()
    store.save(scan)
    store.add_audit(scan.id, "SCAN_CREATED", {})
    store.add_audit(scan.id, "CANDIDATE_GENERATED", {})
    store.add_audit(scan.id, "VERIFIER_RESULT", {"status": "CONFIRMED"})
    monkeypatch.setattr(main_module, "store", store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/console/audit", params={"actor": "AI_PLANNER", "limit": 1}
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["actor_type"] == "AI_PLANNER"
    assert body["stable_order"] == "sequence ASC"
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_last_event_id_parser_and_rejection() -> None:
    assert main_module._parse_event_cursor("evt-000000000042") == 42
    assert main_module._parse_event_cursor("42") == 42
    with pytest.raises(main_module.HTTPException):
        main_module._parse_event_cursor("scan-aaaaaaaaaaaa:1")


def test_screenshot_store_disabled_and_mime_path_quota_controls(tmp_path: Path) -> None:
    content = PNG_MAGIC + b"safe-fixture"
    disabled = ScreenshotStore(tmp_path / "shots")
    with pytest.raises(PermissionError, match="disabled"):
        disabled.persist(
            artifact_id="shot-0123456789abcdef",
            scan_id="scan-aaaaaaaaaaaa",
            event_id="evt-000000000001",
            origin="http://lab-api:8001",
            capture_type="VIEWPORT",
            mime_type="image/png",
            width=100,
            height=100,
            content=content,
            redacted=True,
        )

    enabled = ScreenshotStore(tmp_path / "shots", enabled=True, max_bytes=len(content) + 1)
    metadata = enabled.persist(
        artifact_id="shot-0123456789abcdef",
        scan_id="scan-aaaaaaaaaaaa",
        event_id="evt-000000000001",
        origin="http://lab-api:8001",
        capture_type="VIEWPORT",
        mime_type="image/png",
        width=100,
        height=100,
        content=content,
        redacted=True,
    )
    assert enabled.read(metadata) == content
    assert metadata.sha256_digest == hashlib.sha256(content).hexdigest()
    expired = metadata.model_copy(
        update={"retention_expiry": datetime.now(UTC) - timedelta(seconds=1)}
    )
    assert enabled.delete_expired(
        project_root=enabled.root, artifacts=[expired], now=datetime.now(UTC)
    ) == [metadata.artifact_id]
    assert not (enabled.root / metadata.local_storage_reference).exists()
    with pytest.raises(ValueError, match="project-scoped"):
        enabled.delete_expired(
            project_root=tmp_path, artifacts=[], now=datetime.now(UTC)
        )

    # Recreate one artifact so the quota assertion exercises quota rather than duplicate IDs.
    enabled.persist(
        artifact_id="shot-0123456789abcdef",
        scan_id="scan-aaaaaaaaaaaa",
        event_id="evt-000000000001",
        origin="http://lab-api:8001",
        capture_type="VIEWPORT",
        mime_type="image/png",
        width=100,
        height=100,
        content=content,
        redacted=True,
    )
    with pytest.raises(ValueError, match="quota"):
        enabled.persist(
            artifact_id="shot-fedcba9876543210",
            scan_id="scan-aaaaaaaaaaaa",
            event_id="evt-000000000002",
            origin="http://lab-api:8001",
            capture_type="VIEWPORT",
            mime_type="image/png",
            width=100,
            height=100,
            content=content,
            redacted=True,
        )
    with pytest.raises(ValueError, match="MIME"):
        ScreenshotStore(tmp_path / "bad", enabled=True).persist(
            artifact_id="shot-fedcba9876543210",
            scan_id="scan-aaaaaaaaaaaa",
            event_id="evt-000000000002",
            origin="http://lab-api:8001",
            capture_type="VIEWPORT",
            mime_type="image/webp",
            width=100,
            height=100,
            content=content,
            redacted=True,
        )


def test_screenshot_metadata_rejects_external_origin_and_unsafe_reference() -> None:
    base = {
        "artifact_id": "shot-0123456789abcdef",
        "run_id": "scan-aaaaaaaaaaaa",
        "scan_id": "scan-aaaaaaaaaaaa",
        "event_id": "evt-000000000001",
        "timestamp": datetime.now(UTC),
        "approved_target_origin": "https://evil.example",
        "capture_type": "VIEWPORT",
        "redaction_status": "REDACTED",
        "mime_type": "image/png",
        "width": 100,
        "height": 100,
        "byte_size": 100,
        "sha256_digest": "a" * 64,
        "retention_expiry": datetime.now(UTC) + timedelta(hours=24),
        "local_storage_reference": "../escape.png",
    }
    with pytest.raises(ValidationError):
        ScreenshotMetadata.model_validate(base)


@pytest.mark.asyncio
async def test_forged_finding_is_excluded_from_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "findings.db"))
    store.initialize()
    scan = _scan()
    scan.findings = [
        Finding(
            id="forged-finding",
            title="Not verifier generated",
            severity="CRITICAL",
            category="BOLA",
            confidence="CONFIRMED",
            description="forged",
            remediation="none",
            evidence_names=[],
        )
    ]
    store.save(scan)
    monkeypatch.setattr(main_module, "store", store)
    response = await main_module.console_findings(limit=50)
    assert response["items"] == []
    assert "Only deterministic verifier" in response["provenance_policy"]
