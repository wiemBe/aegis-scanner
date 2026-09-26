"""WP3 / G-OBS-1 — secure structured logging, bounded metrics, alert-policy guards.

These tests prove the observability layer cannot become a secret-exfiltration, high-cardinality,
authority, or availability boundary: unique sentinels injected through every request surface never
appear in any log line or in ``/metrics``; unknown paths collapse to a single bounded ``UNMATCHED``
series; the log schema is strict and JSON-valid; and a logging/metrics failure can never change a
response or a controller verdict. Liveness/readiness/security-header behavior is unchanged.
"""

from __future__ import annotations

import io
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import Response

import aegis.main as aegis_main
import aegis.observability as aegis_obs_singletons
import lab_api.main as lab_main
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis_obs.logging import LOG_SCHEMA_VERSION, StructuredLogger, build_record
from aegis_obs.metrics import MAX_ROUTE_LABELS, MetricsRegistry
from aegis_obs.middleware import observe_request
from aegis_obs.normalize import ROUTE_OTHER

ROOT = Path(__file__).resolve().parents[1]

_ALLOWED_LOG_KEYS = {
    "schema_version",
    "timestamp_utc",
    "level",
    "service",
    "event",
    "request_id",
    "method",
    "route",
    "status_code",
    "status_class",
    "duration_ms",
    "code",
    "exception_class",
}
_REQUIRED_LOG_KEYS = {"schema_version", "timestamp_utc", "level", "service", "event", "request_id"}


def _parse_logs(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


# --- Log schema is strict and JSON-valid ---------------------------------------------------------


def test_build_record_only_emits_allowlisted_keys() -> None:
    record = build_record(
        service="control-plane",
        event="http_request",
        level="INFO",
        request_id="req-abc",
        method="GET",
        route="/api/scans/{scan_id}",
        status_code=200,
        duration_seconds=0.01,
        code="OK",
        exception_class="ValueError",
    )
    assert set(record).issubset(_ALLOWED_LOG_KEYS)
    assert _REQUIRED_LOG_KEYS <= set(record)
    assert record["schema_version"] == LOG_SCHEMA_VERSION
    assert record["status_class"] == "2xx"


def test_build_record_coerces_out_of_contract_values() -> None:
    record = build_record(
        service="totally-unknown-service",
        event="not-an-event",
        level="CRITICALish",
        request_id="req-x",
        method="TRACE",
        route="/x",
        status_code=799,
        exception_class="SomethingSecretError",
    )
    assert record["service"] == "unknown"
    assert record["event"] == "http_request"
    assert record["level"] == "INFO"
    assert record["method"] == ROUTE_OTHER
    assert record["status_class"] == "OTHER"
    assert record["exception_class"] == "Exception"  # not on the allowlist -> generic


def test_logger_writes_single_line_valid_json() -> None:
    buf = io.StringIO()
    StructuredLogger(stream=buf).log(
        service="lab-api", event="http_request", level="INFO", request_id="req-1"
    )
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["service"] == "lab-api"


def test_logger_never_raises_on_unserializable_field() -> None:
    buf = io.StringIO()
    logger = StructuredLogger(stream=buf)
    # An object json cannot encode is coerced by default=str; the logger must not raise.
    logger.emit({"schema_version": LOG_SCHEMA_VERSION, "weird": {1, 2, 3}})
    assert buf.getvalue()  # something was written


# --- Redaction: sentinels injected everywhere never appear in logs or metrics --------------------


@pytest.fixture
def control_plane_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry]:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()
    monkeypatch.setattr(aegis_main, "store", store)
    monkeypatch.setattr(aegis_main, "settings", Settings())
    buf = io.StringIO()
    registry = MetricsRegistry(service="control-plane")
    monkeypatch.setattr(aegis_obs_singletons.logger, "_stream", buf)
    monkeypatch.setattr(aegis_main, "obs_logger", aegis_obs_singletons.logger)
    monkeypatch.setattr(aegis_main, "obs_metrics", registry)
    return httpx.ASGITransport(app=aegis_main.app, raise_app_exceptions=False), buf, registry


async def test_no_sentinel_leaks_into_logs_or_metrics(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
) -> None:
    transport, buf, registry = control_plane_capture
    sentinels = {
        "query": "S3NT1NEL-QUERY-aaaa",
        "path": "S3NT1NEL-PATH-bbbb",
        "authz": "S3NT1NEL-AUTHZ-cccc",
        "cookie": "S3NT1NEL-COOKIE-dddd",
        "body": "S3NT1NEL-BODY-eeee",
        "reqid": "S3NT1NEL-REQID-ffff" * 10,  # oversized + malformed request id
    }
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get(
            f"/api/nonexistent/{sentinels['path']}?token={sentinels['query']}",
            headers={
                "Authorization": f"Bearer {sentinels['authz']}",
                "Cookie": f"session={sentinels['cookie']}",
                "X-Request-ID": sentinels["reqid"],
            },
        )
        await client.post("/api/scans", content=sentinels["body"].encode())
        metrics_body = (await client.get("/metrics")).text

    haystack = buf.getvalue() + "\n" + metrics_body
    for name, value in sentinels.items():
        assert value not in haystack, f"sentinel {name} leaked"
    # logs are still present and valid JSON
    logs = _parse_logs(buf)
    assert logs
    assert all(set(rec).issubset(_ALLOWED_LOG_KEYS) for rec in logs)


async def test_metrics_never_contains_request_id_or_user_values(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
) -> None:
    transport, _buf, _registry = control_plane_capture
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get(
            "/api/scans/UNIQUE-SCANID-9f9f9f", headers={"X-Request-ID": "req-UNIQUEID-7a7a"}
        )
        body = (await client.get("/metrics")).text
    assert "UNIQUE-SCANID-9f9f9f" not in body
    assert "req-UNIQUEID-7a7a" not in body
    assert "aegis_http_requests_total" in body


# --- Cardinality: unknown paths collapse; bounded series -----------------------------------------


async def test_unknown_paths_collapse_to_single_unmatched_series(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
) -> None:
    transport, _buf, registry = control_plane_capture
    before = registry.route_label_count()
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(25):
            await client.get(f"/no/such/route/{i}")
        body = (await client.get("/metrics")).text
    # Unknown routes never create a distinct known-route label...
    assert registry.route_label_count() == before + 1  # only /metrics itself is a real template
    # ...and there is exactly one UNMATCHED request-counter series.
    unmatched_request_lines = [
        line
        for line in body.splitlines()
        if line.startswith("aegis_http_requests_total{") and 'route="UNMATCHED"' in line
    ]
    assert len(unmatched_request_lines) == 1


def test_registry_route_cardinality_is_hard_bounded() -> None:
    registry = MetricsRegistry(service="control-plane", max_route_labels=8)
    for i in range(50):
        registry.observe_request(
            method="GET", route=f"/api/thing/{i}", status_code=200, duration_seconds=0.001
        )
    assert registry.route_label_count() <= 8
    body = registry.render()
    assert f'route="{ROUTE_OTHER}"' in body  # overflow collapsed to OTHER


def test_default_max_route_labels_is_defined() -> None:
    assert isinstance(MAX_ROUTE_LABELS, int) and MAX_ROUTE_LABELS > 0


def test_scan_completion_counter_bounds_unknown_status() -> None:
    registry = MetricsRegistry(service="control-plane")
    registry.record_scan_completion("PASS")
    registry.record_scan_completion("PASS")
    registry.record_scan_completion("TOTALLY-UNKNOWN-STATUS")
    body = registry.render()
    assert 'aegis_scan_completions_total{service="control-plane",status="PASS"} 2' in body
    assert f'status="{ROUTE_OTHER}"' in body  # unknown terminal status collapsed
    assert "TOTALLY-UNKNOWN-STATUS" not in body


# --- Metrics recording + serialization failure ---------------------------------------------------


def test_observe_request_increments_counter_and_histogram() -> None:
    registry = MetricsRegistry(service="lab-api")
    registry.observe_request(
        method="GET", route="/api/v1/me", status_code=200, duration_seconds=0.02
    )
    body = registry.render()
    assert 'aegis_http_requests_total{service="lab-api",method="GET",route="/api/v1/me"} 1' in body
    assert 'aegis_http_request_duration_seconds_count' in body
    assert 'aegis_http_responses_total' in body and 'status_class="2xx"' in body


def test_metrics_render_failure_returns_fixed_body(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = MetricsRegistry(service="lab-api")

    def boom() -> str:
        raise RuntimeError("internal detail that must not leak")

    monkeypatch.setattr(registry, "_render_locked", boom)
    body = registry.render()
    assert body.startswith("# metrics_unavailable")
    assert "internal detail" not in body


async def test_metrics_endpoint_returns_503_on_render_failure(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, _buf, registry = control_plane_capture
    monkeypatch.setattr(registry, "render", lambda: "# metrics_unavailable\n")
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
    assert resp.status_code == 503
    assert "metrics_unavailable" in resp.text


# --- Logging/metrics failure cannot change response or controller verdict -------------------------


class _ExplodingLogger(StructuredLogger):
    def emit(self, record: dict[str, Any]) -> None:  # type: ignore[override]
        raise RuntimeError("logging backend down")


class _ExplodingRegistry(MetricsRegistry):
    def observe_request(self, **_kwargs: Any) -> None:  # type: ignore[override]
        raise RuntimeError("metrics backend down")


async def test_logging_and_metrics_failure_do_not_break_requests() -> None:
    app = FastAPI()

    @app.middleware("http")
    async def mw(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        return await observe_request(
            request,
            call_next,
            service="lab-api",
            registry=_ExplodingRegistry(service="lab-api"),
            logger=_ExplodingLogger(),
        )

    @app.get("/ok")
    async def ok() -> dict[str, str]:
        return {"verdict": "PASS"}

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ok")
    # The response (the controller-owned verdict payload) is unchanged despite obs failures.
    assert resp.status_code == 200
    assert resp.json() == {"verdict": "PASS"}


async def test_exception_message_is_never_logged() -> None:
    secret = "EXC-SENTINEL-should-not-be-logged-1234"  # noqa: S105 - test sentinel, not a credential
    buf = io.StringIO()
    logger = StructuredLogger(stream=buf)
    app = FastAPI()

    @app.middleware("http")
    async def mw(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        return await observe_request(
            request,
            call_next,
            service="lab-api",
            registry=MetricsRegistry(service="lab-api"),
            logger=logger,
        )

    @app.get("/boom")
    async def boom() -> dict[str, str]:
        raise ValueError(secret)

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/boom")
    assert resp.status_code == 500
    logs = _parse_logs(buf)
    assert secret not in buf.getvalue()
    error_logs = [rec for rec in logs if rec.get("event") == "http_error"]
    assert error_logs and error_logs[0]["code"] == "UNHANDLED_EXCEPTION"
    assert error_logs[0]["exception_class"] == "ValueError"


# --- Liveness / readiness / security headers unchanged -------------------------------------------


async def test_liveness_and_security_headers_unchanged(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
) -> None:
    transport, _buf, _registry = control_plane_capture
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    headers = {k.lower() for k in resp.headers}
    assert "content-security-policy" in headers
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "x-request-id" in headers


async def test_readiness_still_fail_closed_and_sets_gauge(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Point at an absent store so readiness fails closed; the gauge must reflect 0, not falsely 1.
    monkeypatch.setattr(aegis_main, "store", ScanStore("/nonexistent/definitely/absent.db"))
    transport, _buf, registry = control_plane_capture
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/ready")
        body = (await client.get("/metrics")).text
    assert resp.status_code == 503
    assert resp.json()["ready"] is False
    assert 'aegis_readiness_ready{service="control-plane"} 0' in body


async def test_health_and_metrics_scrapes_are_not_access_logged(
    control_plane_capture: tuple[httpx.ASGITransport, io.StringIO, MetricsRegistry],
) -> None:
    transport, buf, _registry = control_plane_capture
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await client.get("/health")
        await client.get("/metrics")
    routes_logged = {rec.get("route") for rec in _parse_logs(buf)}
    assert "/health" not in routes_logged
    assert "/metrics" not in routes_logged


# --- lab-api observability -----------------------------------------------------------------------


async def test_lab_api_request_metrics_and_no_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    buf = io.StringIO()
    registry = MetricsRegistry(service="lab-api")
    monkeypatch.setattr(lab_main._obs_logger, "_stream", buf)
    monkeypatch.setattr(lab_main, "_obs_metrics", registry)
    transport = httpx.ASGITransport(app=lab_main.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/health")
        await client.get("/api/v1/accounts/SENSITIVE-ACCT-9999?q=SENTINEL-LAB-QUERY")
        body = (await client.get("/metrics")).text
    assert health.status_code == 200
    assert "x-request-id" in {k.lower() for k in health.headers}
    assert "SENSITIVE-ACCT-9999" not in body and "SENTINEL-LAB-QUERY" not in body
    assert "SENSITIVE-ACCT-9999" not in buf.getvalue()
    assert "aegis_http_requests_total" in body


# --- Uvicorn raw access logging disabled in Docker configuration ---------------------------------


def test_compose_disables_uvicorn_access_log() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service in ("control-plane", "lab-api"):
        command = compose["services"][service]["command"]
        assert "--no-access-log" in command, f"{service} must disable the raw uvicorn access log"


def test_dockerfile_default_command_disables_uvicorn_access_log() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "--no-access-log" in dockerfile


def test_alert_policy_uses_only_fixed_metric_names_and_bounded_labels() -> None:
    text = (ROOT / "deploy" / "observability" / "alerts.yml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert parsed["groups"], "alert policy must define groups"
    # References our fixed metric names.
    for metric in ("aegis_readiness_ready", "aegis_http_responses_total",
                   "aegis_http_request_duration_seconds_bucket",
                   "aegis_process_start_timestamp_seconds", "aegis_readiness_check"):
        assert metric in text, f"alert policy should reference {metric}"
    # Never uses a high-cardinality / user-controlled label (checked in PromQL label syntax).
    for forbidden in ("request_id=", "scan_id=", "campaign_id=", "finding_id=", "target=", "url="):
        assert forbidden not in text, f"alert policy must not use label {forbidden!r}"


def test_metrics_endpoint_has_no_host_port_exposed() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service in ("control-plane", "lab-api"):
        spec = compose["services"][service]
        assert "ports" not in spec, f"{service} must not publish a host port"
    assert compose["networks"]["security-lab"].get("internal") is True
