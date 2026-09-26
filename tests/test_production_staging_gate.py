"""Read-only staging soak/failure gate contracts."""

from __future__ import annotations

import json

import httpx
import pytest

from aegis.deploy.staging_gate import run_gate, validate_base_url


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000",
        "http://staging.example:8000",
        "http://127.0.0.1",
        "http://user:secret@127.0.0.1:8000",
        "http://127.0.0.1:8000/path",
    ],
)
def test_gate_refuses_non_loopback_or_ambiguous_origins(url: str) -> None:
    with pytest.raises(ValueError):
        validate_base_url(url)


def test_healthy_soak_requires_health_readiness_and_metrics() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/ready":
            return httpx.Response(200, json={"ready": True, "checks": []})
        if request.url.path == "/metrics":
            return httpx.Response(200, text="aegis_readiness_ready 1\n")
        return httpx.Response(404)

    report = run_gate(
        base_url="http://127.0.0.1:8000",
        mode="healthy",
        samples=3,
        interval_seconds=0,
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    assert report.passed is True
    assert report.completed_samples == 3
    assert all(item.code == "HEALTHY" for item in report.observations)


def test_failure_drill_requires_live_process_to_fail_readiness_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/ready":
            return httpx.Response(503, json={"ready": False, "checks": []})
        return httpx.Response(404)

    report = run_gate(
        base_url="http://localhost:8000",
        mode="not-ready",
        samples=2,
        interval_seconds=0,
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    assert report.passed is True
    assert all(item.code == "FAIL_CLOSED" for item in report.observations)
    assert all(item.metrics_status is None for item in report.observations)


def test_gate_stops_on_first_failure_without_recording_response_content() -> None:
    sentinel = "SECRET-RESPONSE-MUST-NOT-LEAK"  # noqa: S105 - leak-detection sentinel

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(500, text=sentinel)
        return httpx.Response(500, text=sentinel)

    report = run_gate(
        base_url="http://127.0.0.1:8000",
        mode="healthy",
        samples=10,
        interval_seconds=0,
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    encoded = json.dumps(report, default=lambda value: value.__dict__)
    assert report.passed is False
    assert report.completed_samples == 1
    assert sentinel not in encoded


def test_report_schema_contains_no_url_or_body_fields() -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(503, json={"ready": False}))
    report = run_gate(
        base_url="http://127.0.0.1:8000",
        mode="healthy",
        samples=1,
        interval_seconds=0,
        timeout_seconds=1,
        transport=transport,
    )
    keys = set(report.observations[0].__dict__)
    assert keys == {
        "timestamp_utc",
        "health_status",
        "ready_status",
        "metrics_status",
        "passed",
        "code",
    }
    assert "url" not in keys and "body" not in keys
