"""Read-only staging soak and readiness-failure observation gate.

This gate deliberately does not inject faults or mutate deployment state. Operators perform an
approved platform-level fault drill, while this process records only bounded health/readiness/
metrics outcomes through the localhost ingress. No response body or exception text is emitted.
"""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_GATE_FAILED = 4
_MAX_BODY_BYTES = 1_048_576


@dataclass(frozen=True)
class Observation:
    timestamp_utc: str
    health_status: int
    ready_status: int
    metrics_status: int | None
    passed: bool
    code: str


@dataclass(frozen=True)
class GateReport:
    schema_version: str
    mode: str
    started_at_utc: str
    completed_at_utc: str
    requested_samples: int
    completed_samples: int
    passed: bool
    observations: tuple[Observation, ...]


def validate_base_url(raw: str) -> str:
    """Restrict the gate to the loopback ingress; no remote target probing is permitted."""

    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise ValueError("base URL is invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or port is None
    ):
        raise ValueError("base URL must be an explicit loopback HTTP origin with a port")
    return raw.rstrip("/")


def _bounded_json(response: httpx.Response) -> dict[str, object] | None:
    body = response.content
    if len(body) > _MAX_BODY_BYTES:
        return None
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def observe(client: httpx.Client, mode: str) -> Observation:
    now = datetime.now(UTC).isoformat()
    try:
        health = client.get("/health")
        ready = client.get("/ready")
        health_body = _bounded_json(health)
        ready_body = _bounded_json(ready)
        health_ok = (
            health.status_code == 200
            and health_body is not None
            and health_body.get("status") == "ok"
        )
        if mode == "healthy":
            metrics = client.get("/metrics")
            metrics_body = metrics.content[:_MAX_BODY_BYTES]
            metrics_ok = (
                metrics.status_code == 200
                and len(metrics.content) <= _MAX_BODY_BYTES
                and b"aegis_readiness_ready" in metrics_body
            )
            ready_ok = (
                ready.status_code == 200
                and ready_body is not None
                and ready_body.get("ready") is True
            )
            passed = bool(health_ok and ready_ok and metrics_ok)
            code = "HEALTHY" if passed else "HEALTHY_EXPECTATION_FAILED"
            metrics_status: int | None = metrics.status_code
        else:
            ready_ok = (
                ready.status_code == 503
                and ready_body is not None
                and ready_body.get("ready") is False
            )
            passed = bool(health_ok and ready_ok)
            code = "FAIL_CLOSED" if passed else "FAIL_CLOSED_EXPECTATION_FAILED"
            metrics_status = None
        return Observation(now, health.status_code, ready.status_code, metrics_status, passed, code)
    except httpx.HTTPError:
        return Observation(now, 0, 0, None, False, "REQUEST_FAILED")


def run_gate(
    *,
    base_url: str,
    mode: str,
    samples: int,
    interval_seconds: float,
    timeout_seconds: float,
    transport: httpx.BaseTransport | None = None,
) -> GateReport:
    started = datetime.now(UTC).isoformat()
    observations: list[Observation] = []
    with httpx.Client(
        base_url=base_url,
        timeout=timeout_seconds,
        trust_env=False,
        follow_redirects=False,
        transport=transport,
    ) as client:
        for index in range(samples):
            observation = observe(client, mode)
            observations.append(observation)
            if not observation.passed:
                break
            if index + 1 < samples:
                time.sleep(interval_seconds)
    passed = len(observations) == samples and all(item.passed for item in observations)
    return GateReport(
        schema_version="aegis-staging-gate-v1",
        mode=mode,
        started_at_utc=started,
        completed_at_utc=datetime.now(UTC).isoformat(),
        requested_samples=samples,
        completed_samples=len(observations),
        passed=passed,
        observations=tuple(observations),
    )


def _write_report(path: Path, report: GateReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.deploy.staging_gate")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--mode", choices=("healthy", "not-ready"), required=True)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--timeout-seconds", type=float, default=3.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        base_url = validate_base_url(args.base_url)
        if not 1 <= args.samples <= 720:
            raise ValueError("samples must be between 1 and 720")
        if not 0 <= args.interval_seconds <= 300:
            raise ValueError("interval must be between 0 and 300 seconds")
        if not 0.1 <= args.timeout_seconds <= 30:
            raise ValueError("timeout must be between 0.1 and 30 seconds")
    except ValueError as exc:
        print(f"STAGING GATE FAILED (input): {exc}")
        return EXIT_BAD_INPUT
    report = run_gate(
        base_url=base_url,
        mode=args.mode,
        samples=args.samples,
        interval_seconds=args.interval_seconds,
        timeout_seconds=args.timeout_seconds,
    )
    if args.output is not None:
        _write_report(args.output, report)
    print(json.dumps(asdict(report), separators=(",", ":")))
    return EXIT_OK if report.passed else EXIT_GATE_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
