"""WP4 / G-SHUT-1 — fail-closed admission and bounded process drain."""

from __future__ import annotations

import asyncio
import io
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import ValidationError

import aegis.main as main_module
from aegis.models import ScanCreate, ScanStatus
from aegis.planner import build_planner
from aegis.process_lifecycle import ProcessLifecycle, ProcessState, ServiceDraining
from aegis.safety import SafetyController
from aegis.service import ScanService
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis_obs.logging import StructuredLogger
from aegis_obs.metrics import MetricsRegistry

ROOT = Path(__file__).resolve().parents[1]
SECRET_SENTINEL = "SENTINEL-SHUTDOWN-MUST-NOT-LEAK"  # noqa: S105 - test sentinel


async def test_serving_admission_runs_and_short_work_drains() -> None:
    lifecycle = ProcessLifecycle(grace_seconds=0.2)
    lifecycle.mark_serving()
    completed = asyncio.Event()

    async def short_work() -> None:
        await asyncio.sleep(0)
        completed.set()

    lifecycle.submit(work_id="short", work_factory=short_work)
    result = await lifecycle.drain()

    assert completed.is_set()
    assert result.timed_out is False
    assert lifecycle.state is ProcessState.STOPPED


async def test_drain_immediately_closes_admission_and_is_idempotent() -> None:
    lifecycle = ProcessLifecycle(grace_seconds=0.2)
    lifecycle.mark_serving()
    release = asyncio.Event()

    async def in_flight() -> None:
        await release.wait()

    lifecycle.submit(work_id="existing", work_factory=in_flight)
    first = asyncio.create_task(lifecycle.drain())
    await asyncio.sleep(0)

    assert lifecycle.state is ProcessState.DRAINING
    with pytest.raises(ServiceDraining, match="SERVICE_DRAINING"):
        lifecycle.submit(work_id="new", work_factory=in_flight)

    release.set()
    first_result = await first
    second_result = await lifecycle.drain()
    assert first_result == second_result
    assert lifecycle.state is ProcessState.STOPPED


async def test_long_work_times_out_is_cancelled_and_callback_is_bounded() -> None:
    lifecycle = ProcessLifecycle(grace_seconds=0.01, cancellation_seconds=0.05)
    callback_ids: list[str] = []
    cancelled = asyncio.Event()
    lifecycle.mark_serving()

    async def long_work() -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    lifecycle.submit(
        work_id="long", work_factory=long_work, on_timeout=callback_ids.append
    )
    result = await lifecycle.drain()

    assert result.timed_out is True
    assert result.cancelled == 1
    assert callback_ids == ["long"]
    assert cancelled.is_set()


async def test_scan_timeout_persists_incomplete_and_survives_restart_reconciliation(
    tmp_path: Path,
) -> None:
    settings = Settings(database_path=str(tmp_path / "aegis.db"))
    store = ScanStore(settings.database_path)
    store.initialize()
    service = ScanService(
        settings,
        store,
        build_planner(settings),
        SafetyController(settings),
    )
    lifecycle = ProcessLifecycle(grace_seconds=0.01, cancellation_seconds=0.05)
    lifecycle.mark_serving()

    async def long_loop(*_args: Any, **_kwargs: Any) -> None:
        await asyncio.Event().wait()

    service._loop = long_loop  # type: ignore[method-assign]
    scan = lifecycle.create_and_submit(
        create=lambda: service.create(ScanCreate()),
        work_id=lambda created: created.id,
        work_factory=lambda created: service.run(created.id),
        on_timeout=lambda created: service.mark_shutdown_timeout(created.id),
    )
    await lifecycle.drain()

    persisted = store.get(scan.id)
    assert persisted is not None
    assert persisted.status is ScanStatus.INCOMPLETE
    assert persisted.status is not ScanStatus.PASS
    assert persisted.stop_reason == "SHUTDOWN_DRAIN_TIMEOUT"

    # Startup reconciliation touches only QUEUED/RUNNING. The explicit timeout terminal remains.
    ScanStore(settings.database_path).initialize()
    reconciled = store.get(scan.id)
    assert reconciled is not None
    assert reconciled.status is ScanStatus.INCOMPLETE
    assert reconciled.stop_reason == "SHUTDOWN_DRAIN_TIMEOUT"


async def test_create_and_register_are_atomic_against_drain() -> None:
    lifecycle = ProcessLifecycle(grace_seconds=0.2)
    lifecycle.mark_serving()
    ran = asyncio.Event()

    async def work(_created: str) -> None:
        ran.set()

    created = lifecycle.create_and_submit(
        create=lambda: "durable-id",
        work_id=lambda value: value,
        work_factory=work,
    )
    # Once durable creation returns, the task is already registered; drain sees it or its completed
    # callback. There is no yielded interval containing durable-but-untracked work.
    assert created == "durable-id"
    assert lifecycle.in_flight == 1
    await lifecycle.drain()
    assert ran.is_set()


class _ExplodingObserver:
    def log(self, **_fields: object) -> None:
        raise RuntimeError("observer detail must not affect drain")

    def record_lifecycle_event(self, _event: str) -> None:
        raise RuntimeError("observer detail must not affect drain")

    def set_process_state(self, _state: str) -> None:
        raise RuntimeError("observer detail must not affect drain")


async def test_observer_failure_cannot_break_drain() -> None:
    observer = _ExplodingObserver()
    lifecycle = ProcessLifecycle(
        grace_seconds=0.1,
        logger=observer,
        metrics=observer,
    )
    lifecycle.mark_serving()
    result = await lifecycle.drain()
    assert result.timed_out is False
    assert lifecycle.state is ProcessState.STOPPED


async def test_draining_ready_is_503_health_stays_live_and_mutation_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "ready.db"))
    store.initialize()
    lifecycle = ProcessLifecycle(grace_seconds=0.2)
    lifecycle.mark_serving()
    release = asyncio.Event()

    async def in_flight() -> None:
        await release.wait()

    lifecycle.submit(work_id="hold", work_factory=in_flight)
    drain_task = asyncio.create_task(lifecycle.drain())
    await asyncio.sleep(0)
    monkeypatch.setattr(main_module, "store", store)
    monkeypatch.setattr(main_module, "settings", Settings(database_path=store.database_path))
    monkeypatch.setattr(main_module, "process_lifecycle", lifecycle)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        ready = await client.get("/ready")
        health = await client.get("/health")
        rejected = await client.post("/api/scans", json={})

    assert ready.status_code == 503
    lifecycle_check = next(
        check for check in ready.json()["checks"] if check["name"] == "process_lifecycle"
    )
    assert lifecycle_check["status"] == "FAIL"
    assert lifecycle_check["detail"] == "process is draining and not accepting work"
    assert health.status_code == 200 and health.json()["status"] == "ok"
    assert rejected.status_code == 503
    assert rejected.json() == {"detail": "SERVICE_DRAINING"}

    release.set()
    await drain_task


@pytest.mark.parametrize(
    "value",
    [-1, 0, True, False, "true", "false", "nope", ""],
)
def test_invalid_shutdown_grace_fails_closed(value: object) -> None:
    with pytest.raises(ValidationError):
        Settings(shutdown_grace_seconds=value)  # type: ignore[arg-type]


def test_numeric_shutdown_grace_is_bounded_and_env_compatible() -> None:
    assert Settings(shutdown_grace_seconds="10").shutdown_grace_seconds == 10.0  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Settings(shutdown_grace_seconds=121)


async def test_lifecycle_observability_is_fixed_label_and_secret_free() -> None:
    output = io.StringIO()
    metrics = MetricsRegistry(service="control-plane")
    lifecycle = ProcessLifecycle(
        grace_seconds=0.01,
        cancellation_seconds=0.05,
        logger=StructuredLogger(stream=output),
        metrics=metrics,
    )
    lifecycle.mark_serving()

    async def long_work() -> None:
        await asyncio.Event().wait()

    lifecycle.submit(work_id=SECRET_SENTINEL, work_factory=long_work)
    await lifecycle.drain()
    rendered = metrics.render()
    observed = output.getvalue()
    assert "drain_started" in observed and "drain_timeout" in observed
    assert 'event="drain_started"' in rendered and 'event="drain_timeout"' in rendered
    assert SECRET_SENTINEL not in observed
    assert SECRET_SENTINEL not in rendered


def test_compose_shutdown_bounds_align_and_hardening_remains() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    control = compose["services"]["control-plane"]
    assert control["environment"]["SHUTDOWN_GRACE_SECONDS"] == "10"
    assert control["stop_grace_period"] == "15s"
    assert "--timeout-graceful-shutdown 12" in control["command"]
    assert "--no-access-log" in control["command"]
    assert control["read_only"] is True
    assert control["mem_limit"] == "512m"
    assert float(control["cpus"]) == 1.0
    assert control["pids_limit"] == 256
    assert control["restart"] == "unless-stopped"


def test_dockerfile_keeps_non_root_and_graceful_uvicorn_default() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001:10001" in dockerfile
    assert '"--no-access-log"' in dockerfile
    assert '"--timeout-graceful-shutdown", "12"' in dockerfile
