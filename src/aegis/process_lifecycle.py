"""Typed process lifecycle, admission, and bounded background-work draining.

The lifecycle controller is deliberately small and process-local.  It does not decide scan
verdicts; it only owns the safe-to-serve state and the asyncio tasks admitted by this process.
Controller persistence remains authoritative, including restart reconciliation.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, TypeVar


class ProcessState(StrEnum):
    STARTING = "STARTING"
    SERVING = "SERVING"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"


class ServiceDraining(RuntimeError):
    """Typed, fixed admission rejection.  It never contains request data."""

    code = "SERVICE_DRAINING"

    def __init__(self) -> None:
        super().__init__(self.code)


class LifecycleLogger(Protocol):
    def log(self, **fields: object) -> None: ...


class LifecycleMetrics(Protocol):
    def record_lifecycle_event(self, event: str) -> None: ...

    def set_process_state(self, state: str) -> None: ...


TimeoutCallback = Callable[[str], None]
WorkFactory = Callable[[], Coroutine[Any, Any, None]]
T = TypeVar("T")


@dataclass(frozen=True)
class DrainResult:
    timed_out: bool
    admitted: int
    completed: int
    cancelled: int


@dataclass(frozen=True)
class _TrackedWork:
    work_id: str
    task: asyncio.Task[None]
    on_timeout: TimeoutCallback | None


class ProcessLifecycle:
    """Thread-safe state machine and async-safe task registry.

    Synchronous creation/persistence and task registration happen under the same lock, closing the
    admission-vs-drain race.  No await occurs under the lock.  Drain waits for the configured grace,
    cancels remaining tasks, and invokes fixed controller callbacks so timed-out persisted work can
    be left in a reconcile-able non-success state.
    """

    def __init__(
        self,
        *,
        grace_seconds: float,
        cancellation_seconds: float = 1.0,
        logger: LifecycleLogger | None = None,
        metrics: LifecycleMetrics | None = None,
    ) -> None:
        if isinstance(grace_seconds, bool) or grace_seconds <= 0:
            raise ValueError("shutdown grace must be a positive number")
        if isinstance(cancellation_seconds, bool) or cancellation_seconds <= 0:
            raise ValueError("cancellation grace must be a positive number")
        self.grace_seconds = float(grace_seconds)
        self.cancellation_seconds = float(cancellation_seconds)
        self._logger = logger
        self._metrics = metrics
        self._lock = threading.RLock()
        self._state = ProcessState.STARTING
        self._work: dict[asyncio.Task[None], _TrackedWork] = {}
        self._drain_task: asyncio.Task[DrainResult] | None = None
        self._last_result = DrainResult(False, 0, 0, 0)
        self._observe_state(ProcessState.STARTING)

    @property
    def state(self) -> ProcessState:
        with self._lock:
            return self._state

    @property
    def in_flight(self) -> int:
        with self._lock:
            return len(self._work)

    def start(self) -> None:
        """Begin a lifespan startup. Safe for repeated test/application lifespans."""

        with self._lock:
            if self._work:
                raise RuntimeError("cannot restart lifecycle with in-flight work")
            self._drain_task = None
            self._state = ProcessState.STARTING
        self._observe_state(ProcessState.STARTING)

    def mark_serving(self) -> None:
        with self._lock:
            if self._state not in (ProcessState.STARTING, ProcessState.SERVING):
                raise RuntimeError("cannot serve after drain has started")
            self._state = ProcessState.SERVING
        self._observe_state(ProcessState.SERVING)

    def require_serving(self) -> None:
        if self.state is not ProcessState.SERVING:
            raise ServiceDraining()

    def submit(
        self,
        *,
        work_id: str,
        work_factory: WorkFactory,
        on_timeout: TimeoutCallback | None = None,
    ) -> None:
        """Atomically admit and register already-authorized controller work."""

        with self._lock:
            if self._state is not ProcessState.SERVING:
                raise ServiceDraining()
            task: asyncio.Task[None] = asyncio.create_task(
                work_factory(), name=f"aegis-work:{work_id}"
            )
            self._work[task] = _TrackedWork(work_id, task, on_timeout)
            task.add_done_callback(self._work_done)

    def create_and_submit(
        self,
        *,
        create: Callable[[], T],
        work_id: Callable[[T], str],
        work_factory: Callable[[T], Coroutine[Any, Any, None]],
        on_timeout: Callable[[T], None] | None = None,
    ) -> T:
        """Create durable work and register its task in one admission critical section."""

        with self._lock:
            if self._state is not ProcessState.SERVING:
                raise ServiceDraining()
            created = create()
            identifier = work_id(created)
            callback = None if on_timeout is None else lambda _identifier: on_timeout(created)
            task: asyncio.Task[None] = asyncio.create_task(
                work_factory(created), name=f"aegis-work:{identifier}"
            )
            self._work[task] = _TrackedWork(identifier, task, callback)
            task.add_done_callback(self._work_done)
            return created

    def _work_done(self, task: asyncio.Task[None]) -> None:
        with self._lock:
            self._work.pop(task, None)
        # Retrieve failures so a background exception cannot become an unhandled-task warning.
        try:
            task.exception()
        except (asyncio.CancelledError, Exception):  # noqa: S110 - task is already isolated
            pass

    async def drain(self) -> DrainResult:
        """Transition to DRAINING once, wait a bounded interval, then stop."""

        with self._lock:
            if self._state is ProcessState.STOPPED:
                return self._last_result
            if self._drain_task is None:
                self._state = ProcessState.DRAINING
                self._observe_state(ProcessState.DRAINING)
                self._observe_event("drain_started")
                self._drain_task = asyncio.create_task(self._drain_once())
            drain_task = self._drain_task
        return await asyncio.shield(drain_task)

    async def _drain_once(self) -> DrainResult:
        with self._lock:
            admitted = len(self._work)
            initial = tuple(self._work)
        if initial:
            done, pending = await asyncio.wait(initial, timeout=self.grace_seconds)
        else:
            done, pending = set(), set()

        timed_out = bool(pending)
        if timed_out:
            self._observe_event("drain_timeout")
            timed_out_work = {task: self._tracked(task) for task in pending}
            for task in pending:
                task.cancel()
            # Controller cancellation handlers persist conservative status. Bound even a faulty
            # task that swallows cancellation; timeout callbacks run afterwards as a durable guard.
            await asyncio.wait(pending, timeout=self.cancellation_seconds)
            for task in pending:
                tracked = timed_out_work[task]
                if tracked is not None and tracked.on_timeout is not None:
                    try:
                        tracked.on_timeout(tracked.work_id)
                    except Exception:  # noqa: S110 - restart reconciliation is the fallback
                        # Persistence failures remain recoverable via PROCESS_RESTART; never mask
                        # the original shutdown path with a callback or observer exception.
                        pass
        else:
            self._observe_event("drain_completed")

        result = DrainResult(
            timed_out=timed_out,
            admitted=admitted,
            completed=len(done),
            cancelled=len(pending),
        )
        with self._lock:
            self._state = ProcessState.STOPPED
            self._last_result = result
        self._observe_state(ProcessState.STOPPED)
        return result

    def _tracked(self, task: asyncio.Task[None]) -> _TrackedWork | None:
        with self._lock:
            return self._work.get(task)

    def _observe_event(self, event: str) -> None:
        try:
            if self._metrics is not None:
                self._metrics.record_lifecycle_event(event)
        except Exception:  # noqa: S110 - observer failure is availability-neutral
            pass
        try:
            if self._logger is not None:
                self._logger.log(
                    service="control-plane",
                    event=event,
                    level="WARNING" if event == "drain_timeout" else "INFO",
                    request_id="-",
                    code=event.upper(),
                )
        except Exception:  # noqa: S110 - observer failure is availability-neutral
            pass

    def _observe_state(self, state: ProcessState) -> None:
        try:
            if self._metrics is not None:
                self._metrics.set_process_state(state.value)
        except Exception:  # noqa: S110 - observer failure is availability-neutral
            pass
