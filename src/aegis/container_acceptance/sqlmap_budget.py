"""Hard, controller-owned request/duration budget enforcement for containerized SQLMap runs.

The pinned SQLMap has no flag to cap its total HTTP request count, so the ceiling is enforced from
outside: the SQLMap process runs in a *named, detached* container and a controller watchdog counts
the requests SQLMap itself logs (``HTTP request [#…]`` in its ``-t`` traffic file, tied to this
run's volume) and the wall-clock elapsed. When either controller-owned ceiling is reached, the
watchdog deterministically terminates the child process with ``docker kill`` and records a typed
``BUDGET_STOP`` (``REQUEST_CEILING`` / ``DURATION_CEILING``). Threads are pinned to 1, so the count
advances one request at a time and the stop is prompt.

The ceilings come from the controller-owned :class:`SqlmapProfile`; the model-facing ``SqlmapPlan``
(strict ``extra="forbid"``) cannot carry or widen them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from aegis.container_acceptance.contracts import (
    BudgetStopReason,
    ContainerAcceptanceError,
    SqlmapBudgetOutcome,
)
from aegis.container_acceptance.docker_cli import docker
from aegis.container_acceptance.images import require_pinned
from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.runner import _HARDENING

_COUNT_SNIPPET = (
    "import sys\n"
    "try:\n"
    "  sys.stdout.write(str(open('/out/traffic.txt',encoding='utf-8',errors='replace')"
    ".read().count('HTTP request [')))\n"
    "except Exception:\n"
    "  sys.stdout.write('0')\n"
)


@dataclass(frozen=True)
class BudgetRun:
    stdout: str
    exit_code: int
    traffic_text: str
    outcome: SqlmapBudgetOutcome


def _exec_request_count(container: str) -> int:
    result = docker("exec", container, "python", "-c", _COUNT_SNIPPET, timeout=15)
    text = result.stdout.strip()
    return int(text) if result.returncode == 0 and text.isdigit() else 0


def _running(container: str) -> bool:
    result = docker("inspect", container, "--format", "{{.State.Running}}", timeout=15)
    return result.stdout.strip() == "true"


def run_sqlmap_with_budget(
    range_: InternalRange,
    *,
    image_ref: str,
    argv: tuple[str, ...],
    exec_id: str,
    max_http_requests: int,
    max_duration_seconds: int,
    poll_interval: float = 0.25,
) -> BudgetRun:
    """Run a SQLMap container under hard request/duration ceilings, killing it deterministically."""

    image = require_pinned(image_ref)
    volume = range_.create_output_volume(exec_id)
    container = f"aegis-p28-sqlmap-{exec_id}"
    started = docker(
        "run", "-d", "--name", container, "--network", range_.network, "--label", range_.label,
        *_HARDENING, "-v", f"{volume}:/out", image, *list(argv[1:]),
        timeout=60,
    )
    if started.returncode != 0:
        raise ContainerAcceptanceError(
            f"SQLMAP_DETACHED_START_FAILED:{started.stderr.strip()[:120]}"
        )

    start_time = time.monotonic()
    stop_reason = BudgetStopReason.COMPLETED
    terminated = False
    observed = 0
    max_iters = int(max_duration_seconds / poll_interval) + 40
    for _ in range(max_iters):
        alive = _running(container)
        observed = _exec_request_count(container) if alive else observed
        elapsed = time.monotonic() - start_time
        if observed >= max_http_requests:
            docker("kill", container, timeout=15)
            stop_reason, terminated = BudgetStopReason.REQUEST_CEILING, True
            break
        if elapsed >= max_duration_seconds:
            docker("kill", container, timeout=15)
            stop_reason, terminated = BudgetStopReason.DURATION_CEILING, True
            break
        if not alive:
            stop_reason = BudgetStopReason.COMPLETED
            break
        time.sleep(poll_interval)
    else:
        docker("kill", container, timeout=15)
        stop_reason, terminated = BudgetStopReason.DURATION_CEILING, True

    elapsed = time.monotonic() - start_time
    logs = docker("logs", container, timeout=20)
    inspect = docker("inspect", container, "--format", "{{.State.ExitCode}}", timeout=15)
    exit_code = int(inspect.stdout.strip()) if inspect.stdout.strip().lstrip("-").isdigit() else -1
    traffic_text = range_.read_volume_file(volume, "/out/traffic.txt")
    # Authoritative final count from the persisted traffic file (survives the killed container).
    final_count = traffic_text.count("HTTP request [")
    observed = max(observed, final_count)
    removed = docker("rm", "-f", container, timeout=20).returncode == 0

    outcome = SqlmapBudgetOutcome(
        max_http_requests=max_http_requests,
        max_duration_seconds=max_duration_seconds,
        observed_requests=observed,
        elapsed_seconds=round(elapsed, 3),
        stop_reason=stop_reason,
        container_terminated=terminated,
        container_removed=removed,
    )
    return BudgetRun(
        stdout=logs.stdout,
        exit_code=exit_code,
        traffic_text=traffic_text,
        outcome=outcome,
    )
