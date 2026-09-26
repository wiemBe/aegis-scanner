"""Thread-safe, dependency-light, bounded metrics registry (WP3 / G-OBS-1).

A minimal Prometheus/OpenMetrics text exporter with hard cardinality bounds. It measures HTTP
traffic, in-flight requests, readiness, and controller-owned scan completions — nothing that could
leak a secret or explode series count. Labels may only be fixed service names, allowlisted methods,
bounded status classes, controller-owned enumerations, and a **capped** set of normalized route
templates. A request id, scan id, target, URL, exception text, or any user input can never become a
label; unknown methods/routes/statuses collapse to fixed ``OTHER``/``UNMATCHED`` labels.

Collecting metrics never mutates controller truth and is never an authorization decision. Rendering
never raises; a serialization failure makes :meth:`MetricsRegistry.render` return a fixed failure
body, and the ``/metrics`` handler maps that to a fixed 503 without exposing internal state.
"""

from __future__ import annotations

import threading
import time
from typing import Final

from aegis_obs.normalize import (
    KNOWN_SERVICES,
    ROUTE_OTHER,
    ROUTE_UNMATCHED,
    bound_route,
    normalize_method,
    status_class,
)

# Fixed latency buckets (seconds). Upper bound is generous; +Inf is implicit.
DURATION_BUCKETS: Final[tuple[float, ...]] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

# The fixed readiness checks mirrored from aegis.readiness.REQUIRED_SCHEMA / the readiness report.
READINESS_CHECKS: Final[tuple[str, ...]] = ("persistence", "credential_isolation")

# Controller-owned terminal scan statuses (bounded enumeration). Anything else collapses to OTHER.
SCAN_TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {"PASS", "FAIL", "INCOMPLETE", "REVIEW", "ERROR"}
)

# Explicit maximum distinct route-template label values tracked. Matched templates come from the
# finite route table; this cap is the hard ceiling that guarantees bounded series even under abuse.
MAX_ROUTE_LABELS: Final = 64

_METRIC_UNAVAILABLE_BODY: Final = "# metrics_unavailable\n"


def _fmt(value: float) -> str:
    return repr(int(value)) if float(value).is_integer() else repr(value)


def _labels(pairs: tuple[tuple[str, str], ...]) -> str:
    if not pairs:
        return ""
    inner = ",".join(f'{name}="{val}"' for name, val in pairs)
    return "{" + inner + "}"


class MetricsRegistry:
    """In-process, thread-safe metric store with bounded cardinality."""

    def __init__(self, *, service: str, max_route_labels: int = MAX_ROUTE_LABELS) -> None:
        self._service = service if service in KNOWN_SERVICES else "unknown"
        self._max_routes = max_route_labels
        self._lock = threading.Lock()
        # Set once per process. A restart loop shows as this timestamp advancing repeatedly, which
        # the restart-loop alert detects with changes(). Only the fixed service label; low card.
        self._start_time = time.time()
        self._known_routes: set[str] = set()
        self._requests: dict[tuple[str, str], int] = {}  # (method, route)
        self._responses: dict[tuple[str, str, str], int] = {}  # (method, route, status_class)
        self._hist_buckets: dict[tuple[str, str], list[int]] = {}  # (method, route) -> counts
        self._hist_sum: dict[tuple[str, str], float] = {}
        self._hist_count: dict[tuple[str, str], int] = {}
        self._in_flight = 0
        self._ready = 0
        self._ready_checks: dict[str, int] = {name: 0 for name in READINESS_CHECKS}
        self._scan_completions: dict[str, int] = {}

    # --- cardinality control -------------------------------------------------------------------

    def _bound_route_label(self, route: str) -> str:
        route = bound_route(route)
        if route in (ROUTE_UNMATCHED, ROUTE_OTHER) or route in self._known_routes:
            return route
        if len(self._known_routes) < self._max_routes:
            self._known_routes.add(route)
            return route
        return ROUTE_OTHER

    # --- recording -----------------------------------------------------------------------------

    def inc_in_flight(self) -> None:
        with self._lock:
            self._in_flight += 1

    def dec_in_flight(self) -> None:
        with self._lock:
            if self._in_flight > 0:
                self._in_flight -= 1

    def observe_request(
        self, *, method: str, route: str, status_code: int, duration_seconds: float
    ) -> None:
        m = normalize_method(method)
        sc = status_class(status_code)
        duration = duration_seconds if duration_seconds and duration_seconds > 0 else 0.0
        with self._lock:
            r = self._bound_route_label(route)
            self._requests[(m, r)] = self._requests.get((m, r), 0) + 1
            self._responses[(m, r, sc)] = self._responses.get((m, r, sc), 0) + 1
            buckets = self._hist_buckets.setdefault((m, r), [0] * len(DURATION_BUCKETS))
            for i, upper in enumerate(DURATION_BUCKETS):
                if duration <= upper:
                    buckets[i] += 1
            self._hist_sum[(m, r)] = self._hist_sum.get((m, r), 0.0) + duration
            self._hist_count[(m, r)] = self._hist_count.get((m, r), 0) + 1

    def set_readiness(self, *, ready: bool, checks: dict[str, bool]) -> None:
        with self._lock:
            self._ready = 1 if ready else 0
            for name in READINESS_CHECKS:
                if name in checks:
                    self._ready_checks[name] = 1 if checks[name] else 0

    def record_scan_completion(self, status: str) -> None:
        label = status if status in SCAN_TERMINAL_STATUSES else ROUTE_OTHER
        with self._lock:
            self._scan_completions[label] = self._scan_completions.get(label, 0) + 1

    # --- introspection (tests) -----------------------------------------------------------------

    def route_label_count(self) -> int:
        with self._lock:
            return len(self._known_routes)

    def series_count(self) -> int:
        with self._lock:
            return (
                len(self._requests)
                + len(self._responses)
                + len(self._hist_buckets) * (len(DURATION_BUCKETS) + 3)
                + 1  # in_flight
                + 1  # ready
                + len(self._ready_checks)
                + len(self._scan_completions)
            )

    # --- rendering -----------------------------------------------------------------------------

    def render(self) -> str:
        try:
            return self._render_locked()
        except Exception:  # noqa: BLE001 - never expose raw internal state on a render failure
            return _METRIC_UNAVAILABLE_BODY

    def _render_locked(self) -> str:
        svc = self._service
        lines: list[str] = []
        with self._lock:
            requests = dict(self._requests)
            responses = dict(self._responses)
            hist_buckets = {k: list(v) for k, v in self._hist_buckets.items()}
            hist_sum = dict(self._hist_sum)
            hist_count = dict(self._hist_count)
            in_flight = self._in_flight
            ready = self._ready
            ready_checks = dict(self._ready_checks)
            scan_completions = dict(self._scan_completions)

        lines.append("# HELP aegis_http_requests_total Total HTTP requests received.")
        lines.append("# TYPE aegis_http_requests_total counter")
        for (method, route), value in sorted(requests.items()):
            labels = _labels((("service", svc), ("method", method), ("route", route)))
            lines.append(f"aegis_http_requests_total{labels} {_fmt(value)}")

        lines.append("# HELP aegis_http_responses_total HTTP responses by status class.")
        lines.append("# TYPE aegis_http_responses_total counter")
        for (method, route, sc), value in sorted(responses.items()):
            labels = _labels(
                (("service", svc), ("method", method), ("route", route), ("status_class", sc))
            )
            lines.append(f"aegis_http_responses_total{labels} {_fmt(value)}")

        lines.append("# HELP aegis_http_request_duration_seconds HTTP request duration.")
        lines.append("# TYPE aegis_http_request_duration_seconds histogram")
        for (method, route), buckets in sorted(hist_buckets.items()):
            cumulative = 0
            for i, upper in enumerate(DURATION_BUCKETS):
                cumulative += buckets[i]
                labels = _labels(
                    (
                        ("service", svc),
                        ("method", method),
                        ("route", route),
                        ("le", repr(upper)),
                    )
                )
                lines.append(f"aegis_http_request_duration_seconds_bucket{labels} {cumulative}")
            count = hist_count.get((method, route), 0)
            inf_labels = _labels(
                (("service", svc), ("method", method), ("route", route), ("le", "+Inf"))
            )
            lines.append(f"aegis_http_request_duration_seconds_bucket{inf_labels} {count}")
            base = _labels((("service", svc), ("method", method), ("route", route)))
            lines.append(
                f"aegis_http_request_duration_seconds_sum{base} "
                f"{_fmt(hist_sum.get((method, route), 0.0))}"
            )
            lines.append(f"aegis_http_request_duration_seconds_count{base} {count}")

        svc_label = _labels((("service", svc),))
        lines.append("# HELP aegis_process_start_timestamp_seconds Process start (unix seconds).")
        lines.append("# TYPE aegis_process_start_timestamp_seconds gauge")
        lines.append(f"aegis_process_start_timestamp_seconds{svc_label} {_fmt(self._start_time)}")

        lines.append("# HELP aegis_http_in_flight_requests In-flight HTTP requests.")
        lines.append("# TYPE aegis_http_in_flight_requests gauge")
        lines.append(f"aegis_http_in_flight_requests{svc_label} {in_flight}")

        lines.append("# HELP aegis_readiness_ready Readiness verdict (1 ready, 0 not ready).")
        lines.append("# TYPE aegis_readiness_ready gauge")
        lines.append(f"aegis_readiness_ready{svc_label} {ready}")

        lines.append("# HELP aegis_readiness_check Per-check readiness (1 pass, 0 not pass).")
        lines.append("# TYPE aegis_readiness_check gauge")
        for name in READINESS_CHECKS:
            labels = _labels((("service", svc), ("check", name)))
            lines.append(f"aegis_readiness_check{labels} {ready_checks.get(name, 0)}")

        lines.append("# HELP aegis_scan_completions_total Scan completions by terminal status.")
        lines.append("# TYPE aegis_scan_completions_total counter")
        for status, value in sorted(scan_completions.items()):
            labels = _labels((("service", svc), ("status", status)))
            lines.append(f"aegis_scan_completions_total{labels} {_fmt(value)}")

        return "\n".join(lines) + "\n"
