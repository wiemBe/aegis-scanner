"""Shared observability middleware wiring (WP3 / G-OBS-1).

Two entry points share one bounded, secret-free observation core (metrics + at most one structured
log line, never a body/query/header/URL/exception message):

- :func:`observe_request` — for an app that already uses a Starlette ``BaseHTTPMiddleware`` (the
  control plane, whose existing ``security_headers`` middleware wraps this).
- :class:`ObservabilityASGIMiddleware` — a **pure ASGI** middleware for the lab API. It never
  buffers or consumes the response body, so a streaming response and a mid-stream exception (the
  synthetic "connection drop" the negative-control targets rely on) pass through byte-for-byte
  unchanged. A ``BaseHTTPMiddleware`` would buffer that stream and mask the drop.

Both re-raise any downstream exception unchanged, so HTTP status, security headers, authorization,
budgets, cleanup, and controller verdicts are unaffected. All logging/metrics work is wrapped so a
failure there can never propagate to the request path.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, MutableMapping
from time import monotonic
from typing import Any, Final
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import Response

from aegis_obs.logging import StructuredLogger, bounded_exception_label
from aegis_obs.metrics import MetricsRegistry
from aegis_obs.normalize import ROUTE_UNMATCHED, bound_route, is_valid_request_id

# Routes excluded from per-request access logs to avoid scrape noise. Their metrics are still
# recorded, and ``/ready`` is still logged (at WARNING) when it fails closed — see _should_log.
_LOG_EXCLUDED_PATHS: Final = frozenset({"/health", "/metrics"})
_READINESS_PATH: Final = "/ready"
_UNHANDLED_EXCEPTION_CODE: Final = "UNHANDLED_EXCEPTION"

CallNext = Callable[[Request], Awaitable[Response]]
Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def _safe_resolve[ObserverT](getter: Callable[[], ObserverT]) -> ObserverT | None:
    try:
        return getter()
    except Exception:  # noqa: BLE001 - observer discovery must never break the application
        return None


def _safe_inc_in_flight(registry: MetricsRegistry | None) -> None:
    if registry is None:
        return
    try:
        registry.inc_in_flight()
    except Exception:  # noqa: BLE001, S110 - metrics must never break a request
        pass


def _safe_dec_in_flight(registry: MetricsRegistry | None) -> None:
    if registry is None:
        return
    try:
        registry.dec_in_flight()
    except Exception:  # noqa: BLE001, S110 - metrics must never mask a response or exception
        pass


def resolve_request_id(raw: str | None) -> str:
    """Return the client request id if valid/bounded, else a fresh generated one (fail safe)."""

    if raw is not None and is_valid_request_id(raw):
        return raw
    return f"req-{uuid4().hex[:16]}"


def route_template(request: Request) -> str:
    """Return the matched route template (e.g. ``/api/scans/{scan_id}``) or ``UNMATCHED``."""

    return _route_from_scope(request.scope)


def _route_from_scope(scope: MutableMapping[str, Any]) -> str:
    route = scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str) or not template:
        return ROUTE_UNMATCHED
    return bound_route(template)


def _header_value(scope: MutableMapping[str, Any], name: bytes) -> str | None:
    for key, value in scope.get("headers", ()):  # raw ASGI header pairs (bytes, bytes)
        if bytes(key).lower() == name:
            try:
                return bytes(value).decode("latin-1")
            except Exception:  # noqa: BLE001 - a malformed header is treated as absent
                return None
    return None


def disable_uvicorn_access_log() -> None:
    """Silence Uvicorn's default access logger (defence in depth alongside ``--no-access-log``)."""

    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    access.disabled = True


def _should_log(path: str, status_code: int, errored: bool) -> tuple[bool, str, str]:
    """Return (emit, level, event) applying the bounded scrape-noise policy.

    An unhandled exception always logs as ``http_error``/ERROR. Otherwise ``/health`` and
    ``/metrics`` scrapes are silent; ``/ready`` is silent when ready and logs at WARNING (not ERROR)
    when it fails closed — a fail-closed readiness 503 is expected state, not a server fault.
    """

    if errored:
        return True, "ERROR", "http_error"
    if path in _LOG_EXCLUDED_PATHS:
        return False, "INFO", "http_request"
    if path == _READINESS_PATH:
        if status_code >= 400:
            return True, "WARNING", "http_request"
        return False, "INFO", "http_request"
    if status_code >= 500:
        return True, "ERROR", "http_error"
    if status_code >= 400:
        return True, "WARNING", "http_request"
    return True, "INFO", "http_request"


def _emit_observation(
    *,
    service: str,
    registry: MetricsRegistry | None,
    logger: StructuredLogger | None,
    request_id: str,
    method: str,
    route: str,
    path: str,
    status_code: int,
    duration: float,
    errored: bool,
    exception_class: str | None,
) -> None:
    """Record metrics + log with all failures swallowed (never affect the request path)."""

    if registry is not None:
        try:
            registry.observe_request(
                method=method, route=route, status_code=status_code, duration_seconds=duration
            )
        except Exception:  # noqa: BLE001, S110 - metrics must never break a request
            pass
    if logger is not None:
        try:
            emit, level, event = _should_log(path, status_code, errored)
            if emit:
                logger.log(
                    service=service,
                    event=event,
                    level=level,
                    request_id=request_id,
                    method=method,
                    route=route,
                    status_code=status_code,
                    duration_seconds=duration,
                    code=_UNHANDLED_EXCEPTION_CODE if errored else None,
                    exception_class=exception_class,
                )
        except Exception:  # noqa: BLE001, S110 - logging must never break a request
            pass


async def observe_request(
    request: Request,
    call_next: CallNext,
    *,
    service: str,
    registry: MetricsRegistry,
    logger: StructuredLogger,
) -> Response:
    """Observe one request (BaseHTTPMiddleware form); return the response, re-raise errors."""

    request_id = resolve_request_id(request.headers.get("x-request-id"))
    request.state.request_id = request_id
    _safe_inc_in_flight(registry)
    start = monotonic()
    try:
        response = await call_next(request)
    except BaseException as exc:  # noqa: BLE001 - observe, then re-raise unchanged
        _safe_dec_in_flight(registry)
        _emit_observation(
            service=service,
            registry=registry,
            logger=logger,
            request_id=request_id,
            method=request.method,
            route=_route_from_scope(request.scope),
            path=request.url.path,
            status_code=500,
            duration=monotonic() - start,
            errored=True,
            exception_class=bounded_exception_label(exc),
        )
        raise
    _safe_dec_in_flight(registry)
    _emit_observation(
        service=service,
        registry=registry,
        logger=logger,
        request_id=request_id,
        method=request.method,
        route=_route_from_scope(request.scope),
        path=request.url.path,
        status_code=response.status_code,
        duration=monotonic() - start,
        errored=False,
        exception_class=None,
    )
    return response


class ObservabilityASGIMiddleware:
    """Pure ASGI observability middleware (no body buffering; streaming/exceptions pass through).

    The registry/logger are resolved through getters at request time so a test can monkeypatch the
    hosting module's singletons.
    """

    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        service: str,
        get_registry: Callable[[], MetricsRegistry],
        get_logger: Callable[[], StructuredLogger],
        set_request_id_header: bool = True,
    ) -> None:
        self.app = app
        self.service = service
        self._get_registry = get_registry
        self._get_logger = get_logger
        self._set_request_id_header = set_request_id_header

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        registry = _safe_resolve(self._get_registry)
        logger = _safe_resolve(self._get_logger)
        request_id = resolve_request_id(_header_value(scope, b"x-request-id"))
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["request_id"] = request_id

        status_holder = {"status": 500, "started": False}

        async def send_wrapper(message: MutableMapping[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                status_holder["status"] = int(message.get("status", 500))
                status_holder["started"] = True
                if self._set_request_id_header:
                    headers = list(message.get("headers") or [])
                    headers.append((b"x-request-id", request_id.encode("latin-1")))
                    message = {**message, "headers": headers}
            await send(message)

        _safe_inc_in_flight(registry)
        start = monotonic()
        try:
            await self.app(scope, receive, send_wrapper)
        except BaseException as exc:  # noqa: BLE001 - observe, then re-raise so the drop is preserved
            _safe_dec_in_flight(registry)
            _emit_observation(
                service=self.service,
                registry=registry,
                logger=logger,
                request_id=request_id,
                method=str(scope.get("method", "")),
                route=_route_from_scope(scope),
                path=str(scope.get("path", "")),
                status_code=status_holder["status"] if status_holder["started"] else 500,
                duration=monotonic() - start,
                errored=True,
                exception_class=bounded_exception_label(exc),
            )
            raise
        _safe_dec_in_flight(registry)
        _emit_observation(
            service=self.service,
            registry=registry,
            logger=logger,
            request_id=request_id,
            method=str(scope.get("method", "")),
            route=_route_from_scope(scope),
            path=str(scope.get("path", "")),
            status_code=status_holder["status"],
            duration=monotonic() - start,
            errored=False,
            exception_class=None,
        )
