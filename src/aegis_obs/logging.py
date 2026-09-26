"""Secure structured JSON logging (WP3 / G-OBS-1).

A tiny, dependency-light JSON logger that writes one bounded record per line to stdout. The record
schema is versioned and **closed**: only the fixed fields below are ever emitted, and every one is
normalized/bounded first. The logger never emits a request/response body, query string, cookie,
authorization header, credential, target URL, raw evidence, model output, ``str(exception)``, a
stack-local path, or any other attacker-controlled string.

Two hard safety properties:

- **The logger never raises.** If serialization fails, it emits a single fixed fallback record and
  returns; a logging failure can never weaken authorization, budgets, cleanup, readiness, controller
  verdicts, or HTTP security behavior.
- **The schema is enforced.** :func:`build_record` only copies allowlisted, normalized fields, so a
  caller cannot smuggle an unexpected key into the output.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime
from typing import IO, Any, Final

from aegis_obs.normalize import (
    KNOWN_SERVICES,
    bound_field,
    bound_route,
    normalize_method,
    status_class,
)

LOG_SCHEMA_VERSION: Final = "obslog-v1"

_ALLOWED_RECORD_KEYS: Final = frozenset(
    {
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
)
_REQUIRED_RECORD_KEYS: Final = frozenset(
    {"schema_version", "timestamp_utc", "level", "service", "event", "request_id"}
)

# The closed set of levels and events. Anything else is coerced to a safe default.
_LEVELS: Final = frozenset({"INFO", "WARNING", "ERROR"})
_EVENTS: Final = frozenset(
    {
        "http_request",
        "http_error",
        "startup",
        "drain_started",
        "drain_completed",
        "drain_timeout",
        "log_serialization_failed",
    }
)

# Bounded allowlist of exception classes. Anything else is reported as the generic ``Exception`` —
# the class *name* only, never ``str(exc)`` and never the message.
_EXCEPTION_ALLOWLIST: Final = frozenset(
    {
        "HTTPException",
        "RequestValidationError",
        "ValidationError",
        "ValueError",
        "KeyError",
        "TypeError",
        "RuntimeError",
        "TimeoutError",
        "OSError",
        "ConnectionError",
    }
)

# Duration is clamped so a pathological clock can never produce an unbounded field.
_MAX_DURATION_MS: Final = 3_600_000  # 1 hour


def bounded_exception_label(exc: BaseException) -> str:
    """Return a safe, bounded label for an exception: an allowlisted class name or ``Exception``."""

    name = type(exc).__name__
    return name if name in _EXCEPTION_ALLOWLIST else "Exception"


def _bounded_ms(duration_seconds: float) -> int:
    if not isinstance(duration_seconds, int | float) or duration_seconds != duration_seconds:
        return 0
    ms = int(duration_seconds * 1000)
    if ms < 0:
        return 0
    return min(ms, _MAX_DURATION_MS)


def _bounded_status_code(value: object) -> int:
    """Keep only real HTTP status codes; collapse every other value to the fixed sentinel 0."""

    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
        return value
    return 0


def _timestamp_utc() -> str:
    """Return a timestamp without ever exposing caller-controlled data on failure."""

    try:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:  # noqa: BLE001 - a logging fallback must remain no-raise
        return "1970-01-01T00:00:00.000000Z"


def _fallback_record() -> dict[str, Any]:
    """Return a complete, constant, closed-schema serialization-failure record."""

    return {
        "schema_version": LOG_SCHEMA_VERSION,
        "timestamp_utc": _timestamp_utc(),
        "level": "ERROR",
        "service": "unknown",
        "event": "log_serialization_failed",
        "request_id": "-",
    }


def _exact_string(value: object) -> str | None:
    """Accept plain strings only; never call ``str``/``repr`` on arbitrary objects."""

    return value if type(value) is str else None


def build_record(
    *,
    service: str,
    event: str,
    level: str,
    request_id: str,
    method: str | None = None,
    route: str | None = None,
    status_code: int | None = None,
    duration_seconds: float | None = None,
    code: str | None = None,
    exception_class: str | None = None,
) -> dict[str, Any]:
    """Assemble a bounded, schema-versioned record from allowlisted, normalized fields only.

    ``exception_class`` is expected to already be an allowlisted class name (see
    :func:`bounded_exception_label`); it is bounded again here as defence in depth.
    """

    record: dict[str, Any] = {
        "schema_version": LOG_SCHEMA_VERSION,
        "timestamp_utc": _timestamp_utc(),
        "level": level if level in _LEVELS else "INFO",
        "service": service if service in KNOWN_SERVICES else "unknown",
        "event": event if event in _EVENTS else "http_request",
        "request_id": bound_field(request_id),
    }
    if method is not None:
        record["method"] = normalize_method(method)
    if route is not None:
        record["route"] = bound_route(route)
    if status_code is not None:
        safe_status = _bounded_status_code(status_code)
        record["status_code"] = safe_status
        record["status_class"] = status_class(safe_status)
    if duration_seconds is not None:
        record["duration_ms"] = _bounded_ms(duration_seconds)
    if code is not None:
        record["code"] = bound_field(code)
    if exception_class is not None:
        label = bound_field(exception_class)
        record["exception_class"] = label if label in _EXCEPTION_ALLOWLIST else "Exception"
    return record


class StructuredLogger:
    """Writes bounded JSON records, one per line, to a stream (stdout by default). Never raises."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._lock = threading.Lock()

    @staticmethod
    def _sanitize_record(record: object) -> dict[str, Any]:
        """Rebuild an emitted record through the closed schema without stringifying objects."""

        if not isinstance(record, dict):
            return _fallback_record()
        keys = set(record)
        if not _REQUIRED_RECORD_KEYS.issubset(keys) or not keys.issubset(_ALLOWED_RECORD_KEYS):
            return _fallback_record()
        try:
            duration_ms: object = record.get("duration_ms")
            duration_seconds: float | None = None
            if isinstance(duration_ms, int | float) and not isinstance(duration_ms, bool):
                duration_seconds = float(duration_ms) / 1000
            status: object = record.get("status_code")
            safe_status = (
                status if isinstance(status, int) and not isinstance(status, bool) else None
            )
            return build_record(
                service=_exact_string(record.get("service")) or "unknown",
                event=_exact_string(record.get("event")) or "log_serialization_failed",
                level=_exact_string(record.get("level")) or "ERROR",
                request_id=_exact_string(record.get("request_id")) or "-",
                method=_exact_string(record.get("method")),
                route=_exact_string(record.get("route")),
                status_code=safe_status,
                duration_seconds=duration_seconds,
                code=_exact_string(record.get("code")),
                exception_class=_exact_string(record.get("exception_class")),
            )
        except Exception:  # noqa: BLE001 - logging must stay no-raise
            return _fallback_record()

    def emit(self, record: object) -> None:
        try:
            safe_record = self._sanitize_record(record)
            line = json.dumps(safe_record, separators=(",", ":"), ensure_ascii=True)
        except Exception:  # noqa: BLE001 - hostile mappings/serializers must remain no-raise
            try:
                line = json.dumps(_fallback_record(), separators=(",", ":"), ensure_ascii=True)
            except Exception:  # noqa: BLE001 - no output is safer than propagating a log failure
                return
        try:
            with self._lock:
                self._stream.write(line + "\n")
                self._stream.flush()
        except Exception:  # noqa: BLE001, S110 - logging must never propagate a failure to callers
            pass

    def log(self, **fields: Any) -> None:
        """Build and emit a record. Any build error is swallowed to guarantee no-raise."""

        try:
            record = build_record(**fields)
        except Exception:  # noqa: BLE001 - never let a logging call break the caller
            record = _fallback_record()
        self.emit(record)
