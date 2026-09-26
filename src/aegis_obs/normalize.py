"""Bounded normalization helpers for observability (WP3 / G-OBS-1).

Every value that could become a log field or a metric label passes through one of these pure
functions first. They exist to guarantee **bounded cardinality** and **no attacker-controlled
strings**: an unknown HTTP method, an unmatched route, or an out-of-range status collapses to a
fixed label rather than echoing whatever the client sent.
"""

from __future__ import annotations

import re

# The one place service names are defined. Metric/log ``service`` may only be one of these.
SERVICE_CONTROL_PLANE = "control-plane"
SERVICE_LAB_API = "lab-api"
KNOWN_SERVICES = frozenset({SERVICE_CONTROL_PLANE, SERVICE_LAB_API})

# Allowlisted HTTP methods; anything else collapses to ``OTHER``.
METHOD_ALLOWLIST = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Fixed labels for the route dimension when no known template applies.
ROUTE_UNMATCHED = "UNMATCHED"
ROUTE_OTHER = "OTHER"

# Fixed status classes; anything outside 1xx–5xx collapses to ``OTHER``.
STATUS_CLASSES = frozenset({"1xx", "2xx", "3xx", "4xx", "5xx"})
STATUS_OTHER = "OTHER"

# Field/length bounds. Route templates are code-controlled and short; the cap is defence in depth.
MAX_ROUTE_LEN = 128
MAX_FIELD_LEN = 256

# Reuse the control plane's existing request-id contract exactly (see aegis.main).
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")


def normalize_method(method: str | None) -> str:
    """Return an allowlisted upper-case method, or ``OTHER``."""

    if not isinstance(method, str):
        return ROUTE_OTHER
    upper = method.upper()
    return upper if upper in METHOD_ALLOWLIST else ROUTE_OTHER


def status_class(status_code: int) -> str:
    """Return the bounded status class (``2xx`` …) for a status code, or ``OTHER``."""

    if isinstance(status_code, bool) or not isinstance(status_code, int):
        return STATUS_OTHER
    label = f"{status_code // 100}xx"
    return label if label in STATUS_CLASSES else STATUS_OTHER


def bound_route(template: str | None) -> str:
    """Return a bounded route-template label; ``UNMATCHED`` when there is no matched template."""

    if not isinstance(template, str) or not template:
        return ROUTE_UNMATCHED
    return template[:MAX_ROUTE_LEN]


def bound_field(value: str | None) -> str:
    """Length-bound a free-ish string field before it is logged. Non-strings become ``""``."""

    if not isinstance(value, str):
        return ""
    return value[:MAX_FIELD_LEN]


def is_valid_request_id(value: str | None) -> bool:
    """True only for a syntactically valid, size-bounded request id."""

    return isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value) is not None
