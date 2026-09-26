"""Shared, secure observability for the control plane and lab API (WP3 / G-OBS-1).

- :mod:`aegis_obs.logging` — bounded, schema-versioned structured JSON logging that never emits a
  secret, a body, a URL, or ``str(exception)``, and never raises.
- :mod:`aegis_obs.metrics` — a thread-safe, cardinality-bounded Prometheus text registry.
- :mod:`aegis_obs.middleware` — the shared per-request observation used by both apps.
- :mod:`aegis_obs.normalize` — the pure helpers that bound every label/field.

Observability here is read-only: it never mutates controller truth, never gates authorization, and a
logging or metrics failure can never weaken readiness, budgets, cleanup, or HTTP security behavior.
"""

from aegis_obs.logging import LOG_SCHEMA_VERSION, StructuredLogger
from aegis_obs.metrics import MAX_ROUTE_LABELS, MetricsRegistry
from aegis_obs.middleware import (
    ObservabilityASGIMiddleware,
    disable_uvicorn_access_log,
    observe_request,
    resolve_request_id,
    route_template,
)

__all__ = [
    "LOG_SCHEMA_VERSION",
    "MAX_ROUTE_LABELS",
    "MetricsRegistry",
    "ObservabilityASGIMiddleware",
    "StructuredLogger",
    "disable_uvicorn_access_log",
    "observe_request",
    "resolve_request_id",
    "route_template",
]
