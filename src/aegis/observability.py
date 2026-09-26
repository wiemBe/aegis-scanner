"""Process-wide observability singletons for the control plane (WP3 / G-OBS-1).

Kept in its own module so both :mod:`aegis.main` (HTTP middleware, ``/metrics``) and
:mod:`aegis.service` (scan-completion counter) share one registry and logger without a circular
import. These are read-only observers: recording a metric or a log never mutates controller truth.
"""

from __future__ import annotations

from aegis_obs.logging import StructuredLogger
from aegis_obs.metrics import MetricsRegistry
from aegis_obs.normalize import SERVICE_CONTROL_PLANE

metrics: MetricsRegistry = MetricsRegistry(service=SERVICE_CONTROL_PLANE)
logger: StructuredLogger = StructuredLogger()
