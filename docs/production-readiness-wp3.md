# Production Readiness — Work Package 3 (G-OBS-1)

**Scope.** Secure structured application logging, bounded operational metrics, and version-controlled
alert-policy definitions for the control plane and lab API. It closes `G-OBS-1` only. It does **not**
implement graceful shutdown (`G-SHUT-1`), the private-provider production overlay, or any Phase 3.0
work, and it does not modify historical Phase 2.9 evidence.

Built on WP2-correction HEAD `30d93f0` (branch `codex/phase-2-9-live-adapter`).

The post-review correction after `160c63e` closes three boundary defects found during independent
adjudication: histogram buckets are accumulated exactly once, every logger emission is rebuilt
through the closed schema without `str`/`repr` coercion, and observer lifecycle/getter failures are
isolated from both normal responses and downstream exceptions.

**Security objective.** Operators can detect failures and degraded behavior without logs or metrics
becoming a new secret-exfiltration, high-cardinality, authority, or availability boundary.

---

## 1. Structured logging

A shared, dependency-light JSON logging layer ([`aegis_obs`](../src/aegis_obs/)) is used by both
services. One bounded record is written per line to **stdout only**.

**Exact log schema** (`schema_version = "obslog-v1"`; closed key set — no other key is ever emitted):

| Field | Meaning | Bounding |
|---|---|---|
| `schema_version` | `"obslog-v1"` | fixed |
| `timestamp_utc` | ISO-8601 UTC | generated |
| `level` | `INFO` / `WARNING` / `ERROR` | closed set (else `INFO`) |
| `service` | `control-plane` / `lab-api` | closed set (else `unknown`) |
| `event` | `http_request` / `http_error` / `startup` / `log_serialization_failed` | closed set |
| `request_id` | reused request-id (validated) | `≤256` chars |
| `method` | HTTP method | allowlist, else `OTHER` |
| `route` | **normalized route template** | matched template or `UNMATCHED`, `≤128` |
| `status_code` | HTTP status code | `100…599`, else fixed `0` |
| `status_class` | `1xx`…`5xx` | closed set (else `OTHER`) |
| `duration_ms` | request duration | clamped `0…3_600_000` |
| `code` | fixed error/stop code (e.g. `UNHANDLED_EXCEPTION`) | `≤256` |
| `exception_class` | allowlisted class name, else `Exception` | closed allowlist |

**Redaction guarantees.** The logger only ever copies the allowlisted fields above. It **never** logs
a request/response body, query string, cookie, authorization header, API key, provider credential,
authorization reference, target URL, raw evidence, model output, `str(exception)`, a stack-local
path, or any arbitrary user-controlled string. On an exception it logs only a fixed `code`, an
allowlisted `exception_class` (or generic `Exception`), the request id, and safe request metadata.
Unmatched routes log the fixed label `UNMATCHED`, never the attacker-controlled path. Externally
supplied request ids are validated against `[A-Za-z0-9._:-]{1,64}`; oversized/malformed values are
replaced with a generated `req-<hex16>`. Every string field is length-bounded, and if serialization
fails the logger emits one fixed `log_serialization_failed` record and returns — **it never raises**,
so a logging failure cannot weaken authorization, budgets, cleanup, readiness, controller verdicts,
or HTTP security behavior. The fallback itself contains all required `obslog-v1` fields and no
caller-derived value. Even the low-level `emit()` boundary rejects unexpected keys and never uses
`default=str`, `str()`, or `repr()` to serialize an arbitrary object.

**Uvicorn access log.** Uvicorn's default access logger (which can print raw paths/query strings) is
disabled two ways: `--no-access-log` in the base Compose commands and the Dockerfile `CMD`, and
`disable_uvicorn_access_log()` at app startup (clears handlers, disables, stops propagation). No
duplicate unsafe access line remains.

**Scrape-noise policy.** `/health` and `/metrics` are excluded from per-request logs; `/ready` is
silent when ready and logs at **WARNING** (not ERROR) when it fails closed; genuine 5xx and unhandled
exceptions log at ERROR. Metrics are still recorded for all routes.

## 2. Metrics

A thread-safe, dependency-light registry ([`aegis_obs/metrics.py`](../src/aegis_obs/metrics.py))
exports a Prometheus/OpenMetrics text body at an internal-only `GET /metrics`.

**Exact metric names, labels, and types:**

| Metric | Type | Labels |
|---|---|---|
| `aegis_http_requests_total` | counter | `service, method, route` |
| `aegis_http_responses_total` | counter | `service, method, route, status_class` |
| `aegis_http_request_duration_seconds` | histogram | `service, method, route` (+ `le`) |
| `aegis_http_in_flight_requests` | gauge | `service` |
| `aegis_process_start_timestamp_seconds` | gauge | `service` |
| `aegis_readiness_ready` | gauge | `service` |
| `aegis_readiness_check` | gauge | `service, check` (`persistence`, `credential_isolation`) |
| `aegis_scan_completions_total` | counter | `service, status` (controller terminal status) |

Histogram buckets (seconds): `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, +Inf`.
Observations are stored in one non-cumulative finite bucket and made cumulative exactly once during
rendering. Finite buckets are therefore monotonic and never exceed `_count`; `+Inf == _count`,
including for observations above the largest finite bucket.

**Cardinality bounds.** Labels may contain **only** fixed service names, allowlisted methods
(`GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS`, else `OTHER`), normalized route templates, bounded status
classes (`1xx…5xx`, else `OTHER`), and controller-owned enumerations. A request id, scan id, campaign
id, finding id, target, URL, hostname, model output, exception text, or user input can **never** be a
label. Unknown methods/routes/statuses collapse to fixed `OTHER`/`UNMATCHED`. The distinct route-label
set is hard-capped at `MAX_ROUTE_LABELS = 64` (overflow → `OTHER`), so per process the worst-case
series count is bounded by roughly:

```
requests_total:   methods(≤8) × routes(≤66)              ≈ 528
responses_total:  methods(≤8) × routes(≤66) × classes(6) ≈ 3168
duration hist:    methods(≤8) × routes(≤66) × (buckets 11 + _sum + _count + +Inf ≈ 14) ≈ 7392
gauges/counters:  in_flight(1) + start_ts(1) + ready(1) + checks(2) + scan_status(≤6)  ≈ 11
```

Matched templates come from the finite route table, so real cardinality is far below the cap; the cap
is the ceiling that holds even under path-fuzzing abuse. Collecting metrics never mutates controller
truth and is never an authorization decision. A serialization failure makes `render()` return a fixed
`# metrics_unavailable` body and the endpoint return **503** — raw internal state is never exposed.

**Internal scraping model.** `/metrics` is reachable only inside the `security-lab` Compose network:
no host port, no new external network, no public ingress. A future Prometheus sidecar on that internal
network would scrape `http://control-plane:8000/metrics` and `http://lab-api:8001/metrics`. That
sidecar/scrape is **NOT_EVALUATED** here.

**Example safe queries** (labels are all bounded):

```promql
sum by (status_class) (rate(aegis_http_responses_total{service="control-plane"}[5m]))
histogram_quantile(0.95, sum by (le) (rate(aegis_http_request_duration_seconds_bucket[5m])))
aegis_readiness_ready{service="control-plane"}
sum by (status) (aegis_scan_completions_total{service="control-plane"})
```

## 3. Readiness and health semantics (unchanged)

`/health` remains liveness; `/ready` remains fail-closed readiness (WP1). Observability is read-only:
`/ready` returns the evaluator's report **as-is** and only mirrors the verdict into the readiness
gauges afterward — a metrics/logging failure can never convert a failed check to PASS. Readiness
observations record no path, exception, database content, or credential.

Every observer hook is availability-neutral: registry/logger resolution, in-flight increment and
decrement, request observation, and log emission are individually isolated. In-flight decrement is
attempted exactly once per request. An observer failure cannot change a successful response or mask
the original downstream exception.

## 4. Alert policy

Version-controlled rules live in [`deploy/observability/alerts.yml`](../deploy/observability/alerts.yml),
using fixed metric names and bounded labels only:

| Alert | Condition |
|---|---|
| `AegisControlPlaneNotReady` | `aegis_readiness_ready{service="control-plane"} == 0` for 5m |
| `AegisPersistenceReadinessFailing` | `aegis_readiness_check{check="persistence"} == 0` for 2m |
| `AegisHttp5xxElevated` | `rate(aegis_http_responses_total{status_class="5xx",route!="/ready"}[5m]) > 0.2` for 10m |
| `AegisRequestLatencyHigh` | p95 `aegis_http_request_duration_seconds` > 1s for 10m |
| `AegisRestartLoop` | `changes(aegis_process_start_timestamp_seconds[15m]) > 3` |

These alerts are **policy only**. No alert manager, Prometheus server, scrape, or notification route
is deployed or tested here — firing/delivery is **NOT_EVALUATED**.

## 5. Retention / aggregation assumptions

Logs are emitted to **stdout only**; retention, rotation, and aggregation are the platform's
responsibility (e.g. the container runtime's log driver) and are **NOT_EVALUATED**. Metrics are
in-process and reset on restart; durable storage/retention is the (NOT_EVALUATED) scraper's concern.
No external log aggregation, Prometheus scraping, or alert delivery is proven by this WP.

## 6. Verification

- **Focused WP3 tests** — [`tests/test_wp3_observability.py`](../tests/test_wp3_observability.py):
  strict schema, single-line valid JSON, secret-free no-raise behavior for arbitrary/unserializable
  records; exact single- and multi-observation histogram invariants; sentinels injected into
  query string / unmatched path / Authorization / Cookie / body / malformed request id never appear
  in logs or `/metrics`; `/metrics` never contains request ids or user values; unknown paths collapse
  to one `UNMATCHED` series and never grow known-route cardinality; registry route cardinality is
  hard-bounded; render-failure → fixed 503; getter/inc/dec/observe/log failures do not change a
  response or mask a downstream exception; exception message never logged (only
  `UNHANDLED_EXCEPTION` + `ValueError`);
  liveness + security headers unchanged; readiness still fail-closed and gauge reflects 0; health/
  metrics scrapes not access-logged; Uvicorn access log disabled in Compose + Dockerfile; no host port.
- **Real provider-free Docker run** — recorded in §7 of this file's companion report.

## 7. NOT_EVALUATED

- External log aggregation / retention / rotation backend.
- Prometheus (or any) scraper and its storage/retention.
- Alert manager, alert firing, and notification delivery.
- Runtime digest pull and the provider-backed production path (carried over from WP2).

## 8. Conservative status

**NOT_PRODUCTION_READY.** WP3 closes `G-OBS-1`. The next required blocker is **`G-SHUT-1`** (graceful
shutdown/drain), then a digest-pinned company-private provider/gateway production path, then final
staging soak/failure validation.
