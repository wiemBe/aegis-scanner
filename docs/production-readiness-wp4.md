# Production Readiness Work Package 4 — Graceful Shutdown (`G-SHUT-1`)

Status: **CLOSED for the supported single-process/single-writer deployment**, subject to the test
and real-Docker evidence recorded for this work package. This does not make the system production
ready. At the WP4 checkpoint the company-private digest-pinned provider/gateway path and final
staging soak/failure validation were open; WP5 subsequently implements the repository path and
observer, leaving environment-specific execution evidence open.

## Lifecycle and admission contract

`ProcessLifecycle` is the single process state owner:

1. `STARTING`: initialization in progress; readiness fails and new mutations are rejected.
2. `SERVING`: readiness may pass if persistence and credential isolation also pass; work may be
   admitted.
3. `DRAINING`: entered once at shutdown before waiting; readiness is 503 and new scan/state-creating
   mutations return the fixed, secret-free `SERVICE_DRAINING` code.
4. `STOPPED`: terminal for that lifespan. Repeated drain calls return the first result.

State and the in-flight task registry share one re-entrant lock. Scan durability creation and
async-task registration occur in the same critical section, so drain cannot observe durable work
without also seeing its task. The lifecycle controls admission only; it does not replace safety,
authorization, budget, credential isolation, verifier decisions, or persistent controller truth.

Read-only GET surfaces, `/health`, `/ready`, and `/metrics` remain callable while Uvicorn accepts
connections. `/health` stays a liveness signal. Authenticated emergency-stop and logout POSTs are
drain-safe because they reduce active authority; other new mutations are rejected.

## Exact bounds and timeout semantics

| Layer | Bound |
|---|---:|
| Application drain (`SHUTDOWN_GRACE_SECONDS`) | 10 seconds |
| Cancellation-persistence allowance | 1 second, internal bounded cleanup |
| Uvicorn `--timeout-graceful-shutdown` | 12 seconds |
| Compose `stop_grace_period` | 15 seconds |

`SHUTDOWN_GRACE_SECONDS` is validated as numeric, greater than zero, and at most 120. Boolean,
negative, zero, empty, and non-numeric inputs fail closed during settings construction. The outer
timeouts leave room for cancellation persistence and lifespan teardown.

Normal completion retains the existing audit/verifier path. At grace expiry, remaining tasks are
cancelled. Scan cancellation already persists `INCOMPLETE`; the lifecycle timeout callback then
sets `SHUTDOWN_DRAIN_TIMEOUT`, re-runs only the deterministic verifier over already-persisted
evidence, and persists `FAIL` only for verified findings or `INCOMPLETE` otherwise. It cannot create
`PASS`. If that final persistence fails, stale `QUEUED`/`RUNNING` rows remain covered by the existing
startup `PROCESS_RESTART` reconciliation. Exceptions from logging, metrics, timeout callbacks, or
task-result observation do not replace the original shutdown decision.

## Audit and observability

The closed `obslog-v1` schema adds exactly three lifecycle events: `drain_started`,
`drain_completed`, and `drain_timeout`. The fixed-label metrics are `aegis_process_state{state=...}`
and `aegis_lifecycle_events_total{event=...}`. No work id, scan id, request body, target, header,
credential, exception message, or model output is logged or used as a label.

## Deployment invariants

The change retains numeric `USER 10001:10001`, read-only root filesystem, `/data` volume,
no-new-privileges, the WP2 resource/restart limits, the immutable-image production preflight, and
raw Uvicorn access-log suppression. Control-plane command overrides in the Nuclei, ZAP, and Beast
overlays carry the same no-access-log and 12-second graceful timeout flags.

## Validation evidence

Offline gates on 2026-09-26:

- WP4 + readiness + WP2 + WP3 focused set: `112 passed, 3 skipped`;
- Phase 1.3 streaming/unstable controls: `257 passed`;
- full suite: `1877 passed, 2 skipped`;
- `ruff check src tests scripts`: clean;
- `mypy --strict`: clean across 195 source files.

Provider-free real Docker project `aegis-wp4-01a0de65` built two unique images. Both services became
healthy. Runtime inspection confirmed UID:GID `10001:10001`, read-only rootfs, control-plane
512 MiB/1 CPU/256 PID and lab-api 256 MiB/0.5 CPU/128 PID, `unless-stopped`, and a 15-second stop
timeout. A completed synthetic scan stopped with `drain_completed` in 0.31 seconds. With lab-api
paused and a scan confirmed in flight, a real container SIGTERM produced `drain_timeout` after the
10-second application grace and `docker stop` returned in 10.34 seconds. After restart the scan was
`INCOMPLETE` with `SHUTDOWN_DRAIN_TIMEOUT` and audit events `SCAN_CANCELLED` plus
`SHUTDOWN_DRAIN_TIMEOUT`; it was not PASS/COMPLETE. Teardown removed the project volume/network,
both containers, and both test images; project-label/image-prefix queries returned zero leftovers.

`/ready` 503 and `SERVICE_DRAINING` admission are proven by in-process integration tests while a
drain is held open. Direct HTTP observation of those two responses during the real Docker SIGTERM
was **NOT_EVALUATED** because Uvicorn closes its listening socket before application lifespan
teardown becomes externally queryable; no PASSED claim is made for that timing observation.

## Scope and remaining blockers

The supported topology remains single replica/single writer. Backup/restore, application-specific
incident response, and SQLite locking/tuning retain their recorded out-of-scope dispositions. No
paid provider call, private-provider overlay, prompt tuning, Phase 3.0 work, `.env.gateway` read, or
historical Phase 2.9 evidence modification is part of WP4.

WP5 subsequently implements the digest-pinned company-private provider/gateway path and a read-only
staging validation gate. Actual registry pull, endpoint/TLS/model verification, and staging soak/
failure evidence remain environment activation work. See
[production-readiness-wp5.md](production-readiness-wp5.md).
