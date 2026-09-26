# Production Readiness Gap Audit — Work Package 1

**Scope of this document.** A conservative audit of the control plane's production deployment path.
It separates verified facts from assumptions and NOT_EVALUATED dimensions, produces a prioritized
P0/P1/P2 gap register with direct file references, and names the single highest-risk blocker that is
closed in the companion commit. It is **not** a production-readiness certification and makes no such
claim. Phase 2.9 evidence and semantics are untouched.

Audited at commit parent `00ecf25` on branch `codex/phase-2-9-live-adapter`.

> **Update (WP2).** `G-ROOT-1`, `G-LIMITS-1`, and `G-ROLL-1` (P1 rows below) are now addressed on the
> base stack — non-root `USER 10001:10001`, explicit mem/cpu/pids/restart limits, and an immutable
> digest-pinned production overlay with a fail-closed preflight. See
> [production-readiness-wp2.md](production-readiness-wp2.md).
>
> **Update (WP3).** `G-OBS-1` is now closed: shared secret-free structured JSON logging, a
> bounded-cardinality internal `/metrics` endpoint, and version-controlled alert-policy definitions.
> The post-review correction additionally proves closed-schema behavior at the raw emit boundary,
> valid Prometheus histogram accumulation, and availability-neutral observer lifecycle failures.
> See [production-readiness-wp3.md](production-readiness-wp3.md).
>
> **Operator scope decision (P2 removed from the roadmap).** `G-BACKUP-1`, `G-IR-1`, and `G-DBLOCK-1`
> are explicitly **out of scope** — see §5a. They are not implemented and are no longer tracked as
> remaining blockers.
>
> **Remaining required blockers:** `G-SHUT-1` (graceful shutdown/drain); a digest-pinned
> company-private provider/gateway production path; final staging soak/failure validation. Overall
> status remains **NOT_PRODUCTION_READY**.

---

## 1. Production deployment path (as built)

The production topology is the base [`docker-compose.yml`](../docker-compose.yml) plus a provider
overlay (`docker-compose.ollama.yml` / `docker-compose.provider.yml` / `docker-compose.deepseek.yml`)
and, for the human UI, `docker-compose.dashboard.yml`. Two long-lived services are built from the
root [`Dockerfile`](../Dockerfile):

| Service | Command | Network | Rootfs | Healthcheck | Restart | Limits | User |
|---|---|---|---|---|---|---|---|
| `control-plane` | `uvicorn aegis.main:app :8000` | `security-lab` (internal) | `read_only` + tmpfs | **none** | **none** | **none** | **root (uid 0)** |
| `lab-api` | `uvicorn lab_api.main:app :8001` | `security-lab` (internal) | `read_only` + tmpfs | `/health` (3s/2s/10) | none | none | root (uid 0) |

The provider credential path is isolated: the control plane refuses to start if `AI_AUTH_TOKEN` is
present in its own environment ([`main.py:88`](../src/aegis/main.py)), and the credential is mounted
only into the `llm-gateway` service via an untracked `.env.gateway`
([`settings.py:57`](../src/aegis/settings.py), [`runbook.md` §6](runbook.md)).

---

## 2. Verified facts (positive posture — do not regress)

- **Provider-credential isolation is fail-closed.** Import-time guard rejects `AI_AUTH_TOKEN` on the
  control plane ([`main.py:88`](../src/aegis/main.py)); `AI_AUTH_TOKEN` / `DEEPSEEK_API_KEY` are
  `SecretStr`, gateway-only ([`settings.py:59`](../src/aegis/settings.py),
  [`settings.py:73`](../src/aegis/settings.py)).
- **Secrets hygiene.** `.gitignore` excludes `.env*`, `secrets/`, `*.secret`, `*.db`; `.dockerignore`
  excludes `.env`, `*.pem`, `*.key`, `*private*key*`, `*.db`, `artifacts`.
- **Per-scan budget enforcement is fail-closed and typed** ([`budget.py`](../src/aegis/budget.py)):
  request / iteration / model-call / token-reservation / time ceilings raise `BudgetExceeded`.
- **Per-campaign budget admission is atomic and typed**
  ([`multi_agent/budget.py`](../src/aegis/multi_agent/budget.py)): global + per-agent
  model-call/token/request/command ceilings raise `AgentBudgetExceeded`.
- **Crash recovery for scans is deterministic.** On startup the store reconciles any stale
  `QUEUED`/`RUNNING` scan to a terminal `INCOMPLETE`/`FAIL` with `stop_reason=PROCESS_RESTART`
  ([`storage.py:50-63`](../src/aegis/storage.py)).
- **Audit trail is persisted, ordered, redacted.** SQLite `audit_events` with stable sequencing and
  content-free evidence refs ([`storage.py`](../src/aegis/storage.py),
  [`audit.py`](../src/aegis/audit.py)).
- **HTTP hardening headers** (CSP, nosniff, frame-deny, no-store, request-id) on every response
  ([`main.py:165-183`](../src/aegis/main.py)).
- **Rootfs hardening** on both base services: `read_only: true`, `tmpfs: [/tmp]`,
  `no-new-privileges:true`, `internal` network ([`docker-compose.yml`](../docker-compose.yml)).
- **Runner services are hardened and drop privilege** (`USER 10001`/`65532`/`10002`, mem/cpu/pids
  limits, healthchecks) in their overlays — the pattern exists in-repo and is simply absent from the
  base stack.

## 3. Assumptions (believed true, not re-proven here)

- The production provider is `internal_openai_compatible` against a private endpoint; public egress
  is a deprecated/disabled profile ([`settings.py:7-19`](../src/aegis/settings.py)).
- Orchestration is Docker Compose on a single host (no Kubernetes/systemd manifests exist in-repo).
- The `aegis-data` named volume is backed by durable host storage.

## 4. NOT_EVALUATED in WP1

- Backup/restore of the `aegis-data` SQLite volume (no mechanism or procedure exists to evaluate).
- Rollback of the `control-plane`/`lab-api` images (built locally, untagged; no registry/digest pin).
- Log aggregation / metrics / alerting backend (no logging emitted by `src/` — see G-OBS-1).
- Formal incident-response procedure (runbook covers teardown, not IR).
- Multi-host / HA / horizontal scaling of the control plane (SQLite is single-writer).
- Live provider behavior (out of scope; no paid calls in WP1).

---

## 5. Ranked gap register

### P0 — production blockers

| ID | Gap | Evidence | Independently closable |
|---|---|---|---|
| **G-READY-1** | **Liveness masquerades as readiness; no fail-closed readiness signal.** `/health` returns `{"status":"ok"}` unconditionally once the process is up ([`main.py:229-231`](../src/aegis/main.py)); there is no `/ready` probe that verifies safe-to-serve preconditions, and the base-stack `control-plane` service has **no healthcheck at all** ([`docker-compose.yml`](../docker-compose.yml)). An orchestrator/load balancer cannot distinguish a healthy control plane from one whose persistence volume detached or whose schema is absent after startup, and `depends_on: condition: service_healthy` on the control plane is impossible. Post-startup persistence loss (volume unmount, disk-full, file removal) is invisible: `/health` still answers 200 while scans and the **audit trail** silently fail. Fail-open. | `main.py:229`, `docker-compose.yml` | **Yes** — additive endpoint + healthcheck; no dependency on other gaps. |

### P1 — hardening / operability

| ID | Gap | Evidence |
|---|---|---|
| G-ROOT-1 | ✅ **Closed (WP2).** Base `control-plane`/`lab-api` now run non-root (`USER 10001:10001`). | [`Dockerfile`](../Dockerfile) |
| G-LIMITS-1 | ✅ **Closed (WP2).** Explicit `mem_limit`/`cpus`/`pids_limit`/`restart` on both services. | [`docker-compose.yml`](../docker-compose.yml) |
| G-OBS-1 | ✅ **Closed (WP3 + correction).** Secret-free closed-schema JSON logging + mathematically valid bounded internal `/metrics` + availability-neutral observer hooks + alert policy. | [`aegis_obs`](../src/aegis_obs/), [wp3](production-readiness-wp3.md) |
| G-SHUT-1 | **OPEN (next blocker).** No graceful shutdown/drain. `lifespan` has no teardown after `yield` ([`main.py`](../src/aegis/main.py)); in-flight `BackgroundTasks` scans are cut on SIGTERM. Partially mitigated by `PROCESS_RESTART` reconciliation (§2). | `main.py` |
| G-ROLL-1 | ✅ **Closed (WP2).** Immutable digest-pinned production overlay + fail-closed preflight. | [`docker-compose.prod.yml`](../docker-compose.prod.yml) |

### 5a. P2 — OUT OF SCOPE (operator scope decision)

The following P2 items are **removed from the required production-readiness roadmap** by operator
decision. They are **not implemented** and are **not** remaining blockers. Documented honestly:

| ID | Disposition | Constraint documented |
|---|---|---|
| G-BACKUP-1 | **ACCEPTED_RISK / OUT_OF_SCOPE** | SQLite data is disposable/reconstructible. **No backup, recovery-point, or recovery-time guarantee is provided.** No backup coverage, HA, enterprise durability, or disaster recovery is claimed. |
| G-IR-1 | **PLATFORM-OWNED / OUT_OF_SCOPE** | Application-specific incident response is not provided. Organizational/platform incident response applies externally and remains outside this repository. |
| G-DBLOCK-1 | **ACCEPTED_CONSTRAINT / OUT_OF_SCOPE** | The deployment is strictly **single-replica, single-writer**. Horizontal scaling, multiple application workers, and shared concurrent writers are **unsupported**. Any future change to these constraints must **reopen** the SQLite concurrency/locking evaluation. |

**Remaining required blockers after WP3:** (1) `G-SHUT-1` graceful shutdown/drain; (2) a digest-pinned
company-private provider/gateway production path; (3) final staging soak/failure validation.

---

## 6. Selected blocker and rationale

**Fixed in this work package: G-READY-1** (companion commit).

It ranks first because it is the only **fail-open** gap in the register — every other item degrades
operability or hardening, but G-READY-1 lets a **degraded or unsafe control plane present as
healthy** to whatever routes traffic to it, and it silently masks loss of the persistence/audit
substrate, which is this system's product of record. It is independently closable with no coupling to
the P1/P2 items, and it maps directly to the mandate that **any UNKNOWN operational state must fail
closed** with **typed contracts and deterministic controller decisions**. The remedy is additive and
backward compatible: a new `/ready` endpoint and a `control-plane` healthcheck; the existing
`/health` liveness contract is unchanged. The codebase already establishes the exact convention
(`200 READY / 503 NOT_READY`) in the runner services
([`zap_runner/server.py:5`](../src/zap_runner/server.py)); WP1 brings the control plane in line.

## 7. Conservative status

**NOT_PRODUCTION_READY.** Closing G-READY-1 removes the sole fail-open blocker but leaves the P1
hardening set (root user, resource/restart limits, logging/metrics, graceful drain, deterministic
rollback) open. The system is suitable for continued **staging validation** only.

**Post-audit correction.** The companion implementation was subsequently tightened so the
readiness contract does not infer write availability from permission bits plus a read-only SQLite
open. The final point-in-time check requires an existing regular file, caller-available filesystem
blocks, a successful SQLite `mode=rw` open, and all required table/column contracts. It performs no
persistent mutation, returns only fixed diagnostics, and explicitly makes no guarantee about future
capacity after the probe completes. Zero capacity and ambiguous filesystem/SQLite states fail
closed. The overall status remains **NOT_PRODUCTION_READY**.

## 8. Exact next recommended work package

**WP2 — Container runtime hardening for the base stack (G-ROOT-1 + G-LIMITS-1 + G-ROLL-1):** add a
non-root `USER` to the root `Dockerfile`; set `mem_limit`/`cpus`/`pids_limit`/`restart: unless-stopped`
on `control-plane` and `lab-api`; and pin both images to a tagged/digest-referenced build so rollback
is deterministic. These share one surface (base compose + root Dockerfile), are self-contained, and
do not touch authorization, budget, credential-isolation, cleanup, or controller-owned verdicts.
