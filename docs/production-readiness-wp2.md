# Production Readiness — Work Package 2

**Scope.** Closes the three container-runtime gaps named in the WP1 register:
`G-ROOT-1` (base services run as root), `G-LIMITS-1` (no resource/restart limits), and `G-ROLL-1`
(no immutable image reference / deterministic rollback). It changes only the base stack, the root
`Dockerfile`, a new production overlay, and a typed preflight. It does **not** touch authorization,
budgets, credential isolation, readiness semantics, cleanup, or any Phase 2.9 evidence or verdict.
It is **not** a production-readiness certification.

Built on WP1 HEAD `1279b09` (branch `codex/phase-2-9-live-adapter`).

---

## 1. Non-root runtime (G-ROOT-1)

The root [`Dockerfile`](../Dockerfile) (used by both `control-plane` and `lab-api`) now creates a
dedicated unprivileged system user/group and runs as it:

| Property | Value |
|---|---|
| User / group name | `aegis` / `aegis` (system account) |
| Numeric UID:GID (`Dockerfile USER`) | **`10001:10001`** |
| `/app` (application code) | root-owned, **not** writable by the runtime user (read-only) |
| `/data` (SQLite volume mount) | owned `10001:10001`, mode `0700` — the only runtime-writable path |
| `/tmp` | provided solely by the existing compose `tmpfs` |

`ScanStore.initialize()` writes `/data/aegis.db`; a **fresh** named volume inherits `/data`'s
image-time ownership (`10001:10001`), so the non-root user can create and open the store while the
container root filesystem stays `read_only`. No sudo, no added Linux capabilities, no `setcap`/setuid,
no privileged mode, and no Docker socket are introduced. `read_only`, `no-new-privileges:true`, the
internal network, and the `/ready` healthcheck are unchanged.

**Guarantee.** The two long-lived services no longer run as UID 0. **Not** guaranteed: kernel-level
isolation beyond namespaces/`no-new-privileges` (no user-namespace remap, seccomp profile, or AppArmor
is configured here).

**Volume migration caveat (NOT_EVALUATED).** An `aegis-data` volume first created by an earlier
**root** build is owned by root and will **not** be re-chowned by Docker on upgrade; the non-root user
would then fail to write it. A fresh deploy is unaffected. Existing-volume migration
(`chown 10001:10001` of the volume, or recreation) is documented in the runbook but not exercised here.

## 2. Runtime resource controls (G-LIMITS-1)

Explicit, conservative ceilings on both services in [`docker-compose.yml`](../docker-compose.yml),
**verified from `docker inspect`** of a live stack (not merely from YAML):

| Service | `mem_limit` | `cpus` | `pids_limit` | `restart` |
|---|---|---|---|---|
| `control-plane` | `512m` (`Memory=536870912`) | `1.0` (`NanoCpus=1000000000`) | `256` | `unless-stopped` |
| `lab-api` | `256m` (`Memory=268435456`) | `0.5` (`NanoCpus=500000000`) | `128` | `unless-stopped` |

No host networking, published ports, privileged mode, or extra capabilities were added. `restart:
unless-stopped` restarts on crash but honours a deliberate `docker stop`.

**Guarantee.** A runaway scan cannot exhaust host memory/CPU, a fork bomb is bounded by the PID cap,
and a crashed service is restarted. **These limits are containment ceilings, not a load-test SLO** —
they do not prove capacity or throughput under load.

## 3. Deterministic production image + rollback (G-ROLL-1)

A mutable tag (`latest`, `0.2.0`) is insufficient. The production path pins an **immutable digest**.
This covers the two **base** services (`control-plane`, `lab-api`) only; the provider-backed path is
NOT_READY (§5).

- **Reference contract (required):** `registry/repository@sha256:<64 lowercase hex characters>` with
  an **explicit registry host** (dotted domain, `host:port`, or `localhost[:port]`) and **≥1
  repository component**. Rejected: missing/empty, leading/trailing whitespace (rejected, **not**
  stripped), bare/local name (`aegis@sha256:…`), implicit-namespace name (`aegis/app@sha256:…`),
  tag-only, `latest`, **tag+digest** (`…/aegis:1.2@sha256:…`), uppercase/short/long/non-hex digest,
  and non-`sha256` algorithm. A valid reference is returned **byte-for-byte unchanged**.
- **Overlay:** [`docker-compose.prod.yml`](../docker-compose.prod.yml) sets, for both services,
  `build: !reset null` (removes the base local-build fallback on merge) and
  `image: "${AEGIS_IMAGE:?…}"`. Both services use the **same** `AEGIS_IMAGE`. Compose errors if it is
  unset.
- **Fail-closed preflight (no bypass):**
  [`python -m aegis.deploy.preflight`](../src/aegis/deploy/preflight.py)
  ([`image_reference.py`](../src/aegis/deploy/image_reference.py)) rejects a bad reference **before any
  render** (exit `2`), then **always** renders and analyzes the merged production config: exit `3`
  unless **both** services use exactly the digest with **no** `build` key. There is no `--no-render`
  option and no NOT_EVALUATED success path — Docker unavailable, Compose unavailable/failure, timeout,
  invalid JSON, or ambiguous output all return exit `3`, and `PREFLIGHT OK` is never printed without a
  completed render proof. Valid reference → exit `0`.
- **No credential/attacker echo:** all preflight/validator diagnostics are fixed, credential-free
  strings. Raw Compose stderr, raw exceptions, and the caller-supplied reference/algorithm/secret-shaped
  input are never surfaced in errors.
- **No silent fallback:** proven from the rendered configuration
  (`docker compose -f docker-compose.yml -f docker-compose.prod.yml config`), the merged production
  config contains **no** `build:` for either service — verified in an offline analysis unit test, a
  Docker-gated render test, and by the preflight itself.
- **Credentials:** never embedded. The digest is not a secret; registry auth is the operator's
  `docker login` (Docker credential store), never Compose/scripts/logs/docs.

**Rollback procedure** (base services; details in runbook §6a):

1. Record the currently deployed digest before changing anything:
   `docker compose -f docker-compose.yml -f docker-compose.prod.yml config | grep image` → save it.
2. Deploy a new digest: set `AEGIS_IMAGE=<new digest>`, run the preflight, `up -d` (base + prod overlay
   only — **not** `docker-compose.provider.yml`), then confirm `GET /ready` → `200 {"ready": true}`.
3. Roll back: set `AEGIS_IMAGE=<prior recorded digest>`, run the preflight again, `up -d`, re-check
   `/ready`. Because the reference is a digest, the rollback restores the exact prior bits.

## 4. Verification performed

- **Focused WP2 tests** — [`tests/test_wp2_container_hardening.py`](../tests/test_wp2_container_hardening.py):
  Dockerfile numeric non-root `USER` (and ≠ 0), no extra privilege; base-stack `read_only` /
  `no-new-privileges` / tmpfs retained; non-zero mem/cpu/pids + `unless-stopped` on both services;
  prod overlay resets `build` and pins `AEGIS_IMAGE`; the image-reference validator (valid digest
  accepted **byte-for-byte unchanged**, incl. port-registry/multi-component repo; missing / tag-only /
  `latest` / bare-local / implicit-namespace / **tag+digest** / leading+trailing-whitespace / short /
  long / uppercase / non-hex / `sha512` / `md5` all rejected; **secret-shaped input never echoed** in
  errors); preflight rendered-config analysis (exact digest on both services with no build; active
  build, image mismatch, and missing service all rejected). **Preflight CLI (no bypass):** no
  `--no-render` option; Docker unavailable → exit 3 with no `PREFLIGHT OK`; Compose failure / timeout /
  invalid JSON → exit 3 (raw stderr not surfaced); bad reference → exit 2 with no render attempted;
  valid → exit 0. Docker-gated: real rendered-config digest proof and a real `main()` exit-0; built
  image runs non-root, **cannot** write `/app`, **can** initialize `/data/aegis.db`.
- **Readiness tests** — [`tests/test_readiness.py`](../tests/test_readiness.py) unchanged and green.
- **Real provider-free Docker run** (unique project, base stack, **zero paid calls**): control-plane
  and lab-api effective **`uid=10001 gid=10001`**; control-plane **healthy through `/ready`** (`200
  {"ready": true}`); **`/data/aegis.db` created on the named volume** (233 KB) owned `10001:10001`
  mode `0700`; **root filesystem read-only** (write to `/app` → `OSError`); limits/restart visible via
  `docker inspect` (values in §2); `down -v --remove-orphans` → `rc=0`; **0 leftover containers, 0
  networks, 0 volumes**.

## 5. NOT_EVALUATED / out of scope

- **Runtime digest pull** — no registry image is available to pull; validated only through the
  fail-closed preflight and rendered Compose configuration. Pull/verify of a live digest is
  **NOT_EVALUATED**.
- **Complete provider-backed production path — NOT_READY / NOT_EVALUATED.** The only provider overlays
  today are public-egress profiles (`docker-compose.provider.yml` forces the deprecated public OpenAI
  profile; deepseek/ollama overlays are not the company-private model). A digest-pinned private-provider
  `llm-gateway` production overlay does not exist and is not evaluated. Production is base-services-only.
- **Existing pre-root `aegis-data` volume migration** — documented in runbook §6a (stop → back up →
  chown to `10001:10001` via a **pinned-digest** tool image → verify ownership → readiness → rollback),
  but **not executed** (NOT_EVALUATED).
- **Load/throughput under the limits**, user-namespace/seccomp/AppArmor hardening, and image supply-
  chain signing of the base `Dockerfile` — not addressed here.

## 6. Remaining blockers (unchanged by WP2)

- **P1:** `G-OBS-1` (no application logging/metrics), `G-SHUT-1` (no graceful shutdown/drain).
- **P2:** `G-BACKUP-1` (no volume backup/restore), `G-IR-1` (no incident-response runbook),
  `G-DBLOCK-1` (SQLite without WAL/`busy_timeout`).

## 7. Conservative status

**NOT_PRODUCTION_READY.** WP2 removes the root-user, unbounded-resource, and mutable-image blockers on
the base stack, but the P1/P2 set above remains open. Suitable for continued **staging validation**
only. Neither the resource limits nor the digest pin is a security or capacity guarantee: limits bound
containment, not load; a digest proves image *immutability*, not image *safety*.
