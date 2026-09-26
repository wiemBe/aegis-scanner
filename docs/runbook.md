# Operator Runbook — Aegis AI Security Lab (Phase 1.0)

Authorized synthetic lab only. No external or production targets. All commands run through Docker
Compose (the supported Python 3.12 runtime).

## 0. Phase 1.0 Operator Console

Start the same localhost-only stack used by the management demo, then open:

```text
http://127.0.0.1:8000/console/   Operator Console
http://127.0.0.1:8000/           engineering dashboard
```

The console hydrates persisted events before following `/api/console/events` through SSE. A `STALE`
or `GAP` badge means live state is not current; do not present it as live until automatic hydration
returns the badge to `LIVE`. System Health uses actual checks or explicit unknown/unavailable
labels—never reinterpret an unavailable topology/secret result as green.

Presentation mode is available in the console sidebar. Follow the
[management guide](management-demo-phase-1.0.md) and leave the honest limitations visible. Nuclei,
ZAP, and Burp DAST must remain `PLANNED NOT CONNECTED`.

For frontend development and verification (Node is not required in the runtime image):

```bash
cd console
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

The production build is emitted to `src/aegis/console/` and bundled into the Python package. See
[troubleshooting](operator-console-troubleshooting.md), the
[event reference](audit-event-envelope.md), and the
[screenshot policy](screenshot-privacy-retention.md).

## 0.1 Phase 1.1 security-tool integration kernel

The kernel (`src/aegis/engine/`) is provider-independent. Only `AEGIS_NATIVE` is enabled; Nuclei,
ZAP and Burp DAST are disabled, fail-closed skeletons and must stay `DISABLED` in the console.

- Do not install, connect, credential, or enable Nuclei/ZAP/Burp DAST. Enabling any of them requires
  the [Phase 1.2 prerequisites](phase-1.2-nuclei-prerequisites.md) — flipping the catalog flag alone
  is a scope/safety regression.
- Engine readiness is at `GET /api/console/engines`; the console Integrations view shows honest,
  independent `configured` / `reachable` / `enabled` / `authorized` states.
- The console Run Replay shows the finding lifecycle (tool-reported vs verifier-confirmed) and the
  execution-policy decision panel (jobs constructed vs jobs rejected). No engine observation becomes
  a verified finding without the deterministic verifier or explicit human review.

Backend + frontend gates for Phase 1.1 (network disabled where applicable):

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'

# Frontend (Node not required in the runtime image; console/node_modules already present)
docker run --rm --network none -v "$PWD:/workspace" -w /workspace/console node:22-alpine \
  sh -c 'npm run typecheck && npm run lint && npm test && npm run build'
```

The Vite build re-emits `src/aegis/console/`. See [Phase 1.1](phase-1.1-security-tool-kernel.md).

## Phase 1.2 — controlled Nuclei profile

Build and start the isolated profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml ps
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml logs nuclei-runner
```

The runner must report `ready=True failures=none signature_probe=SIGNED_VERIFIED`. It has no host
port. The control plane exposes the profile through the existing scan API only when
`NUCLEI_ENABLED=true` and a fresh attestation matches all pins.

Live acceptance is `scripts/phase_1_2_acceptance.py`; execute it inside the control-plane container
with the internal control-plane and runner URLs. Expected result: vulnerable 5/5, patched-negative
5/5, three out-of-scope, three denied-capability and three template/RPC controls, with zero
unauthorized executions/traffic. See [operations](nuclei-operations.md) for failure codes and
[isolation](nuclei-runner-isolation.md) for topology checks.

The backend gate now includes all four source packages:

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api -p aegis_nuclei -p nuclei_runner && \
         pytest -q'
```

Never enable runtime updates, mount a template directory, add a credential/proxy variable or expose
the runner port. Any engine/template/signature mismatch is a stop condition, not an upgrade prompt.

## Phase 1.4 — BEAST MODE disposable adversary sandbox

Prerequisites: Docker/Compose, local Ollama, and the already-approved `qwen3:8b` digest. Never use
`AI_PROVIDER=demo`, a mock gateway or staging/production for Phase 1.4 acceptance. Generate fresh
boundary tokens in the shell without printing or persisting them, then combine the base, Ollama and
Beast overlays:

```bash
export AI_MODEL=qwen3:8b
export BEAST_SUPERVISOR_TOKEN="$(openssl rand -hex 32)"
export BEAST_BOUNDARY_TOKEN="$(openssl rand -hex 32)"
docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  -f docker-compose.beast.yml up -d --build
```

Confirm `control-plane`, `llm-gateway`, `lab-api`, `beast-target-gateway`, `beast-sandbox` and
`beast-rpc-relay` are healthy. The sandbox health must report bash, Python, curl, httpie, jq,
openssl, nmap, ffuf, sqlmap and Nuclei. Do not add a host mount, Docker socket, external network,
published sandbox port or extra capability.

Run the full live matrix inside the control-plane container. It performs five vulnerable and five
patched trials for each of four scenarios and fails rather than substituting commands:

```bash
docker exec ai-security-lab-control-plane-1 python scripts/phase_1_4_acceptance.py \
  --base-url http://10.213.47.10:8000 --trials 5 --control-trials 3 \
  --output /data/phase-1.4-live-model-acceptance.json
docker cp ai-security-lab-control-plane-1:/data/phase-1.4-live-model-acceptance.json \
  artifacts/phase-1.4-live-model-acceptance.json
docker cp ai-security-lab-control-plane-1:/data/phase-1.4-live-model-acceptance.json.sha256 \
  artifacts/phase-1.4-live-model-acceptance.json.sha256
```

When no Beast run is active, run the destructive boundary controls. These commands are acceptance
probes only and are not primary scenario commands:

```bash
docker exec ai-security-lab-control-plane-1 python scripts/phase_1_4_boundary_acceptance.py \
  --supervisor-url http://beast-rpc-relay:8094 \
  --output /data/phase-1.4-boundary-acceptance.json
```

The red `STOP BEAST MODE` action must be tested during a live command/model run. STOPPED must remain
terminal, the workspace must be destroyed, and preflight must reject reactivation until an operator
POSTs `/api/beast/targets/{target_ref}/restore` and the deterministic health probe succeeds.

Stop and preserve evidence on any wrong model/digest/runtime metadata, missing explicit stop,
repeated non-adaptive sequence, command not attributable to AI_MODEL, incomplete linkage, boundary
reachability, failed process-tree kill, failed cleanup or non-verifier conclusion. Such a result is
NO-GO; do not replace it with a controller-authored scan.

## Phase 1.3 — controlled ZAP passive OpenAPI profile

Build and start (combine with the Nuclei and dashboard overlays as needed):

```bash
docker compose -f docker-compose.yml -f docker-compose.zap.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.zap.yml logs zap-runner zap-scope-guard
```

The runner must report `runner-boot ready=True failures=none zap=2.17.0 ... addonlist_verified=True`
and the guard `guard-boot version=zap-scope-guard/1.3.0 allowed_origins=http://lab-api:8001`. The
first boot needs the pinned `zaproxy/zap-stable` index digest (~3.6 GB) locally or pullable at build
time; nothing is downloaded at runtime.

Request the capability through the existing scan API only:

```json
{"capability": "zap_passive_header_openapi_v1", "variant": "vulnerable"}
{"capability": "zap_passive_header_openapi_v1", "variant": "patched", "retest_of": "<scan id>"}
```

Never add a URL, OpenAPI document, plan, job, rule, option, header or credential — the request
schemas refuse them. Live acceptance (inside the control-plane container, host kept awake):

```bash
caffeinate -ims docker compose ... exec -T control-plane python - \
  --base-url http://10.213.47.10:8000 --runner-url http://zap-runner:8092 \
  < scripts/phase_1_3_acceptance.py > phase-1.3-live.json
docker exec -i <zap-runner> python3 - zap-runner < scripts/zap_topology_probe.py
docker exec -i <zap-scope-guard> python - zap-scope-guard < scripts/zap_topology_probe.py
docker run --rm --network none --read-only -v "$PWD/tests/fixtures:/fixtures:ro" \
  -v "$PWD/scripts:/scripts:ro" --entrypoint python3 aegis-zap-runner:1.3.0 \
  /scripts/zap_parser_controls.py /fixtures/zap-2.17.0-traditional-json-vulnerable.json
```

Reconcile the acceptance JSON with `docker logs <lab-api>` (by the guard's source IP) to count
unauthorized target traffic independently. The backend gate now covers seven packages:

```bash
mypy --explicit-package-bases -p aegis -p lab_api -p aegis_nuclei -p nuclei_runner \
     -p aegis_zap -p zap_runner -p zap_guard
```

Stop conditions (never "upgrade" at runtime): any image, jar, JVM or add-on drift; a forbidden add-on
id present; silent mode not confirmed; guard not attested. See
[Phase 1.3](phase-1.3-zap-passive-openapi.md) and the [troubleshooting](operator-console-troubleshooting.md)
failure codes.

## 1. Phase 0.9 one-command management demo

Prerequisites: Docker/Compose is running and the already-approved local `qwen3:8b` model is present
in Ollama on `127.0.0.1:11434`. The command performs its own fail-closed preflight, topology checks,
live discovery, linked patched retest, evidence packaging, and checksum generation:

```bash
scripts/run_management_demo.sh
```

Wait for `MANAGEMENT DEMO READY`, then open the printed `/demo?discovery=...&retest=...` URL. The
stack remains running for presentation. Cleanup affects only the `aegis-management-demo` project:

```bash
scripts/run_management_demo.sh --cleanup
```

Do not hand-edit or overwrite a failed run. Keep its artifacts as evidence, diagnose the failed
guard, and create a new run ID. See [Phase 0.9](phase-0.9.md). Phase 0.9 did not redesign or migrate
the engineering dashboard; the subsequently completed console is covered by the
[Phase 1.0 runbook section](#0-phase-10-operator-console) and
[Phase 1.0 design contract](phase-1.0-operator-console.md).

## 2. Choose a provider

| Goal | `AI_PROVIDER` | Notes |
| --- | --- | --- |
| Offline demo, no model | `demo` | default; no Ollama, no egress |
| Local/private model (dev) | `ollama` | `qwen3:4b` on this host, or `qwen3:8b` on a GPU host |
| Company private endpoint | `internal_openai_compatible` | disabled until real details supplied |
| Public OpenAI (deprecated) | `openai_responses` | disabled; not the deployment model |

## 3. Local Ollama (LOCAL_LLM)

Prerequisite (operator): install Ollama, then pull only the authorized model:

```bash
ollama --version          # confirm Ollama is installed
ollama pull qwen3:4b      # only this model is authorized without further approval
```

If Ollama is **not** installed, install it from the official source and re-run — do not proceed
without it. The macOS install step is: download and run the official installer from
<https://ollama.com/download> (or `brew install ollama` if you use Homebrew), then `ollama serve`.

Bring up the stack (native macOS Ollama reached via Docker `host-gateway`; no host rebinding):

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
               -f docker-compose.dashboard.yml up --build -d
```

Verify:

```bash
# control plane reports LOCAL_LLM
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane \
  python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read())"
# gateway reports ollama + the model
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane \
  python -c "import urllib.request;print(urllib.request.urlopen('http://llm-gateway:8080/health').read())"
```

Dashboard: <http://127.0.0.1:8000>.

### Switch models (configuration only)

```bash
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
# remote Ollama host (keep it private; do not bind Ollama to 0.0.0.0 without operator approval):
AI_BASE_URL=http://<gpu-host>:11434 AI_MODEL=qwen3:8b \
  docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
```

## 4. Phase 0.8 staged acceptance (deterministic execution queue)

Build the dev image, then run each stage per model. Recreate the stack with the model under test
(`AI_MODEL=<model> docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d`) before
its run. Narrow, control and extended evidence are written to separate files and must never be
overwritten or combined.

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-ai-security-lab-dev .

# Narrow 5/5 positive regression (run for BOTH models first — Part G).
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=narrow aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Controls — ONLY after a model passes narrow 5/5 (Part H): patched(5)+auth(3)+scope(3)+state(3).
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=controls aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Twenty-trial stability extension — ONLY for a model that passed narrow + controls.
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=extension aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Aggregate model comparison + candidate-rejection distribution + execution-policy audit.
docker run --rm --network none -v "$PWD":/work -w /work \
  aegis-ai-security-lab-dev python scripts/compare_phase_0_8.py
```

If neither model passes the narrow 5/5 positive regression, stop after evidence and diagnosis — do
not run controls or the extension and do not loosen a threshold. A NO-GO is a legitimate outcome; do
not retry a generation, coerce a response, or inject a replacement candidate. Phase 0.8 result: both
approved models GO (see [Phase 0.8](phase-0.8.md)). The superseded Phase 0.7 harness
(`scripts/phase_0_7_acceptance.py`, model-based selection) and its NO-GO evidence are retained
immutably.

## 5. Network isolation checks

```bash
# control plane must NOT reach the model endpoint or the internet (deny-all egress)
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane python -c "
import urllib.request
for u in ('http://host.docker.internal:11434/api/version','http://1.1.1.1'):
    try: urllib.request.urlopen(u,timeout=4); print('REACHABLE (BAD)',u)
    except Exception as e: print('blocked (good)',u,type(e).__name__)"
# gateway MUST reach the pinned Ollama endpoint
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T llm-gateway python -c "
import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:11434/api/version',timeout=6).read())"
```

## 5a. Control-plane readiness gate (fail-closed)

The control plane exposes two distinct probes:

- `GET /health` — **liveness**. Answers `200 {"status":"ok"}` as soon as the process is up. Use it
  only to detect a hung/dead process.
- `GET /ready` — **readiness**, fail-closed. Answers `200` with `{"ready": true, ...}` only when the
  control plane is safe to serve, and `503` with `{"ready": false, ...}` otherwise. Route production
  traffic and gate rollouts on this, never on `/health`.

`/ready` runs deterministic, side-effect-free checks (it never writes or creates a database) and
treats any state it cannot positively confirm as **NOT_READY**:

- `persistence` — at probe time, the SQLite path must be an existing regular file, its parent must
  have write permission, the filesystem must report caller-available blocks, SQLite must open the
  existing file with `mode=rw`, and the required tables **and columns** must exist. Missing storage,
  zero available capacity, read-write open failure, malformed schema or an ambiguous filesystem/
  SQLite result is `NOT_READY`. The probe is a point-in-time signal: it cannot guarantee that space
  or write availability will remain unchanged after the response.
- `credential_isolation` — the control plane holds no provider credential (`AI_AUTH_TOKEN` /
  `DEEPSEEK_API_KEY`). Only credential *presence* is inspected; the value is never read or emitted.

The base `docker-compose.yml` wires the `control-plane` service healthcheck to `/ready`, so a
control plane that is up but not safe-to-serve is reported **unhealthy** to the orchestrator. Manual
check:

```bash
# 200 + {"ready": true, ...} when safe to serve; 503 + {"ready": false, ...} otherwise.
docker compose -f docker-compose.yml exec -T control-plane \
  python -c "import urllib.request,sys; \
    r=urllib.request.urlopen('http://127.0.0.1:8000/ready'); print(r.status, r.read().decode())" \
  || echo 'NOT_READY (503) — control plane is failing closed as designed'
```

## 5b. Observability — logging, metrics, alerts (WP3 / G-OBS-1)

Full detail: [production-readiness-wp3.md](production-readiness-wp3.md).

**Structured logs.** Both services emit bounded, secret-free JSON to **stdout** (schema
`obslog-v1`). Records contain only: `schema_version, timestamp_utc, level, service, event,
request_id, method, route (normalized template or UNMATCHED), status_code, status_class,
duration_ms, code, exception_class`. They **never** contain bodies, query strings, cookies, auth
headers, credentials, target URLs, raw evidence, model output, `str(exception)`, or raw paths.
Uvicorn's raw access log is disabled (`--no-access-log` + startup disable). `/health` and `/metrics`
scrapes are not logged; `/ready` logs only when it fails closed.

```bash
# One line of structured JSON per request (redacted, bounded):
docker compose -f docker-compose.yml logs --no-log-prefix control-plane | tail -5
```

**Metrics.** Internal-only `GET /metrics` (Prometheus text) on both services — **no host port, no
public ingress**; reachable only inside the `security-lab` network. Fixed metric names:
`aegis_http_requests_total`, `aegis_http_responses_total`, `aegis_http_request_duration_seconds`,
`aegis_http_in_flight_requests`, `aegis_process_start_timestamp_seconds`, `aegis_readiness_ready`,
`aegis_readiness_check`, `aegis_scan_completions_total`. Labels are bounded (service, allowlisted
method, normalized route, status class, controller enums); unknown values collapse to
`OTHER`/`UNMATCHED`; distinct routes are hard-capped at 64.

```bash
# Scrape from inside the internal network (no port is published to the host):
docker compose -f docker-compose.yml exec -T control-plane \
  python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/metrics').read().decode()[:400])"
```

**Alerts.** Version-controlled rules: [`deploy/observability/alerts.yml`](../deploy/observability/alerts.yml)
(control plane not ready, persistence/readiness failure, elevated 5xx, high p95 latency, restart
loop). These are **policy only**.

**NOT_EVALUATED.** External log aggregation/rotation/retention, any Prometheus scraper and its
storage, and alert-manager firing/delivery are **not deployed or tested** here.

**Operational constraints (accepted / out of scope).** SQLite data is disposable/reconstructible:
**no backup, recovery-point, or recovery-time guarantee** (no backup coverage, HA, enterprise
durability, or DR is claimed). Application-specific incident response is not provided —
organizational/platform IR applies externally. The deployment is strictly **single-replica,
single-writer**; horizontal scaling, multiple workers, and concurrent writers are unsupported, and
any future change here must reopen the SQLite concurrency/locking evaluation.

## 6. Production (company private AI endpoint)

Supply the real institutional details (endpoint, model, auth) — the provider is disabled until then:

```dotenv
# .env
AI_PROVIDER=internal_openai_compatible
AI_BASE_URL=https://<company-endpoint>
AI_MODEL=<company-approved-model>
AI_ALLOWED_MODELS=<company-approved-model>
AI_AUTH_MODE=none|bearer
```

If `AI_AUTH_MODE=bearer`, put the credential only in an untracked `.env.gateway`:

```dotenv
# .env.gateway  (mounted only into llm-gateway; never in .env, chat or a commit)
AI_AUTH_TOKEN=<company-issued token>
```

The control plane refuses to start if `AI_AUTH_TOKEN` is present in its own environment.

## 6a. Deterministic base-image deploy + rollback (WP2 / G-ROLL-1)

> **Scope.** This section covers ONLY the deterministic, digest-pinned deployment of the two base
> long-lived services, **`control-plane` and `lab-api`**. It does **not** stand up a model provider.
>
> **The complete provider-backed production deployment path is NOT_READY / NOT_EVALUATED.** The only
> provider overlays that exist today are the public-egress profiles: `docker-compose.provider.yml`
> forces the **deprecated public OpenAI** profile (`AI_PROVIDER=openai_responses`), and
> `docker-compose.deepseek.yml` / `docker-compose.ollama.yml` are likewise not the company-private
> production model. **Do not** use `docker-compose.provider.yml` for the company-private endpoint. A
> dedicated private-provider **production** overlay (digest-pinned `llm-gateway`, private
> `AI_BASE_URL`, no public egress) has **not** been implemented or evaluated; until it is, treat
> production as base-services-only and gate any provider rollout on that future work (§6, §7).

The base stack builds `control-plane`/`lab-api` locally (`build: .`), which is fine for local/demo
use but is **not** deterministic for production. The production overlay
[`docker-compose.prod.yml`](docker-compose.prod.yml) removes that local-build fallback and pins both
services to a single **immutable image digest**, so a rollout — and its rollback — restore exact bits.

- Reference form (required): `registry/repository@sha256:<64 lowercase hex characters>` with an
  explicit registry host and at least one repository component. A mutable tag (`latest`, `0.2.0`), a
  bare/local name (`aegis@sha256:…`), and a tag+digest reference are all rejected.
- The digest is **not** a secret. **Never** put registry or provider credentials in `AEGIS_IMAGE`, in
  the overlay, in scripts, or in deploy logs. Registry auth is your own `docker login` (its credentials
  live in the Docker credential store).
- Both services run non-root (`USER 10001:10001`) with `read_only` rootfs, `no-new-privileges`, and
  the resource/restart limits from the base compose (mem `512m`/`256m`, cpus `1.0`/`0.5`, pids
  `256`/`128`, `restart: unless-stopped`). These are containment ceilings, **not** a load-test SLO.

**Record the current digest** (before changing anything):

```bash
# Save the digest you are currently running so you can roll back to it.
docker compose -f docker-compose.yml -f docker-compose.prod.yml config | grep -E '^\s+image:' | sort -u
```

**Deploy a new digest** — the preflight is mandatory and always renders + proves the merged config
(there is no bypass); it exits non-zero on a missing/tag-only/`latest`/bare/tag+digest/malformed/
non-`sha256` reference **or** if the rendered config cannot be proven (Docker/Compose unavailable,
timeout, render failure, invalid output):

```bash
export AEGIS_IMAGE=registry.example.com/aegis@sha256:<64-hex>
python -m aegis.deploy.preflight
# Base services only — do NOT add docker-compose.provider.yml (see scope note above):
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
# Gate on readiness, never on /health:
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec -T control-plane \
  python -c "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8000/ready'); print(r.status)"
```

**Roll back** — restore the prior digest you recorded and repeat the preflight + `up -d` + `/ready`
check:

```bash
export AEGIS_IMAGE=<prior recorded digest>
python -m aegis.deploy.preflight
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### First-time non-root `aegis-data` volume migration — NOT_EVALUATED

A fresh `aegis-data` volume inherits `/data`'s ownership (`10001:10001`) from the image, so the
non-root control plane can write it. A volume created by an **older root build** stays root-owned and
must be migrated once before upgrading. The procedure below is **documented but NOT executed here** —
validate it in staging on a disposable copy before touching a real volume. Use a **pinned-digest**
tool image (the repo's already-trusted `python:3.12-slim` digest), never a mutable tag:

```bash
PROJECT=<compose-project-name>
PY=python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

# 1. Stop the stack so nothing writes /data during migration.
docker compose -f docker-compose.yml -f docker-compose.prod.yml -p "$PROJECT" down

# 2. Back up the volume first (restore point) — keep this archive off the box.
docker run --rm -v "${PROJECT}_aegis-data":/data -v "$PWD":/backup "$PY" \
  tar czf "/backup/aegis-data-backup-$(date +%Y%m%dT%H%M%SZ).tgz" -C /data .

# 3. Migrate ownership to the non-root runtime UID/GID.
docker run --rm -v "${PROJECT}_aegis-data":/data "$PY" chown -R 10001:10001 /data

# 4. Verify ownership before restarting.
docker run --rm -v "${PROJECT}_aegis-data":/data "$PY" \
  stat -c '%u %g %a' /data /data/aegis.db     # expect: 10001 10001 (dir 700)

# 5. Restart and gate on readiness.
docker compose -f docker-compose.yml -f docker-compose.prod.yml -p "$PROJECT" up -d
docker compose -f docker-compose.yml -f docker-compose.prod.yml -p "$PROJECT" exec -T control-plane \
  python -c "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8000/ready'); print(r.status)"

# 6. Rollback (only if readiness fails): restore the backup and revert to the prior image digest.
#    docker run --rm -v "${PROJECT}_aegis-data":/data -v "$PWD":/backup "$PY" \
#      sh -c 'rm -rf /data/* && tar xzf /backup/aegis-data-backup-<STAMP>.tgz -C /data'
#    export AEGIS_IMAGE=<prior recorded digest>; python -m aegis.deploy.preflight
#    docker compose -f docker-compose.yml -f docker-compose.prod.yml -p "$PROJECT" up -d
```

Not covered (see [production-readiness-wp2.md](production-readiness-wp2.md)): runtime digest **pull**
verification (NOT_EVALUATED — no registry image available to pull); the **provider-backed** production
path incl. a private-provider/`llm-gateway` overlay (NOT_READY / NOT_EVALUATED); execution of the
volume migration above (NOT_EVALUATED); and volume backup/restore automation.

## 7. Quality gates

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'
```

## 8. Tear down (keep evidence)

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml -f docker-compose.dashboard.yml down
```

`artifacts/` is git-ignored and holds generated evidence; it never contains model secrets or raw
sensitive values.

## 9. Phase 0.5 — Contract V2 benchmark (reproduce)

Only the planner contract changed from Phase 0.4; all other variables are frozen. Bring the stack up
per §2, then run five isolated trials per model into **separate** evidence files (never overwrite the
immutable V1 baselines):

```bash
# qwen3:4b (no repair)
AI_MODEL=qwen3:4b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:4b \
  -e LOCAL_EVIDENCE_PATH=artifacts/contract-v2-qwen3-4b-no-repair.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py

# foundation-sec:8b-q4 (recreate the stack with the model first, then run)
AI_MODEL=foundation-sec:8b-q4 docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
AI_MODEL=foundation-sec:8b-q4 docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=foundation-sec:8b-q4 \
  -e LOCAL_EVIDENCE_PATH=artifacts/contract-v2-foundation-sec-no-repair.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py
```

Read-only post-processing (never re-runs a scan, never touches the V1 baselines):

```bash
export PYTHONPATH="$PWD/src:$PWD/scripts"
python scripts/build_failure_matrix.py                 # Part A: artifacts/contract-v1-failure-matrix.json
python scripts/compare_contracts.py \
  --v1 qwen3:4b=artifacts/local-llm-acceptance.json \
       foundation-sec:8b-q4=artifacts/foundation-sec-acceptance.json \
  --v2-no-repair qwen3:4b=artifacts/contract-v2-qwen3-4b-no-repair.json \
                 foundation-sec:8b-q4=artifacts/contract-v2-foundation-sec-no-repair.json
```

Result: NO-GO for both models under Contract V2 (no repair) — V2 removes the structural/evidence-
reference rejections (0/0) but both small models under-act at discovery (terminal `review`/`stop`).
Part D (bounded repair) precondition is not met (zero validation failures) and is not implemented.
See [Phase 0.5](phase-0.5.md).

## 10. Phase 0.6 — qwen3:8b under the unchanged Contract V2 harness (reproduce)

Only the **model** changed from Phase 0.5; every other variable is frozen. `qwen3:8b` is already in
`AI_ALLOWED_MODELS`, so no allowlist change is needed. Select the model **inline per run** and write
to a **separate** evidence file so no baseline is overwritten. Optionally set the dashboard status to
`LOCAL_LLM_QWEN8B_TESTING` while evaluating (configuration only, in `.env`).

```bash
# Bring the stack up on qwen3:8b (per §2, model selected inline)
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  -f docker-compose.dashboard.yml up --build -d

# Five isolated trials -> new evidence file
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e LOCAL_EVIDENCE_PATH=artifacts/qwen3-8b-acceptance.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py
```

Read-only post-processing (three-model Contract V2 comparison + terminal-decision distribution; never
re-runs a scan, never touches any baseline):

```bash
PYTHONPATH="$PWD/src:$PWD/scripts" python scripts/compare_phase_0_6.py
# -> artifacts/phase-0.6-three-model-comparison.json
# -> artifacts/phase-0.6-terminal-decision-distribution.json
```

Topology + secret scan under the evaluated model, and offline quality gates:

```bash
AI_MODEL=qwen3:8b bash scripts/ollama_topology_tests.sh > artifacts/ollama-topology-qwen3-8b.txt
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'
```

Result: **NO-GO for `qwen3:8b`** — 5/5 valid terminal `review` at the generative discovery step
(identical to `qwen3:4b`), 0/5 hypothesis. Because more than one of five trials terminated instead of
hypothesizing, the Part E path applied: the benchmark stopped after evidence + diagnosis, the Part D
twenty-trial run was NOT started, and no schema repair / forced hypothesis / hard-coded sequence /
prompt edit / silent retry was performed. A proposal-only Phase 0.7 design is in
[Phase 0.6 §7](phase-0.6.md). Keep `.env` `AI_MODEL` at the committed `qwen3:4b` default after the run
so the model-agnostic offline suite stays deterministic (the Phase 0.5 `.env` was backed up to
`.env.phase-0.5.bak`).
