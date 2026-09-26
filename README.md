# Aegis AI Security Lab

A bounded, guardrailed **multi-agent security-testing runtime** that runs against a set of
**synthetic, internal-only** vulnerable applications. An LLM proposes read-only security
hypotheses under strict typed schemas; a deterministic controller validates, authorizes,
executes and verifies them. Findings are only ever confirmed by an independent deterministic
verifier — never by the model.

> ⚠️ **Not production-ready as a general tool. No external or production targets are authorized.**
> Every scan is limited to the documented synthetic range (or a separately approved private test
> environment). Application data must **never** be sent to OpenAI or any public AI provider.

- Python **3.12**, packaged as `aegis-ai-security-lab` (`src/` layout).
- Runs entirely offline by default (`DEMO_HEURISTIC`) — no model, no `.env`, no egress.
- Docker Compose is the supported runtime; overlays add a local LLM, a dashboard, or production.

---

## Table of contents

1. [Architecture](#architecture)
2. [Deployment modes](#deployment-modes)
3. [Requirements](#requirements)
4. [Quick start — offline demo (no model)](#quick-start--offline-demo-no-model)
5. [Local LLM demo (Ollama)](#local-llm-demo-ollama)
6. [Operator Console](#operator-console)
7. [Production deployment](#production-deployment)
8. [Development & quality gates](#development--quality-gates)
9. [Compose file reference](#compose-file-reference)
10. [Safety & budgets](#safety--budgets)
11. [Phase history](#phase-history)
12. [Further documentation](#further-documentation)

---

## Architecture

The model path is split across services so a compromised model loop cannot become arbitrary
egress or leak a credential (full map in [Phase 0.3](docs/phase-0.3.md)):

- **control-plane** — orchestrates each decision over the internal `planner-rpc` network. Holds
  **no** credential (refuses to start if `AI_AUTH_TOKEN`/provider token is present), keeps
  deny-all direct egress, and never reaches the model endpoint.
- **llm-gateway** — the **only** component that talks to a model endpoint and the only credential
  holder. It selects a typed `PlannerProvider` from `AI_PROVIDER`:

  ```
  PlannerProvider
    ├── DemoHeuristicProvider            (offline heuristic, no model)
    ├── OllamaProvider                   (native /api/chat, LOCAL_LLM)
    ├── InternalOpenAICompatibleProvider (company /chat/completions, INTERNAL_LLM)
    └── OpenAIResponsesProvider          (deprecated public profile; disabled)
  ```

  Every provider pins scheme/host/port/path, disables redirects and env-proxy inheritance, bounds
  response size and timeout, sends the strict planner JSON Schema, and re-validates the returned
  content with Pydantic. It **fails closed** on malformed JSON, schema violations, model mismatch,
  timeout, redirects, oversized bodies, or an unexpected endpoint — and never lets the model choose
  its own model name or endpoint.

- **lab-api** — the synthetic vulnerable range (bank/shop/ops/etc.), internal-only.
- **dashboard** (optional overlay) — a non-root Nginx proxy bound to **127.0.0.1:8000**, the only
  ingress; it holds no credentials and its upstream is fixed to the control plane.

The multi-agent runtime (Phase 1.7+) adds Lead Orchestrator, Recon, Surface, Authorization,
Injection/Chain, Report and Cloud-Boundary agent roles. Agent messages are strict and typed;
targets, credentials and resources stay controller-owned references; per-agent and global budgets
are atomic; replayed/stale/spoofed/unauthorized actions fail closed.

---

## Deployment modes

The **same code** runs all modes. Switching models or providers is **configuration only** — no
source change.

| Mode | `AI_PROVIDER` | Provider | Egress |
| --- | --- | --- | --- |
| `DEMO_HEURISTIC` | `demo` | offline heuristic rules (no model — never call this "AI") | none |
| `LOCAL_LLM` | `ollama` | private Ollama (`qwen3:4b` dev; `qwen3:8b` / `foundation-sec:8b-q4` GO under [Phase 0.8](docs/phase-0.8.md)) | gateway → Ollama only |
| `INTERNAL_LLM` | `internal_openai_compatible` | company private OpenAI-compatible endpoint | gateway → company endpoint only |

The deprecated public OpenAI Responses path is retained as a **disabled** compatibility profile and
must not be used as a default.

---

## Requirements

- **Docker** with Compose v2 (`docker compose`). Check the daemon with `make docker-check`.
- **Python 3.12** — only needed for the local dev workflow (`make venv`); the containers ship it.
- **Ollama** (local or on a GPU box) — only for `LOCAL_LLM` mode.
- For the [standalone RHEL/Fedora production stack](docs/aegis-ai-prod-rhel.md): rootless
  **Podman** + SELinux.

---

## Quick start — offline demo (no model)

The default config needs no `.env`, no Ollama and no egress:

```bash
docker compose -f docker-compose.yml -f docker-compose.dashboard.yml up --build -d
mkdir -p artifacts
docker compose exec -T control-plane python - < scripts/demo_e2e.py > artifacts/phase-0.2-e2e.json
```

Expected end-to-end: import the lab OpenAPI, collect owner controls (`user_a → A-100`,
`user_b → B-200`), test the BOLA route `user_a → B-200` (returns 200 + the wrong owner's account)
→ deterministic `HIGH/CONFIRMED` `FAIL`; then the patched route returns 403 → deterministic scoped
`PASS`. The agent never modifies code or target state. `PASS` means this fixture's authorization
comparison passed — not that the application is secure.

---

## Local LLM demo (Ollama)

Development host reference: Apple M4 Air, native Ollama, model `qwen3:4b`.

**1. Operator step — install Ollama and pull the model:**

```bash
ollama pull qwen3:4b        # ~2.5 GB; the only model authorized without further approval
```

**2. Bring up the stack with the Ollama overlay** (native Ollama reached via Docker's host-gateway):

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
               -f docker-compose.dashboard.yml up --build -d
```

Open <http://127.0.0.1:8000>, choose **Discover vulnerability**, then **Retest patched endpoint**.
The dashboard shows mode (`LOCAL_LLM`), exact model, runtime/version, model digest, context length,
temperature, seed, token/timing usage, safety approvals, deterministic verification, and the linked
retest.

Ollama keeps its default localhost binding — **no host port is published for it**; it is not exposed
to the LAN.

**Switch models with configuration only** (model must be in `AI_ALLOWED_MODELS`):

```bash
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
```

For a remote Ollama host: set `AI_BASE_URL=http://<host>:11434` (keep it private; do not bind Ollama
to `0.0.0.0` without explicit operator approval).

---

## Operator Console

After the supported stack is up:

- **Operator Console** — <http://127.0.0.1:8000/console/>
- **Engineering dashboard** — <http://127.0.0.1:8000/>
- **Multi-agent read-only view** — <http://127.0.0.1:8000/multi-agent>
- **Phase 0.9 management view** — `/demo?discovery=<scan>&retest=<scan>`

The console provides Mission Control, Runs, Findings, Audit, Evidence, Integrations and System
Health. All projections are redacted: findings stay verifier-owned; API evidence cards exclude
response bodies and credentials; browser screenshots are disabled by default.

Reference: [console architecture](docs/operator-console-architecture.md),
[event envelope](docs/audit-event-envelope.md),
[troubleshooting](docs/operator-console-troubleshooting.md).

### One-command management demo

With Docker and the approved local `qwen3:8b` Ollama model available:

```bash
scripts/run_management_demo.sh            # runs a real-model discovery + linked patched retest
scripts/run_management_demo.sh --cleanup  # remove only that Compose project
```

---

## Production deployment

The default production path uses a **company-private OpenAI-compatible endpoint**. An explicit,
separately isolated OpenRouter/Qwen3.8 27B profile is also available when public AI egress is an
accepted deployment constraint; it is never selected implicitly.

Status: the deployment path is `DEPLOYMENT_PATH_READY` (repository/config checks complete). Real
registry pull, private endpoint/TLS/model validation, and staging soak/failure evidence remain
environment-specific activation gates — see [production readiness WP5](docs/production-readiness-wp5.md)
and the [operator runbook §6](docs/runbook.md#6-production-company-private-ai-endpoint).

### A) Docker Compose — immutable image + private provider

Images are pinned by **sha256 digest** (a digest cannot move the way `latest` can). The bearer token
is supplied as a **read-only host file** mounted only into `llm-gateway`; it never enters a Compose
environment, rendered config, image, command line, or the control-plane process.

```bash
export AEGIS_IMAGE=registry.example.com/aegis@sha256:<64-hex>
export AEGIS_PROVIDER_MODEL=<your-model-id>

python -m aegis.deploy.preflight                    # fail-closed render + validation, no pull/start
python -m aegis.deploy.private_provider_preflight   # validate provider inputs (non-secret)

docker compose -f docker-compose.yml \
               -f docker-compose.prod.yml \
               -f docker-compose.private-provider.prod.yml up -d

curl --fail http://127.0.0.1:8000/ready             # 200 {"ready":true} when safe to serve
```

`make production-preflight` proves the immutable topology without pulling, starting, or calling
anything. Registry auth is the operator's own `docker login` (credentials live in the Docker
credential store, never in these files).

### B) Standalone Fedora/RHEL — rootless Podman + SELinux

The single-file definition is [`aegis-ai-prod.yml`](aegis-ai-prod.yml): rootless Podman, SELinux,
digest-pinned images, a gateway-only token file, and loopback-only ingress.

```bash
make aegis-ai-prod-preflight CONTAINER_ENGINE=podman
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml pull
podman compose -p aegis-ai-prod -f aegis-ai-prod.yml up -d
curl --fail http://127.0.0.1:8000/ready
```

Environment variables, host/user preparation, the systemd service, TLS ingress, update and rollback
commands are in the [Fedora/RHEL runbook](docs/aegis-ai-prod-rhel.md). The bearer token value is
never placed in the environment — it is a SELinux-labelled read-only file mounted only into
`llm-gateway`.

### Operational gates

- **Readiness** — `/ready` returns `200` only when safe to serve, `503` otherwise
  ([runbook §5a](docs/runbook.md)).
- **Observability** — secret-free structured JSON logging + bounded internal `/metrics` + alert
  policy in `deploy/observability/` ([WP3](docs/production-readiness-wp3.md)).
- **Graceful shutdown** — bounded drain on `SIGTERM` (15-second Compose stop bound).
- **Staging gate** — read-only soak/failure observer: `make staging-gate MODE=healthy SAMPLES=12`.
- **Cleanup** — `make cleanup-check` fails if any `aegis`-labelled container or network is left
  behind.

### OpenRouter + Qwen3.8 27B (explicit opt-in)

The OpenRouter profile pins the exact model ID `qwen/qwen3.8-27b`, requires strict JSON Schema
support, requests ZDR and denies provider data collection on every call. The key is mounted only
into `llm-gateway`; a CONNECT proxy restricts public egress to `openrouter.ai:443`.

```bash
export OPENROUTER_API_KEY_SOURCE=/absolute/path/openrouter-api-key
docker compose -f docker-compose.yml -f docker-compose.openrouter.yml up --build -d
```

For immutable Fedora/RHEL production deployment, SELinux file labels, extension-manifest examples,
verification, update and rollback commands, see the
[OpenRouter/Qwen deployment guide](docs/openrouter-qwen38.md).

### Extensions

A declarative extension manifest can add bounded prompt guidance, agent profiles over existing
roles, and tool aliases for **already-registered** capability/profile pairs only. It **cannot** load
arbitrary code, commands, URLs, new capabilities, or new authority.

---

## Development & quality gates

```bash
make venv        # create the venv (Python 3.12) and install the project + dev deps
make lint        # ruff across the repo
make typecheck   # mypy (python_version=3.12)
make test        # full offline test suite
make check       # CI-equivalent: lint + typecheck + full suite (no secrets, no egress)
```

Containerized equivalent (no host toolchain, network isolated):

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api -p aegis_nuclei -p nuclei_runner \
              -p aegis_zap -p zap_runner -p zap_guard && \
         pytest -q'
```

Other useful `make` targets: `docker-check`, `range-image` (build the pinned egress-free range image;
needs `make vendor-range-wheels` first), `container-acceptance`, `test-artifact-empty`.

Run `make help` for the full list.

---

## Compose file reference

Base stack + overlays are layered with repeated `-f` flags. The base runs both application services
on internal-only networks with **no published host port**.

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Base stack (control-plane + lab-api, internal networks only) |
| `docker-compose.dashboard.yml` | Optional loopback-only Nginx ingress on `127.0.0.1:8000` |
| `docker-compose.ollama.yml` | `LOCAL_LLM` overlay — private Ollama provider |
| `docker-compose.deepseek.yml` | DeepSeek OpenAI-compatible gateway overlay (live-provider smoke) |
| `docker-compose.openrouter.yml` | OpenRouter + exact `qwen/qwen3.8-27b` isolated gateway overlay |
| `docker-compose.openrouter.prod.yml` | Immutable image enforcement for the OpenRouter overlay |
| `docker-compose.provider.yml` | Generic provider/gateway overlay |
| `docker-compose.prod.yml` | Production overlay — immutable digest-pinned images |
| `docker-compose.private-provider.prod.yml` | Company-private OpenAI-compatible provider overlay |
| `docker-compose.dashboard.prod.yml` | Production ingress overlay |
| `aegis-ai-prod.yml` | Standalone Fedora/RHEL production stack (rootless Podman + SELinux) |
| `docker-compose.range.yml` | Synthetic vulnerable application range (Phase 1.6) |
| `docker-compose.nuclei.yml` | Controlled Nuclei profile (Phase 1.2) |
| `docker-compose.zap.yml` | Passive ZAP OpenAPI profile (Phase 1.3) |
| `docker-compose.zap-active.yml` | Isolated active reflected-XSS ZAP profile (Phase 1.5) |
| `docker-compose.beast.yml` | BEAST MODE disposable adversary sandbox (Phase 1.4, synthetic only) |
| `docker-compose.phase-1-7*.yml` | Multi-agent runtime overlays (recon / combined / 1.7-A) |
| `docker-compose.mock-egress.yml` | Mock egress endpoint for isolation tests |

---

## Safety & budgets

- **Scope** — exact hostname allowlist; same-origin scheme/host/port, including OpenAPI import.
  Only the selected lab account route, synthetic object IDs and credential profiles are authorized.
- **Methods** — only `GET`, `HEAD`, `OPTIONS` are representable; only fresh `GET` evidence can prove
  a BOLA test.
- **Input hardening** — strict schemas forbid arbitrary headers, bodies, URLs, shell commands, or
  extra tools. Encoded paths, traversal, query strings, fragments and authority overrides are
  rejected. OpenAPI descriptions/examples/servers/refs/extensions never enter the model context.
- **Evidence isolation** — model observations carry fixed identity + status metadata, never raw
  response bodies. Target credentials are resolved only by the executor and redacted.
- **Budgets** — default max **8 target requests (incl. import)**, 6 iterations, 6 model calls;
  bounded response bodies, no redirects, bounded total scan time (300 s scan / 90 s model default
  for local inference). Token admission uses conservative cumulative reservations (an admission
  policy, not billing).
- **Fail-closed verdicts** — budget exhaustion, missing evidence and errors can never become `PASS`.
  Confirmed findings stay `FAIL` even if a later step fails. Review requests and safety rejections
  are always visible.

### Honest labels

- `DEMO_HEURISTIC` — observation-dependent offline rules. **No model calls; never describe it as AI.**
- `LOCAL_LLM` / `INTERNAL_LLM` — real model adapters with schema-constrained decisions. Ollama runs
  are labelled `LOCAL_LLM`, never `LIVE_LLM`.
- Verification is always **deterministic**. Decision summaries are short explanations, not hidden
  chain-of-thought (never stored or displayed). SQLite audit records are persisted, not
  tamper-proof.

Future production work still requires authenticated onboarding, ownership approval, SSO/RBAC,
central immutable audit, encrypted secret storage, global concurrency/rate limits, a kill switch,
retention policies and dedicated egress enforcement. These are **not** implemented by this lab.

---

## Phase history

Each phase is an incremental, independently verdicted increment. Full evidence lives in `docs/`.
GO verdicts are scoped to the synthetic lab — never production or broad-coverage claims.

| Phase | Increment | Status |
| --- | --- | --- |
| [0.2](docs/phase-0.2.md) / [0.3](docs/phase-0.3.md) | Offline BOLA e2e; split provider architecture | GO (synthetic) |
| [0.4](docs/phase-0.4.md)–[0.7](docs/phase-0.7.md) | Local-model contract iterations (V1/V2, model-based selection) | NO-GO (preserved) |
| [0.8](docs/phase-0.8.md) | Deterministic execution queue; local-model acceptance matrix | GO — `qwen3:8b` & `foundation-sec:8b-q4` |
| [0.9](docs/phase-0.9.md) | Reproducible synthetic-lab management demo | GO (synthetic) |
| [1.0](docs/phase-1.0.md) | Aegis Operator Console (React/TS) | GO (localhost console) |
| [1.1](docs/phase-1.1-security-tool-kernel.md) | Provider-independent security-tool integration kernel | GO (bounded BOLA via engine) |
| [1.2](docs/phase-1.2-nuclei-integration.md) | Controlled Nuclei profile (one signed template) | GO (one synthetic capability) |
| [1.3](docs/phase-1.3-zap-passive-openapi.md) | Passive-only ZAP OpenAPI profile | GO (one passive capability) |
| [1.4](docs/phase-1.4-beast-mode.md) | BEAST MODE disposable adversary sandbox | Synthetic-lab only |
| [1.5](docs/phase-1.5-zap-active-reflected-xss.md) | Narrow active reflected-XSS ZAP profile (single-use lease) | **GO** (one rule, one endpoint) |
| [1.6](docs/phase-1.6-aegis-vulnerable-application-range.md) | Vulnerable application range: 4 apps, 19 scenarios, 3 chains | Catalog increment |
| [1.7](docs/phase-1.7-multi-agent-runtime.md) | Multi-agent runtime (Lead/Surface/Auth; [recon](docs/phase-1.7-controlled-recon.md), injection/chain) | Offline-accepted; live 1.7-A **NO-GO** (`PROVIDER_MODEL_MISMATCH`) |
| [1.8](docs/phase-1.8-report-agent.md) | Report agent | Offline-accepted |
| [1.9](docs/phase-1.9-cloud-boundary-agent.md) | Cloud-boundary agent | Increment |
| [2.0](docs/phase-2.0-closure.md) | Multi-primitive causal chain | Increment |

Repository history begins at the Phase 1.1 baseline; see [repository provenance](docs/repository-provenance.md).
The canonical, always-current status is [`PROJECT_STATE.md`](PROJECT_STATE.md).

---

## Further documentation

- **Operator runbook** — [docs/runbook.md](docs/runbook.md)
- **Production readiness** — [WP1](docs/production-readiness-wp1.md) ·
  [WP2](docs/production-readiness-wp2.md) · [WP3](docs/production-readiness-wp3.md) ·
  [WP4](docs/production-readiness-wp4.md) · [WP5](docs/production-readiness-wp5.md) ·
  [gap audit](docs/production-readiness-gap-audit-wp1.md)
- **Threat model** — [docs/threat-model-tool-integrations.md](docs/threat-model-tool-integrations.md)
- **Tool integration internals** — Nuclei
  ([supply chain](docs/nuclei-template-supply-chain.md), [isolation](docs/nuclei-runner-isolation.md),
  [ops](docs/nuclei-operations.md), [evidence](docs/nuclei-evidence-and-verification.md)); ZAP
  ([runner isolation](docs/zap-runner-isolation.md), [OpenAPI projection](docs/zap-openapi-projection.md),
  [rule manifest](docs/zap-passive-rule-manifest.md), [evidence](docs/zap-evidence-and-verification.md))
- **Engine adapter contract** — [docs/engine-adapter-contract.md](docs/engine-adapter-contract.md)
- **Finding/evidence schema** — [docs/normalized-finding-evidence-schema.md](docs/normalized-finding-evidence-schema.md)
- **Canonical project state** — [PROJECT_STATE.md](PROJECT_STATE.md)
