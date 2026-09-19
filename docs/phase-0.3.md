# Phase 0.3 — Local/Private LLM Acceptance

## Scope

The production environment must **not** send application data to OpenAI or any public AI provider.
The public OpenAI live-call plan is cancelled. Phase 0.3 makes the same code run against:

1. a local Ollama model in development (`qwen3:4b` on Apple M4 Air, native runtime);
2. a larger local Ollama model on another host (`qwen3:8b`, Fedora + RTX 4070) — configuration only;
3. the company's private, internal OpenAI-compatible endpoint in production.

Public AI egress is not the intended deployment model. The former public-OpenAI/Squid topology is
retained only as an optional, **disabled** compatibility profile (`AI_PROVIDER=openai_responses`).

No production readiness, broad vulnerability coverage, or immutable audit is claimed.

## Provider-agnostic control plane + typed gateway providers

The control plane contains **no** Ollama-, OpenAI- or company-specific request logic. It maps
`AI_PROVIDER` to a mode label only and speaks a single internal planner/gateway contract. All
provider specifics live behind a typed interface on the isolated gateway:

```
PlannerProvider                                   AI_PROVIDER            mode label
  ├── DemoHeuristicProvider                        demo                   DEMO_HEURISTIC
  ├── OllamaProvider                               ollama                 LOCAL_LLM
  ├── InternalOpenAICompatibleProvider             internal_openai_...    INTERNAL_LLM   (disabled)
  └── OpenAIResponsesProvider                      openai_responses       PUBLIC_LLM_DEPRECATED
```

`GatewayPlanResponse` carries only a validated `AgentDecision`, provider-reported `usage`, and
non-secret `ProviderRunMetadata` (provider type, runtime + version, model, digest, context length,
temperature, seed, prompt/eval token counts, timing, stop reason). Ollama runs are `LOCAL_LLM`,
never `LIVE_LLM`.

### OllamaProvider (LOCAL_LLM)

- Native `POST /api/chat`, `stream: false`.
- The strict planner Pydantic JSON Schema is passed through Ollama's `format` field; the returned
  content is **re-validated** with Pydantic (`AgentDecision`).
- Non-thinking mode (`think: false`): no separated chain-of-thought. A probe confirmed `qwen3:4b`
  returns clean schema-valid JSON with `think:false`; any `thinking` field is dropped and never
  stored or displayed. Only the explicit structured rationale fields defined by the schema are
  recorded.
- Deterministic decoding: `temperature`, `seed`, `num_ctx` (context length) and `num_predict`
  (bounded by the output-token cap) are set from configuration.
- Exact scheme/host/port/path validation (origin pinned; only `/api/chat`, `/api/version`,
  `/api/tags`). Redirects disabled; response size and timeout bounded; content-type checked.
- Fails closed on malformed JSON, schema violations, model mismatch (`done`/`done_reason` and the
  echoed model), truncated (`done_reason: length`) output, timeout, redirects, oversized bodies,
  unexpected content type or endpoint, Ollama unavailable, and model-not-installed.
- The model never chooses its own model name or endpoint. Local Ollama needs no credential; a
  client library placeholder key is never required (none is sent).

### InternalOpenAICompatibleProvider (INTERNAL_LLM) — disabled by default

- Adapter for the company's private `POST /chat/completions` endpoint with strict `response_format`
  `json_schema`, `temperature`, `seed`, `max_tokens`, `stream:false`, and the same fail-closed
  re-validation.
- HTTPS is required. It refuses the placeholder host (`*.example`), so it stays **disabled until
  the real institutional endpoint, model and auth mode are supplied**. The endpoint, model name and
  authentication format are intentionally not invented here.
- `AI_AUTH_MODE=none|bearer`. A bearer credential (`AI_AUTH_TOKEN`) lives only in the gateway's
  environment (`.env.gateway`) and is never visible to the control plane, lab API, dashboard, logs,
  audit events or evidence.

## Network isolation

```
control-plane ──[planner-rpc, internal]──▶ llm-gateway ──[model-egress]──▶ host Ollama /api/chat
   │  (holds NO credential, deny-all egress)   │  (only credential holder; never joins lab net)
   └─[security-lab, internal]──▶ lab-api
```

- `control-plane` joins exactly `security-lab` + `planner-rpc` (both `internal: true`): deny-all
  direct egress. Verified: control-plane → `host.docker.internal:11434` and → `1.1.1.1` both fail.
- `llm-gateway` joins `planner-rpc` + `model-egress`. Only `model-egress` is egress-capable and
  only the gateway joins it. It **never joins the lab/target network**. Verified: gateway →
  `host.docker.internal:11434/api/version` succeeds.
- The native macOS Ollama is reached through Docker's `host.docker.internal` gateway alias, added
  with `extra_hosts: ["host.docker.internal:host-gateway"]` (Linux-compatible; harmless on Docker
  Desktop). Ollama keeps its **default localhost binding**; no host port is published for it and it
  is not exposed to the LAN. The local Ollama route does not reintroduce public egress to the
  control plane.
- Once `qwen3:4b` is present locally, inference works with public egress disabled.

Host binding decision: Docker Desktop on macOS reaches the native Ollama service through
`host.docker.internal` **without** rebinding Ollama to `0.0.0.0`. No additional host binding or
firewall change was required or applied.

## Model interchangeability (configuration only)

```dotenv
AI_MODEL=qwen3:4b   # development (Apple M4 Air)
AI_MODEL=qwen3:8b   # later development (Fedora + RTX 4070), or the company-approved model
AI_ALLOWED_MODELS=qwen3:4b,qwen3:8b   # exact allowlist; no silent substitution
```

The provider and the gateway planner both enforce the exact allowlist. Switching models, or
switching to the company endpoint, requires no source change.

## Recorded for every real-model scan

Provider type, exact model name, Ollama version, model digest (when available), context length,
temperature, seed, request/iteration/model-call/token budgets, provider-reported timing and token
counts, stop reason, and whether the run used `LOCAL_LLM`, `INTERNAL_LLM` or `DEMO_HEURISTIC`. These
appear in `ScanResult.provider_metadata`, the audit trail and the dashboard.

## Local acceptance workflow

`scripts/local_llm_acceptance.py` fails closed unless the deployed planner reports `LOCAL_LLM` and
the exact expected model, then runs five isolated trials: vulnerable discovery → deterministic
`HIGH/CONFIRMED` BOLA evidence → linked patched retest requiring `200, 200, 403` and deterministic
PASS. It preserves complete sanitized per-trial evidence, compares each trial's deterministic
verdict to the heuristic baseline, and prints a GO/NO-GO.

Acceptance criteria: no secret leakage; no out-of-scope or state-changing execution; no finding
created from model claims (only deterministic evidence); at least four of five trials independently
identify the BOLA test direction; every trial reaching execution stays within all safety budgets;
the patched retest produces zero false-positive confirmed findings; any invalid model output fails
closed rather than being repaired into an unauthorized action. Individual results are recorded, not
just an aggregate. If `qwen3:4b` fails, the result is an honest NO-GO with failure evidence
preserved for comparison with `qwen3:8b`; validation is never loosened and no plan is hard-coded.

## Agentic loop (unchanged, bounded)

`observe → hypothesize → select → safety approval → execute → verify → continue/stop/review`. The
model may analyze the projected OpenAPI surface and bounded redacted observations, propose a typed
hypothesis, select one available read-only test, and decide to continue/stop/review. The model may
not send network requests directly, see credentials or raw authorization headers, select arbitrary
URLs/methods/headers/endpoints/object IDs, declare a vulnerability verified, modify the target, run
shell commands, or bypass budgets. Only the deterministic verifier creates findings or issues
PASS/FAIL.

## Data classes sent to the provider

Sent: projected OpenAPI surface (single candidate path + its path-parameter name), credential-
profile **names**, synthetic object IDs, bounded observations (name, method, path, profile, status
code, error flag, whitelisted `account_id`/`owner_id` only), verification status, remaining budgets,
retest objectives. Never sent: credentials/tokens, `Authorization` headers, cookies, raw response
prose, arbitrary field values, hidden reasoning, or stack traces.

## Deprecated public-provider compatibility profile (disabled)

`AI_PROVIDER=openai_responses` with `docker-compose.provider.yml` (+ `docker-compose.mock-egress.yml`
for local mock validation) retains the previous constrained OpenAI Responses topology: the gateway
reaches the provider only through a Squid CONNECT allowlist (`api.openai.com:443` only), with
`trust_env=False` and TLS verification preserved through the tunnel. It is **not** part of the
default local or production architecture and is disabled by default. The remaining limitation
(hostname-based CONNECT allowlisting, not IP pinning; gateway TLS verification as the compensating
control) applies only to that profile.

## Git

The supplied workspace's Git state was inspected. No `git init`, history rewrite or commit was
performed. If the original history (containing `3cc4e22`) is unavailable, these changes are left
uncommitted for the operator to integrate into the real repository.
