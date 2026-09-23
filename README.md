# Aegis AI Security Lab — Phase 1.7 multi-agent evaluation runtime

A bounded, guardrailed security-testing demonstration for the included synthetic services.
**Not production-ready. No external or production targets are authorized.**

Phase 1.7 adds an incremental, controlled
[multi-agent evaluation runtime](docs/phase-1.7-multi-agent-runtime.md) over the existing range,
provider gateway, tool controls, verifier, SQLite audit storage and Operator Console. The initial
vertical slice implements Lead Orchestrator, Surface Agent and Authorization Agent roles for the
`aegis-bank` BOLA scenario. Agent communication is strict and typed; targets, credentials and
resources remain controller-owned references; global/per-agent budgets are atomic; replayed,
stale, spoofed and unauthorized actions fail closed; and only the independent range verifier can
confirm or PASS a run. Vulnerable and patched offline synthetic acceptance passes for both the
single-agent baseline and multi-agent path with equal budget limits and seven target requests each.
The baseline uses one structured model call and the multi-agent path four. These measurements use
an offline structured fixture, not a live model, and do not establish a multi-agent improvement.
The read-only view is at `/multi-agent`. Injection Agent and Chain Agent execution remain future
work. ZAP Active is not an agent capability and was not started for this slice.

**Phase 1.7-A live-provider smoke: NO-GO (2026-09-23).** The exact four-case matrix was started
against the configured DeepSeek OpenAI-compatible gateway and synthetic Bank range. Case 1
(`single-agent / vulnerable`) failed closed on its first and only provider call with
`PROVIDER_MODEL_MISMATCH`: the provider-reported model identity did not equal the requested
`deepseek-chat` binding. Per the stop rule, cases 2–4 were not attempted and no retry or model-name
relaxation was used. One documented-surface target request occurred; no hypothesis, broker action,
verifier result or finding was produced. Cleanup and final range health passed, the isolated stack
was removed, structural secret scans were clean, and all 1,034 offline tests remain green. Provider
token usage and the required gateway request projection were unavailable after the rejected
provider envelope, so their gates also fail. Evidence is under
`artifacts/phase-1.7a-live-20260922T210938Z/`. This does not change the offline initial-slice GO and
does not support a Phase 1.7 completion or multi-agent-superiority claim.

Phase 1.6 now includes the completed
[Aegis Vulnerable Application Range catalog](docs/phase-1.6-aegis-vulnerable-application-range.md):
four internal-only applications, 19 deterministic vulnerable/patched scenarios, three end-to-end
attack chains, independent fresh-evidence verifiers, and isolated ops, browser, metadata and admin
fixtures. Container acceptance confirms all 38 scenario outcomes and all six chain outcomes. This
catalog increment is not a Phase 1.6 GO or a claim of broad OWASP coverage; evaluation aggregation,
engine integration and the Range UI remain separate work.

Phase 1.5 adds the project's first
[active scanning capability](docs/phase-1.5-zap-active-reflected-xss.md), deliberately as narrow as
it can be: a second, separate ZAP profile `ZAP_LAB_ACTIVE_REFLECTED_XSS_V1` in which exactly one
reviewed release rule (40012, reflected XSS) mutates exactly one bounded query parameter on exactly
one approved read-only `GET` operation in the synthetic lab. It runs from its own digest-pinned
11-add-on image, requires a single-use activation lease that the operator confirms with an exact
phrase, and reaches the target only through the scope guard's additive ACTIVE mode, which allows a
query string only on the projected parameter and enforces a hard request budget. ZAP's payload is
never stored — the parser keeps a structural class and a digest — and a fresh deterministic Aegis
verifier is still the only authority that can confirm a finding or grant a patched PASS. An
emergency stop kills a scan in flight.

**Phase 1.5 is a GO** (evidence-backed, 2026-09-21). The lease is an HMAC-SHA-256 authenticated
single-use token that the runner's root-owned admission component verifies, arms, consumes and
revokes itself (a valid signature alone never executes anything); the active-rule manifest review
is operator-countersigned (record `countersign-zap-active-reflected-xss-v1`, any digest change
fails closed); the Operator Console has a full ZAP Active view with the activation ceremony, a
prominent `STOP ACTIVE SCAN`, the five-way alert-state separation and the interpretation warnings.
The live acceptance on the real pinned image is 5/5 vulnerable (`VERIFIED_VULNERABLE`,
verifier-owned), 5/5 patched (`PASS` from the fresh verifier plus complete coverage, never from
zero alerts alone), one real mid-scan emergency stop and eight zero-traffic negative controls —
54 forwarded / 0 blocked requests through the guard, reconciled exactly. The GO is scoped to one
controller-owned reflected-XSS rule against one anonymous, read-only, resettable synthetic-lab
endpoint; no test-environment, staging or production readiness, broad active scanning, broad OWASP
coverage, authenticated scanning, arbitrary rules, AI-selected attacks or browser execution is
claimed. Phase 1.3 passive ZAP is untouched and retains its GO.

Phase 1.5 remains preserved. ZAP Active has not been run against the range and remains isolated
from Phase 1.7 agent execution.

## Phase 1.4 baseline

Phase 1.4 adds [BEAST MODE](docs/phase-1.4-beast-mode.md), a real `qwen3:8b`-controlled arbitrary
shell inside a disposable, resource-bounded and network-isolated adversary sandbox. The model owns
commands, tool arguments, scripts, raw HTTP and adaptive next steps; immutable outer controls own the
single synthetic target, read-only method/path scope, static network reachability, resource ceilings,
audit retention, emergency stop, cleanup and verifier authority. There is no command allowlist or
deterministic command fallback. Phase 1.4 is SYNTHETIC_LAB only; staging and production Beast shell
activation are disabled. The final verdict is recorded after live 5-trial-per-scenario acceptance.

## Phase 1.3 baseline

Phase 1.3 adds one operational, **passive-only** [ZAP integration](docs/phase-1.3-zap-passive-openapi.md).
ZAP `2.17.0` runs from a digest-pinned image with exactly eight verified add-ons in a non-root,
read-only, shell-less `zap-runner` container whose only network path to the synthetic target is an
independent scope guard that forwards only armed, allowlisted GET requests within a hard budget. The
controller projects a minimal read-only OpenAPI document from controller-owned inventory; ZAP imports
it from a local file and passively analyses the responses with one admitted rule. ZAP passively
analyzes responses from controller-approved read-only API operations. ZAP alerts are independently
correlated and verified by Aegis. Real pinned-image acceptance is vulnerable 5/5 and patched 5/5 with
every negative control failing closed and zero unauthorized target traffic. **GO only for this one
synthetic, anonymous, passive capability.** No active scanning, spidering, scripting,
authentication, production target, Burp DAST or OWASP coverage claim is enabled.

Details: [runner isolation](docs/zap-runner-isolation.md),
[OpenAPI projection](docs/zap-openapi-projection.md),
[supply chain and rule manifest](docs/zap-passive-rule-manifest.md),
[evidence and verification](docs/zap-evidence-and-verification.md) and
[historical active-scan prerequisites draft](docs/historical-zap-active-staging-prerequisites-draft.md).

## Earlier phases

Phase 1.2 adds one operational, tightly constrained
[Nuclei integration](docs/phase-1.2-nuclei-integration.md). Nuclei `v3.11.1` runs in a separate
non-root, read-only, no-shell container with no public egress, planner/model access, credential,
host mount or published port. It can reach only the synthetic target and can execute only the one
checked-in official signed `git-config` template from nuclei-templates `v10.4.8`. The controller
owns target/profile/template selection and constructs a strict typed RPC; Nuclei output is
TOOL_REPORTED and only a fresh deterministic Aegis verifier can confirm a finding or patched PASS.
Real pinned-binary acceptance is vulnerable 5/5 and patched-negative 5/5 with every negative control
passing and zero unauthorized traffic. **GO only for this one synthetic, anonymous, read-only HTTP
capability.** No broad template scan, Nuclei AI/DAST/OAST, authentication, production target,
Burp DAST or automatic OWASP coverage is enabled.

Supply chain and operations: [template pins](docs/nuclei-template-supply-chain.md),
[runner isolation](docs/nuclei-runner-isolation.md), [operations](docs/nuclei-operations.md), and
[evidence/verification](docs/nuclei-evidence-and-verification.md).

Phase 1.1 adds a provider-independent [security-tool integration kernel](docs/phase-1.1-security-tool-kernel.md)
(`src/aegis/engine/`): typed engine contracts, a model-immutable capability/profile catalog, a
deterministic execution policy that rejects disallowed jobs before any tool traffic, one enabled
`AEGIS_NATIVE` adapter (the migrated Phase 0.8 BOLA path, behaviour unchanged), and fail-closed
disabled skeletons for `NUCLEI`, `ZAP` and `BURP_DAST`. Engine observations are untrusted; only the
deterministic verifier or explicit human review promotes a result. Phase 1.1 verdict: **GO for the
bounded synthetic-lab and the single read-only BOLA capability, executed through the new engine
interface**. At that Phase 1.1 baseline, Nuclei/ZAP/Burp DAST were not operational; Phase 1.2
enabled the bounded Nuclei profile and Phase 1.3 the passive ZAP profile described above. Burp DAST
remains disabled.

Phase 1.0 added the [Aegis Operator Console](docs/phase-1.0.md), a distinct local React/TypeScript
surface over the completed Phase 0.9 scan, audit, finding, retest, and evidence contracts. It adds
no vulnerability class, target, model authority, or autonomous capability. The existing engineering
dashboard remains at `/`; the console is at `/console/`; the Phase 0.9 focused view remains at
`/demo`.

Phase 1.0 verdict: **GO for the localhost operator console over the bounded synthetic-lab
capability**. This is not a production-readiness or broad-coverage verdict. Its historical Nuclei,
ZAP and Burp state is superseded only by the Phase 1.2 Nuclei and Phase 1.3 passive ZAP profiles;
Burp DAST remains disabled.

Phase 0.9 verdict: **GO for the reproducible synthetic-lab demonstration** after two consecutive
fresh `qwen3:8b` runs. This is not a production-readiness or broad-coverage verdict.

Repository history begins at the Phase 1.1 baseline; earlier Git history was unavailable. See
[repository provenance](docs/repository-provenance.md).

## Operator Console

After starting the supported Compose stack, open:

- Operator Console: <http://127.0.0.1:8000/console/>
- Engineering dashboard: <http://127.0.0.1:8000/>
- Phase 0.9 management view: `/demo?discovery=<scan>&retest=<scan>`

The console provides Mission Control, Runs, Findings, Audit, Evidence, Integrations, System Health,
and a management presentation mode. Historical audit hydration is followed by a reconnectable SSE
stream. All Phase 1.0 projections are redacted; findings remain verifier-owned; API evidence cards
exclude response bodies and credentials; browser screenshots are disabled by default.

Architecture and policies: [console architecture](docs/operator-console-architecture.md),
[event envelope](docs/audit-event-envelope.md),
[screenshot privacy/retention](docs/screenshot-privacy-retention.md), and
[management guide](docs/management-demo-phase-1.0.md).

## Reproducible management demo

With Docker and the approved local `qwen3:8b` Ollama model already available:

```bash
scripts/run_management_demo.sh
```

The command validates the constrained topology, runs one real-model discovery plus deterministic
linked patched retest, writes a unique checksummed evidence package, leaves the demo stack running,
and prints the localhost management-view URL. Remove only that Compose project with:

```bash
scripts/run_management_demo.sh --cleanup
```

Audit API records and the Phase 0.9 manifest expose stable event IDs, timestamps, actor types,
scan/finding/retest links, and redacted evidence references. They do not expose response bodies,
credentials, Authorization headers, cookies, hidden reasoning, or raw exception prose through the
management projection.

The AI proposes bounded read-only security hypotheses (a strict, capability-discriminated candidate
schema). The deterministic controller then validates, orders, compiles, authorizes, executes and
verifies them: validated candidates are admitted into a deterministic, model-independent execution
queue (`execution_policy_version = 1`) — there is **no** model-based selection call — and the linked
patched retest is controller-constructed from the confirmed finding. A separate safety controller
authorizes execution; a deterministic verifier alone determines findings and a narrowly scoped PASS.
The control plane is **provider-agnostic**: it talks only to an internal planner/gateway contract and
holds no provider credential and no provider-specific request logic.

## Deployment model

Application data must **not** be sent to OpenAI or any public AI provider. Public AI egress is not
the intended deployment model. The supported providers are:

| Mode | Provider | Where | Egress |
| --- | --- | --- | --- |
| `DEMO_HEURISTIC` | offline heuristic | control plane | none |
| `LOCAL_LLM` | private Ollama (`qwen3:4b` dev; `foundation-sec:8b-q4` and `qwen3:8b` both **GO** under Phase 0.8, see [Phase 0.8](docs/phase-0.8.md)) | your machine / a GPU box | gateway → Ollama only |
| `INTERNAL_LLM` | company private OpenAI-compatible endpoint | production | gateway → company endpoint only |

The same code runs all three. Switching `qwen3:4b` → `qwen3:8b`, or dev Ollama → the company
endpoint, is **configuration only** — no source change. The deprecated public OpenAI Responses path
(`openai_responses` + Squid overlay) is retained as an optional, **disabled** compatibility profile
and must not be used as the default local or production architecture.

## Honest labels

- `DEMO_HEURISTIC`: observation-dependent offline rules. No model calls; never describe this as AI.
- `LOCAL_LLM` / `INTERNAL_LLM`: real model adapters using schema-constrained decisions. Ollama runs
  are labelled `LOCAL_LLM`, never `LIVE_LLM`.
- Verification is always deterministic. Decision summaries are short explanations, not private
  chain-of-thought; hidden reasoning is never stored or displayed. SQLite audit records are
  persisted, not immutable or tamper-proof.

## Provider architecture

The model path is split across services so a compromised model loop cannot become arbitrary egress
or leak a credential (full control map in [Phase 0.3](docs/phase-0.3.md)):

- **control-plane**: delegates each decision to the gateway over the internal `planner-rpc`
  network. It holds **no** credential (refuses to start if `AI_AUTH_TOKEN` is present), keeps
  deny-all direct egress, and never reaches the model endpoint.
- **llm-gateway**: the only component that talks to a model endpoint and the only credential holder.
  It selects a typed `PlannerProvider` from `AI_PROVIDER`:

  ```
  PlannerProvider
    ├── DemoHeuristicProvider            (offline heuristic)
    ├── OllamaProvider                   (native /api/chat, stream=false, non-thinking, LOCAL_LLM)
    ├── InternalOpenAICompatibleProvider (company /chat/completions, INTERNAL_LLM; disabled)
    └── OpenAIResponsesProvider          (deprecated public profile; disabled)
  ```

  Every provider pins scheme/host/port/path, disables redirects and env-proxy inheritance, bounds
  response size and timeout, passes the strict planner Pydantic JSON Schema to the model, and
  re-validates the returned content with Pydantic. It fails closed on malformed JSON, schema
  violations, model mismatch, timeout, redirects, oversized bodies, unexpected content type or
  endpoint, and never lets the model choose its own model name or endpoint.

## Run the local Ollama demonstration

Docker Compose is the supported Python 3.12 runtime. Development host in this phase: Apple M4 Air,
native Ollama, model `qwen3:4b`.

Prerequisites (operator step): install Ollama and pull the model:

```bash
ollama pull qwen3:4b        # ~2.5 GB; only this model is authorized without further approval
```

Bring up the stack with the Ollama overlay (native macOS Ollama reached via Docker's host-gateway):

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
               -f docker-compose.dashboard.yml up --build -d
```

Open <http://127.0.0.1:8000>. Choose **Discover vulnerability**, then **Retest patched endpoint**.
The dashboard shows the mode (`LOCAL_LLM`), the exact model, provider runtime/version, model digest,
context length, temperature, seed, model-call and token/timing usage, safety approvals, deterministic
verification, and the linked retest.

Ollama keeps its default localhost binding; **no host port is published for it** and it is not
exposed to the LAN. Once `qwen3:4b` is present locally, inference works with public egress disabled.

### Switch models with configuration only

```bash
# Larger local model on a GPU box, no code change (must be in AI_ALLOWED_MODELS):
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
```

For a remote Ollama host, set `AI_BASE_URL=http://<host>:11434` (keep it private; do not bind
Ollama to `0.0.0.0` without explicit operator approval).

## Phase 0.8 local-model acceptance matrix

Staged so narrow, control and extended evidence stay separate. Run the narrow positive regression
first for each model; run controls only after a model passes 5/5; run the extension only after a
model also passes every control:

```bash
# 1) narrow 5/5 positive regression (per model, recreate the stack with AI_MODEL=<model>)
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=narrow aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py
# 2) controls (PHASE_0_8_MODE=controls)   3) winner extension (PHASE_0_8_MODE=extension)
python scripts/compare_phase_0_8.py   # aggregate model comparison + rejection + policy audit
```

It fails closed unless the deployed planner reports `LOCAL_LLM` and the exact expected model. It never
retries a failed generation, loosens validation or inserts a candidate. Evidence is written to
separate model-, mode-specific files.

**Phase 0.8 result:** both `qwen3:8b` and `foundation-sec:8b-q4` pass the narrow 5/5 positive
regression (valid candidate, deterministic queue admission, typed read-only execution, HIGH/CONFIRMED
discovery and linked patched retest, all 5/5) and every control (patched-negative complete-coverage
PASS 5/5; missing-auth, out-of-scope and state-changing-only blocked deterministically at preflight
3/3 with **zero model calls and zero target requests**). The `qwen3:8b` twenty-trial stability
extension is 20/20. Per-model and overall **GO** for the synthetic-lab acceptance (not production
readiness). See [Phase 0.8](docs/phase-0.8.md) and `artifacts/phase-0.8-model-comparison.json`.

Phase 0.7 (the superseded model-based-selection design) was NO-GO for both models; its evidence is
preserved immutably. See [Phase 0.7](docs/phase-0.7.md).

**Phase 0.4 result:** the cybersecurity-specialized `foundation-sec:8b-q4` was evaluated under the
exact same contract (set `AI_MODEL=foundation-sec:8b-q4`, `EXPECTED_MODEL=foundation-sec:8b-q4`, and
`LOCAL_EVIDENCE_PATH` to a new file so the qwen3:4b baseline stays untouched). Outcome: **NO-GO** —
5/5 independent BOLA discovery and 5/5 deterministic `HIGH/CONFIRMED`, but 0/5 complete linked
retest (follow-up decisions fail strict validation, fail-closed). Side-by-side comparison and the
*proposed-only* bounded schema-repair design are in [Phase 0.4](docs/phase-0.4.md).

**Phase 0.5 / 0.6 result (Contract V2):** Contract V2 (an explicitly discriminated decision union)
removed the entire structural / evidence-reference rejection class, but all three approved models
then *under-act* at the generative discovery step, returning a **structurally valid** terminal
decision instead of a hypothesis: `qwen3:4b` → 5/5 `review`, `foundation-sec:8b-q4` → 5/5 `stop`, and
`qwen3:8b` (Phase 0.6, 8.2 B) → **5/5 `review`** — matching `qwen3:4b`, so scaling within this family
did not help. All three are **NO-GO** under V2 with zero fabricated findings, zero leakage, zero
budget overruns and zero schema coercion. See [Phase 0.5](docs/phase-0.5.md) and
[Phase 0.6](docs/phase-0.6.md) (the latter includes a *proposal-only* Phase 0.7 design). No production
readiness or broad vulnerability coverage is claimed.

## Offline demonstration (no model)

The default config (`AI_PROVIDER=demo`) needs no `.env`, no Ollama and no egress:

```bash
docker compose -f docker-compose.yml -f docker-compose.dashboard.yml up --build -d
mkdir -p artifacts
docker compose exec -T control-plane python - < scripts/demo_e2e.py > artifacts/phase-0.2-e2e.json
```

Expected: import the lab OpenAPI, collect `user_a → A-100` / `user_b → B-200` owner controls, test
`user_a → B-200` (vulnerable route returns 200 + the wrong owner's account), deterministic
`HIGH/CONFIRMED` `FAIL`; then the patched route repeats the confirmed direction and returns 403 for
deterministic scoped `PASS`. Both implementations coexist in the same synthetic API; the agent never
modifies code or target state. PASS means this tested fixture authorization comparison passed, not
that the application is secure.

## Network isolation

- `docker-compose.yml` runs both application services only on internal Docker networks; neither
  publishes a host port. The optional dashboard override adds a non-root Nginx proxy bound to
  **127.0.0.1:8000**; only the proxy joins a second network, its upstream is fixed to the control
  plane, and it receives no credentials.
- The control plane has **deny-all direct egress** (`security-lab` + `planner-rpc`, both internal).
  It cannot reach the internet or the model endpoint.
- The Ollama overlay puts the gateway on `planner-rpc` + `model-egress`; only `model-egress` is
  egress-capable and only the gateway joins it, reaching the pinned Ollama endpoint via Docker's
  `host-gateway` alias (Linux-compatible; harmless on Docker Desktop). The gateway never joins the
  lab/target network. The local Ollama route does not reintroduce public egress to the control
  plane.

## Production (company private AI endpoint)

Set the internal provider (disabled by default until the real institutional details are supplied):

```dotenv
AI_PROVIDER=internal_openai_compatible
AI_BASE_URL=https://internal-ai.example        # replace with the real company endpoint
AI_MODEL=<company-approved-model>
AI_ALLOWED_MODELS=<company-approved-model>
AI_AUTH_MODE=none|bearer                        # bearer requires AI_AUTH_TOKEN in .env.gateway
```

Any internal bearer credential lives only in an **untracked `.env.gateway`** mounted into
`llm-gateway`; it is never visible to the control plane, lab API, dashboard, logs, audit events or
evidence. The provider requires HTTPS and refuses the placeholder host, so it stays disabled until
configured. No public OpenAI egress is required.

## Safety and budgets

- Exact hostname allowlist and same-origin scheme/hostname/port, including OpenAPI import.
- Only the selected lab account route, synthetic object IDs and credential profiles are authorized.
- Only GET, HEAD and OPTIONS are representable; only fresh GET evidence can prove this BOLA test.
- Strict schemas forbid arbitrary headers, bodies, URLs, shell commands or additional tools.
- Encoded paths, traversal, query strings, fragments and authority overrides are rejected.
- OpenAPI descriptions, examples, servers, refs and extensions cannot enter the model context.
- Model observations contain fixed identity fields and status metadata, never raw response bodies.
- Target credentials are resolved only by the executor; known values and sensitive keys are redacted.
- Names must be unique across a scan; evidence is bound to method, path, principal and fixture owner.
- No redirects; HTTP response bodies and total elapsed scan time are bounded.
- Maximum 8 target requests **including import**, 6 iterations, 6 model calls by default; local
  inference timeouts are generous (300s scan / 90s model default) but every scan is still bounded.
- Token admission uses cumulative conservative reservations. Provider-reported usage is tracked
  separately and over-reservation output is rejected. This is an admission policy, not billing.
- Budget exhaustion, missing evidence and errors cannot become PASS. Confirmed findings remain FAIL
  even if a later step fails. Review requests and safety rejections are visible.

## Quality gates

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api -p aegis_nuclei -p nuclei_runner \
              -p aegis_zap -p zap_runner -p zap_guard && \
         pytest -q'
```

See [canonical project state](PROJECT_STATE.md), [Phase 0.2](docs/phase-0.2.md) and
[Phase 0.3](docs/phase-0.3.md). Future production work still requires authenticated onboarding,
ownership approval, SSO/RBAC, central immutable audit, encrypted secret storage, global
concurrency/rate limits, kill switch, retention policies, and dedicated egress enforcement. These
are not implemented by this lab.
