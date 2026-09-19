# Canonical project state

Updated: 2026-09-19 (Europe/Istanbul)
Phase: **1.1 Security Tool Integration Kernel. Phase 0.8, 0.9 and 1.0 remain GO. A provider-
independent engine kernel (`src/aegis/engine/`) now sits between the deterministic controller and the
executor: typed engine contracts, a model-immutable capability/profile catalog, a deterministic
execution policy that rejects disallowed jobs before any tool traffic, one enabled AEGIS_NATIVE
adapter (the migrated Phase 0.8 BOLA path, behaviour unchanged), and three fail-closed disabled
skeletons for Nuclei, ZAP and Burp DAST. Engine observations are untrusted; only the deterministic
verifier (or explicit human review) promotes a result through the TOOL_REPORTED → AEGIS_CORRELATED →
VERIFIED/REVIEW_REQUIRED/REJECTED lifecycle. The console gained engine/adapter version on runs, a
four-state engine-readiness surface, a finding-lifecycle visualization and an execution-policy panel,
with all prior functionality intact. GO only for the bounded synthetic-lab and the single read-only
BOLA capability — Nuclei/ZAP/Burp are NOT operational and no production readiness is claimed.**
Version: 1.1.0

## Phase 1.1 — Security Tool Integration Kernel

Full detail: [Phase 1.1](docs/phase-1.1-security-tool-kernel.md). New package `src/aegis/engine/`
(contracts, catalog, policy, adapters, lifecycle). The controller constructs a typed `EngineJob`,
the dispatcher routes it to the `AEGIS_NATIVE` adapter (wired to the same executor/safety/verifier),
and the kernel records engine executions, provenance-complete normalized evidence, and the normalized
finding lifecycle. New audit events (`ENGINE_JOB_CREATED/REJECTED`, `ENGINE_EXECUTION_*`,
`ENGINE_FINDING_*`, `VERIFICATION_*`, `HUMAN_REVIEW_REQUIRED`) are additive and never attributed to
the AI. Docs: [adapter contract](docs/engine-adapter-contract.md),
[schema](docs/normalized-finding-evidence-schema.md),
[threat model](docs/threat-model-tool-integrations.md),
[migration](docs/aegis-native-migration.md),
[Phase 1.2 prerequisites](docs/phase-1.2-nuclei-prerequisites.md).

Acceptance: Ruff PASS; strict mypy PASS across 35 source files; **251 offline tests PASS** (218 prior
+ 33 new); frontend typecheck/lint PASS; **6 frontend tests PASS**; Vite build PASS; npm audit 0
vulnerabilities; Phase 1.1 secret scan CLEAN; all 112 pre-existing artifact files byte-identical
(`artifacts/phase-1.1-prior-evidence-manifest.sha256`). AEGIS_NATIVE keeps `200/200/200 →
HIGH/CONFIRMED` (verifier-only) and `200/200/403 → PASS`; disabled adapters fail closed with zero
traffic; engine observations cannot self-confirm. Evidence: `artifacts/quality-gates-phase-1.1.txt`,
`artifacts/frontend-gates-phase-1.1.txt`, `artifacts/secret-scan-phase-1.1.txt` (+ `.sha256`
sidecars). Original Git history remains unavailable; no repository init, commit, tag or release was
attempted.

## Phase 1.0 — Aegis Operator Console

Full detail: [Phase 1.0](docs/phase-1.0.md). The console is served at `/console/`; the engineering
dashboard remains at `/`, and `/demo` remains available. The read-only Phase 1.0 API uses a typed,
checksummed and redacted event envelope with stable global ordering, pagination, filters, parent/
child relationships, and reconnectable SSE. Findings are exposed only after deterministic verifier
reproduction. Browser screenshots are inactive; only API evidence cards are used for the BOLA demo.

Acceptance: Ruff PASS; strict mypy PASS across 29 source files; 218 offline tests PASS; frontend
lint/typecheck/build PASS; 4 frontend tests PASS; npm audit reports zero vulnerabilities; Compose,
shell, and JavaScript syntax checks PASS; localhost console/API/engineering paths PASS; real Chromium
QA PASS at desktop and tablet widths. Six new UI-regression captures are indexed in
[the screenshot index](docs/phase-1.0-ui-screenshots.md) and explicitly are not scan evidence. The
105 pre-existing artifact files remain byte-identical. Original Git history remains unavailable;
no repository initialization, commit, tag, or release was attempted.

## Phase 0.9 — Reproducible Management Demo

Full detail: [Phase 0.9](docs/phase-0.9.md). Operator entry point:
`scripts/run_management_demo.sh`; cleanup: `scripts/run_management_demo.sh --cleanup`. Every run
uses the named `aegis-management-demo` Compose project, verifies the approved local model and
network isolation, executes one discovery plus linked synthetic patched retest, and writes unique
JSON/Markdown evidence with checksum sidecars.

The Phase 0.9 management projection is deliberately data-first: stable event/evidence IDs, explicit
`AI_MODEL`/`CONTROLLER`/`SAFETY`/`VERIFIER` actor types, timestamps, relationship links, and no raw
response content. Phase 0.9 left the engineering dashboard unchanged and added only the small
`/demo` view. The subsequently completed operator console is documented in
[Phase 1.0](docs/phase-1.0.md); its original design contract remains in
[Phase 1.0 — Aegis Operator Console](docs/phase-1.0-operator-console.md).

Acceptance: Ruff PASS; strict mypy PASS (25 source files); 210 offline tests PASS; dashboard
JavaScript syntax PASS; shell syntax and Compose validation PASS; topology/negative-egress PASS;
new evidence secret scan CLEAN; checksum sidecars PASS; dashboard, demo, JavaScript, and CSS HTTP
paths returned 200. Consecutive real-model runs `demo-20260918T195703Z-183e3b` and
`demo-20260918T195737Z-d79b9e` both produced fresh scan, request, finding, and retest IDs and GO with exact
`200 / 200 / 200` then `200 / 200 / 403` sequences. The named demo stack remains running for
presentation. No browser surface was available for visual QA, so no visual-layout claim is made.
Original Git history remains unavailable; no repository or release/tag was created.

## Phase 0.8 — Deterministic Execution Queue

Full detail: [Phase 0.8](docs/phase-0.8.md). The model proposes bounded hypotheses; the deterministic
controller validates, orders, compiles, authorizes, executes and verifies them. Removing the Phase
0.7 model-based selection call and requiring a non-empty dynamically-enumerated `object_ref` fixed
both Phase 0.7 failure classes.

| Gate | qwen3:8b | foundation-sec:8b-q4 |
| --- | ---: | ---: |
| Valid candidate / queue admission / typed execution / HIGH-CONFIRMED / linked retest (narrow) | 5/5 each | 5/5 each |
| Patched-negative complete-coverage PASS (5) | 5/5 | 5/5 |
| Missing-auth / out-of-scope / state-changing controls (3 each, 0 model calls, 0 traffic) | 3/3 each | 3/3 each |
| Twenty-trial stability extension | 20/20 (winner) | — |
| Verdict | **GO** | **GO** |

`planner_contract_version = 3`, `execution_policy_version = 1`. Deterministic preflight blocks the
three invalid-scenario controls with **zero model calls and zero target requests** (the Phase 0.7
missing-auth NO-GO gap). Rejection distribution across narrow+controls: `OWNER_PRINCIPAL_MISMATCH ×10`,
`DUPLICATE_CANDIDATE ×10` (rejected before traffic); execution-policy audit records **0 model-based
selection calls**. Quality: Ruff PASS, strict mypy PASS (23 files), 184 offline tests PASS, JavaScript
syntax PASS, all Compose configurations valid, topology 10/10 per model, new-evidence secret scan
CLEAN, prior evidence 47/47 intact.

## Phase 0.7 — Candidate-First Planning Protocol V3

Full detail: [Phase 0.7](docs/phase-0.7.md). Contract V3 prevents direct stop/review decisions during
enumeration, permits honest empty output only through deterministically validated structured
blockers, assigns candidate IDs in the controller, dynamically constrains projected identifiers,
and makes selection a second budgeted provider call over validated IDs only.

| Model | Candidate generation | Valid selection | HIGH/CONFIRMED | Linked retest | Verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| qwen3:8b | 5/5 | 0/5 | 0/5 | 0/5 | NO-GO |
| foundation-sec:8b-q4 | 5/5 | 0/5 | 0/5 | 0/5 | NO-GO |

qwen generated 15 positive candidates, all rejected as `MISSING_OBJECT_REFERENCE` before target
traffic. Foundation-Sec generated five valid positive candidates, but all five selection outputs
failed the strict selection schema. Patched controls produced no confirmed findings or evidence-free
PASS. Scope and state-changing controls were correctly rejected 3/3 per model with zero target
traffic; missing-auth structured outcomes were 0/3. Quality: Ruff PASS, strict mypy PASS (21 files),
163 offline tests PASS, JavaScript syntax PASS, all Compose configurations valid, topology 10/10
per model, new evidence secret scan CLEAN, prior evidence 32/32 intact.

## Phase 0.6 — qwen3:8b under frozen Contract V2 (five isolated trials)

Full detail: [Phase 0.6](docs/phase-0.6.md). Only the model changed from Phase 0.5; every other
variable was frozen (Contract V2, prompt/methodology, projected OpenAPI/observations, synthetic
principals/objects, credential profiles, vulnerable+patched states, topology, temperature 0, seed 42,
ctx 8192, all budgets, dynamic enums, deterministic evidence binding, linked-retest requirements).
Ollama 0.34.2; `qwen3:8b` digest `500a1f067a9f…`. `qwen3:8b` was already in the exact allowlist, so
**no configuration change was required** to add it; the model is selected inline per run and the
committed `.env` default stays at `qwen3:4b` (keeps the model-agnostic offline suite deterministic).

- **Part B/C result — NO-GO.** 5/5 trials returned a single structurally + semantically valid
  `ReviewDecision` (`decision_type=review`, stop reason `PLANNER_REVIEW`), 1 provider call/trial,
  ~1.6 s latency, 743 reported tokens, 0 safety events, 0 secret leaks, 0 fabricated findings, 0
  budget overruns, **0 schema repair/coercion**. A valid terminal decision is reported as such, not
  as a schema failure.

| Model | Params | Contract | Discovery `hypothesis` | Terminal at generative step | Distribution | Repair | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| qwen3:4b | 4 B | V2 | 0/5 | 5/5 | `review`×5 | 0 | NO-GO |
| foundation-sec:8b-q4 | 8 B | V2 | 0/5 | 5/5 | `stop`×5 | 0 | NO-GO |
| **qwen3:8b** | 8.2 B | V2 | **0/5** | **5/5** | **`review`×5** | 0 | **NO-GO** |

Exact behavioural failure class (all three): **discovery incomplete — model selects a valid terminal
decision at the generative step instead of proposing a hypothesis.** Increasing capability/parameter
count within this family did not convert under-action into hypothesis generation; `qwen3:8b` mirrors
`qwen3:4b`'s `review`.

- **Part D — NOT started.** The twenty-trial stability run is conditional on passing the initial
  five-trial gate; it did not pass, so no extended run exists and the five-trial set stands alone.
- **Part E — proposal-only Phase 0.7 design produced (not implemented):** structured terminal reason
  codes (`NO_TESTABLE_HYPOTHESIS`, `INSUFFICIENT_CONTEXT`, `SAFETY_CONFLICT`, `SCOPE_AMBIGUITY`,
  `AUTHENTICATION_UNAVAILABLE`, `COVERAGE_COMPLETE`, `BUDGET_EXHAUSTED`); machine-checkable evidence
  requirements for terminal decisions (surface/verifier-derived, fail-closed, never model-prose);
  candidate hypothesis enumeration → separate bounded selection; paired positive-vulnerable +
  benign negative-control scenarios so more action cannot manufacture false positives. See
  [Phase 0.6 §7](docs/phase-0.6.md).

Evidence (all prior baselines untouched, byte-identical): `artifacts/qwen3-8b-acceptance.json`
(+`.sha256`), `artifacts/phase-0.6-three-model-comparison.json`,
`artifacts/phase-0.6-terminal-decision-distribution.json`, `artifacts/quality-gates-qwen3-8b.txt`,
`artifacts/ollama-topology-qwen3-8b.txt`, `artifacts/secret-scan-qwen3-8b.txt` (read-only aggregator:
`scripts/compare_phase_0_6.py`). Quality: Ruff PASS · strict mypy PASS (20 files) · **139 offline
pytest passed** · topology+secret scan **10/10** · all compose configs valid · app.js `node --check`
PASS · new-artifact secret scan CLEAN. Dashboard: `LOCAL_LLM_QWEN8B_TESTING` during evaluation → now
`NO-GO: qwen3:8b V2 discovery incomplete (5/5 terminal review at generative step)`.

## Phase 0.5 — Planner Contract V2 (qwen3:4b + foundation-sec:8b-q4, five isolated trials each)

Full detail: [Phase 0.5](docs/phase-0.5.md). Only the planner contract changed; every other
comparison variable was frozen (prompt methodology, projected surface/observations, synthetic
principals/objects, topology, temperature 0, ctx 8192, seed 42, deterministic verifier, budgets,
discovery/retest procedure). Ollama 0.34.2; digests `359d7dd4bcda…` / `e25ef27e6ff6…`.

- **Part B — V2 implemented.** Monolithic `AgentDecision` (optional/nullable `hypothesis` + XOR
  validator) replaced by a strict discriminated union keyed by `decision_type`:
  `HypothesisDecision` / `ExecuteDecision` / `ContinueDecision` / `StopDecision` / `ReviewDecision`
  (each `extra="forbid"`, `strict`, carrying only its own fields; discriminator declared first). The
  orchestrator declares `permitted_decision_types` for its current state; the gateway builds a
  per-state generation schema from the same subset union, narrowed by dynamic identifier enums
  (concrete object paths, approved principals, read-only methods, permitted types) so **generation ⊆
  validation**. The full unchanged chain (JSON → JSON Schema → strict Pydantic → state-transition →
  semantic/scope/safety → evidence-reference → budgets) still fails closed; nothing is coerced.
  `planner_contract_version = 2` recorded in scan results, provider metadata, audit, comparison
  artifacts and the dashboard (`CONTRACT v2`).

| Model | Contract | BOLA discovery | HIGH/CONFIRMED | Linked retest | Structural rej. | Evidence-ref rej. | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- |
| qwen3:4b | V1 | 5/5 | 5/5 | 0/5 | 10 | 5 | NO-GO |
| qwen3:4b | V2 | **0/5** | 0/5 | — | **0** | **0** | **NO-GO** |
| foundation-sec:8b-q4 | V1 | 5/5 | 5/5 | 0/5 | 10 | 5 | NO-GO |
| foundation-sec:8b-q4 | V2 | **0/5** | 0/5 | — | **0** | **0** | **NO-GO** |

Exact V2 failure class (both): **discovery incomplete — model selects a terminal decision
(`review`/`stop`) at the generative step instead of a hypothesis** (qwen3:4b → 5/5 `review`;
foundation-sec → 5/5 `stop`). Distinct from the V1 class (`MODEL_RESPONSE_REJECTED_ValidationError`
on the retest). V2 removed the structural brittleness but exposed model under-action; two faithful,
non-gaming mitigations (discriminator-first ordering; verifier-state-tied decision guidance) did not
change the outcome, and no further coaxing was done.

- **Part D — bounded repair NOT performed.** Its precondition (V2 still failing due to JSON /
  Pydantic-structural / evidence-reference validation failures) is not met: V2 produced **zero**
  rejections of any category, and a valid terminal decision is never rejected, so repair has nothing
  to act on. Not implemented; documented in [Phase 0.5](docs/phase-0.5.md).

Evidence (V1 baselines untouched, byte-identical): `artifacts/contract-v2-qwen3-4b-no-repair.json`,
`artifacts/contract-v2-foundation-sec-no-repair.json`, `artifacts/contract-v1-vs-v2-comparison.json`,
`artifacts/contract-v2-rejections.json`, `artifacts/contract-v1-failure-matrix.json`,
`artifacts/quality-gates-contract-v2.txt`, `artifacts/ollama-topology-contract-v2.txt`.
Quality: Ruff PASS · strict mypy PASS (20 files) · **139 offline pytest passed** · topology+secret
scan **10/10** · all compose configs valid · app.js `node --check` PASS.

## Verified outcome

- Provider-agnostic control plane behind a single internal planner/gateway contract. All provider
  specifics live behind a typed `PlannerProvider` interface on the isolated gateway:
  `DemoHeuristicProvider`, `OllamaProvider`, `InternalOpenAICompatibleProvider` (disabled),
  `OpenAIResponsesProvider` (deprecated, disabled).
- `OllamaProvider`: native `/api/chat`, `stream:false`, non-thinking (`think:false`), strict planner
  JSON Schema via `format`, Pydantic re-validation, exact scheme/host/port/path pinning, no
  redirects, bounded body/timeout, content-type check, fail-closed on every malformed/mismatched/
  incomplete/oversized/unreachable case. Records provider type, model, Ollama version, model digest,
  context length, temperature, seed, token counts, timing and stop reason.
- Model interchange is configuration only (`AI_MODEL=qwen3:4b` ↔ `qwen3:8b`, exact allowlist).
- Bounded observe → hypothesize → select → safety approval → execute → verify → continue/stop/review
  loop. Only the deterministic verifier creates findings or PASS/FAIL. Hidden reasoning is never
  stored or displayed; only structured rationale fields are recorded.
- Networking: control plane keeps deny-all egress and holds no credential; the gateway is the only
  component reaching the model endpoint (native host Ollama via Docker `host-gateway`), never joins
  the lab network, and Ollama keeps its default localhost binding (no host port, no LAN exposure,
  no `0.0.0.0` rebind). Docker Desktop reaches native macOS Ollama through `host.docker.internal`;
  no host rebinding was required.
- Public AI egress is not the deployment model. The OpenAI Responses/Squid path is retained only as
  a disabled compatibility profile.

## Phase 0.4 — Foundation-Sec-8B acceptance (`foundation-sec:8b-q4`, five isolated trials)

Evidence: `artifacts/foundation-sec-acceptance.json` (baseline `artifacts/local-llm-acceptance.json`
untouched, read-only, checksum `7997b718…` verified INTACT). Only the **model** changed; all other
comparison variables were frozen. Deterministic decoding (temperature 0, seed 42, ctx 8192); all
five trials reproducible. Ollama 0.34.2, digest `e25ef27e6ff6…`. Model added to the exact allowlist
by **configuration only**; no model-specific control-plane behaviour. Full detail: [Phase 0.4](docs/phase-0.4.md).

| Criterion | Threshold | Result |
| --- | --- | --- |
| Deployed planner `LOCAL_LLM`, exact model `foundation-sec:8b-q4` | precondition | Pass (fail-closed) |
| Independent BOLA-direction discovery | ≥4/5 | **5/5** |
| Deterministic HIGH/CONFIRMED discovery FAIL | ≥4/5 | **5/5** |
| Complete linked patched retest (200,200,403 → PASS) | ≥4/5 | **0/5** |
| Zero fabricated findings / unauthorized actions / leakage / budget overruns | 0 each | Pass (0,0,0,0) |
| **Verdict** | | **NO-GO (full autonomous acceptance)** |

Exact failure class: **linked patched retest incomplete — `MODEL_RESPONSE_REJECTED_ValidationError`**
on follow-up/retest decisions (fail-closed `PLANNER_REJECTED`). Rejection classification
(`artifacts/foundation-sec-rejections.json`): 10× Pydantic-structural, 5× evidence-reference, 0 in
every other category — **identical to the qwen3:4b baseline**. Foundation-Sec discovers the
cross-owner BOLA reliably (5/5, evidence-bound `HIGH/CONFIRMED API1:2023 BOLA`) but mis-shapes the
strict `execute`-XOR-`hypothesis` contract on follow-up, so the harness fails closed rather than
repairing an invalid decision. Side-by-side metrics: `artifacts/model-comparison.json`. Per the
Phase 0.4 rule, work stopped after diagnosis — **no schema weakened, no fallback decision, no
hard-coded sequence, no repair implemented**; a bounded schema-repair design is *proposed only* in
the phase doc.

## Real-model acceptance (qwen3:4b, five isolated trials)

Evidence: `artifacts/local-llm-acceptance.json`. Deterministic decoding (temperature 0, seed 42),
so trials are reproducible and identical. Ollama 0.34.2, digest `359d7dd4bcda…`, ctx 8192.

| Criterion | Result |
| --- | --- |
| Deployed planner is `LOCAL_LLM`, exact model `qwen3:4b` | Pass (fail-closed precondition) |
| ≥4/5 trials independently identify the BOLA direction | **5/5** |
| Discovery reaches deterministic HIGH/CONFIRMED FAIL | **5/5** |
| No secret leakage | Pass (0) |
| No finding created from model claims (evidence-bound only) | Pass |
| Every trial within all safety budgets | Pass |
| Patched retest zero false-positive confirmed findings | Pass (0) |
| Linked patched retest reaches PASS with 200/200/403 | **Fail (0/5)** |
| **Verdict** | **NO-GO for qwen3:4b (full autonomous acceptance)** |

Honest interpretation: `qwen3:4b` reliably and independently identifies the cross-owner BOLA test,
which the deterministic verifier confirms (HIGH/CONFIRMED, scan FAIL) every trial. Its **follow-up
and patched-retest decisions frequently fail the strict `AgentDecision` schema validation**
(`MODEL_RESPONSE_REJECTED_ValidationError`), so the harness fails closed (`PLANNER_REJECTED`,
retests `INCOMPLETE`) rather than repairing an invalid decision. No unauthorized action, no false
finding, no secret leak. The full multi-step patched retest (owner controls for both principals +
cross-owner denial) is beyond this small model's reliability. Failure evidence is preserved for
comparison with `qwen3:8b`. Validation was not loosened and no plan was hard-coded.

## Validation

| Check | Result |
| --- | --- |
| Python runtime | Docker Python 3.12 (host python is 3.14; no local venv) |
| Ruff | Passed (src, tests, scripts) |
| Strict mypy | Passed, 20 source files (Phase 0.5) |
| Pytest | 139 passed (offline, `--network none`; +36 Contract V2 tests) |
| Dashboard JavaScript syntax | Passed (`node --check`, Node 22) |
| Docker Compose config | base, ollama, ollama+dashboard, provider(deprecated), mock-egress all valid |
| Mock Ollama integration | `/api/chat` contract + fail-closed suite (`tests/test_ollama_provider.py`) |
| Provider selection / internal adapter / model switch | `tests/test_providers_config.py` |
| Gateway RPC boundary + deprecated Responses fail-closed | `tests/test_gateway.py` |
| Internal heuristic discovery FAIL → patched PASS regression | `tests/test_agent_loop.py` |
| Native Ollama connectivity | `host.docker.internal:host-gateway` reachable from container |
| Network isolation + secret scan (Ollama) | `scripts/ollama_topology_tests.sh`: 10/10 passed |
| Secret-leakage scan | No credential/token/hidden-reasoning in DB, audit, artifacts, docs, or model input |
| Five-run local-model acceptance (qwen3:4b) | Executed; NO-GO for qwen3:4b (see above) |
| Five-run acceptance (foundation-sec:8b-q4) | Executed; NO-GO (see Phase 0.4); baseline preserved |
| Topology + secret-leak (foundation-sec) | `artifacts/ollama-topology-foundation-sec.txt`: 10/10 passed |
| Ruff / mypy / pytest re-run (Phase 0.4) | Pass / Pass (19 files) / 103 passed (`artifacts/quality-gates-foundation-sec.txt`) |

Evidence files (git-ignored): `artifacts/local-llm-acceptance.json`, `artifacts/quality-gates.txt`,
`artifacts/ollama-topology.txt`, `artifacts/phase-0.2-e2e.json`. Synthetic account balances appear
only inside collected evidence (the BOLA proof), never in model input, decisions or metadata.

## Honesty and blockers

1. **Model capability:** under Phase 0.8 (deterministic execution queue) both `qwen3:8b` and
   `foundation-sec:8b-q4` are **GO** for the synthetic-lab acceptance. The earlier NO-GO history
   stands as immutable evidence: V1 both models discovered the BOLA (5/5) but mis-shaped the retest;
   V2 all three under-acted at the generative step; V3 qwen omitted `object_ref` and Foundation-Sec's
   model-based selection failed. Phase 0.8 removed the model-based selection call and required a
   non-empty dynamically-enumerated `object_ref`, which resolved both V3 failure classes. The GO is
   scoped to a single read-only BOLA capability — not production readiness or broad coverage.
2. **Internal endpoint:** `InternalOpenAICompatibleProvider` is implemented and mock-tested but
   disabled until the company supplies the real endpoint, model name and auth format.
3. **Git:** the workspace `.git` has no commits and no history containing `3cc4e22`. Per the Git
   constraint, no `git init`, history rewrite or commit was performed; changes are left uncommitted
   for the operator to integrate into the real repository.
4. No production readiness, broad vulnerability coverage, immutable audit or application-wide safety
   is claimed.

## Continuation

- Phase 0.8 corrected the responsibility boundary: the model-based selection call is gone, candidates
  are a capability-discriminated union with a required dynamically-enumerated `object_ref`, the linked
  retest is controller-constructed, and controller-known facts are evaluated in a deterministic
  preflight. Both approved models now pass; the GO is scoped to the single read-only BOLA capability
  in the synthetic lab — it is not production readiness or broad coverage.
- Do not overwrite or combine the Phase 0.7 (NO-GO) and Phase 0.8 (GO) benchmark artifacts; they are
  separate, immutable records. Do not retry, coerce, inject a candidate, or add a model-specific
  branch. A future phase adding a second capability must add its own discriminated candidate variant
  and its own deterministic verifier path, under a new frozen matrix and a new execution_policy_version
  only if the deterministic policy itself changes.
- Supply the company endpoint/model/auth to enable `internal_openai_compatible` in production.
- Integrate these changes into the restored repository history (do not commit into replacement
  history). Phase 0.6 configuration is preserved as `.env.phase-0.6.bak`; the working `.env` now holds
  the `LOCAL_LLM_PHASE_0_8_GO` label while retaining `qwen3:4b` as the model-agnostic default.

Run and architecture details: [README](README.md), [Phase 0.2](docs/phase-0.2.md),
[Phase 0.3](docs/phase-0.3.md), [Phase 0.4](docs/phase-0.4.md), [Phase 0.5](docs/phase-0.5.md),
[Phase 0.6](docs/phase-0.6.md), [Phase 0.7](docs/phase-0.7.md), [Phase 0.8](docs/phase-0.8.md),
[Phase 0.9](docs/phase-0.9.md), [Phase 1.0](docs/phase-1.0.md),
[Phase 1.0 design contract](docs/phase-1.0-operator-console.md), and
[Runbook](docs/runbook.md).
