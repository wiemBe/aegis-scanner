# Canonical project state

Production deployment update (2026-09-26): the repository now contains the immutable,
company-private provider/gateway overlay, gateway-only credential-file handling, a fail-closed
rendered-Compose preflight, and a read-only staging soak/failure observer. Code/config status is
`DEPLOYMENT_PATH_READY`; real registry pull, private endpoint/TLS/model validation, platform
observability delivery, and staging soak/failure evidence remain `NOT_EVALUATED`. No external or
production target authorization is added. See `docs/production-readiness-wp5.md`.

Updated: 2026-09-22 (Europe/Istanbul)
Phase: **1.7 Multi-Agent Evaluation Runtime — INITIAL AEGIS-BANK BOLA VERTICAL SLICE IMPLEMENTED,
OFFLINE SYNTHETIC ACCEPTANCE ONLY, NOT a production or live-model GO. Lead, Surface and
Authorization roles execute through strict typed records, atomic global/per-agent budgets, the
controller-owned target/credential/resource registry, controlled broker, fresh range verifier,
existing SQLite database and a bounded console projection. Vulnerable and patched modes pass for
single-agent and multi-agent paths under equal limits and seven target requests. The offline
fixture records one versus four model calls; no multi-agent improvement is claimed. Injection and
Chain execution, live-model benchmarking and broader range coverage remain unimplemented. Phase
1.6 and the isolated Phase 1.5 ZAP Active profile remain preserved; ZAP Active is not agent-enabled.**
Version: 1.7.0-dev (Phase 1.5 remains the newest ZAP profile with a GO verdict)

### Phase 1.7-A live-provider smoke — NO-GO

On 2026-09-23, the authorized four-case DeepSeek smoke stopped at case 1 as required. The
`single-agent / vulnerable BOLA` path made one documented-surface request and one provider call;
the gateway rejected the response as `PROVIDER_MODEL_MISMATCH` because the provider-reported model
identity did not match the requested `deepseek-chat` binding. No retry, schema weakening, output
repair, offline fallback or model-identity relaxation occurred. Cases 2–4 were not attempted. No
hypothesis, broker action, verifier outcome or finding was produced; provider token usage and the
gateway request projection were unavailable after rejection and are recorded as failed/unknown,
not zero or inferred.

Cleanup reset and health passed (generations 5 then final 6); zero agent commands executed; the
isolated Compose project has zero remaining containers. Structural scans of the acceptance SQLite
database, artifacts, logs, captured console/API material and non-gateway container metadata were
clean without reading or comparing the configured provider key. Post-smoke Ruff and strict mypy
pass, and 1,034/1,034 offline tests pass. Checksummed evidence:
`artifacts/phase-1.7a-live-20260922T210938Z/`. Verdict: **NO-GO** for live Phase 1.7-A; the accepted
offline runtime semantics remain scoped only to the initial BOLA slice.

## Phase 1.7 — Multi-Agent Evaluation Runtime (initial slice, offline only)

Architecture and trust boundaries:
[Phase 1.7 — Multi-Agent Evaluation Runtime](docs/phase-1.7-multi-agent-runtime.md).

Implemented: all ten core typed records; registries for five eventual roles; operational Lead,
Surface and Authorization roles; shared provider-gateway generation; controller-resolved Bank BOLA
broker actions; nonce/expiry/identity/capability checks; atomic global/per-agent budgets; monotonic
run states and stop propagation; verifier-owned vulnerable confirmation and patched PASS; verified
reset/cleanup; equivalent single-agent baseline; SQLite persistence; and `/multi-agent` plus bounded
read APIs. ZAP Active is absent from the capability registry.

Offline acceptance (`OFFLINE_STRUCTURED_FIXTURE`): vulnerable single/multi `CONFIRMED`, patched
single/multi `PASS`, one surface discovery, one valid hypothesis, zero false positives, seven target
requests, cleanup verified in every run. Single-agent uses 1 model call / 104 input / 151 output
fixture tokens; multi-agent uses 4 calls / 212 input / 206 output fixture tokens. Limits are equal:
6 model calls, 12,000 tokens, 8 target requests, 0 commands, 30 seconds, 524,288 evidence bytes.
Elapsed milliseconds are not used for comparison because in-process fixture timing is noise.

Dedicated acceptance: 10/10 Phase 1.7 tests pass. Repository gates: Ruff PASS; strict mypy PASS
across 145 source files; 1,034/1,034 offline tests PASS. No live provider was invoked, so this phase
makes no model-quality, adaptation or superiority claim.

## Phase 1.6 — Aegis Vulnerable Application Range (active, not a GO)

Full specification and current evidence:
[Phase 1.6 — Aegis Vulnerable Application Range](docs/phase-1.6-aegis-vulnerable-application-range.md).
The completed catalog covers all 19 specified vulnerable/patched scenarios across `aegis-bank`,
`aegis-shop`, `aegis-ops` and `aegis-cloud`, plus the bank recovery, cloud internal-service and shop
privileged-viewer chains. Phase 1.5 behavior remains preserved, and ZAP Active was not run against
the range.

## Phase 1.5 — Controlled ZAP Active Reflected-XSS Scanning (GO)

Full detail and final evidence: [Phase 1.5](docs/phase-1.5-zap-active-reflected-xss.md).

**Verdict: GO.** Maximum claim: *"GO for one controller-owned reflected-XSS active rule against one
anonymous, read-only, resettable synthetic-lab endpoint under a runner-validated single-use lease,
fixed network and traffic budgets, emergency stop, independently verified evidence and verified
cleanup."* No broader claim is made.

Pins: base image unchanged from Phase 1.3 — ZAP `2.17.0`, index
`sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`, jar
`015dda47…`, OpenJDK `17.0.20+8-1-deb12u1-Debian`. Add-ons (11) = the eight Phase 1.3 add-ons plus
`ascanrules-release-83.zap` `9c1b64c2fceda629f7c0ab0c21b5901035494f78da51d584972eaf85e94e91cc`,
`oast-beta-0.24.0.zap` `f06ecea02e2c1df4a164e737dd632afba4430225b2fdc2feb6042bdb1e976b3d` and
`database-alpha-0.9.0.zap` `4c58ca142288d9ddc6ae3fd8fe6815e3894462bae67eb0776e540a2d9ddaf87d`
(inventory digest `933320c1637bedf51227fb139c0776263e0ad65ce01287283c8b1a29253119b9`); active rule
`40012`; active manifest SHA-256
`0a7b38a165c05d1fe9bae3ecfc11f1716ff55d0d88c34f146641ae4af0745e15` — **operator-countersigned
2026-09-21** (record `countersign-zap-active-reflected-xss-v1`; any digest change fails closed);
runner image `aegis-zap-active-runner:1.5.0` (`sha256:ea3cfe03fb29…`), guard
`aegis-zap-scope-guard:1.5.0` (`sha256:dc09296b7b18…`), admission
`aegis-zap-active-admission:1.5.0` (`sha256:d46bb154f3e1…`); vulnerable projection
`ca0cb0123641b73b…`, patched projection `0691f1f13961e623…`.

Offline gate: Ruff PASS; strict mypy PASS across **135 source files**; **1028 offline tests PASS**,
0 failed (incl. the dedicated lease suite, the countersign drift suite and the executor-level lease
behaviours); frontend typecheck/lint PASS, **20 frontend tests PASS**, Vite production build PASS,
npm audit 0; `docker compose config` validates for every overlay (active and Beast fail closed
without their operator secrets); secret scans clean; prior evidence byte-identical (112+136+27).

Live acceptance (arm64, real pinned image, compose project `aegis-phase15-live`, torn down):
**5/5 vulnerable** (COMPLETED, rule 40012 only, `VERIFIED` by the fresh-marker verifier, verdict
`VERIFIED_VULNERABLE` owner `AEGIS_VERIFIER`, 3 forwarded/0 blocked each) and **5/5 patched**
(COMPLETED, complete coverage and drained queues, zero alerts, verifier `PASS` `ENTITY_ENCODED`,
verdict `PASS` owner `AEGIS_VERIFIER`, 7 forwarded/0 blocked each); one real mid-scan emergency
stop (lease consumed → engine killed: `STOPPED`/`EMERGENCY_STOP`/`KILLED_BY_GUARD`, ordered steps
all true, never a PASS); 8 live negatives all refused with zero target traffic (unknown target,
projection/allowlist digest mismatch, unexpected query parameter, expired lease, invalid signature,
unarmed lease, replayed lease); guard reconciliation **54 forwarded / 0 blocked** across the whole
matrix; deterministic reset, session destruction and lease revocation 10/10; topology proof (runner
never on `active-target`; all networks `internal: true`; no internet egress). Evidence:
`artifacts/phase-1.5-live-20260921T164151Z/` (summary SHA-256 `cc7f1c30c5c98167c9856b1042cdfdafb…`).
Six defects were found by the live matrix and fixed before the verdict (admission base pinned to
Python 3.11 for the cp311 hash lock; shared admission contracts moved into `aegis_zap_active`;
single-arm activation flow; 16 KiB admission status ceiling; ordered emergency stop under a stop
lock with durable guard revocation; `KILLED_BY_GUARD` classification for stop-killed engines).

Not claimed: closed-test-environment, staging or production readiness; broad active scanning or
OWASP coverage; authenticated scanning; arbitrary ZAP rules; AI-selected attacks; browser
execution; application-wide safety. `ZAP_TEST_ENV_ACTIVE_V1` remains inert. amd64 pins are verified
at build time, not executed.

## Phase 1.3 — Controlled ZAP Passive OpenAPI Integration

Full detail: [Phase 1.3](docs/phase-1.3-zap-passive-openapi.md). Also:
[isolation](docs/zap-runner-isolation.md); [projection](docs/zap-openapi-projection.md);
[supply chain and rule manifest](docs/zap-passive-rule-manifest.md);
[evidence and verification](docs/zap-evidence-and-verification.md);
[historical active-scan prerequisites draft](docs/historical-zap-active-staging-prerequisites-draft.md).

Pins: ZAP `2.17.0`, image index `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`
(arm64 `sha256:05cbf4cab5d2fdaef55b0cd0b586f22d0ce4f75e0995f3cea2db23afbbdfd2f8`, amd64
`sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa`); jar
`015dda4709b5ef79736086bb41e8e2a4e95b04cf6625f14d6bcc02b197c99c0c`; OpenJDK
`17.0.20+8-1-deb12u1-Debian`; add-ons automation 0.60.0, callhome 0.23.0, commonlib 1.43.0, network
0.29.0, openapi 57.0.0, pscan 0.6.0, pscanrules 75.0.0, reports 0.46.0 (inventory digest
`56c67a0d4ddf3c541de9e9fef411e51b8503aeb5fcf731e759215fee9ceca55c`); passive rule 10021; manifest
SHA-256 `94933d15c53dea51591573b4959f4f4655fbc54586b43a5da03427a78dcf2ba3`; vulnerable projection
`ca9a56e8b29ac37150dbd448b28aa2e535299205981c068dec550d3af13d1389`.

Acceptance (arm64): Ruff PASS; strict mypy PASS across 69 source files; **721 offline tests PASS**;
frontend typecheck/lint PASS, **8 frontend tests PASS**, Vite build PASS, npm audit 0; real pinned
ZAP vulnerable 5/5 and patched complete-coverage PASS 5/5 (2 expected = 2 observed requests each);
state-changing, alternate-server and external-`$ref` projections 3/3 each with zero runner calls;
injected jobs/options/remote definitions all rejected with zero executions; redirect, extra-request
and timeout runtime controls 3/3 each fail closed; parser controls fail closed in the runner image;
exactly 19 authorized executions, 6 guard refusals, **0 unauthorized target requests** by the target's
own access log. Nuclei Phase 1.2 regression GO; AEGIS_NATIVE regression 3/3 (heuristic planner);
Burp DAST DISABLED; topology, hardening, secret and visual gates PASS; all 136 prior artifacts
byte-identical. A first live run exposed (via host sleep) a runner response-bound bug that was
fixed and re-run. The rule-manifest review is AI-assisted and not operator-countersigned.

## Phase 1.2 — Controlled Nuclei Integration

Full detail: [Phase 1.2](docs/phase-1.2-nuclei-integration.md). Supply chain:
[manifest](docs/nuclei-template-supply-chain.md); [isolation](docs/nuclei-runner-isolation.md);
[operations](docs/nuclei-operations.md); [evidence](docs/nuclei-evidence-and-verification.md).

Pins: Nuclei `v3.11.1`; arm64 binary SHA-256 `f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`;
amd64 `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`;
nuclei-templates `v10.4.8` commit `e5f19e6144135e107962bb943231413796fd7fe7`;
`git-config` template SHA-256 `bd8bdfa0b5ed5bf4d3712edb793adfd0987d9282e51c6f7d673bf14b9e4dd524`;
manifest SHA-256 `8c69c056d9d11990bf11cbc688252d30426654a7ccb16996d3559c84fa472845`.

Acceptance: Ruff PASS; strict mypy PASS across 49 source files; **464 offline tests PASS**; frontend
typecheck/lint PASS; **6 frontend tests PASS**; Vite build PASS; real pinned Nuclei vulnerable 5/5,
patched-negative 5/5, out-of-scope 3/3, denied state-changing/non-HTTP 3/3 and template/RPC controls
3/3; exactly 10 authorized executions and zero unauthorized traffic. Live topology allows only the
synthetic target and blocks the control-plane listener, LLM gateway, Ollama and public IP. All prior
Phase 1.1 evidence remains byte-identical.

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
sidecars). Original Git history remains unavailable; the Phase 1.1 working snapshot was later
imported honestly as the root commit and tagged `phase-1.1-go` before Phase 1.2 work began.

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
