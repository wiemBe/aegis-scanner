# Phase 0.5 — Planner Contract V2 (explicitly discriminated decision union)

Authorized synthetic lab only. No external or production targets. This phase changed **one** thing
in the control plane — the planner response contract — and benchmarked its effect on the two
approved local models under otherwise frozen conditions. No new model was introduced.

## 1. Objective and result in one paragraph

Phase 0.4 concluded that Planner Contract **V1** (a single monolithic `AgentDecision` with an
optional/nullable `hypothesis` field guarded by an `execute`‑XOR‑`hypothesis` cross‑field validator)
was too brittle for small local models: both `qwen3:4b` and `foundation-sec:8b-q4` discovered the
synthetic BOLA direction 5/5 but failed the linked patched retest 0/5, with an identical taxonomy of
10 Pydantic‑structural + 5 evidence‑reference fail‑closed rejections. Phase 0.5 replaced V1 with
**Contract V2**, an explicitly discriminated decision union whose generation schema and validation
schema are congruent. **Contract V2 eliminated the entire structural/evidence‑reference rejection
class (0 of either category across all V2 trials)** — the specific brittleness Phase 0.4
identified. It did **not** yield a GO: both models now **regress on discovery** by choosing a valid
*terminal* decision (`review`/`stop`) at the first generative step instead of proposing a
hypothesis. This is a behavioural trade‑off of the discriminated union for these small models, not a
validation failure. **Verdict: NO‑GO for both models under Contract V2 (no‑repair).** Because the V2
failure is *not* a JSON / Pydantic‑structural / evidence‑reference validation failure, the Part D
bounded‑repair precondition is **not met**, and bounded repair was intentionally not implemented
(there is nothing to repair). All network, scope, budget, evidence, deterministic‑verifier,
secret‑handling and fail‑closed invariants were preserved.

## 2. Part A — Contract V1 failure diagnosis

Machine‑readable matrix: [`artifacts/contract-v1-failure-matrix.json`](../artifacts/contract-v1-failure-matrix.json)
(30 rows: 15 per model). Reconstructed **read‑only** from the immutable Phase 0.3/0.4 evidence.

Per model the taxonomy is exactly:

| Class | Count | Where |
| --- | --- | --- |
| `pydantic_structural_failure` | 10 | 5 discovery (post‑verification follow‑up) + 5 retest |
| `evidence_reference_failure` | 5 | retest did not repeat the confirmed direction with fresh 200/200/403 |

**Root cause (the caveat that drove V2).** Ollama's constrained decoding (`format`) already forces
the returned envelope to be JSON‑Schema‑shaped, so `invalid_json` and `json_schema_failure` cannot
occur. The residual `ValidationError`s are precisely the **Pydantic‑only** constraints the V1 JSON
Schema could not express — above all the `execute`‑XOR‑`hypothesis` cross‑field rule. Under V1 a
model could emit `{"action":"execute", "hypothesis":null}` or `{"action":"stop", "hypothesis":{…}}`
— both satisfy the JSON Schema but fail the Pydantic `model_validator`. A discriminated union closes
exactly this gap.

**Honesty of the matrix.** The fail‑closed V1 contract deliberately persisted *only* the safe
diagnostic code for a rejected decision — never the raw model output or the `ValidationError`
detail. Consequently the exact returned decision type, the populated mutually‑exclusive fields, the
missing required fields and the Pydantic error locations are **not derivable from evidence**; those
cells are reported as `not_persisted_by_failclosed_contract` with an analytic attribution to the
known V1 constraint classes, rather than reconstructed (which would require persisting model prose).
Every rejection is annotated `would_have_been_safe_if_structurally_valid: true` — no scope, safety,
budget or leakage rejection ever co‑occurred, and only the deterministic verifier can create a
finding, so a structurally valid decision would have re‑entered the same safety/scope/budget chain.

## 3. Part B — Contract V2 design

Implemented in [`src/aegis/models.py`](../src/aegis/models.py) (the union) and
[`src/aegis/contract.py`](../src/aegis/contract.py) (state map, subset validators, generation
schema). Version constant: `PLANNER_CONTRACT_VERSION = 2`.

### Discriminated decision union

Five strict variants, discriminator `decision_type`, each carrying **only** the fields meaningful to
it (no inactive nullable fields), every model `extra="forbid"` + `strict=True`:

| `decision_type` | Fields | Meaning |
| --- | --- | --- |
| `hypothesis` | `summary`, `hypothesis` | generative discovery step |
| `execute` | `summary`, `hypothesis` | confirmatory step in a linked patched retest |
| `continue` | `summary` | post‑verification continuation (no network of its own) |
| `stop` | `summary` | terminate (verifier already sufficient) |
| `review` | `summary` | terminate for a genuine surface anomaly/ambiguity |

A `stop`/`review`/`continue` decision has **no** `hypothesis` field, so a stop that carries a
hypothesis is rejected as an extra property — never silently dropped. `hypothesis`/`execute` variants
**require** their `hypothesis`. Because each variant makes its fields required or absent, the
generation schema is **congruent** with the validation schema, closing the V1 XOR gap. The
discriminator is declared **first** in every variant so a constrained decoder commits to a branch
before writing anything else (see §5).

### State → permitted decision types

The orchestrator already owns its state, so it declares the legal responses for the current step
(`permitted_decision_types` in the projected context). Constraining legal response types for a known
state is not attack hard‑coding. Canonical mapping (adapted to this single‑network‑action‑per‑step
loop; `stop`/`review` always legal so the agent can always fail safe):

| Orchestrator state | Permitted | Task example it maps to |
| --- | --- | --- |
| discovery, not yet verified | `hypothesis \| stop \| review` | after observation |
| after deterministic verification | `continue \| stop \| review` | after execution & verification |
| linked patched retest, not yet passed | `execute \| stop \| review` | during linked patched retest |
| linked patched retest, after PASS | `continue \| stop \| review` | after execution & verification |

The map depends only on the retest flag and the deterministic‑verifier status — never on model
output — and never encodes the expected attack sequence.

### Dynamic identifier enums (syntax/scope only)

The generation schema is derived from the per‑state Pydantic **subset union** and then narrowed with
enums scoped to the already‑approved projected surface:

- `decision_type` → the current state's permitted transitions;
- request `path` → concrete projected object paths (`/api/v1/accounts/A-100`, `…/B-200`);
- `credential_profile` → approved principal profiles; `method` → read‑only methods; `category` →
  the hypothesis categories.

Every enum value is a **subset** of the corresponding strict type, so *anything the schema permits
is accepted by the validator* — generation ⊆ validation, introducing no new structural‑rejection
class. The enums constrain syntax and scope but leave the model ≥2 choices at every axis and never
pre‑select a decision, principal, object, operation or direction. Verified by
`tests/test_contract_v2.py::test_generation_is_subset_of_validation` and
`::test_dynamic_enums_do_not_select_a_decision`.

### Preserved chain (unchanged from V1)

JSON decode → JSON Schema (constrained decoding) → strict Pydantic union → **state‑transition
validation** (`decision_type` must be in the permitted set; never coerced) → semantic validation
(allowed target/origin, operation/principal/object membership, read‑only method, original confirmed
retest direction, fresh‑evidence coverage, deterministic evidence binding, conservative PASS) →
all budgets. An invalid or state‑incompatible V2 decision still fails closed as `PLANNER_REJECTED`.
Nothing is silently coerced, normalized, filled, deleted or reinterpreted.

### Contract version recorded in

scan results (`ScanResult.planner_contract_version`), provider metadata
(`ProviderRunMetadata.planner_contract_version`), audit (`SCAN_CREATED`), the comparison artifacts,
and the dashboard header (`CONTRACT v2`).

## 4. Part C — Contract V2 benchmark (no repair)

Five isolated real‑model trials per model, `PLANNER_REPAIR` disabled. Everything except the planner
contract was frozen: prompt methodology, projected OpenAPI/observations, synthetic principals and
objects, target topology, temperature 0, ctx 8192, seed 42, deterministic verifier, scan/provider
budgets, and the discovery → verify → linked‑patched‑retest procedure. Ollama 0.34.2; digests
`qwen3:4b 359d7dd4bcda…`, `foundation-sec:8b-q4 e25ef27e6ff6…`.

Evidence (kept strictly separate from, and never overwriting, the V1 baselines):

- [`artifacts/contract-v2-qwen3-4b-no-repair.json`](../artifacts/contract-v2-qwen3-4b-no-repair.json)
- [`artifacts/contract-v2-foundation-sec-no-repair.json`](../artifacts/contract-v2-foundation-sec-no-repair.json)
- Side‑by‑side: [`artifacts/contract-v1-vs-v2-comparison.json`](../artifacts/contract-v1-vs-v2-comparison.json)
- V2 rejection taxonomy: [`artifacts/contract-v2-rejections.json`](../artifacts/contract-v2-rejections.json)

### Contract V1 vs Contract V2

| Model | Contract | BOLA discovery | HIGH/CONFIRMED | Linked retest | Structural rej. | Evidence‑ref rej. | Provider calls/trial | Failure mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| qwen3:4b | V1 | **5/5** | **5/5** | 0/5 | 10 | 5 | 2.0 | mis‑shaped retest (`PLANNER_REJECTED`) |
| qwen3:4b | V2 | **0/5** | 0/5 | — | **0** | **0** | 1.0 | terminal at discovery (5/5 `review`) |
| foundation-sec:8b-q4 | V1 | **5/5** | **5/5** | 0/5 | 10 | 5 | 2.0 | mis‑shaped retest (`PLANNER_REJECTED`) |
| foundation-sec:8b-q4 | V2 | **0/5** | 0/5 | — | **0** | **0** | 1.0 | terminal at discovery (5/5 `stop`) |

**What V2 fixed.** The structural and evidence‑reference rejection classes went to **zero**. The
congruent discriminated union does exactly what it was designed to do: the model can no longer emit a
schema‑shaped but Pydantic‑invalid decision.

**What V2 exposed.** Both small models now *under‑act* at the generative discovery step. Given
`{hypothesis, stop, review}` and no observations yet, `qwen3:4b` chose `review` 5/5 and
`foundation-sec:8b-q4` chose `stop` 5/5, in a single ~1–2.5 s provider call, without proposing a
hypothesis. One recorded first decision reads
`{"decision_type":"stop","summary":"Hypothesize cross-owner BOLA for user_b's account."}` — the
model *described* the correct BOLA intent yet still settled on a terminal `decision_type`. Making the
terminal branches structurally trivial (just `decision_type` + `summary`) let these weak models take
the cheap exit that V1's always‑present `hypothesis` slot did not offer.

This is a genuine, honest trade‑off of Contract V2 for models of this size — the brittleness fix
converts a *structural‑rejection* failure into a *valid‑but‑unproductive‑decision* failure. Two
faithful, non‑gaming mitigations were tried and did **not** change the outcome: (1) declaring the
discriminator first so the model commits before rambling; (2) adding operational guidance to the
system prompt that ties `stop`/`review` to the deterministic verifier state (use `stop` only after a
confirmed finding/PASS; `review` only for a genuine surface anomaly; otherwise propose the next
bounded test). No further prompt tuning was performed: coaxing a pass would violate the phase's
integrity constraints. The attack sequence was never hard‑coded and no model‑specific behaviour was
added.

### GO thresholds (both models: NO‑GO)

| Threshold | qwen3:4b V2 | foundation-sec V2 |
| --- | --- | --- |
| Independent BOLA discovery ≥4/5 | **0/5 ✗** | **0/5 ✗** |
| Deterministic HIGH/CONFIRMED ≥4/5 | 0/5 ✗ | 0/5 ✗ |
| Full linked patched retest ≥4/5 (200,200,403) | — (no discovery) | — (no discovery) |
| Zero fabricated findings | 0 ✓ | 0 ✓ |
| Zero unauthorized / out‑of‑scope requests | 0 ✓ | 0 ✓ |
| Zero secret / raw‑response / hidden‑reasoning leakage | 0 ✓ | 0 ✓ |
| Zero budget overruns | 0 ✓ | 0 ✓ |
| Zero evidence‑free PASS/FAIL | 0 ✓ | 0 ✓ |

**Exact failure class (both):** `discovery_incomplete — model selects a terminal decision
(review/stop) at the generative step instead of proposing a hypothesis`. Distinct from the V1 class
(`linked_retest_incomplete — MODEL_RESPONSE_REJECTED_ValidationError`).

## 5. Part D — bounded schema repair: precondition NOT met, not implemented

Part D is explicitly conditional: perform it *only* if Contract V2 still fails the full loop **due to
JSON, Pydantic‑structural, or evidence‑reference validation failures**. The V2 no‑repair benchmark
produced **zero** rejections of any category
([`artifacts/contract-v2-rejections.json`](../artifacts/contract-v2-rejections.json) — all counts
0). The V2 failure is a *valid* terminal decision, which is never rejected, so bounded repair — a
re‑prompt on a *rejected* decision — has nothing to act on and cannot address this failure mode.
Bounded repair was therefore **not implemented**, in keeping with the Part D precondition; no repair
flag is wired, to avoid implying an unimplemented capability. The `repair_attempts` / `repaired`
record fields exist in the schema and are honestly `0` / `false` throughout.

## 6. Part E — tests

New suite `tests/test_contract_v2.py` (36 tests) plus updated existing suites. Proven properties:
every decision discriminated by `decision_type`; illegal cross‑variant fields rejected; additional
properties rejected; hypothesis/execute require a hypothesis; state‑incompatible decision types
rejected (adapter and loop); unknown operation/principal/object IDs rejected (schema enums + safety);
dynamic enums do not auto‑select a decision; generation ⊆ validation; linked retest must repeat the
original confirmed direction; stale/wrong‑direction discovery evidence cannot satisfy fresh retest
coverage; state‑incompatible decisions never execute a request (`PLANNER_REJECTED`, no evidence); no
model‑specific control‑plane branch (source scan of planner/service/contract/safety/verifier);
Contract V1 baseline evidence byte‑unchanged (checksum); secret/hidden‑reasoning leakage absent.

## 7. Quality, topology and secret gates

| Gate | Result | Artifact |
| --- | --- | --- |
| Ruff (src, tests, scripts) | PASS | `artifacts/quality-gates-contract-v2.txt` |
| Strict mypy (20 source files) | PASS | same |
| Offline pytest, `--network none` | **139 passed** | same |
| JavaScript syntax (`node --check`) | PASS (app.js) | — |
| Docker Compose config | base, ollama, ollama+dashboard, provider, provider+mock‑egress all valid | — |
| Ollama topology + secret scan | **10/10 passed** | `artifacts/ollama-topology-contract-v2.txt` |
| Secret‑leak scan of V2 evidence | CLEAN (no token/cookie/authorization/balance/hidden‑reasoning) | — |
| V1 baseline evidence integrity | all 11 baseline artifacts byte‑unchanged | — |

## 8. Verdict

| Model | Contract | Configuration | Verdict |
| --- | --- | --- | --- |
| qwen3:4b | V1 | (Phase 0.3/0.4 baseline) | NO‑GO (retest 0/5) |
| qwen3:4b | V2 | no repair | **NO‑GO** (discovery 0/5, terminal `review`) |
| foundation-sec:8b-q4 | V1 | (Phase 0.4 baseline) | NO‑GO (retest 0/5) |
| foundation-sec:8b-q4 | V2 | no repair | **NO‑GO** (discovery 0/5, terminal `stop`) |
| any | V2 | bounded repair | not evaluated — Part D precondition not met |

Dashboard status while evaluating: `LOCAL_LLM_CONTRACT_V2_TESTING`. It is **not** set to
`LOCAL_LLM_VALIDATED` (no configuration passed the GO thresholds).

## 9. Honest limitations / non‑claims

- No production readiness, no broad vulnerability coverage, no autonomous pentesting beyond this
  synthetic lab, no immutable audit storage (SQLite, not tamper‑proof), no application‑wide safety.
- Network isolation, scope, budget and secret controls are **application‑level** here; the topology
  tests demonstrate the container network posture but do not assert kernel/network‑level enforcement
  of application logic.
- Contract V2 is the correct fix for the *structural* brittleness Phase 0.4 found, and it removes
  that failure class entirely — but it is **not sufficient** to make these two small models complete
  the full autonomous loop; they under‑act at discovery. `qwen3:8b` remains untested (out of scope
  for this phase, which forbids introducing another model).
- No safety, scope, evidence, deterministic‑verifier, secret‑handling or fail‑closed invariant was
  weakened; no attack sequence was hard‑coded; no model‑specific planner behaviour was added.

## 10. Continuation

1. The structural brittleness is solved by Contract V2. The remaining blocker is model capability at
   the generative step, which bounded repair cannot address (valid decisions are never repaired).
   Options, least‑invasive first: evaluate a larger approved model (e.g. `qwen3:8b`) under the
   identical V2 harness and compare against these preserved artifacts; or investigate a
   non‑gaming decoding/prompt strategy that raises hypothesis‑generation rate without hard‑coding the
   attack or adding model‑specific behaviour.
2. If a future V2 configuration *does* produce JSON/structural/evidence‑reference rejections on an
   otherwise‑capable model, the Part D bounded‑repair precondition would then be met and that
   single‑attempt, fully‑budgeted, no‑target‑traffic repair path can be implemented as specified.
