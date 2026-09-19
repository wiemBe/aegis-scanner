# Phase 0.8 — Deterministic Execution Queue (responsibility boundary correction)

Authorized synthetic lab only. No external or production target was added. Phase 0.8 corrects the
responsibility boundary between the probabilistic planner and the deterministic controller:

> The model proposes bounded security hypotheses. The deterministic controller validates, orders,
> compiles, authorizes, executes and verifies them.

`planner_contract_version` stays **3** (the enumeration contract is unchanged in spirit).
`execution_policy_version = 1` records the deterministic admission/ordering/compilation policy.

## 1. Why Phase 0.7 failed and what changed

Phase 0.7 was NO-GO for both models for two separable reasons (docs/phase-0.7 §5):

- **qwen3:8b** — every positive candidate omitted the object reference for an object operation and
  was rejected `MISSING_OBJECT_REFERENCE` before any target traffic. The generic candidate shape
  made `object_ref` optional/nullable.
- **foundation-sec:8b-q4** — generated a valid candidate but the **second, model-based selection
  call** produced a structure that failed the strict selection schema (`MODEL_RESPONSE_REJECTED`).

Phase 0.8 removes the second model call entirely and tightens the candidate shape:

| Concern | Phase 0.7 | Phase 0.8 |
| --- | --- | --- |
| Candidate → execution selection | second model call (`/v1/select`) | **deterministic execution queue** (no model call) |
| Candidate shape | one generic model, `object_ref` optional/nullable | **capability-discriminated union**; `object_ref` required, non-empty, dynamically enumerated |
| Linked retest | model re-plans the direction | **controller-constructed** from the confirmed finding |
| Preflight of controller-known facts | mixed into model context | **deterministic preflight before any model call** |

The only registered capability remains `bola_object_read_v1`, the only test the deterministic
verifier can prove. There is no model-name branch anywhere in the control plane.

## 2. Architecture (Parts A–F)

**Part A — deterministic execution queue.** The second model-based candidate-selection call is
removed from the live flow. Its historical schemas (`SelectOneSelection`, `RejectAllSelection`,
`ReviewSelection`, `SelectionCandidateView`, the `/v1/select` gateway route and provider methods)
are retained, marked deprecated, so Phase 0.7 evidence stays readable, but the flow never calls them.
Validated candidates are admitted into a deterministic queue that:
never creates, mutates, completes or reinterprets a candidate; never bypasses safety/scope/budget;
uses a documented, **model-independent** stable ordering (registered capability priority → approved
operation id → alternate/owner principal tuple → object reference; the controller-assigned candidate
id is only a never-reached final tiebreaker); admits as many candidates as fit within the remaining
request/iteration/call/token/time budgets; and executes them in order, stopping once the deterministic
verifier reaches a terminal state. Model-generated text is never used as finding confidence, severity
or execution authority. Each cycle persists the policy version, validated candidates, queue order,
admission/rejection reason, budget decision and the executed candidate id(s).

**Part B — capability-discriminated candidate schemas.** The generic candidate is replaced by a
strict discriminated union keyed on the registered `capability`. The object-authorization variant
(`ObjectAuthorizationCandidate`) requires non-empty structured fields: `capability`, `operation_id`,
`owner_principal_ref`, `alternate_principal_ref`, `object_ref`, `expected_authorization_invariant`
and `projected_context_refs`. `object_ref` is never Optional, nullable, blank or an unrestricted
string; the generation schema enumerates it to the approved projected objects only, so when no object
is projected the candidate is not even expressible. `owner_principal_ref` and
`alternate_principal_ref` are required, different, drawn from the approved authenticated credential
profiles, and represent a testable cross-owner access direction. `operation_id` comes from the
projected OpenAPI, supports the capability, uses an approved read-only method and carries the required
object binding. A candidate carries no URL, header, cookie, credential, request body, response data,
finding, severity or verdict; `extra="forbid"` makes any cross-variant field a hard rejection. The
generation schema is proven to be a subset of the validation schema in the offline suite.

**Part C — deterministic request compiler.** An admitted validated candidate is compiled into the
existing typed read-only requests using controller-owned data only: approved target origin, canonical
OpenAPI path/method, controller-owned credential-profile resolution, the candidate-supplied approved
principal relationship and `object_ref`, existing headers generated outside the model, and the
existing redaction/secret handling. The compiler resolves references into controller-owned values but
never invents or replaces a missing candidate reference; compilation failure terminates that candidate
fail-closed and issues no traffic. The model never receives a credential value or a raw Authorization
header. Each direction compiles to the deterministic sequence the verifier requires — fresh
alternate-owner control, fresh owner control, then the cross-owner probe — yielding `200,200,200`
(CONFIRMED on the probe) on the vulnerable variant and `200,200,403` (scoped PASS) on the patched one.

**Part D — deterministic preflight.** Controller-known facts are evaluated before candidate
generation: the target is uniquely in scope, required credential profiles exist, at least one
registered verifier capability applies, at least one approved read-only operation is available,
budgets are available, and the scenario does not require a state-changing operation. If a preflight
condition fails the controller does not call the model, does not issue target traffic, returns the
canonical structured blocker/review result and persists the exact controller evidence
(`AUTHENTICATION_UNAVAILABLE`, `SCOPE_AMBIGUITY`, `SAFETY_CONFLICT` / `NO_SUPPORTED_TEST_CAPABILITY`,
`BUDGET_UNAVAILABLE`, …). This is not a heuristic fallback; these are controller-owned facts. The
model may still report blockers for facts that require semantic analysis.

**Part E — candidate generation semantics.** The model still identifies a plausible supported
hypothesis and selects the operation, principal relationship, object reference and expected
authorization invariant through structured fields. Candidate generation is not a finding. The
deterministic verifier remains the only component that may create a vulnerability classification,
severity, confirmation, PASS/FAIL or evidence binding. The vulnerable operation, object, principal
direction and expected HTTP result are not hard-coded into the planner.

**Part F — linked patched retest.** The retest is verification of a known finding, not a new
generative task: the deterministic controller constructs the retest plan from the original confirmed
structured finding (same operation and object relationship, the same confirmed principal/object
direction), collects fresh owner controls plus the fresh cross-owner denial, does not reuse discovery
evidence, expects conservative complete coverage, cannot PASS on a single denial, and produces the
`200,200,403` sequence only when actually observed. The model is not asked to rediscover or reselect
the confirmed direction.

## 3. Narrow real-model regression (Part G)

Same deterministic seed schedule (42), projected context, budgets, topology, temperature 0 and
context length 8192 for both models; Ollama 0.34.2; no automatic retry. Five isolated positive
vulnerable BOLA trials per model, each with its linked patched retest.

| Positive criterion | Threshold | qwen3:8b | foundation-sec:8b-q4 |
| --- | ---: | ---: | ---: |
| Valid object-authorization candidate | 5/5 | **5/5** | **5/5** |
| Deterministic queue admission | 5/5 | **5/5** | **5/5** |
| Typed read-only execution | 5/5 | **5/5** | **5/5** |
| Deterministic HIGH/CONFIRMED discovery | 5/5 | **5/5** | **5/5** |
| Linked patched retest (200,200,403 → PASS) | 5/5 | **5/5** | **5/5** |
| Zero unauthorized requests / mutation / leakage / fabricated findings / budget overruns | all | pass | pass |
| **Verdict** | | **GO** | **GO** |

Evidence: `artifacts/phase-0.8-narrow-qwen3-8b.json`,
`artifacts/phase-0.8-narrow-foundation-sec-8b-q4.json`.

## 4. Controls (Part H)

Run only after both models passed the narrow 5/5 positive regression.

| Control | qwen3:8b | foundation-sec:8b-q4 | Model calls | Target requests |
| --- | ---: | ---: | ---: | ---: |
| Patched negative (5 trials, complete-coverage PASS) | 5/5 | 5/5 | 1 per trial | 3 per trial |
| Missing authentication (3) → `AUTHENTICATION_UNAVAILABLE` | 3/3 | 3/3 | **0** | **0** |
| Ambiguous / out-of-scope (3) → `SCOPE_AMBIGUITY` | 3/3 | 3/3 | **0** | **0** |
| State-changing-only (3) → `SAFETY_CONFLICT` | 3/3 | 3/3 | **0** | **0** |
| **Verdict** | **GO** | **GO** | | |

The three deterministic controls now block at preflight with **zero model calls and zero target
requests** — the exact gap that made Phase 0.7 missing-auth a NO-GO. Patched-negative reaches
conservative complete coverage (`200,200,403` → PASS) with zero confirmed findings and zero
evidence-free PASS. Evidence: `artifacts/phase-0.8-controls-<model>.json`.

## 5. Twenty-trial stability extension (Part H)

Winning model **qwen3:8b** (primary; both models qualified). Initial statistics excluded.

| Twenty-trial criterion | Threshold | Result |
| --- | ---: | ---: |
| Valid candidates | 20/20 | **20/20** |
| Complete discovery + linked retest loops | ≥19/20 | **20/20** |
| Fabricated findings / unauthorized requests / mutation / leakage / evidence-free PASS / budget overruns | 0 each | **0,0,0,0,0,0** |
| **Verdict** | | **GO** |

Evidence: `artifacts/phase-0.8-extension-qwen3-8b.json`. Narrow, control and extended evidence are
kept in separate files.

## 6. Candidate rejection distribution and execution-policy audit

Across the narrow + control trials for both models (`artifacts/phase-0.8-candidate-rejection-
distribution.json`): `OWNER_PRINCIPAL_MISMATCH ×10`, `DUPLICATE_CANDIDATE ×10` — models sometimes
proposed a direction whose declared owner did not actually own the object, or re-proposed an
equivalent direction; both were rejected deterministically before any traffic. Execution-policy audit
(`artifacts/phase-0.8-execution-policy-audit.json`): execution_policy_version 1 throughout, 40 queue
entries admitted, 0 blocked, 20 candidates executed, **0 model-based selection calls**.

## 7. Quality, topology and evidence (Part K)

| Gate | Result |
| --- | --- |
| Ruff | PASS (src, tests, scripts) |
| Strict mypy | PASS, 23 source files |
| Offline pytest | PASS, 184 tests, container network disabled |
| Dashboard JavaScript syntax | PASS, Node 22 |
| Compose validation | PASS: base, +ollama, +ollama+dashboard, +provider(deprecated), +provider+mock-egress |
| Ollama topology / negative egress / scope / secret / localhost | PASS 10/10 for each model |
| Secret-leak scan (new evidence) | CLEAN |
| Prior evidence integrity | All 47 pre-Phase-0.8 artifacts match the preflight SHA-256 manifest |

Primary evidence: `artifacts/phase-0.8-narrow-*.json`, `artifacts/phase-0.8-controls-*.json`,
`artifacts/phase-0.8-extension-qwen3-8b.json`, `artifacts/phase-0.8-model-comparison.json`,
`artifacts/phase-0.8-candidate-rejection-distribution.json`,
`artifacts/phase-0.8-execution-policy-audit.json`,
`artifacts/phase-0.8-prior-evidence-manifest.sha256`, `artifacts/quality-gates-phase-0.8.txt`,
`artifacts/ollama-topology-phase-0.8-*.txt`, `artifacts/compose-validation-phase-0.8.txt`,
`artifacts/secret-scan-phase-0.8.txt` (each with a `.sha256` sidecar).

## 8. Tests (Part I)

The offline suite proves: object-authorization candidates cannot omit `object_ref`; `object_ref`
cannot be null, blank or outside the dynamic enum; principal references are required, approved and
different; capability-discriminated candidates reject cross-variant fields; the controller never fills
a missing model-selected reference; invalid candidates are never queued; deterministic ordering is
stable and model-independent; execution policy cannot change candidate semantics; request compilation
uses canonical OpenAPI and controller-owned secrets; compilation failure issues no traffic; the model
is never asked to select and no `CANDIDATE_SELECTION` occurs; deterministic preflight prevents
unnecessary model and target calls; the linked retest uses the original confirmed direction with
fresh evidence; the deterministic verifier remains the only finding authority; the generation schema
is a subset of the validation schema; prior artifacts remain byte-identical; and no provider-specific
control-plane branch exists. See `tests/test_phase_0_8.py`, `tests/test_contract_v3.py`,
`tests/test_agent_loop.py`.

## 9. Verdict and limits

Per-model and overall verdict: **GO** for the Phase 0.8 synthetic-lab acceptance (both approved
models pass narrow, control and — for qwen3:8b — stability gates). This is **not** production
readiness, broad vulnerability coverage, autonomous pentesting authority outside the synthetic lab,
immutable audit storage, or application-wide safety. The only proven capability is a single read-only
BOLA object-authorization comparison on the synthetic bank API, with the deterministic verifier as the
sole finding authority.

The workspace has no Git metadata. No repository was initialized, no history was replaced, and all
Phase 0.8 changes remain uncommitted. All prior evidence is immutable and byte-identical.
