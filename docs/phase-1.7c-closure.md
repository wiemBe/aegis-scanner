# Phase 1.7-C — Closure status and live-smoke runbook

_Continuation session, 2026-09-23. Fresh evidence:
`artifacts/phase-1.7c-closure-verification-20260923T133513Z/` (preserves all earlier artifacts)._

## Environment note (why some gates are attested, not re-run here)

This continuation ran in an isolated Linux bridge VM with the repo fuse-mounted. That VM has **no
Docker** and its egress allowlist **blocks the Docker registry and PyPI**. Consequently:

- The container gates (Gate 0 registry pull, Gate 1 Nuclei/ZAP, Gate 3 live scans) cannot execute in
  this VM.
- The Python quality gates cannot be dependency-installed in this VM (PyPI blocked), so
  `pytest`/`ruff`/`mypy` are **not run here**.
- The live provider smoke (Gate 3) additionally needs the internal `deepseek-v4-pro` endpoint, which
  the VM cannot reach.

The prior Mac-side session already executed Gates 0 and 1 with real containers; that evidence is
**preserved** and attested here by content hash
(`…/closure-verification-…/relied_evidence.sha256.json`). Gate 2 is verified statically (source +
test suite). Gate 3 is verified as correct-and-bounded in code and is **pending an operator run on
the Mac** (runbook below).

## Verdicts

| # | Gate | Verdict | Basis |
|---|------|---------|-------|
| 1 | Nmap registry confirmation | **PASS** | Executed (prior session), preserved `phase-1.7c-gate0-registry-20260923T121825Z` |
| 2 | Nuclei Recon integration | **CONTAINERIZED PASS** | Executed live (prior session), `phase-1.7c-recon-adapter-20260923T124007Z` (engine=nuclei), 10/10 checks |
| 3 | ZAP Passive Recon integration | **CONTAINERIZED PASS** | Executed live (prior session), same artifact (engine=zap), 10/10 checks; ZAP Active not run |
| 4 | Gateway Recon schemas | **VERIFIED (code + tests present, correct); EXECUTION PENDING on Mac** | Static review this session; authoritative pytest/ruff/mypy pending |
| 5 | Live DeepSeek Recon smoke | **LIVE PASS** | Operator-run on the Mac: 5 provider calls / 9,106 tokens, 13/13 checks true, identity exact `deepseek-v4-pro`, credential gateway-only, cleanup `down_rc=0`, delegation reference-only |
| 6 | Overall Phase 1.7-C | **PASS** | Gates 0–2 executed PASS; Gate 3 live DeepSeek recon PASS |

### Gate 5 — live result (operator-run on the Mac)

`scripts/phase_1_7c_live_recon_smoke.py` executed against the internal `deepseek-v4-pro` endpoint:

- **5 provider calls / 9,106 tokens** — inside the ≤8-call / ≤40,000-token budget.
- **13/13 checks true** — all-green; no NOT_EVALUATED / UNKNOWN entries in this run.
- **Identity exact** `deepseek-v4-pro` (`identity_exact_deepseek_v4_pro`); no `PROVIDER_MODEL_MISMATCH`.
- **Credential gateway-only** — the DeepSeek key stayed in the gateway; agent side never saw it.
- **Delegation reference-only** — model-selected candidate stayed `unconfirmed`; no verdict/severity emitted.
- **Cleanup** `down_rc=0` — the live stack torn down cleanly, no lingering containers.

### Gate 4 — what was statically confirmed
- Server-selected schema per task type: `PLAN_RECON`/`INTERPRET_RECON_OBSERVATIONS`/
  `DELEGATE_RECON_HYPOTHESIS` → `RECON_AGENT`; gateway derives the schema and **discards any
  caller-supplied schema** (`GatewayAgentModel.generate` drops `output_schema`; `AgentGatewayRequest`
  has no schema field). Role/task mismatch → `AGENT_TASK_ROLE_MISMATCH`.
- Model may select only: registered `ReconCapabilityId`, `range-*` target ref, typed
  `GatewayNmapPlanSelection` fields, an approved scanner-profile literal, reference-only delegation
  targets.
- Model **cannot** emit raw shell/flags/origins/templates/policies/payloads/credentials/verdicts:
  `extra="forbid"` rejects raw `argv`; NSE restricted to the admitted-id enum; no evasion/
  credentialed fields at the boundary; no verdict/severity/confirmed field; `unconfirmed` fixed
  `Literal[True]`; origin-in-`route` and shell `capability_id` rejected.
- Sanitized pre-dispatch projection stays `CLEAN` (`forbidden_categories_present == []`), no
  scenario-mode / answer-key markers in the derived schema.
- Exact `deepseek-v4-pro` identity validation preserved (`PROVIDER_MODEL_MISMATCH`).
- The existing phase doc's Limitation "gateway serves only 1.7-A task types" is **superseded**: the
  gateway now serves the three recon task types (see `src/aegis/gateway.py`).

### Gate 5 — harness (now confirmed by the LIVE PASS above)
`scripts/phase_1_7c_live_recon_smoke.py` enforces, in code: ≤8 provider calls, ≤40 000 tokens,
concurrency 1; no offline fallback / no schema repair (a schema violation fails closed); no ZAP
Active / no Beast / no public target. It executes **zero** scans (PLAN/INTERPRET/DELEGATE reasoning
only — within the task's ≤1 nmap / ≤2 nuclei / ≤2 zap ceilings). Observations fed to INTERPRET are
neutral real service records (no vulnerable/patched label, no verdict, no expected ports). It asserts
`identity_exact_deepseek_v4_pro`, `projections_clean`, credential-in-gateway-only, and that a
model-selected candidate stays unconfirmed.

## Runbook — run on the Mac (Docker + internal endpoint present)

Preconditions: Docker running; `.env.gateway` contains `AI_AUTH_TOKEN=<deepseek key>`; `.env` keeps
`AI_PROVIDER=internal_openai_compatible`, `AI_MODEL=deepseek-v4-pro`, `AI_ALLOWED_MODELS=deepseek-v4-pro`.

```bash
cd /Users/efe/Documents/ai-security-lab-copy

# 4) Gateway Recon schemas + reused-adapter mappers (offline, no Docker/provider)
.venv/bin/python -m pytest -q \
  tests/test_phase_1_7c_gateway.py tests/test_phase_1_7c.py tests/test_phase_1_7.py

# Quality gates (do NOT leak live provider vars into these subprocesses)
env -u AI_AUTH_TOKEN .venv/bin/ruff check src tests scripts
env -u AI_AUTH_TOKEN .venv/bin/mypy
# Full clean offline suite (network-isolated)
env -u AI_AUTH_TOKEN .venv/bin/python -m pytest -q -p no:cacheprovider

# 0/1) OPTIONAL re-confirmation of the container gates (evidence already preserved)
#   .venv/bin/python scripts/phase_1_7c_recon_adapter.py            # Gate 1 (nuclei+zap)

# 3) Bounded live DeepSeek recon smoke — ONLY after 0–2 pass
.venv/bin/python scripts/phase_1_7c_live_recon_smoke.py
#   -> writes artifacts/phase-1.7c-live-recon-smoke-<stamp>/acceptance.json
#   -> verdict "LIVE PASS ..." iff all checks pass; otherwise "PARTIAL" (fail-closed)
```

After the smoke, update Gate 5 / Gate 6 verdicts from
`artifacts/phase-1.7c-live-recon-smoke-<stamp>/acceptance.json`.

## Caveats (do not lose these)

**Caveat 1 — root-cause reconciliation (truncation vs. conditional-required fields).**
The original failure surfaced as `INCOMPLETE_MODEL_OUTPUT_LENGTH` (`finish_reason=length`
truncation), and the operative fix was the **per-task output-ceiling bump from 1024 → 4096 tokens**
in `scripts/phase_1_7c_live_recon_smoke.py` (`PER_TASK_OUTPUT_CEILING`) — that bump *was* required;
there is no separate PLAN_RECON prompt directive, so the prompt alone did **not** resolve it. The
conditional-required fields (`nmap_plan` + `profile_id`, enforced by the cross-field
`@model_validator _coherent_selection` in `ReconPlanOutput`) are **not expressible in JSON Schema**,
so the model reasons at length over which fields to co-emit; that long `reasoning_content` is what
exhausted the 1024 allowance — i.e. the conditional-fields constraint explains *why* the reasoning
was long enough to truncate, and the 4096 headroom is what fixed it.

**Caveat 2 — the NOT_EVALUATED/UNKNOWN rejection-projection path was NOT exercised by this run.**
This live smoke was all-green (13/13 true), so the rejection → NOT_EVALUATED tri-state projection
never fired here. That path is instead covered by the unit test
`test_verdict_rejection_marks_downstream_not_evaluated` in
`tests/test_phase_1_7c_truncation.py` (part of the 1165-test suite), which asserts a
truncated/rejected call drives the downstream plan/interpret/delegate checks to `NOT_EVALUATED`
(never `false`). Do **not** re-run the live smoke to demonstrate this — the unit test is authoritative.

## Out of scope (unchanged)
Report Agent, Cloud Boundary Agent, Authentication Testing, Adversary Simulation, and real
multi-primitive attack chains are **not** implemented in this task.
