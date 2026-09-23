# Phase 2.0 — Closure (offline verdict-semantics reconciliation)

_Continuation session, 2026-09-23. This is an **offline** reconciliation: no provider calls,
containers, scanners, capabilities or verifiers were executed, and the original live evidence was
not modified. The corrected semantic verdict is regenerated from the persisted artifacts by
`scripts/phase_2_0_reconcile_closure.py` into
`artifacts/phase-2.0-closure-reconciliation/reconciliation.json`._

## Final status (bounded)

- `attack_chain_status = "LIVE_GO"`
- `live_multi_agent_stage_handoffs = "NOT_EVALUATED"`
- `separate_live_agent_stage_jobs_persisted = "NOT_EVALUATED"`

**Final claim.** LIVE GO for one verifier-confirmed multi-primitive attack chain and its patched
break inside the bounded synthetic range. **Live multi-agent stage handoffs: NOT_EVALUATED.**

`passed=true` stands for the bounded attack-chain acceptance only. The three status fields above are
always present so it cannot be read as multi-agent-stage acceptance.

## 1. Agent-handoff check correction

The original verdict carried `real_agent_handoffs_persisted=true`. That name was misleading: **no
separate `CLOUD_BOUNDARY_AGENT` or `AUTHORIZATION_AGENT` jobs were ever created.** The authoritative
ledger's `chain_jobs` table holds **only `CHAIN_AGENT` jobs** (one per arm); both stages were
executed directly by `CHAIN_AGENT` through the Tool Broker. `CLOUD_BOUNDARY_AGENT` /
`AUTHORIZATION_AGENT` are producing-agent **labels** on the two persisted chain links, not
independent queued/claimed/closed jobs.

Correction (semantics only — chain behavior untouched):

- **Renamed** `real_agent_handoffs_persisted` → `chain_link_handoff_metadata_persisted`. It validates
  link metadata only: two ordered links, producing/consuming role labels, evidence references,
  source SHA-256 hashes, `depends_on_link_id`, and the credential-reference dependency.
- **Added** `separate_live_agent_stage_jobs_persisted` — returns `True` only for real distinct
  per-stage agent jobs with their own non-`CHAIN_AGENT` `agentjob://` addresses; producing-agent
  labels alone can never satisfy it. For the bounded run it is `NOT_EVALUATED`.
- **Preserved** `live_multi_agent_stage_handoffs = "NOT_EVALUATED"` as a bounded future acceptance
  item.

Principle: **producing-agent role labels are not proof of live agent execution; link metadata and
separate live agent jobs are distinct concepts.**

## 2. Attempt vs. phase usage (reported separately)

The two rejected first-attempt calls were rejected at output validation before usage was recorded,
so their token cost is genuinely unavailable and is reported as unknown — **never coerced to zero.**

| Attempt | Artifact | Outcome | Calls | Tokens |
|---|---|---|---|---|
| 1 | `artifacts/phase-2.0-live-multi-primitive-chain-20260923T194011Z` | `PARTIAL` (fail-closed) | 2 (both rejected) | UNKNOWN |
| 2 | `artifacts/phase-2.0-live-multi-primitive-chain-20260923T194626Z` | `LIVE_GO` (authoritative) | 7 | 11,267 |

Usage fields (from `reconciliation.json`):

- `authoritative_attempt_provider_calls = 7`
- `authoritative_attempt_provider_tokens = 11267`
- `phase_cumulative_provider_calls = 9`
- `phase_cumulative_known_provider_tokens = 11267`
- `phase_cumulative_unknown_token_calls = 2`
- `within_authoritative_attempt_call_ceiling = true`
- `within_authoritative_attempt_token_ceiling = true`
- `within_phase_call_ceiling = true`
- `within_phase_token_ceiling = "UNKNOWN"`

`within_phase_token_ceiling` stays `"UNKNOWN"` because two calls have unavailable usage. It would
only become `true` given an explicit, auditable request-side input-token bound plus output-token
bound proving the cumulative total stayed below 60,000 — it is **not** inferred from likely prompt
size. Ceilings: ≤12 calls, ≤60,000 tokens.

## 3. Objective rejection and bounded correction

The first live campaign failed fail-closed on the very first model call: `PLAN_ATTACK_CHAIN`'s
`objective` field was capped at **300** chars while the mode-blind objective handed in was **320**, so
the model's verbatim echo overflowed (`objective: string_too_long`). Everything else in that run
worked. The contract prose fields were widened to **600** with headroom, the input objective was
shortened, and a regression guard test was added; the campaign was re-run **once**, transparently,
with **explicit operator authorization** — not silently. The authorization record is the PHASES.md
Phase 2.0 caveat and this document; no separate signed audit artifact was produced.

## 4. Provenance

The failed first attempt is preserved as fail-closed evidence; the second attempt is authoritative.
`reconciliation.json` records the SHA-256 of both `acceptance.json` files and the authoritative
ledger, and embeds the relevant `chain_jobs` / `chain_links` rows (`distinct_job_roles` =
`["CHAIN_AGENT"]`). Original live evidence is unmodified.

## 5. Tests

`tests/test_phase_2_0.py` (50 offline tests, all green) adds focused regressions proving: role
labels alone cannot satisfy a live-agent-job check; link metadata and separate agent jobs are
distinct concepts; unknown provider usage is never converted to zero; and attempt totals and phase
totals are reported separately. Ruff and mypy(strict) are clean on the changed files.
