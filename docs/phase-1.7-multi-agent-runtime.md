# Phase 1.7 — Multi-Agent Evaluation Runtime

Status: implemented initial BOLA vertical slice; offline synthetic acceptance only. This is not a
production-readiness or multi-agent-superiority claim.

## Reused architecture

Phase 1.7 is additive. `aegis.multi_agent` adapts the existing components:

| Existing component | Phase 1.7 use |
|---|---|
| provider gateway and hardened providers | shared role-scoped structured generation endpoint |
| deterministic controller scheduling | typed `AgentTask` records and controller transitions |
| range inventory/controller | target reference resolution, mode selection, reset and health |
| HTTP execution controls | controlled broker with fixed read-only operations and alias resolution |
| `RangeVerifier` | sole BOLA confirmation/PASS authority using fresh requests |
| SQLite database | `agent_runs` and `agent_events` tables in the existing database |
| Operator Console service | read-only `/multi-agent` view and bounded projection APIs |

There is no Redis, message bus, second database, agent shell, Docker socket, or unrestricted HTTP
client. Nuclei and passive ZAP remain catalog-only for this slice. ZAP Active is absent from the
agent capability registry and the console labels it disabled.

## State machines

Run transitions are controller-owned and fail closed:

```text
QUEUED -> RESETTING -> RUNNING -> VERIFYING -> CLEANING_UP -> COMPLETED
   |          |           |          |              |
   +----------+-----------+----------+--------------+-> CANCELLED
              +-----------+----------+--------------+-> FAILED
```

`COMPLETED`, `FAILED`, and `CANCELLED` are terminal and have no outgoing transition. Task states
are `QUEUED -> RUNNING -> COMPLETED`; a controller error changes active work to `FAILED`, while an
emergency stop changes every queued/running task to `CANCELLED`. Cancellation performs a
controller-owned reset and health check.

## Typed communication

The controller persists strict Pydantic records for `AgentRun`, `AgentTask`, `AgentObservation`,
`AgentHypothesis`, `AgentActionRequest`, `AgentActionResult`, `FindingCandidate`,
`VerifierResultRef`, `AgentBudgetLedger`, and `AgentAuditEvent`. Unknown properties and malformed
JSON are rejected. Agent-authored schemas deliberately have no URL, header, credential, verdict,
severity, cleanup, budget, or free-form request fields.

The Lead can delegate only typed surface or authorization tasks. Surface and Authorization agents
receive controller references and bounded observations. Every broker action is bound to run, task,
agent and role, has a short expiry and one-use nonce, and is rechecked against task context and the
role/capability registry.

## Trust boundaries

- The model gateway owns provider access and secrets. The control plane uses `GatewayAgentModel`.
- The gateway derives the output schema from controller task type; callers cannot supply a weaker
  schema. Provider reasoning fields are never read or returned.
- Inventory resolves `range-bank` to its origin. No model contract can carry an origin.
- The broker resolves credential aliases and resource references. Their values never enter model
  or console contexts.
- Agent observations and candidates are untrusted. Only `RangeVerifier` produces confirmation or
  PASS.
- Scenario mode and controller ground truth never enter an agent context.
- Global and per-agent counters are admitted under one `asyncio.Lock`, including model calls,
  tokens, target requests, command count, elapsed time and evidence bytes.
- Reset, mode selection, verification, evaluation and cleanup remain controller owned.

## Initial BOLA flow

The multi-agent path uses four structured model calls: Lead surface task, Surface interpretation,
Lead authorization task, and Authorization proposal. It makes one documented-surface request,
three broker comparison requests, and three fresh verifier requests. The single-agent baseline uses
one combined structured model call and the same observation envelope, capabilities, seven target
requests, verifier, global limits and per-agent limits.

Both paths evaluate vulnerable and patched modes without exposing the selected mode. A vulnerable
result is a controller FAIL-equivalent `CONFIRMED`; patched rejection is `PASS`. A candidate never
self-promotes.

## Offline acceptance

Run:

```bash
PYTHONPATH=src .venv/bin/python scripts/phase_1_7_acceptance.py
.venv/bin/pytest -q tests/test_phase_1_7.py
```

The 10 dedicated tests cover shared-gateway schema validation, arbitrary-origin exclusion,
answer-key/secret exclusion, unauthorized
capabilities, strict malformed output, cross-agent spoofing, identity binding, stale/replayed
actions, concurrent budgets, stop propagation, terminal-state monotonicity, vulnerable/patched
verifier outcomes, cleanup, persistence, safe console projection and equivalent baseline limits.

## Honest limitations

- Offline acceptance uses `OFFLINE_STRUCTURED_FIXTURE`; it proves controller semantics, not live
  model quality or multi-agent improvement.
- No live provider benchmark has been run for Phase 1.7. Model-call and token differences are
  measured but not interpreted as an improvement.
- The runtime has no durable distributed worker recovery; it is intentionally in-process and uses
  the current SQLite persistence model.
- Injection Agent and Chain Agent are registered but have no capabilities or execution path.
- Nuclei/passive ZAP agent delegation and all ZAP Active work are out of scope.

## Phase 1.7-A live-provider smoke (2026-09-23)

Verdict: **NO-GO**. The configured DeepSeek `internal_openai_compatible` gateway and requested
`deepseek-chat` model were used with the authorized synthetic Bank only. The required sequence
stopped at case 1 (`single_agent / vulnerable`) after one provider call returned a model identity
that failed the gateway's exact requested-model binding (`PROVIDER_MODEL_MISMATCH`). This was not a
transport failure, so no retry was allowed. The response was not coerced, repaired or replaced.

Before the provider call the single-agent path made one documented-surface request. It produced no
validated model output, hypothesis, broker admission, verifier outcome or controller finding.
Provider tokens are unknown because the gateway rejected the envelope before returning usage. The
safe gateway request projection was likewise not returned, so the required captured-projection
proof is a failed gate rather than a source-inspection inference. Cases 2–4 were not run.

Controller cleanup and the final reset/health check passed. The acceptance project was fully torn
down, structural secret scans were clean without reading the key, and the post-smoke repository
gates passed. See the checksummed artifact at
`artifacts/phase-1.7a-live-20260922T210938Z/acceptance.json` and `SHA256SUMS` beside it.
