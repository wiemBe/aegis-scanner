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
- Injection and Chain execution exist only as the bounded, offline-accepted Phase 1.7-B slice:
  `HTTP_API_SURFACE_RECON` (documented HTTP/API surface only — **not** network/Nmap/Nuclei/ZAP
  recon, none of which are implemented as Recon Agent capabilities), controller-owned reflected-XSS
  and boolean-SQL-injection detection probes (model payload authorship is structurally impossible),
  and a `DELEGATION_WORKFLOW_CHAIN` (recon → injection → independent verify delegation). That chain
  is **not** a multi-primitive attack chain and does **not** complete any Phase 1.6 range attack
  chain. There is no live-provider execution path for the 1.7-B gates yet (the gateway serves only
  the 1.7-A task types).
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

## Phase 1.7-C controlled Recon Agent (offline-accepted, 2026-09-23)

Phase 1.7-C upgrades the recon role (`AgentRole.RECON_AGENT`, class `CONTROLLED_RECON_AGENT`) into a
controlled Recon Agent with four registered capabilities: `aegis.recon.network_service_discovery`
(typed `NmapScanPlan` → controller-rendered, shell-free argv; `RANGE_FULL_RECON` supports full TCP,
bounded/full UDP, version + OS detection and NSE discovery/version/vuln/safe against synthetic-range
targets, while `AUTHORIZED_ENV_RECON` fails closed without a signed lease), the reused Phase 1.2
`aegis.recon.nuclei_reviewed_exposure` and Phase 1.3 `aegis.recon.zap_passive_openapi` (scanner
alerts stay `confirmed=False` candidates), and the existing `aegis.surface.openapi`. A recon plan is
expanded into single-purpose jobs (TCP discovery, UDP discovery, service/version+NSE, OS detection),
each rendered to its own shell-free argv; NSE runs only the pinned admitted script IDs (broad
categories crash/hang nmap on a bounded target). Source spoofing, decoy/fragmentation evasion and
credentialed brute-force are **`UNSUPPORTED_IN_PHASE_1_7C_RECON`** — rejected pre-execution with zero
traffic and reserved for future dedicated Adversary-Simulation / Authentication-Testing capabilities
(not architecturally prohibited). Recon emits only eight typed, deduplicated observation kinds and
never confirms, PASSes or sets severity; the verifier retains sole authority and Recon has no path to
it.

The nmap worker's supply chain is pinned by immutable RepoDigest
(`instrumentisto/nmap@sha256:96f6ed19…`, nmap 7.98, linux/arm64). Determined experimentally: nmap
needs uid 0 for raw sockets, so SYN/UDP/OS jobs run as `user 0:0` + only `NET_RAW` while connect/
version/NSE run non-root with no added capability. A **real containerized run**
(`scripts/phase_1_7c_containerized.py`) executed the worker against Bank + Shop on an internal,
egress-blocked network: **CONTAINERIZED PASS** — 8101/8102 discovered (service `http`, product
`Uvicorn`), OS detection executed (inconclusive in Docker), and every negative control (no egress, no
host FS / Docker socket, scope escape rejected, no published port, container removal, malformed XML →
INCOMPLETE, recon-cannot-confirm) verified experimentally, with clean cleanup. The Nuclei/ZAP passive
*runners* were not re-executed in that harness (reuse covered by Phase 1.2/1.3), so the recon suite
overall is PARTIAL. Offline acceptance (`scripts/phase_1_7c_acceptance.py`, 13/13 PASS) is preserved.
**No paid DeepSeek run was performed.** Full report:
[docs/phase-1.7-controlled-recon.md](phase-1.7-controlled-recon.md).
