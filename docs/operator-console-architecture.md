# Operator Console architecture

## Phase 1.2 Nuclei projection

The console remains read-only. `GET /api/console/engines` now adds controller-safe Nuclei
provenance: pinned and attested version/digest, manifest version/digest, admitted-template count,
signature probe, health timestamp and latest execution/request/result/lifecycle counts. Run Replay,
Mission Control and Audit Explorer use the structured `NUCLEI_*` events and preserve the
TOOL_REPORTED versus verifier-confirmed split. Evidence uses rendered execution/verifier cards; no
browser screenshot is fabricated for tool output.

The management view states: “Nuclei is an Aegis-controlled detection engine. Its results are
independently correlated and verified; Nuclei does not directly confirm Aegis findings.”

## Surfaces

| Surface | Path | Purpose |
| --- | --- | --- |
| Engineering dashboard | `/` | Existing scan initiation and engineering details |
| Phase 0.9 management view | `/demo` | Existing two-scan management projection |
| Operator Console | `/console/` | Phase 1.0 operations, replay, findings, audit, evidence and health |
| Console API | `/api/console/*` | Read-only redacted projections |
| Live stream | `/api/console/events` | One-way SSE over persisted audit events |

The console source is in `console/`. Vite writes a content-hashed production build to
`src/aegis/console/`; FastAPI serves it as local package data. No runtime build tool or external
asset host is required.

## Data flow

```text
SQLite scans + audit rows
          │
          ▼
read-only allowlist projection ──► checksummed event envelope ──► history API
          │                                                   └─► SSE stream
          ├──────────────────────► verifier re-evaluation ──────► findings API
          └──────────────────────► redacted evidence cards ─────► replay/evidence UI
```

The projection layer is not in the scan execution path. It does not issue target requests, call the
model, alter scan status, or create findings. Historical hydration pages forward in stable sequence
order, then the client opens SSE from the last accepted sequence. The client rejects duplicates,
detects a sequence gap, marks the surface stale, and rehydrates.

## Trust boundaries

- Planner text is untrusted and rendered only through React text nodes.
- Persisted audit details are untrusted until the server allowlist projection removes sensitive or
  nonessential fields.
- Scan findings are not trusted merely because they exist in SQLite; the console re-runs the
  deterministic verifier and displays matching records only.
- Health rows use actual HTTP/database checks or explicit `NOT_CONFIGURED`/`NOT_AVAILABLE` states.
- Screenshot metadata and bytes are a separate, disabled-by-default boundary; they never enter the
  model context.

## Runtime constraints

The dashboard remains bound through Nginx to `127.0.0.1:8000`. Internal services publish no host
ports. CSP permits only same-origin scripts, styles, images, and connections. The console uses no
WebSocket, service worker, local-storage secret, analytics, or third-party request.

## Phase 1.1 — security-tool integration kernel

The engine kernel (`src/aegis/engine/`) sits between the deterministic controller and the executor.
It does not change the data-flow above; it adds a typed, provider-independent execution boundary and
a normalized finding/evidence lifecycle on top of the same records.

```text
AI hypothesis ─► controller ─► build_engine_job (policy) ─► EngineDispatcher ─► adapter ─► executor
                    │                    │ reject → ENGINE_JOB_REJECTED (zero traffic)
                    │                    ▼
                    │            EngineExecution ─► EngineObservation / EngineReportedFinding (untrusted)
                    ▼                    │
        deterministic verifier ◄─────────┘
                    │
   TOOL_REPORTED ─► AEGIS_CORRELATED ─► VERIFIED | REVIEW_REQUIRED | REJECTED
```

- **Catalog** (`catalog.py`): model-immutable capability + profile registry. Only `AEGIS_NATIVE` is
  enabled.
- **Policy** (`policy.py`): `build_engine_job` rejects unknown/disabled/out-of-scope/state-changing/
  missing-auth/unsupported-method/command-field/budget jobs before any traffic.
- **Adapters** (`adapters.py`): one enabled `AegisNativeAdapter` (wraps the existing executor/safety),
  three fail-closed disabled skeletons, one `EngineDispatcher`.
- **Lifecycle** (`lifecycle.py`): provenance-complete `NormalizedEvidence` and finding-state
  transitions; only the deterministic verifier promotes to `VERIFIED`.

New console projections: `/api/console/engines` (four-state readiness), run-detail `lifecycle` and
`execution_policy`, and engine/adapter version on runs. New audit events (`ENGINE_JOB_CREATED`,
`ENGINE_JOB_REJECTED`, `ENGINE_EXECUTION_*`, `ENGINE_FINDING_*`, `VERIFICATION_*`,
`HUMAN_REVIEW_REQUIRED`) flow through the same envelope, ordering, redaction and checksum path.

See [Phase 1.1](phase-1.1-security-tool-kernel.md), [adapter contract](engine-adapter-contract.md),
[schema](normalized-finding-evidence-schema.md) and
[threat model](threat-model-tool-integrations.md).

## Phase 1.3 ZAP additions

Additive only. Run projections carry a `zap` summary (pins, projection digest, operation/import and
expected/observed request counts, passive-queue completion, tool-reported/correlated/verifier counts,
coverage state). `/api/console/engines` adds ZAP readiness provenance (pinned version and image
digest, add-on inventory digest, profile, approved rule count, scope-guard state, latest execution).
Mission Control selects a ZAP workflow for ZAP runs and shows a coverage panel; Run Replay adds ZAP
jump targets and comparison; evidence adds `ZAP_EXECUTION_CARD` and `ZAP_ALERT_CARD` (untrusted) next
to `VERIFIER_PROBE_CARD`; the Management view states: “ZAP passively analyzes responses from
controller-approved read-only API operations. ZAP alerts are independently correlated and verified by
Aegis.” All alert content renders as React text. See
[ZAP evidence and verification](zap-evidence-and-verification.md).
