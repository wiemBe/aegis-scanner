# Phase 1.0 backlog — Aegis Operator Console

Status: **planned, not implemented in Phase 0.9**.

The Aegis Operator Console is the proposed operator-facing product layer over the bounded scan,
audit, finding, retest, and evidence contracts established by Phase 0.9. It must not weaken the
controller, verifier, scope, budget, redaction, or network boundaries. No frontend redesign or
migration is part of Phase 0.9; the existing engineering dashboard and the small additive management
demo remain in place.

## Backlog

- **Live Mission Control:** show active synthetic scans, bounded budgets, terminal state, and
  controller progress without implying that controller or verifier actions are AI decisions.
- **Structured audit explorer:** filter by stable event ID, timestamp, actor type, scan, finding,
  linked retest, and event class. Preserve the explicit `AI_MODEL`, `CONTROLLER`, `SAFETY`, and
  `VERIFIER` responsibility boundary.
- **Scan and finding detail pages:** link discovery, deterministic finding, and patched retest while
  presenting management-oriented finding summaries separately from technical evidence.
- **AI/controller/verifier responsibility visualization:** make the handoff explicit: the AI
  proposes a bounded hypothesis; the controller validates, admits, compiles, authorizes, and
  executes; the verifier alone creates findings and remediation verdicts.
- **SSE-based live event updates:** add a one-way Server-Sent Events stream backed by persisted audit
  events, including reconnect cursors based on stable event IDs. Polling remains a fallback.
- **Visual evidence replay:** replay already-recorded typed events and redacted evidence references;
  never re-execute a request merely to animate the UI.
- **Safe API evidence cards:** show stable evidence ID, read-only method, scoped synthetic path,
  synthetic credential-profile label, status code, timestamp, and relationships. Do not show
  Authorization headers, cookies, credentials, raw response bodies, or exception prose.
- **Optional Playwright screenshots for authorized synthetic web targets:** disabled by default and
  permitted only for explicit allowlisted synthetic targets. This capability must not expand target
  scope or create a browser-driven autonomous test path.
- **Screenshot hashing and event linkage:** content-address each image with SHA-256 and link it to a
  stable capture event, scan, finding, retest, and redacted request-evidence reference.
- **Screenshot redaction, retention, and size limits:** redact before persistence, bound dimensions
  and bytes, reject unsupported formats, define short retention, and make deletion auditable.
- **No screenshot or raw evidence exposure to the model by default:** neither images nor response
  bodies enter planner context. Any future exception requires a separate threat model, explicit
  operator opt-in, purpose limitation, and new acceptance evidence.
- **Management-oriented finding summaries:** explain impact, proof, remediation state, and honest
  limits without replacing the verifier-authored technical record or overstating coverage.
- **Honest scope labels:** every relevant view must display **SYNTHETIC LAB**, **READ-ONLY**,
  **AUTHORIZED TARGET**, and **NOT PRODUCTION READINESS** where applicable.

## Phase 0.9 data contract carried forward

Phase 1.0 should consume, not reinterpret, the Phase 0.9 contract:

- audit events have stable `<scan-id>:<audit-id>` event IDs, timestamps, and actor types;
- events and the demo manifest link discovery scan, verifier finding, and linked retest IDs;
- observations expose redacted evidence references with stable evidence IDs and no response content;
- the demo manifest is versioned with `manifest_schema_version`;
- synthetic-lab and read-only labels are data, not presentation-only decoration.

Schema evolution must be additive or versioned. A UI must not infer finding provenance from prose,
attribute deterministic actions to the model, or fetch hidden/raw evidence as a default code path.

## Acceptance criteria for starting Phase 1.0

1. The Phase 0.9 audit and manifest contract is covered by offline tests and two fresh demo runs.
2. An SSE threat model covers authorization, replay, backpressure, reconnect, and data minimization.
3. Screenshot capture has a separate allowlist, redaction pipeline, byte/dimension caps, retention
   policy, checksum verification, and deletion audit before it can be enabled.
4. Browser and model data flows prove screenshots and raw evidence are excluded from planner input
   by default.
5. Visual labels and management summaries pass wording tests for synthetic-lab, read-only, and
   non-production scope.

## Explicit non-goals

Phase 1.0 planning does not authorize production targets, state-changing requests, unrestricted
browser automation, a new vulnerability class, a public model/API, model-generated findings, or
model access to screenshots/raw evidence. None of those capabilities should be inferred from the
console backlog.
