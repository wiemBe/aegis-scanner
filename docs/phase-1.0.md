# Phase 1.0 — Aegis Operator Console

Status: **GO**, limited to the authorized synthetic lab and one read-only BOLA capability. This is
not a production-readiness verdict.

## Outcome

Phase 1.0 adds a separate operator-facing React/TypeScript console at `/console/`. The engineering
dashboard remains at `/`, and the Phase 0.9 management view remains at `/demo`. The console reads
the existing Phase 0.9 scan, audit, finding, retest, and evidence records; it does not change the
planner, deterministic execution queue, safety controller, verifier, or linked-retest semantics.

The seven console views are Mission Control, Runs, Findings, Audit, Evidence, Integrations, and
System Health. Presentation mode is a focused management surface available from the console.

## Backlog reconciliation

The Phase 1.0 backlog was directionally consistent but materially narrower than the implementation
request. The following requirements were additive rather than cosmetic:

- seven named primary views instead of only mission/audit/detail concepts;
- a fully typed event envelope, global sequence, richer filters, heartbeat, gap signaling, duplicate
  suppression, connection limits, and historical pagination before live SSE;
- explicit API evidence cards and a separate disabled browser-screenshot contract;
- integration registry, actual health checks, management presentation mode, CSP/security headers,
  audit-access logging, request IDs, and tablet QA;
- a React + TypeScript + Vite application because the repository had no maintainable frontend
  framework.

The backlog used the historical actor labels `AI_MODEL`, `SAFETY`, and `VERIFIER`. The Phase 1.0
envelope translates those records into the required actor contract (`AI_PLANNER`, `CONTROLLER`,
`TOOL_RUNNER`, `VERIFIER`, `OPERATOR`, `SYSTEM`) while retaining safety as a distinct stage/status
and preserving the Phase 0.9 API unchanged. This is an additive presentation projection, not a
rewrite of historical evidence.

## Demonstrated workflow

The visual replay accurately shows one AI-generated cross-owner direction followed by deterministic
candidate validation, deterministic queue admission, controller request compilation, safety
authorization, three fresh reads, and deterministic verification. It does not misdescribe the
compiler-expanded owner control, alternate-owner control, and cross-owner probe as three model
decisions.

The discovery and patched comparison is:

```text
Vulnerable: 200 / 200 / 200
Patched:    200 / 200 / 403
```

Only findings reproduced by `DeterministicVerifier` are exposed through the findings API. A forged
persisted finding is excluded by test.

## Security and privacy

- All runtime scripts, styles, and assets are local; there are no CDN, analytics, font, or icon
  requests.
- A strict CSP, `nosniff`, no-referrer, denied framing, restricted browser permissions, request ID,
  and no-store headers apply to the console and APIs.
- Audit metadata is allowlist-projected. Authorization values, cookies, credentials, raw response
  content, reasoning fields, traceback/exception prose, and unapproved model prose cannot enter the
  Phase 1.0 event envelope.
- React renders untrusted strings as text. A hostile-tag unit test verifies that model text does not
  become DOM markup.
- SSE is one-way, bounded to eight concurrent connections, uses stable global cursors, supports
  `Last-Event-ID`, emits heartbeat comments and explicit gap events, and never carries raw evidence.
- Screenshot capture is disabled. The future byte store validates origin, identifiers, MIME magic,
  byte/dimension caps, digest, retention, quota, and project-scoped deletion. Screenshots are not
  planner input.
- The console calls the audit record "structured, checksummed audit evidence" and explicitly does
  not claim immutability.

## Integrations

`AEGIS_NATIVE` is the only operational scan engine. The Local LLM row reports the actual gateway
state and model metadata; it is never forced green when unavailable. Nuclei, ZAP, and Burp DAST are
shown only as `PLANNED NOT CONNECTED`. Their forward-compatible engine enum values do not imply an
integration.

## Verification

- Ruff: PASS.
- strict mypy: PASS across 29 source files.
- complete offline pytest: **218 passed**.
- frontend ESLint: PASS.
- TypeScript project typecheck: PASS.
- frontend unit tests: **4 passed**.
- Vite production build: PASS; no external runtime assets.
- npm audit: **0 vulnerabilities**.
- existing dashboard JavaScript syntax and shell syntax: PASS.
- Compose validation: PASS.
- localhost health, engineering dashboard, console, runs, audit, findings, integrations, and system
  health HTTP checks: PASS with security headers.
- real headless Chromium QA: PASS at 1440×1000 and 900×1100 for Mission Control, Audit Explorer,
  Run Replay, Finding Detail, and Management View.
- Phase 0.8/0.9 offline regression tests remain included in the 218-test pass.
- all 105 pre-existing Phase 0.8/0.9 artifact files are byte-identical to the pre-change hash
  inventory. Six new Phase 1.0 UI-regression PNGs are stored separately.

Topology and negative-egress checks remain those of the localhost-only Compose design; current
runtime health deliberately reports topology/secret results as unavailable when their signed result
is not mounted into the application, rather than showing fabricated green status.

## Verdict and limits

Phase 1.0 is GO for a localhost operator console over the previously validated synthetic-lab
capability. Honest limitations are permanently present in presentation mode: synthetic lab, one
read-only BOLA capability, no broad vulnerability coverage, not production readiness, and not
unrestricted autonomous pentesting.

Original Git history is still unavailable. No repository initialization, commit, tag, or release was
attempted; the working tree remains uncommitted.
