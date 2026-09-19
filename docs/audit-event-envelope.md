# Phase 1.0 audit-event envelope

The Phase 1.0 envelope is an additive redacted projection of persisted Phase 0.9 audit rows.

| Field | Meaning |
| --- | --- |
| `event_id` | Stable global cursor, `evt-` plus a 12-digit sequence |
| `sequence` | Monotonic SQLite audit row identifier |
| `timestamp` | UTC-aware event time |
| `run_id`, `scan_id` | Owning scan identifiers |
| `finding_id` | Verifier finding relationship when present |
| `retest_scan_id` | Linked retest relationship when present |
| `parent_event_id`, `child_event_ids` | Same-scan chronological relationships |
| `actor_type` | `OPERATOR`, `AI_PLANNER`, `CONTROLLER`, `TOOL_RUNNER`, `VERIFIER`, or `SYSTEM` |
| `event_type` | Stable persisted event class |
| `stage` | Normalized workflow stage |
| `status` | Structured state such as `RECORDED`, `CONFIRMED`, `PASS`, `FAILED`, or `REJECTED` |
| `engine` | `AEGIS_NATIVE`, `NUCLEI` (Phase 1.2) or `ZAP` (Phase 1.3); `BURP_DAST` reserved |
| `summary` | Server-owned concise summary, never raw model/target prose |
| `evidence_refs` | Approved redacted evidence references |
| `redaction_status` | `REDACTED` or `NOT_REQUIRED` |
| `metadata` | Strict allowlist projection |
| `integrity` | SHA-256 over the redacted event payload |

The checksum detects accidental projection changes; it is not an immutability claim.

## History and SSE

`GET /api/console/audit` accepts a numeric cursor, a limit from 1–100, and filters for scan/finding,
actor, stage, status, engine, event type, model, operation, principal relationship, safety decision,
and time range. Results are in `sequence ASC` order.

`GET /api/console/events` accepts `Last-Event-ID: evt-000000000123` or a `cursor` query fallback.
It first emits persisted events after the cursor, then follows new rows. It suppresses duplicates,
signals a gap, sends heartbeat comments every 15 seconds, and enforces eight concurrent streams.

Audit API and stream access are recorded in a separate access-log table with request ID, route,
outcome, and timestamp. The access log stores no query values or response data.

## Phase 1.3 ZAP events

`ZAP_PROJECTION_CREATED`, `ZAP_PROJECTION_REJECTED`, `ZAP_JOB_ADMITTED`, `ZAP_JOB_REJECTED` and
`ZAP_ALERT_CORRELATED` are `CONTROLLER` events; `ZAP_RUNNER_STARTED` (runner and scope-guard
attestation) is `SYSTEM`; `ZAP_PLAN_VALIDATED`, `ZAP_OPENAPI_IMPORT_STARTED`,
`ZAP_OPENAPI_IMPORT_COMPLETED`, `ZAP_PASSIVE_SCAN_WAIT_STARTED`, `ZAP_PASSIVE_SCAN_DRAINED`,
`ZAP_EXECUTION_COMPLETED`, `ZAP_EXECUTION_FAILED` and `ZAP_ALERT_REPORTED` are `TOOL_RUNNER`;
`ZAP_VERIFICATION_STARTED` and `ZAP_VERIFICATION_COMPLETED` are `VERIFIER`. New stages:
`OPENAPI_PROJECTION`, `PLAN_VALIDATION`, `OPENAPI_IMPORT` and `PASSIVE_SCAN`. The metadata allowlist
adds only ids, digests, versions, counts, codes and labels (for example `projection_digest`,
`urls_added`, `observed_requests`, `blocked_reasons`, `plugin_id`, `claimed_risk`); ZAP alert prose,
report text and HTTP content are never persisted, so they cannot be projected.

## Phase 1.4 Beast audit

Beast records use a dedicated append-only SQLite table and a global SHA-256 previous-digest chain.
Each API replay returns `beast-evt-<12 digits>`, sequence, UTC timestamp, run, event/actor, exact
details, previous digest and digest. This is checksummed local evidence, not an immutable audit-store
claim. Synthetic-lab command text and bounded stdout/stderr are visible to the authorized operator.
React renders them as text, never unsafe HTML.

Activation/lease events: `BEAST_MODE_REQUESTED`, `BEAST_PREFLIGHT_STARTED`,
`BEAST_PREFLIGHT_REJECTED`, `BEAST_APPROVAL_RECORDED`, `BEAST_LEASE_ISSUED`,
`BEAST_MODE_ACTIVATED`, `BEAST_CAPABILITY_AUTHORIZED/REJECTED`, budget warning/exhaustion and lease
expiry. Adaptive-loop events: `AI_ADVERSARY_DECISION`, `AI_SHELL_COMMAND_PROPOSED/STARTED/COMPLETED`,
`AI_SHELL_COMMAND_TIMED_OUT/TERMINATED`, `AI_SHELL_OUTPUT_REDACTED` and
`AI_ADVERSARY_OBSERVATION/STOPPED`. Artifact/network events record creation, admission/rejection,
boundary blocks and sandbox destruction. Verifier, cleanup, emergency-stop, health-restore and final
completion events retain actor separation. Every next-decision event includes its input observation
IDs; commands contain their parent command IDs.
