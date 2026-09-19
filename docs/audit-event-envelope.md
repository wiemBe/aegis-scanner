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
| `engine` | `AEGIS_NATIVE`; forward-compatible with `NUCLEI`, `ZAP`, `BURP_DAST` |
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
