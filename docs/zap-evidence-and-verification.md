# ZAP evidence and independent verification (Phase 1.3)

## What leaves the runner

The runner returns typed metadata and bounded, parsed records only (`ZapRunResponse`): versions,
digests, runner-derived stage facts, guard traffic counters, a parse summary and alert records. It
never returns raw ZAP stdout, `zap.log`, the report, the session database, HTTP history, request or
response bodies, headers or exception prose. The whole per-execution directory is deleted before the
response is sent, and `session_destroyed` is reported only after the deletion is observed.

## Report parser (`zap-traditional-json-parser/1.3.0`)

The profile uses ZAP's `traditional-json` report (alerts and instances, no request/response bodies).
The parser enforces a 128 KiB report bound, ≤ 4 sites, ≤ 8 alerts, ≤ 8 instances per alert,
≤ 8 KiB per string and ≤ 1 KiB evidence; strict UTF-8/JSON with duplicate-key rejection; the pinned
ZAP version; the approved origin as the only site; an allowlist of top-level, site, alert and
instance keys; the admitted rule id and manifest name; instance URIs equal to approved projected URLs
with the matching method; and an empty `attack`.

It **never propagates** `desc`, `solution`, `otherinfo`, `reference`, `riskdesc` or tags (they carry
HTML prose): they are counted as stripped. Evidence text is reduced to a length and SHA-256. The rule
name shown anywhere comes from the manifest, not from the report. ZAP risk and confidence become
`claimed_risk` / `claimed_confidence` labels that never set Aegis severity or confidence. Identical
instances collapse deterministically; conflicting instances fail closed. Record digests exclude
timestamps, so evidence ids are stable.

Missing, empty, truncated, malformed, oversized, version-drifted, foreign-site, out-of-allowlist,
unadmitted-rule or attack-bearing reports produce a typed failure with no records; the execution is
then `FAILED` and the scan `INCOMPLETE`.

## Coverage — when zero alerts can mean PASS

A ZAP execution is `COMPLETED` with `coverage_complete` only when **all** of these hold:

1. the projection was validated and the runner's digests matched the controller's;
2. ZAP ran the fixed plan and it was validated byte-for-byte on disk;
3. ZAP's own log confirmed the exact add-on inventory, silent mode and no active rules;
4. ZAP reported exactly the admitted rule set and no unknown rule;
5. `openapi` added exactly the projected operation count and its stats test passed, with no import
   error;
6. the guard forwarded exactly one request per projected operation, received nothing else, blocked
   nothing, saw no redirect, upstream failure or timeout, and every response was 2xx;
7. `passiveScan-wait` (with `maxDuration: 0`, i.e. wait until the queue is empty) finished before the
   runner's hard wall-clock limit;
8. the plan reported success and exit code 0, and the report was generated at the expected path;
9. the report parsed completely.

A patched **PASS** additionally requires zero ZAP alerts **and** the independent verifier's PASS.
Zero alerts alone is never PASS.

## Lifecycle

```text
ZAP alert -> TOOL_REPORTED -> AEGIS_CORRELATED (rule in job, alert on the scenario operation)
                                   |                 \-> REJECTED (any other operation)
                        fresh typed verifier probes
                                   |
                     VERIFIED / REVIEW_REQUIRED / REJECTED
```

## Independent verifier (`aegis-zap-header-verifier/1.3.0`)

The control plane itself (not the runner, not ZAP) sends two fresh anonymous GETs approved by the
safety controller (`approve_zap_verification` permits only the acceptance targets' control and
scenario operations):

- `BASE_CONTROL` — the status route must return 200 JSON with the exact synthetic marker and exactly
  `X-Content-Type-Options: nosniff` (proves reachability, routing and that the header is observable);
- `HEADER_PROBE` — the catalog route must return 200 JSON with the exact synthetic marker; its
  `X-Content-Type-Options` values are then classified as `ABSENT`, `PRESENT_NOSNIFF` or `INVALID`.

`CONFIRMED` needs an absent header; `PASS` needs exactly one `nosniff`; anything else (redirect,
transport error, wrong content type, missing marker, duplicate/unexpected header values) is
`INSUFFICIENT`. The verifier does not read ZAP risk, confidence, alert name, description, solution,
evidence, rule id, report or exit code. Only body-free facts and body digests are persisted.

## Terminal decisions

| Situation | Result |
| --- | --- |
| Correlated alert + verifier CONFIRMED | `FAIL`, `DETERMINISTIC_CONFIRMED`, one Aegis finding (LOW, CONFIRMED, verifier-owned) |
| Correlated alert + verifier PASS | `REVIEW`, `TOOL_FINDING_REJECTED_BY_VERIFIER` (ZAP cannot self-confirm) |
| Correlated alert + verifier INSUFFICIENT | `REVIEW`, `VERIFICATION_INCONCLUSIVE` |
| Alert on a non-scenario operation | `REVIEW`, `UNCORRELATED_TOOL_ALERT` |
| No alert + complete coverage + verifier PASS | `PASS`, `COVERAGE_COMPLETE` |
| No alert + verifier CONFIRMED | `REVIEW`, `ENGINE_VERIFIER_DISAGREEMENT` |
| Projection or policy rejection | `REVIEW`, `ZAP_PROJECTION_REJECTED_*` / `ZAP_JOB_REJECTED_*` (zero runner/target traffic) |
| Runner, guard, parser or coverage failure | `INCOMPLETE`, `ZAP_EXECUTION_INCOMPLETE_*` |

## Audit events and actors

| Event | Actor |
| --- | --- |
| `ZAP_PROJECTION_CREATED`, `ZAP_PROJECTION_REJECTED`, `ZAP_JOB_ADMITTED`, `ZAP_JOB_REJECTED`, `ZAP_ALERT_CORRELATED` | CONTROLLER |
| `ZAP_RUNNER_STARTED` (runner/guard attestation) | SYSTEM |
| `ZAP_PLAN_VALIDATED`, `ZAP_OPENAPI_IMPORT_STARTED`/`_COMPLETED`, `ZAP_PASSIVE_SCAN_WAIT_STARTED`/`_DRAINED`, `ZAP_EXECUTION_COMPLETED`/`_FAILED`, `ZAP_ALERT_REPORTED` | TOOL_RUNNER |
| `ZAP_VERIFICATION_STARTED`, `ZAP_VERIFICATION_COMPLETED` | VERIFIER |

The AI planner is not involved in this operator-requested capability; no ZAP event is attributed to
`AI_PLANNER`. Plan, import and passive-scan stage events are emitted after the synchronous RPC
returns, from runner-derived facts, and carry `source: RUNNER_DERIVED_STAGE_FACT`.

## Console

Mission Control switches to a ZAP workflow (projection → job → attestation → plan → import →
passive scan → execution → tool finding → correlation → verification) and shows a coverage panel:
projected operations, imported messages, observed versus expected target requests, passive-queue
completion, tool-reported, correlated and verifier-owned counts, and complete/incomplete coverage.
The Integrations card shows configured/reachable/enabled/authorized, the pinned version and image
digest, the add-on inventory digest, the passive profile, the approved rule count, the scope-guard
state and the latest execution. Evidence renders `ZAP_EXECUTION_CARD` and `ZAP_ALERT_CARD` (both
labelled untrusted) and `VERIFIER_PROBE_CARD`. All alert content is rendered as React text; no raw
HTTP bodies are displayed.
