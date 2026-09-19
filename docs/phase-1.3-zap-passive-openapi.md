# Phase 1.3 — Controlled ZAP passive OpenAPI integration

Status: **GO for the bounded synthetic lab only.** ZAP performs passive analysis of
controller-approved, read-only, anonymous operations. This is not active vulnerability testing, not
authenticated testing, not broad OWASP coverage and not production readiness.

> ZAP passively analyzes responses from controller-approved read-only API operations. ZAP alerts
> are independently correlated and verified by Aegis.

## Responsibility boundary

- The operator requests the capability `zap_passive_header_openapi_v1` and, optionally, an
  inventory target reference. The AI planner is not involved in this flow; no model output can name
  ZAP, a job, rule, plan, OpenAPI document or URL, target URL, header, script or option.
- The controller selects `ZAP_LAB_PASSIVE_OPENAPI_V1`, builds the projected read-only OpenAPI surface
  from controller-owned inventory ([projection](zap-openapi-projection.md)) and constructs a typed
  job; every rejection happens before the runner is contacted.
- The isolated runner re-derives the projection, revalidates target, profile, projection digest,
  allowlist digest and budgets, generates the fixed Automation Framework plan and runs the pinned
  ZAP behind the scope guard ([isolation](zap-runner-isolation.md)).
- ZAP sends only the approved GET requests (through the guard) and passively analyses the responses
  with the admitted rule manifest ([manifest](zap-passive-rule-manifest.md)).
- ZAP alerts enter as `TOOL_REPORTED`; only the independent header verifier can produce `VERIFIED`
  or a patched `PASS` ([evidence and verification](zap-evidence-and-verification.md)).

## Frozen profile

| Item | Value |
| --- | --- |
| ZAP | `2.17.0`, `zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef` (arm64 `sha256:05cbf4ca…`, amd64 `sha256:71db37cd…`) |
| Architecture executed | `linux/arm64` (Apple silicon host); amd64 file pins verified from the amd64 image, not executed |
| Jar / Java | `015dda47…` / OpenJDK `17.0.20+8-1-deb12u1-Debian` |
| Add-ons (8) | automation 0.60.0, callhome 0.23.0, commonlib 1.43.0, network 0.29.0, openapi 57.0.0, pscan 0.6.0, pscanrules 75.0.0, reports 0.46.0 — inventory digest `56c67a0d4ddf3c541de9e9fef411e51b8503aeb5fcf731e759215fee9ceca55c` |
| Passive rules | `10021` X-Content-Type-Options Header Missing (pscanrules 75.0.0, release, MEDIUM) |
| Manifest | `1.3.0`, SHA-256 `94933d15c53dea51591573b4959f4f4655fbc54586b43a5da03427a78dcf2ba3` |
| Versions | profile `1.3.0`, adapter `zap-adapter/1.3.0`, runner `zap-runner/1.3.0`, guard `zap-scope-guard/1.3.0`, parser `zap-traditional-json-parser/1.3.0`, projection `1.3.0`, verifier `aegis-zap-header-verifier/1.3.0` |
| Plan | `passiveScan-config` (disableAllRules + manifest rules) → `openapi` (`apiFile`, stats test = projected count) → `passiveScan-wait` (`maxDuration: 0`) → `report` (`traditional-json`) |
| Budgets | 2 requests per scenario execution (one per projected operation), 120 s job budget, 128 KiB report, 8 alerts |

## Synthetic scenario

Every synthetic `/lab/zap/*` route sets `X-Content-Type-Options: nosniff` except
`GET /lab/zap/vulnerable/catalog/{catalog_id}`; the patched catalog route differs only by setting
it. Each acceptance projection has two GET operations (status control + catalog), so the expected
ZAP request count is exactly 2 per execution, plus 2 fresh verifier GETs from the control plane. The
routes carry no credential or business data and are excluded from the application's own OpenAPI.

## Live acceptance (real pinned image, arm64)

| Check | Result |
| --- | --- |
| Vulnerable: projection admitted, only the 2 expected GETs, rule 10021 alert on the catalog route only, correlated, verifier CONFIRMED, verifier-owned LOW finding | **5/5** |
| Patched: complete import (2/2), queue drained, zero alerts, verifier PASS, `COVERAGE_COMPLETE` PASS | **5/5** |
| State-changing OpenAPI (POST approved) | 3/3 `ZAP_PROJECTION_REJECTED_STATE_CHANGING_OPERATION`, zero runner calls, zero traffic |
| Alternate/out-of-scope server | 3/3 `ALTERNATE_SERVER`, zero runner calls, zero traffic |
| External `$ref` | 3/3 `EXTERNAL_REFERENCE`, zero runner calls, zero traffic |
| Remote API definition / target URL via RPC | 3/3 rejected (HTTP 400), zero executions |
| Injected activeScan / spider / script | 9/9 rejected: 3 scan-API field injections (422), 3 `zap_active_scan_v0` (`ACTIVE_SCAN_FORBIDDEN`), 3 runner-RPC job injections (400); zero executions |
| Injected ZAP options / rules via RPC | 3/3 rejected, zero executions |
| Unexpected redirect | 3/3 fail closed (`SCOPE_ESCAPE_BLOCKED`: ZAP followed the 302, guard refused the follow-up) |
| Unexpected extra request | 3/3 fail closed (`REQUEST_BUDGET_EXCEEDED`: ZAP retried after a dropped connection, guard refused) |
| Target timeout | 3/3 fail closed (`TARGET_TIMEOUT`) |
| Malformed / truncated / oversized / hostile report | fail closed: the runner image's own parser against a genuine pinned-ZAP report and 12 mutations — genuine PARSED, every mutation rejected with no records |
| Incomplete passive queue, hung engine, missing report, non-zero exit | fail closed in the offline suite (fault injection is not possible on the real engine) |
| Authorized ZAP executions | exactly **19** (10 scenario + 9 runtime negatives); every non-execution control 0 |
| Guard | 29 forwarded, 6 refused (never forwarded) |
| Unauthorized target traffic (target access log, by source IP) | **0**; 0 direct requests from the runner; 0 non-GET |
| ZAP execution time | 9.0–9.4 s per scenario execution |

The target's access log confirms 5 requests to each of the four scenario paths and 3 to each
runtime-negative route; the redirect follow-ups and retries never reached the target. The three
slow-route requests were forwarded, timed out at the guard, and are absent from the log only because
the lab logs on response completion.

Regressions on the same stack: Nuclei Phase 1.2 acceptance GO (vulnerable 5/5, patched 5/5, controls
3/3 ×3, exactly 10 executions); AEGIS_NATIVE discovery + linked retest 3/3 (`200/200/200` → HIGH
CONFIRMED, `200/200/403` → PASS) with the deterministic `DEMO_HEURISTIC` planner (no model was
used); Burp DAST `DISABLED`. Live topology: the runner reaches only the scope guard; the guard
reaches only the synthetic target.

A first live run was interrupted when the host went to sleep mid-execution; the controller failed
that scan closed (never PASS) but the run exposed a runner robustness bug (wall-clock `duration_ms`
beyond the contract bound raised instead of returning a typed failure). It was fixed with tests and
the full matrix was re-run on the final code with host sleep prevented.

## Offline evidence

Ruff PASS; strict mypy PASS across 69 source files; **721 offline tests PASS** (464 prior + 257 Phase
1.3; one prior assertion intentionally updated for the new enabled profile); frontend typecheck/lint
PASS, **8 frontend tests PASS**, Vite build PASS, npm audit 0 vulnerabilities; visual QA captures of
Mission Control, Run Replay, Integrations and the management view (desktop and tablet); secret scan
clean; 136 prior artifacts byte-identical. Evidence: `artifacts/phase-1.3-*` and
`artifacts/*-phase-1.3.txt` with `.sha256` sidecars and `artifacts/phase-1.3-evidence-manifest.sha256`.

## Explicit exclusions

No active scan, spider, Ajax spider, client spider, fuzzing, forced browsing, OAST, scripting,
requestor, replacer, sequence scanning, GraphQL/SOAP/Postman import, remote OpenAPI URL, remote report
destination, ZAP API/daemon, MCP, LLM features, authentication, production or staging target, Burp
integration or OWASP coverage claim. See [Phase 1.4 prerequisites](phase-1.4-zap-active-staging-prerequisites.md)
for what active staging testing would require.
