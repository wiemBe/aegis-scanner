# Operator Console troubleshooting

- **`/console/` returns 404:** rebuild the Vite bundle (`npm run build` in `console/`) before the
  Python image. Confirm `src/aegis/console/index.html` and hashed assets exist.
- **Console says degraded:** check `/api/console/health`, then the control-plane logs. The UI keeps
  stale records visibly marked rather than inventing current state.
- **Event stream says STALE:** the browser reconnects automatically with its last event ID. A `GAP`
  state triggers bounded historical rehydration. Confirm Nginx buffering is disabled for SSE if a
  deployment override changes proxy behavior.
- **No Mission Control events:** confirm `/api/console/audit?limit=100` returns rows and that the
  selected run ID exists. The client pages up to 500 historical events before following live data.
- **No finding appears:** this is expected unless the deterministic verifier can reproduce the
  persisted finding from bound evidence. Model hypotheses alone never appear as findings.
- **Local LLM is not connected:** verify the gateway health endpoint and exact model/digest. The UI
  intentionally reports `NOT CONNECTED`; do not hard-code green status.
- **Screenshot capture is inactive:** expected in Phase 1.0. Do not enable it without the approved
  runner and controls in the screenshot policy.
- **Visual layout regression:** rerun `node e2e/visual-qa.mjs` in the matching Playwright container
  and compare the explicitly labeled UI-regression PNGs. They are not scan evidence.

## Phase 1.3 ZAP

- **ZAP card shows `DISABLED`:** `ZAP_ENABLED` is off (default). Start the ZAP overlay.
- **`UNREACHABLE` / `NOT_ATTESTED`:** check `docker compose ... logs zap-runner` for
  `runner-boot ready=True failures=none`. `ADDON_INVENTORY_DRIFT`, `ENGINE_INTEGRITY_FAILURE`,
  `ADDON_RUNTIME_MISMATCH`, `JAVA_VERSION_MISMATCH` or `SILENT_MODE_NOT_CONFIRMED` are stop
  conditions: rebuild only from the reviewed pins; never install or update add-ons.
  `GUARD_NOT_ATTESTED` means the scope guard is not healthy or not on `zap-egress`.
- **`ZAP_PROJECTION_REJECTED_*`:** the inventory source failed validation (expected for the three
  negative-control targets). Fix the controller-owned source; never bypass the projection.
- **`ZAP_EXECUTION_INCOMPLETE_SCOPE_ESCAPE_BLOCKED` / `_REQUEST_BUDGET_EXCEEDED` /
  `_REDIRECT_OBSERVED`:** ZAP tried to leave its approved surface (redirect, retry or extra
  request); the guard refused it before the target. Investigate the target's behaviour.
- **`_TARGET_TIMEOUT` / `_TARGET_UNREACHABLE` / `_EXECUTION_TIMEOUT`:** the target or ZAP did not
  finish in time. Results are INCOMPLETE, never PASS.
- **`_PASSIVE_QUEUE_NOT_DRAINED`, `_IMPORT_INCOMPLETE`, `_PLAN_FAILED`, `_REPORT_*`:** coverage was not
  complete; zero alerts from such a run is not a PASS.
- **Host sleep during a run:** a laptop sleeping mid-execution stalls the stack; the scan fails closed
  (`INCOMPLETE`). Keep the host awake (for example `caffeinate -ims`) during acceptance runs.
