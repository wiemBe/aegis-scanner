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
