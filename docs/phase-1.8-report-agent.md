# Phase 1.8 — Report Agent

The Report Agent is an offline, deterministic transport for verifier/controller-owned evidence.
It does not scan, call a model, assign severity, or turn an unconfirmed delegation into a finding.

Run it from the repository root:

```bash
.venv/bin/python scripts/phase_1_8_report_agent.py
```

The default inputs are the checksum-manifested Phase 1.7-B verifier records and the requested
Phase 1.7-D live acceptance plus durable delegation queue. The output is a new timestamped
`artifacts/phase-1.8-report-agent-*` directory containing:

- `report.json`: typed machine-readable report;
- `report.md`: human-readable evidence report;
- `verdict.json`: typed Phase 1.8 gate verdict;
- `SHA256SUMS`: integrity manifest for the rendered bundle.

The report has four non-overlapping sections: verified security findings, target security
validation outcomes, platform/phase assurance checks, and unconfirmed hypotheses. Every confirmed
finding references its verifier record and evidence digest and is explicitly marked
`OFFLINE_VERIFIED_SYNTHETIC`. Severity is copied only from controller ground truth; absent severity
renders as `UNKNOWN`.

The Phase 1.7-B delegation-workflow chain record is a platform/workflow validation, never a
duplicate XSS finding. Patched XSS and SQLi PASS outcomes remain target validations, while Phase
1.7-D checks remain platform assurance and cannot imply target security. The Phase 1.7-D
`confirmed=false` delegation remains an UNKNOWN-severity hypothesis with its queue address and
source evidence digest. Zero report-agent provider calls produce `reporting_pipeline_status =
OFFLINE_PASS` and `live_report_agent_status = NOT_EVALUATED`, not a live GO.
