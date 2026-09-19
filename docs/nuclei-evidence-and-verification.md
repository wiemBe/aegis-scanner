# Nuclei evidence and independent verification

The runner returns typed metadata and bounded parsed records only. It never returns raw stdout,
stderr, request/response bytes or exception prose. The parser enforces total, line and line-count
bounds; strict UTF-8/JSON with duplicate-key rejection; expected template, path and origin; approved
matcher metadata; and refusal of raw request/response, encoded template or interaction fields.
Sensitive-capable fields such as curl commands, IPs, template URLs and extracted values are counted
and stripped.

Stable record digests exclude timestamps. Evidence IDs bind the engine, adapter/parser/profile,
manifest/template digests, execution/job/run, target reference, capability and redaction state.
Audit projections use an allowlist and contain no credentials, cookies, Authorization values,
response bodies, hidden reasoning or uncontrolled tool/error text.

Lifecycle:

```text
Nuclei record -> TOOL_REPORTED -> AEGIS_CORRELATED
                                      |
                 fresh typed verifier probes
                                      |
                         VERIFIED / REVIEW_REQUIRED / REJECTED
```

The SCM verifier checks a fresh synthetic base control and a fixed `/.git/config` path. It evaluates
status, bounded body structure and synthetic route markers. It does not consume Nuclei severity,
description, matcher/extractor content, classification or conclusion. Confirmed severity is owned by
the Aegis capability catalog.

The console renders a `NUCLEI_EXECUTION_CARD` as untrusted tool evidence and separate
`VERIFIER_PROBE_CARD` records. These are data cards, never fabricated browser screenshots. The
Integrations view shows configured/reachable/enabled/authorized independently, pins, manifest,
template count, health time, latest counts and tool-reported versus verifier-confirmed totals.
