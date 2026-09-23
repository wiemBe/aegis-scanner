# Phase 1.9 — Cloud Boundary Agent (single live synthetic vertical slice)

**Status:** LIVE GO for one controller-owned vulnerable/patched cloud-boundary scenario pair in the
synthetic `aegis-cloud` range. This is **not** general cloud coverage, AWS/Azure/GCP support, a real
public-cloud assessment, production-ready cloud testing, or autonomous exploitation.

## Scenario and why it is a cloud boundary

`cloud-metadata-response-v1` (`GT-RANGE-CLOUD-004`, CWE-200) — a synthetic **instance-metadata
credential-exposure boundary**. The `aegis-cloud` integration-check surface can reach an internal
instance-metadata response. In the vulnerable mode that response returns a fresh credential-shaped
field (`access_token` beginning `meta.`); in the patched mode the field is filtered out. This is a
genuine cloud metadata/credential boundary (analogous to an instance-metadata credential exposure),
has both modes, an independent deterministic verifier
(`aegis_range.verifier.RangeVerifier._cloud_metadata`), and is testable entirely inside the range
with no public cloud account.

## Authority model / blinding

The model interprets inventory and observations and produces a typed hypothesis. It is **not**
authoritative for authorization, mode, ground truth, confirmation, severity, PASS/FAIL or cleanup.
The controller owns the mode switch (`RangeController.select_mode`, dependency-aware), the independent
verifier owns CONFIRMED/PASS, and ground truth / severity stay controller-side. The model receives
only the target reference, the capability catalog, the boundary-class vocabulary and the sanitized
live observations — never the mode, scenario id, expected outcome, verifier predicate, credential
value or severity. Hypotheses default `unconfirmed=True`; the model output has no verdict field.

## Pipeline (both modes, live)

1. Controller resets and selects the mode (`aegis-cloud` / `cloud-metadata-response-v1`).
2. A real, persisted, addressable `agentjob://CLOUD_BOUNDARY_AGENT/<id>` job is enqueued and consumed
   (`QUEUED → CLAIMED → CLOSED`, transitions recorded).
3. Live `PLAN_CLOUD_BOUNDARY` → typed plan (registered capability + boundary class + **symbolic**
   destination reference; never a URL).
4. `CloudBoundaryBroker` renders the typed plan into a **shell-free** HTTP execution (fixed method +
   route, controller-resolved destination; asserted free of shell metacharacters).
5. Bounded probe (one benign control + one boundary probe) runs against the live `aegis-cloud`
   container from a throwaway container on the internal `range-access` network. The synthetic
   credential value is **redacted at the source** (`sanitize_probe_response`) and never leaves the
   probe boundary in cleartext.
6. Observations are normalized into typed, reference-only records (`normalize_boundary_observations`);
   target-controlled instruction-like content is flagged as data, never obeyed.
7. Live `INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS` and `SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION` (the
   agent recommends verification; it never confirms).
8. The independent deterministic verifier returns **CONFIRMED** (vulnerable) / **PASS** (patched)
   from controller-owned ground truth.

## Live result

- Verifier: vulnerable → **CONFIRMED** (`fresh_credential_exposed=True`); patched → **PASS**
  (`fresh_credential_exposed=False`).
- All 23 typed verdict checks true. **6 provider calls / 7,043 tokens** (ceilings ≤ 8 / ≤ 40,000).
- Identity exact `deepseek-v4-pro`; projections clean; severity `HIGH` traced to ground truth; no
  credential value anywhere in evidence; credential gateway-only; `down_rc == 0`; no leftovers.
- Evidence: `artifacts/phase-1.9-live-cloud-boundary-<UTC>/`.

## Reuse and caveats

- Reuses the DeepSeek provider-identity infrastructure, the Tool Broker shell-free pattern, the
  persisted addressable-queue design (Phase 1.7-D), and the untrusted-observation / injection
  -resistance boundary — none rebuilt.
- **Live injection negative control:** `NOT_EVALUATED` live (the paid Phase 1.7-D control is not
  repeated). The new HTTP-response ingestion adapter's instruction-resistance and credential
  redaction are covered by offline tests in `tests/test_phase_1_9.py`.

## Run it

```bash
python scripts/phase_1_9_live_cloud_boundary.py
```

Requires Docker and `.env.gateway` (`AI_AUTH_TOKEN=<deepseek key>`). One bounded live run only; on
failure it preserves evidence and stops. Offline coverage: `pytest tests/test_phase_1_9.py`.
