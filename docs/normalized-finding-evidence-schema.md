# Normalized finding & evidence schema (Phase 1.1)

The kernel normalizes every engine result into two provenance-complete records. Both are strict
Pydantic models (`extra="forbid"`) defined in `src/aegis/engine/contracts.py`, serialized as JSON on
`ScanResult` and projected to the console after allowlist redaction.

## NormalizedFinding

Threads the lifecycle and separates every responsibility. No credential, header, response body or
raw model/tool prose is present.

| Field | Meaning |
| --- | --- |
| `normalized_id` | Stable id `"<run_id>:<engine report_key>"`. |
| `engine`, `adapter_version`, `capability_id`, `run_id` | Provenance. |
| `lifecycle_state` | `TOOL_REPORTED` → `AEGIS_CORRELATED` → `VERIFIED` / `REVIEW_REQUIRED` / `REJECTED`. |
| `ai_hypothesis` | What the AI proposed (structured, redacted). |
| `controller_authorization` | The job id + capability + operation the controller authorized. |
| `engine_reported` | The engine's untrusted claim summary. |
| `engine_report_key` | Stable key used for deterministic duplicate correlation. |
| `evidence_ids` | Evidence collected for this finding. |
| `verifier_conclusion` | The verifier's `CONFIRMED`/`PASS`/`INSUFFICIENT` conclusion (null until run). |
| `human_review` | A recorded human decision (null unless review happened). |
| `aegis_finding_id` | The promoted Aegis finding id — set **only** on `VERIFIED`. |
| `severity`, `confidence` | Set **only** on `VERIFIED`, only by the verifier (or `PROBABLE` after explicit human accept). |

### Lifecycle rules

- `correlate_reported_finding` starts at `TOOL_REPORTED`; advances to `AEGIS_CORRELATED` if the
  reported target is inside the authorized job scope, else `REJECTED`. It never sets a verdict.
- `record_verifier_conclusion` promotes to `VERIFIED` **only** for a `DETERMINISTIC_AEGIS_VERIFIER`
  capability with a `CONFIRMED` conclusion; a `HUMAN_REVIEW_REQUIRED` capability can only reach
  `REVIEW_REQUIRED`; a `PASS`/`INSUFFICIENT` conclusion is `REJECTED`.
- `record_human_review` applies an explicit human decision to a `REVIEW_REQUIRED` finding
  (`VERIFIED` with `PROBABLE` confidence, or `REJECTED`).

## NormalizedEvidence

One per engine observation. Every provenance field is mandatory.

| Field | Meaning |
| --- | --- |
| `evidence_id` | `"<scan_id>:<request_name>"`. |
| `engine`, `adapter_version` | Producing engine + adapter version. |
| `engine_execution_id` | The `EngineExecution` that produced it. |
| `run_id`, `scan_id` | Owning scan. |
| `timestamp` | Execution completion (or start). |
| `capability_id` | Capability under test. |
| `target_ref` | Approved operation reference (no raw URL). |
| `request_refs`, `artifact_refs` | Structured references. |
| `redaction_status` | `REDACTED` / `NOT_REQUIRED`. |
| `content_digest` | SHA-256 over the already-redacted response body; the body itself is discarded. |
| `parser_version` | `engine-normalizer/1.1.0`. |
| `source_class` | `ENGINE_OBSERVATION` / `CONTROLLER_DERIVED` / `VERIFIER_DERIVED`. |
| `retention_class` | `EPHEMERAL` / `STANDARD` / `EXTENDED`. |

Digests are stable: normalizing the same execution twice yields byte-identical records
(`test_normalized_evidence_provenance_is_complete_and_stable`).

## Fail-closed bounds

`assert_execution_bounded` rejects oversized output (more than 64 observations or reported findings)
and duplicate request names, so malformed or oversized engine output promotes nothing. Duplicate
reported findings collapse deterministically by `report_key` (`dedupe_reported`).

## Console projection

`finding_lifecycle_projection` exposes the tool-reported vs verifier-confirmed distinction with an
explicit `provenance` (`VERIFIER` vs `ENGINE_UNTRUSTED`); `execution_policy_projection` exposes jobs
constructed vs jobs rejected (with a safe reason code). Neither surfaces a secret or response body.
