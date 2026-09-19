# AEGIS_NATIVE migration notes (Phase 1.1)

Phase 1.1 moved the existing, working BOLA execution path behind the new `SecurityEngine` interface
**without changing its behaviour, request sequence, verification authority or safety properties**.

## What changed

- `ScanService._execute_hypothesis` now, for each compiled read-only hypothesis:
  1. constructs a typed `EngineJob` via `build_engine_job` (controller-owned inputs only);
  2. emits `ENGINE_JOB_CREATED` (or `ENGINE_JOB_REJECTED` + fail-closed);
  3. performs the **unchanged** safety authorization (`TOOL_REQUEST` → `approve_plan` →
     `SAFETY_APPROVED`);
  4. reserves the request budget up front, then dispatches the whole job to `AegisNativeAdapter`
     (`ENGINE_EXECUTION_STARTED`);
  5. binds the returned evidence exactly as before — `REQUEST_STARTED` / append / `OBSERVATION` /
     re-verify per read;
  6. emits `ENGINE_EXECUTION_COMPLETED` and records normalized evidence + the finding lifecycle.
- `AegisNativeAdapter` wraps the same `TestExecutor` and `SafetyController` the service already used.
- `ScanResult` gained additive fields: `engine`, `adapter_version`, `engine_kernel_version`,
  `engine_executions`, `engine_evidence`, `normalized_findings`, `engine_job_rejections` (stored as
  JSON to keep `aegis.models` import-cycle free).
- `operator.Engine` is now an alias of the canonical `SecurityEngine` (identical values).

## What did NOT change

- The planner, deterministic execution queue, candidate validation, safety controller, deterministic
  verifier and linked-retest construction are untouched.
- The request sequence for a candidate is still two fresh owner controls + one cross-owner probe.
- Only the deterministic verifier creates findings or PASS/FAIL; the engine's cross-owner `200` is a
  `TOOL_REPORTED` signal, promoted to `VERIFIED` only by the verifier.
- The existing audit events (`SCAN_CREATED`, `PREFLIGHT`, `CANDIDATE_GENERATED`, `TOOL_REQUEST`,
  `SAFETY_APPROVED`, `REQUEST_STARTED`, `OBSERVATION`, `VERIFIER_RESULT`, `RETEST_PLAN`,
  `TERMINAL_REASON`, `SCAN_COMPLETED`, …) are all still emitted; engine events are additive.

## Preserved acceptance behaviour

- Vulnerable pattern `[200, 200, 200]` becomes HIGH/CONFIRMED only through the deterministic verifier.
- Patched pattern `[200, 200, 403]` produces complete-coverage PASS.
- The linked retest remains controller-constructed (`usage.model_calls == 0`).
- Negative preflight controls (missing-auth / out-of-scope / state-changing) still produce zero model
  calls and zero target requests, and now also produce **no** `ENGINE_JOB_CREATED`.

All 218 prior offline tests still pass unchanged; 33 Phase 1.1 tests were added
(`tests/test_phase_1_1.py`). See `artifacts/quality-gates-phase-1.1.txt`.

## Rollback

The migration is contained in `src/aegis/engine/`, `src/aegis/service.py`, `src/aegis/operator.py`,
`src/aegis/audit.py`, `src/aegis/models.py` and the console. Removing the engine dispatch and
reverting `_execute_hypothesis` to its inline executor loop restores the exact Phase 1.0 path; the
additive `ScanResult` fields are backward-compatible (defaults apply to old records).
