# Phase 1.2 — Nuclei integration prerequisites

Phase 1.1 ships the kernel and a disabled Nuclei skeleton. Phase 1.2 (live Nuclei) must not begin
until **all** of the following exist. None of this is implemented in Phase 1.1.

## Verification / promotion

1. A documented promotion path for Nuclei observations. Nuclei's capability keeps
   `verification_policy = HUMAN_REVIEW_REQUIRED` until a deterministic Aegis verifier exists for the
   specific check; a human-review capability can only reach `REVIEW_REQUIRED`, never `VERIFIED`,
   automatically. Any deterministic verifier must be added with its own test path.

## Scope, network and credentials

2. A separate, non-privileged Nuclei sidecar on an isolated network segment, with egress restricted
   to the approved synthetic origin only (deny-all otherwise), attested by a topology test.
3. A pinned, reviewed template set baked into the image — **no** remote template fetch, no
   auto-update, no arbitrary template path from the job.
4. No credential mounted unless a reviewed synthetic credential profile is explicitly provisioned
   into the sidecar connector boundary; values never cross into the control plane or the job.
5. No shell passthrough: the adapter constructs the Nuclei invocation solely from the typed
   `EngineJob` (approved target + capability + templates), never from model prose or a job field.

## Kernel work

6. A `NucleiAdapter` implementing `SecurityEngineAdapter.execute` that parses Nuclei output into
   `EngineObservation`/`EngineReportedFinding` with fail-closed bounds (oversized/malformed →
   `ENGINE_DISABLED`/`MALFORMED_ENGINE_OUTPUT`), inside the sidecar boundary.
7. An `enabled=True` Nuclei profile added to the catalog **only** once 1–6 hold, plus a
   `PASSIVE`-only activity classification and read-only method restriction.
8. Execution-policy coverage: the existing `build_engine_job` rejections (scope, method, budget,
   environment, disabled, command/flag/template) must be exercised for Nuclei by new tests.

## Evidence and honesty

9. A fresh, immutable Phase 1.2 acceptance matrix with its own artifacts; prior artifacts stay
   byte-identical.
10. The console must continue to show Nuclei's honest `configured`/`reachable`/`enabled`/`authorized`
    states and must not represent it as available until it is truly enabled and authorized.

Do not enable Nuclei by flipping the catalog flag alone. Enabling without 1–10 is a scope and safety
regression.
