# Phase 0.9 — Reproducible Management Demo

Phase 0.9 packages the completed Phase 0.8 GO capability as a repeatable management demonstration.
It adds no vulnerability class, model, external target, or autonomous capability.

## Demonstrated claim

The local `qwen3:8b` model independently proposes one bounded BOLA hypothesis. The deterministic
controller validates it, admits it to execution policy V1, compiles and authorizes read-only
requests, and runs two controls plus one cross-owner probe. The deterministic verifier alone
confirms the finding from fresh `200 / 200 / 200` evidence. A linked controller-built retest repeats
the same direction against the synthetic patched route, observes `200 / 200 / 403`, and reaches a
conservative PASS without model replanning.

This is a synthetic-lab, read-only demonstration. It is not production readiness, broad
vulnerability coverage, or unrestricted autonomous pentesting.

## Operator flow

No source edits are required:

```bash
# 1. Confirm local runtime and the already-installed approved model.
ollama --version
ollama list

# 2. Validate, start, execute, verify, and package one demo run.
scripts/run_management_demo.sh

# 3. Open the localhost URL printed by the command (base dashboard shown here).
open http://127.0.0.1:8000

# 4. When finished, remove only the named demo Compose project.
scripts/run_management_demo.sh --cleanup
```

The run command uses Compose project `aegis-management-demo`, leaves the successful stack running,
and prints the focused demo URL plus the JSON and Markdown evidence paths. Cleanup is project-scoped
and does not prune unrelated containers, networks, volumes, models, or evidence.

## Preconditions and fail-closed checks

The entry point checks Docker/Compose, localhost Ollama, exact `qwen3:8b` digest prefix, disk space,
Phase 0.8 evidence integrity, localhost-only dashboard ingress, control-plane egress denial, gateway
separation from the lab network, and gateway access only to the approved Ollama path. The run aborts
if the planner/model/digest/parameters drift, a candidate is not provider-generated, model-based
selection appears, evidence is stale, routes or response sequences differ, scope is exceeded, the
finding lacks verifier provenance, or the retest does not repeat the confirmed direction.

## Evidence package and UI-ready audit contract

Each unique run writes, without overwriting prior evidence:

- `artifacts/phase-0.9-demo-<run-id>.json`
- `artifacts/phase-0.9-demo-<run-id>.json.sha256`
- `artifacts/phase-0.9-demo-<run-id>.summary.md`
- `artifacts/phase-0.9-demo-<run-id>.summary.md.sha256`

The versioned manifest records provider identity, deterministic generation settings, candidate and
queue records, scan/finding/retest relationships, exact observed status sequences, budgets,
topology/secret checks, and redacted evidence references. Audit API records and manifest timeline
events provide stable event IDs, timestamps, actor types, relationship links, and safe evidence
references. Response excerpts, credentials, headers, cookies, hidden reasoning, and exception prose
are excluded from the management projection.

Request/evidence IDs are namespaced by scan. Verifier finding IDs are also namespaced by scan and
derived from bound evidence, making all of them stable within one scan and fresh across repeated
demo runs.

The manifest records the summary digest and the names of both checksum sidecars. The JSON sidecar
is authoritative for the final manifest bytes; this avoids claiming a circular self-checksum inside
the file it hashes.

## Responsibility boundary

- `AI_MODEL`: candidate generation only.
- `CONTROLLER`: validation, deterministic admission/order, request compilation, execution, linked
  retest construction, and terminal control flow.
- `SAFETY`: read-only/scope/budget authorization or rejection.
- `VERIFIER`: finding creation and remediation verdict from fresh evidence.

The small additive `/demo?discovery=<id>&retest=<id>` view presents this record without changing the
engineering dashboard. The full operator UI is deliberately deferred to the
[Aegis Operator Console Phase 1.0 backlog](phase-1.0-operator-console.md).

## Troubleshooting

- `Docker daemon unavailable`: start Docker Desktop, then rerun.
- `approved localhost Ollama endpoint unavailable`: start local Ollama on `127.0.0.1:11434`.
- `model ... not present` or `digest ... != recorded`: do not download or substitute a model during
  the demo; restore the approved local model and verify its identity.
- port `8000` conflict: stop the conflicting local service or the old demo project only.
- any topology, evidence-integrity, secret, response-sequence, or provenance failure: treat the run
  as NO-GO; do not bypass the guard or hand-edit the manifest.

## Verification and verdict

**GO for the reproducible management demonstration**, narrowly scoped to the authorized synthetic
lab and one read-only BOLA capability. This is not a production-readiness verdict.

- Ruff PASS; strict mypy PASS across 25 source files; 210 offline tests PASS.
- Dashboard JavaScript syntax, shell syntax, and Compose validation PASS.
- All six topology checks PASS on both runs: control-plane internet/model denial, gateway/lab
  isolation, approved Ollama reachability, no internal host ports, and localhost-only dashboard.
- HTTP verification PASS for health, dashboard, demo view, JavaScript, CSS, and scan/audit API.
- Checksum sidecars PASS and new-evidence secret scan CLEAN.
- Consecutive runs `demo-20260918T195703Z-183e3b` and `demo-20260918T195737Z-d79b9e` each produced
  fresh scan/request/finding/retest identifiers, `200 / 200 / 200` discovery, a verifier-created HIGH/CONFIRMED
  finding, `200 / 200 / 403` linked patched retest, and GO without overwriting prior evidence.
- The existing 77 non-demo artifacts were byte-identical after each run; the Phase 0.8 47-file
  prior-evidence manifest also verified intact.
- No browser surface was available for visual QA. HTML, JavaScript, CSS, APIs, and HTTP rendering
  paths were verified, but no visual-layout claim is made.
- Original Git history is unavailable in this workspace. No `git init`, commit, release, or tag was
  attempted; release/tagging remains blocked until the original repository metadata is restored.

The successful `aegis-management-demo` stack is intentionally left running for presentation.
