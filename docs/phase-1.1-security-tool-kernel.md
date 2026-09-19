# Phase 1.1 — Security Tool Integration Kernel

Status: **GO**, limited to the authorized synthetic lab and the one read-only BOLA capability, now
executed through a provider-independent engine interface. This is **not** a production-readiness
verdict, and Nuclei/ZAP/Burp DAST are **not** operational.

## Objective

Establish a provider-independent security-tool integration kernel that lets Aegis integrate
`AEGIS_NATIVE`, `NUCLEI`, `ZAP` and `BURP_DAST` behind common, deterministic contracts — without
giving the AI planner direct access to tools, credentials, arbitrary targets, command lines or
tool-specific flags. Phase 1.1 establishes the contracts and migrates the existing AEGIS_NATIVE path
behind them. It does **not** implement live Nuclei, ZAP or Burp execution.

## Responsibility boundary (unchanged, extended)

- The AI planner proposes bounded, structured security hypotheses only.
- The deterministic controller selects an approved capability and engine profile.
- The controller constructs the typed [`EngineJob`](engine-adapter-contract.md).
- The adapter translates that job into engine-specific execution and must not expand scope or
  interpret arbitrary model prose.
- Engine findings are untrusted observations, not verified Aegis findings.
- Only deterministic Aegis verification or explicit human review may promote a result.
- Credentials remain inside the connector (adapter) boundary.
- No engine receives unrestricted shell access.

## What shipped

New package `src/aegis/engine/`:

| Module | Responsibility |
| --- | --- |
| `contracts.py` | Strict typed contracts: `SecurityEngine`, `EngineCapability`, `EngineProfile`, `EngineJob`, `EngineExecution`, `EngineObservation`, `EngineReportedFinding`, `NormalizedFinding`, `NormalizedEvidence`, `EngineHealth`, `EngineError`, plus lifecycle/error/environment/policy enums. |
| `catalog.py` | The deterministic, model-immutable capability + profile catalog. Only `AEGIS_NATIVE` has an enabled profile. |
| `policy.py` | `build_engine_job` — the typed execution policy. Rejects every disallowed job **before** any adapter/engine invocation. |
| `adapters.py` | `SecurityEngineAdapter` interface, the enabled `AegisNativeAdapter`, three fail-closed `DisabledEngineAdapter` skeletons, and the `EngineDispatcher`. |
| `lifecycle.py` | Evidence-provenance normalization and the finding lifecycle transitions. |

The `ScanService` controller now constructs an `EngineJob` for the compiled read-only hypothesis,
dispatches it to the `AEGIS_NATIVE` adapter (wired to the exact same executor/safety/verifier), and
records the new engine events, normalized evidence, and normalized finding lifecycle. The planner,
deterministic execution queue, safety controller, deterministic verifier and linked-retest semantics
are unchanged.

See [AEGIS_NATIVE migration notes](aegis-native-migration.md),
[engine adapter contract](engine-adapter-contract.md),
[normalized finding/evidence schema](normalized-finding-evidence-schema.md),
[tool-integration threat model](threat-model-tool-integrations.md), and
[Phase 1.2 Nuclei prerequisites](phase-1.2-nuclei-prerequisites.md).

## Finding lifecycle

An adapter result can never become a confirmed Aegis finding on its own:

```text
TOOL_REPORTED -> AEGIS_CORRELATED -> VERIFIED            (deterministic verifier only)
                                  \-> REVIEW_REQUIRED     (needs a human)
                                  \-> REJECTED
```

`severity`/`confidence` are written only when a normalized finding reaches `VERIFIED`, and only from
the deterministic verifier (or, for a human-review capability, marked review-derived `PROBABLE`
after an explicit human decision). For `AEGIS_NATIVE`'s BOLA capability the deterministic verifier is
authoritative; the raw cross-owner `200` the adapter reports is an untrusted `TOOL_REPORTED` signal
that only the verifier promotes.

Each normalized finding records, distinctly: what the AI hypothesized, what the controller
authorized, what the engine reported, which evidence was collected, what the verifier concluded, and
what a human reviewed.

## Evidence provenance

Every `NormalizedEvidence` item records `evidence_id`, `engine`, `adapter_version`,
`engine_execution_id`, `run_id`/`scan_id`, `timestamp`, `capability`, target reference, request
references, artifact references, redaction status, content digest, parser version, source
classification and retention classification. It never carries credentials, cookies, `Authorization`
values, raw secrets, hidden reasoning or uncontrolled exception prose. Response bodies are hashed
into a content digest and discarded.

## Audit events

Added, ordering/ID/pagination/SSE/redaction/checksum preserved: `ENGINE_JOB_CREATED`,
`ENGINE_JOB_REJECTED`, `ENGINE_EXECUTION_STARTED`, `ENGINE_EXECUTION_COMPLETED`,
`ENGINE_EXECUTION_FAILED`, `ENGINE_FINDING_REPORTED`, `ENGINE_FINDING_CORRELATED`,
`ENGINE_FINDING_REJECTED`, `VERIFICATION_STARTED`, `VERIFICATION_COMPLETED`, `HUMAN_REVIEW_REQUIRED`.
Engine execution/reported events are attributed to the tool-runner/controller boundary — never the
AI model. Verification events belong to the verifier.

## Operator Console

Additive, no redesign. Runs carry engine + adapter version; the Audit Explorer keeps its engine
filter; a new `/api/console/engines` readiness surface shows honest, independent `configured`,
`reachable`, `enabled` and `authorized` states with Nuclei/ZAP/Burp DAST as `DISABLED`; the Run
Replay adds a finding-lifecycle visualization (tool-reported vs verifier-confirmed) and an
execution-policy decision panel (jobs constructed vs jobs rejected with a safe reason code). Existing
Mission Control, SSE, replay, evidence, management-presentation and health functionality is
unchanged.

## Rejections (execution policy)

`build_engine_job` rejects, each with a structured audit event and zero tool traffic: unknown
engine/profile/capability; disabled adapter; disallowed environment; out-of-scope origin or
operation; unapproved state-changing behaviour; missing authentication context; unsupported method;
arbitrary command/CLI-flag fields; unknown template or scan configuration; and budget excess. The
`EngineJob` model has no field for a command, flag, raw URL, template or scan config, so injecting
one is a structural impossibility (`extra="forbid"`), not merely a policy.

## Verification

- Ruff: PASS.
- strict mypy: PASS across 35 source files.
- offline pytest: **251 passed** (218 prior + 33 new Phase 1.1), network disabled (`--network none`).
- frontend TypeScript typecheck: PASS.
- frontend ESLint: PASS.
- frontend unit tests: **6 passed** (4 prior + 2 new).
- Vite production build: PASS; no external runtime assets.
- npm audit: **0 vulnerabilities**.
- Phase 1.1 secret/leakage scan: CLEAN (`artifacts/secret-scan-phase-1.1.txt`).
- all 112 pre-existing artifact files are byte-identical
  (`artifacts/phase-1.1-prior-evidence-manifest.sha256`).

Evidence: `artifacts/quality-gates-phase-1.1.txt`, `artifacts/frontend-gates-phase-1.1.txt`,
`artifacts/secret-scan-phase-1.1.txt`, `artifacts/phase-1.1-prior-evidence-manifest.sha256`, each
with a `.sha256` sidecar.

## GO criteria — met

- AEGIS_NATIVE passes all prior acceptance scenarios through the new interface (vulnerable
  `200/200/200` → HIGH/CONFIRMED only via the deterministic verifier; patched `200/200/403` →
  complete-coverage PASS; controller-constructed linked retest; negative preflight controls keep
  zero model calls and zero target requests).
- Disabled adapters fail closed with a structured `ENGINE_DISABLED` result and zero traffic.
- Tool observations cannot directly become verified findings.
- The console accurately distinguishes engine, controller and verifier responsibility.
- All quality, secret, artifact-integrity and frontend gates pass.

## Not claimed

Nuclei, ZAP or Burp integration is **not** operational. No broad OWASP coverage, no production
readiness, no autonomous pentesting, no immutable audit, and no application-wide safety are claimed.
The GO is scoped to the localhost synthetic lab and the single read-only BOLA capability.

## Git

The original repository history is absent (no `.git`). Per the git constraint, no `git init`,
history rewrite, commit, tag or release was performed. All changes are left uncommitted for the
operator to integrate into the restored repository history.
