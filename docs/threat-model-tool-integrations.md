# Threat model — security-tool integrations (Phase 1.1)

Scope: the kernel that will integrate external engines (Nuclei, ZAP, Burp DAST) behind the same
boundary as the native path. Phase 1.1 ships only the contracts and the migrated `AEGIS_NATIVE`
path; the external engines are disabled skeletons. This model covers the integration surface the
kernel introduces, not the whole application.

## Assets

- Synthetic credential values (never leave the executor/connector boundary).
- The authorized synthetic target and its scope.
- The audit trail, evidence and verified findings' integrity.
- The responsibility boundary: AI proposes, controller authorizes, verifier confirms.

## Trust boundaries

1. **AI planner → controller.** The AI is untrusted. It authors only structured hypotheses/blockers.
   It cannot name an engine, profile, target, credential, command, flag, or template.
2. **Controller → adapter.** The controller is trusted to build a typed `EngineJob`; the adapter is
   trusted only to execute that job faithfully and never to widen it.
3. **Adapter → engine/target.** The engine's output is untrusted data.
4. **Engine result → verified finding.** Only the deterministic verifier (or explicit human review)
   crosses this boundary.

## Threats and mitigations

| # | Threat | Mitigation |
| --- | --- | --- |
| T1 | AI selects an unapproved engine/tool | No engine/profile field exists in any model the AI authors; the controller selects the engine deterministically from the named capability. Test: `test_model_schema_cannot_name_an_engine_or_profile`. |
| T2 | Arbitrary command / CLI flag injection | `EngineJob` forbids extra properties and has no command/flag/template/config field; `guard_no_raw_command_fields` maps any such payload to a precise rejection. Tests: `test_engine_job_forbids_command_and_config_fields`, `test_policy_guard_rejects_raw_command_fields`. |
| T3 | Adapter expands target scope | Policy rejects out-of-scope origin/operation before build; the adapter re-validates every request through the safety controller with zero traffic on violation. Tests: `test_native_adapter_refuses_out_of_scope_request_with_zero_traffic`, `test_policy_rejects_out_of_scope_origin_and_operation`. |
| T4 | Engine self-confirms a finding | `EngineReportedFinding` has no severity/confidence/verdict field; lifecycle promotion to `VERIFIED` requires the deterministic verifier; human-review capabilities cap at `REVIEW_REQUIRED`. Tests: `test_engine_reported_finding_has_no_verdict_authority`, `test_reported_finding_cannot_become_verified_without_the_verifier`, `test_non_deterministic_capability_only_reaches_review_required`. |
| T5 | Disabled engine leaks traffic/credentials | Disabled adapters fail closed with `ENGINE_DISABLED`, no network, no credential, no subprocess, no MCP. Test: `test_disabled_adapters_fail_closed_with_zero_traffic`. |
| T6 | State-changing behaviour | Policy rejects state-changing capabilities, non-read-only methods and disallowed environments before any traffic. |
| T7 | Missing auth context | Policy rejects when a capability requires authentication and the referenced authenticated profiles are unavailable. |
| T8 | Malformed / oversized engine output | `assert_execution_bounded` fails closed on oversized/duplicate output; promotes nothing. Test: `test_oversized_and_duplicate_engine_output_fails_closed`. |
| T9 | Duplicate/inconsistent tool findings | Deterministic dedupe by stable `report_key`. Test: `test_duplicate_reports_dedupe_by_stable_key`. |
| T10 | Secret / raw response prose in projections | Response bodies are hashed to a digest and discarded; audit metadata is allowlist-projected; normalized records carry no body/credential. Test: `test_normalized_projections_contain_no_secret_or_response_prose`. |
| T11 | Credential exposure across boundary | `EngineJob` carries credential-profile labels only; values resolve inside the executor/connector boundary; the control plane refuses to start with `AI_AUTH_TOKEN`. |
| T12 | Budget exhaustion / runaway | Deterministic budgets rejected before build; per-request budget reserved up front so exhaustion fails closed with zero traffic. |

## Residual risks / non-goals

- The disabled adapters' future network isolation is documented, not implemented. Enabling any of
  them requires the boundary in [the adapter contract](engine-adapter-contract.md), a verifier or
  human-review path, and new acceptance evidence.
- The audit store is "structured, checksummed" — not immutable.
- This model does not claim application-wide safety, broad vulnerability coverage, or production
  readiness.
