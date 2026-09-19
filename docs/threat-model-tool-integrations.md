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

## Phase 1.3 — ZAP passive OpenAPI integration

Additional assets: the pinned ZAP image/add-on inventory, the controller-owned OpenAPI inventory,
the projected document and the scope guard's arming state. Additional trust boundaries: controller
→ zap-runner RPC, zap-runner → scope guard, and ZAP → target (only through the guard).

| # | Threat | Mitigation | Evidence |
| --- | --- | --- | --- |
| Z1 | Model or caller selects ZAP, a job, rule, plan, option, header or script | Operator names only a capability + inventory reference; `ScanCreate`, `ZapEngineJob` and `ZapRunRequest` forbid extra fields; the plan is generated by trusted code and validated byte-for-byte | `test_scan_request_cannot_supply_openapi_plan_or_tool`, `test_rpc_request_forbids_arbitrary_fields`, `test_injected_jobs_are_rejected`; live RPC/API injection controls |
| Z2 | Active scan, spider, script, OAST, MCP or LLM feature becomes reachable | Only a PASSIVE capability is enabled; the image contains no active-rule, spider, scripting, OAST, client, MCP or LLM add-on; forbidden job types/keys/flags are refused; boot and per-execution add-on attestation | `test_no_active_scan_spider_script_mcp_or_oast_is_reachable`, `test_injected_zap_flags_are_refused`, drift tests |
| Z3 | Image, jar, JVM or add-on drift / runtime add-on install or update | Digest-pinned base, build-time verification, boot re-hash + ZAP `-addonlist` + `zap.log` attestation, per-execution re-hash and `zap.log` check; `-silent -notel`, update keys off, no route out | `test_image_and_add_on_drift_fails_closed`, `test_runtime_inventory_drift_fails_closed`, `test_drift_after_boot_makes_runner_not_ready_with_zero_traffic` |
| Z4 | Hostile or oversized OpenAPI (state-changing ops, remote/file `$ref`, callbacks, webhooks, links, alternate/templated servers, credentials) | Deterministic projection from controller inventory only, whole-document validation, rebuild of a minimal document, runner re-derivation with digest match | `test_projection_rejects_hostile_sources`; live projection negative controls 3/3 each |
| Z5 | Redirect or retry makes ZAP leave the approved surface (observed in real ZAP 2.17.0) | Runner has no route to the target; the guard forwards only armed (method, path) pairs within a hard budget and refuses everything else before forwarding; runner kills ZAP on the first refusal | `test_scope_and_budget_escapes_never_reach_the_target`; live redirect / extra-request controls; target access-log reconciliation |
| Z6 | ZAP reaches internet, host, LLM gateway, Ollama, Nuclei runner or the control-plane listener | Dedicated internal `zap-rpc`/`zap-egress`/`zap-target` networks; control plane bound to its `security-lab` address | live topology probes |
| Z7 | Malformed, truncated, oversized or hostile report; HTML/script in alert fields | Strict bounded parser, key allowlists, prose never propagated, evidence digested, React text rendering | `test_parser_fails_closed`, `test_html_evidence_is_reduced_to_a_digest`, frontend hostile-alert test; parser controls in the runner image |
| Z8 | ZAP self-confirms, or zero alerts is read as PASS | Alerts are TOOL_REPORTED; only the independent header verifier promotes; PASS needs complete coverage + zero alerts + verifier PASS | `test_zap_cannot_self_confirm`, `test_zero_alerts_without_complete_coverage_is_never_pass`, `test_missing_tool_alert_on_vulnerable_target_is_not_pass` |
| Z9 | Raw HTTP, session database or report persisted | Per-execution tmpfs directory destroyed before the response; only typed facts and digests leave the runner | `test_no_raw_http_or_alert_prose_is_persisted_or_projected`, `session_destroyed` in live evidence |
| Z10 | Hung engine or target | Runner wall-clock kill, ZAP 4 s request timeout, guard 5 s upstream timeout; all INCOMPLETE | `test_hung_engine_is_killed_by_the_wall_clock`, `test_slow_target_times_out_and_never_passes`; live timeout control |

Residual risks: the scope guard and runner are lab-grade Python services on Docker internal
networks, not a production egress firewall or sandbox; the rule manifest review is AI-assisted and
not operator-countersigned; `callhome` is a mandatory core add-on that is neutralised rather than
removed; only one passive rule and one synthetic scenario are exercised.

## Phase 1.4 — TRUE ADVERSARY SHELL correction

The Phase 1.4 boundary is intentionally different from T1/T2 above. Inside
`BEAST_ADVERSARY_SANDBOX_V1`, qwen3:8b may select any installed tool, argument, shell syntax, script,
raw request or payload. There is no command-content allowlist. Outside that sandbox, target identity,
network reachability, resources, authorization, audit, emergency stop, cleanup and verifier
authority remain immutable. This exception applies only to Beast Mode in `SYNTHETIC_LAB`; it does
not alter AEGIS_NATIVE, Nuclei or ZAP contracts.

| # | Threat | Mitigation / acceptance evidence |
| --- | --- | --- |
| B1 | Model targets public, production, staging, wildcard or alternate lab service | Controller inventory has two launchable synthetic refs and fixed origin; production/no-reset records reject preflight; static DNS plus internal network exposes only `beast-target`; exact prefix gateway blocks alternate paths/methods. |
| B2 | Command reaches host, Docker, control plane, Ollama, LLM gateway, corporate/public network | No host mounts/socket/corporate network; sandbox joins only `beast-adversary`; public routing and general DNS are disabled; live negative commands probe every named destination. |
| B3 | Shell steals supervisor/control credentials or modifies/signals supervisor | Child receives a minimal environment without tokens, runs uid/gid 65532 with empty groups and no capabilities, cannot read root `/proc/1/environ`, write the read-only image or signal PID 1. |
| B4 | Detached/background process survives | Supervisor is a child subreaper and kills every process owned by the dedicated command identity after each command, stop and destroy; container PID ceiling is independent. |
| B5 | Fork/output/disk/artifact exhaustion | Container CPU/memory/PID/nofile ceilings, per-child rlimits, workspace tmpfs quota, command timeout, output cap and artifact total; live exhaustion/output controls. |
| B6 | Command widens target method, path, rate, concurrency or byte budget | Gateway is armed by authenticated supervisor data, not shell data; it independently counts and blocks. The shell has no boundary token or network-policy capability. |
| B7 | Workspace/tool cache/payload persists | Read-only root; HOME/TMP/XDG point into a per-run workspace; root-only `/tmp` and `/dev/shm`; artifacts are hashed/classified and workspace is destroyed. A second-session probe proves no persistence. |
| B8 | Model repeats a fixed or failed sequence; controller silently substitutes commands | Every qwen decision receives prior normalized observations and an evidence-sufficiency bit; exact model command is transported unchanged; failure is terminal and visible; no fallback exists. Live acceptance requires changed commands after changed evidence and failed-first-command recovery. |
| B9 | Model/tool promotes its own finding | Model can only command or stop. A fresh deterministic verifier owns `CONFIRMED`, `PASS` and `VERIFIED`; success exit codes and prose have no authority. |
| B10 | Emergency stop races an in-flight model or command | Lease revocation and persisted STOPPED state happen first; the session is destroyed; checks after every external boundary plus a final persisted-state reconciliation prevent overwrite; target remains operator-review blocked. |
| B11 | Shell alters/deletes audit or breaks replay linkage | No audit route/mount; commands/results/observations/next decisions carry stable IDs and parent sequence; append-only rows are SHA-256 hash chained. SQLite is not claimed immutable. |
| B12 | Fixture or controller hard-codes the expected attack | Public OpenAPI omits hidden weakness names/markers; controller source contains no expected command; five live trials per scenario retain all model decisions and exact commands for review. |

Residual risk: this is a single-tenant synthetic-lab container/process sandbox, not a hardened VM or
multi-tenant production isolation product. The narrow authenticated RPC relay is strictly required on
the adversary network; the child can reach its listener but cannot authenticate. Phase 1.4 grants no
staging or production authority.
