# Phase 1.7-C — Controlled Recon Tool Capabilities

Phase 1.7-C upgrades the Phase 1.7-B `HTTP_API_SURFACE_RECON` role into a **controlled Recon Agent**
with four *registered* capabilities. The model only ever **selects** a registered capability and an
approved, typed profile; the controller resolves inventory references, expands the plan into
single-purpose jobs, renders each into an argv array with no shell, and owns every safety decision.
Recon produces **typed, bounded observations and hypotheses only** — it never confirms a
vulnerability, never emits PASS/severity/a final finding, and has no path to the verifier.

This document reflects a **real containerized run** (no fixtures for the Nmap capability, no
DeepSeek/provider calls). The evidence directory is
`artifacts/phase-1.7c-containerized-20260923T120248Z/`. Phase 1.7-A live BOLA remains GO; the
offline recon suite remains a separate PASS (`artifacts/phase-1.7c-offline-*`, preserved unchanged).

## Capabilities

| Capability id | What the model selects | Who executes | Confirmation authority |
|---|---|---|---|
| `aegis.recon.network_service_discovery` | a typed `NmapScanPlan` (profile + options) | isolated nmap worker (**executed**) | none — observations only |
| `aegis.recon.nuclei_reviewed_exposure` | the registered capability + target variant | **reused** Phase 1.2 nuclei-runner | none — alerts are candidates |
| `aegis.recon.zap_passive_openapi` | the registered capability + target variant | **reused** Phase 1.3 zap-runner | none — alerts are candidates |
| `aegis.surface.openapi` | the target reference | controller (in-process) | none — observations only |

Registered only for `AgentRole.RECON_AGENT`. The role contract forbids authoring raw flags,
templates, policies, URLs, headers or payloads, and forbids confirming, PASSing or setting severity.

## Supply chain (resolved live, not a placeholder)

Resolved from the operator's Docker environment on 2026-09-23 and asserted by the harness preflight
(fail closed on any mismatch):

| Field | Value |
|---|---|
| Image | `instrumentisto/nmap` (referenced by digest, not tag) |
| Immutable RepoDigest | `sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827` |
| Architecture | `linux/arm64` (Apple Silicon host) ✓ |
| Nmap version | **7.98** (`Nmap version 7.98 ( https://nmap.org )`) |
| Entrypoint / default user | `/usr/bin/nmap` / root (the controller overrides the user per job) |
| Admitted NSE scripts present | banner, http-title, http-headers, http-methods, ssl-cert, vulners (all 6 present; 613 total) |

The `:7.98` tag resolved to this same digest at resolution time. `NMAP_IMAGE_REF` in
`aegis.multi_agent.recon` is `instrumentisto/nmap@sha256:96f6ed19…`.

## Typed job bundle (no combined `-p-`/`--top-ports` command)

`build_nmap_bundle` validates one plan and expands it into **single-purpose jobs**, each with its
own argv, timing/rate bounds (`--max-rate`, `--host-timeout`), privilege profile, and
result/error classification. Full TCP and UDP are never combined into one command.

Executed argv (real run, Bank, RANGE_FULL_RECON, TOP_1000→FULL for containerized):

```
TCP_DISCOVERY   nmap -sS -p- -T4 --max-rate 2000 --host-timeout 120s -n -Pn -oX - aegis-bank
UDP_DISCOVERY   nmap -sU --top-ports=50 -T4 --max-rate 2000 --host-timeout 120s -n -Pn -oX - aegis-shop
SERVICE_VER_NSE nmap -p 8101 -sV --version-intensity 5 --script banner,http-headers,http-methods,http-title -T4 … -oX - aegis-bank
OS_DETECTION    nmap -p 8101 -O --osscan-limit -T4 --max-rate 2000 --host-timeout 120s -n -Pn -oX - aegis-bank
```

The host token is controller-resolved from inventory; follow-ups run against the open ports the
discovery job actually reported. Output is XML to stdout; no output-file, interactive, resume, or
scripting-shell flag is emitted, and a denylist re-checks every rendered token. A Docker-gated test
(`test_generated_argv_combinations_are_accepted_by_real_nmap`) proves every job argv is **accepted
by the pinned nmap binary** (no `QUITTING!`, valid XML), not merely produced by Python.

### Minimum functional container privilege (determined experimentally)

nmap requires **uid 0** for raw sockets — **non-root + `NET_RAW` is NOT sufficient** in this image
(`You requested a scan type which requires root privileges. QUITTING!`). So each job carries the
minimum privilege for its scan type:

| Jobs | Container privilege |
|---|---|
| TCP **connect** scan (`-sT`), service/version (`-sV`), admitted NSE | `--user 65534:65534 --cap-drop ALL` (no added cap) |
| SYN (`-sS`), UDP (`-sU`), OS detection (`-O`) | `--user 0:0 --cap-drop ALL --cap-add NET_RAW` (NET_ADMIN **not** needed) |

`NET_RAW` (and uid 0) is granted only for that job's ephemeral container, never to the general agent
runtime. `nmap_run_profile(job)` returns the exact flags.

### NSE: admitted script IDs only, categories are authorization scope

The `--script` argument is rendered from **only the pinned admitted script IDs**, never a bare
`--script <category>`. This is a real safety/robustness finding: blanket categories pull in hundreds
of scripts, and the `discovery` category crashes nmap on a bounded single target
(`Assertion failed: lua_status(L) == LUA_YIELD (nse_nsock.cc)`, SIGSEGV / exit 139) or hangs.
`nse_categories` therefore expresses the authorized *scope* (gated by the profile); the concrete,
targeted admitted script IDs are what actually run.

## Phase-scoped technique boundary (not an architectural prohibition)

Source spoofing, decoy scans, fragmentation/evasion, and credentialed brute-force are *representable*
in the plan schema (`evasion_experiments`, `credentialed_scripts`) but are classified
**`UNSUPPORTED_IN_PHASE_1_7C_RECON`**: unavailable to the Recon role and the current lease, rejected
pre-execution with zero traffic (`RECON_EVASION_UNSUPPORTED_IN_PHASE_1_7C`,
`RECON_CREDENTIALED_UNSUPPORTED_IN_PHASE_1_7C`), and reserved for future dedicated capabilities —
credentialed brute-force → an **Authentication Testing** capability; spoofing/decoy/fragmentation/
evasion → an **Adversary Simulation** capability. They are not architecturally prohibited from a
future owner enabling them under its own authority; they are simply not this role's, this phase.

## Isolation of the nmap worker (verified experimentally, not only from YAML)

The real run (`scripts/phase_1_7c_containerized.py`) runs each job in an ephemeral container joined
only to an `--internal` (egress-blocked) network with the range targets. Negative controls, all
**PASS**:

| Control | Method | Result |
|---|---|---|
| No public egress | scan `1.1.1.1` from the internal scope network | 0 open services (blocked) |
| No host FS / no Docker socket | `sh -c 'test -S /var/run/docker.sock; test -e /host'` in the worker | `NO_SOCKET`, `NO_HOST_MOUNT` |
| Scope escape rejected pre-execution | plan out-of-inventory target / smuggle evasion / smuggle credentialed | all rejected, zero docker runs |
| No published host port | `docker inspect …NetworkSettings.Ports` on Bank/Shop | `{}` (nothing published) |
| Worker terminates & is removed | `--rm`; post-run `docker ps -a` | no container/network leftovers |
| Malformed/truncated XML → INCOMPLETE | feed truncated XML to the parser | `parse_ok=False` → INCOMPLETE, never PASS |
| Recon cannot confirm | broker has no verify/confirm/promote; report has no verdict/severity | structurally true |

The worker is non-root by default (connect-scan profile), read-only, `cap_drop: ALL`,
`no-new-privileges`, bounded pids/memory/cpu, mounts nothing. The nmap XML parser rejects entity
definitions and external DTDs (XXE/billion-laughs) while accepting nmap's benign `<!DOCTYPE nmaprun>`,
and bounds input size.

## Real containerized results

Bank and Shop brought up on the internal scope network; each scanned by the pinned worker.

| Target | Discovered (TCP) | UDP top-50 | OS detection |
|---|---|---|---|
| range-bank | **8101 open — service `http`, product `Uvicorn`** | (not selected) | executed, inconclusive OS match |
| range-shop | **8102 open — service `http`, product `Uvicorn`** | 21 `open|filtered` (nmap UDP noise, unconfirmed) | executed, inconclusive OS match |

Every scan job exited 0 with `parse_ok=True`. Observations are typed `DISCOVERED_SERVICE` records,
deterministically deduplicated (the richer service/version result is preferred over a discovery
port-number guess). The UDP `open|filtered` entries are labeled with their exact state — nmap could
not confirm them; recon does not confirm them either. OS detection **executed** but the fingerprint
was inconclusive inside Docker (expected, and not required by the task). Cleanup verified: no
container or network leftovers. Wall clock ≈ 131 s.

## Nuclei / ZAP passive runners

**Not executed in this harness** (recorded honestly, not claimed). The reused Phase 1.2 nuclei-runner
and Phase 1.3 zap-runner have their own attested acceptance
(`scripts/phase_1_2_acceptance.py`, `scripts/phase_1_3_acceptance.py`); Phase 1.7-C reuses their
controller build path (`build_nuclei_job` / `build_zap_job`), exercised in the offline suite where
their alerts are normalized to `confirmed=False` candidates. Their live runner execution is
**inconclusive in this harness**.

## Offline acceptance (preserved)

`scripts/phase_1_7c_acceptance.py` (in-process, ASGI, offline fixture) — 13/13 checks PASS: service
discovery on Bank+Shop, out-of-scope/evasion/no-lease rejected, Nuclei/ZAP candidates unconfirmed,
delegation without verdict, prompt-injection resisted, shell-free argv, no ZAP-Active/Beast/shell
capability. Evidence: `artifacts/phase-1.7c-offline-*/` (preserved).

## Tests

`tests/test_phase_1_7c.py` (32) + `tests/test_phase_1_7c_recon_compose.py` (14, incl. Docker-gated
argv-acceptance + isolation-property guards) + the updated `tests/test_phase_1_7.py` role/registry
assertion. ruff + mypy `--strict` clean.

## Limitations (honest)

- **Nuclei/ZAP runners not live-executed here** — covered by their own Phase 1.2/1.3 acceptance;
  inconclusive in this harness.
- **No live provider run** — no paid DeepSeek traffic; also no live-provider gateway path for recon
  task types yet (gateway serves only 1.7-A task types).
- **`AUTHORIZED_ENV_RECON` is intentionally inert** — no signed inventory ships, so it always fails
  closed.
- **OS detection is inconclusive in Docker** — recorded as executed; fingerprint accuracy is not a
  requirement here.
- **UDP top-50 yields `open|filtered` noise** — inherent to UDP scanning of a host without those
  services; labeled as unconfirmed, never a finding.
- Report Agent, Cloud Boundary Agent, and real multi-primitive attack chains are **not** implemented.

## Verdict

**CONTAINERIZED PASS for the exact synthetic Recon capability executed — Nmap network service
discovery (Bank + Shop), with all isolation/negative controls verified experimentally and cleanup
proven.** Overall the recon suite is **PARTIAL**: the Nuclei and ZAP passive *runner* executions were
not performed in this harness (inconclusive here; covered by Phase 1.2/1.3). No live-provider run was
attempted. No claim of live-model performance or multi-agent superiority is made.
