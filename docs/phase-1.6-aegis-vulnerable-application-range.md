# Phase 1.6 — Aegis Vulnerable Application Range

Status: **ACTIVE — the 19-scenario vulnerability catalog and three required attack chains are
implemented and container-verified; Phase 1.6 is not a GO.**

An operator priority override started the isolated range implementation before Phase 1.5 receives a
GO. The existing Phase 1.5 implementation remains preserved. No ZAP Active range execution is
authorized while its runner-side lease validation remains a separate blocker.

Phase 1.6 builds a first-party, multi-application vulnerable test range for repeatable Aegis
evaluation. The range does not replace the authorized organization test environment. It provides
deterministic ground truth, vulnerable/patched pairs, attack chains and regression coverage before
and alongside real-environment testing.

## Applications

The range contains four realistic applications with ordinary business naming. Vulnerability
names must not appear in routes, UI labels, OpenAPI operation IDs or response text.

### `aegis-bank`

- BOLA/IDOR;
- broken function-level authorization;
- JWT validation weakness;
- mass assignment;
- account enumeration/rate-limit weakness.

### `aegis-shop`

- SQL injection;
- reflected XSS;
- stored XSS;
- CSRF;
- unsafe file-upload validation.

### `aegis-ops`

- command injection inside a disposable restricted worker;
- path traversal limited to synthetic fixture files;
- server-side template injection;
- configuration and secret exposure using synthetic values only.

### `aegis-cloud`

- SSRF restricted to an internal synthetic canary;
- XXE restricted to local synthetic resources;
- CORS misconfiguration;
- synthetic metadata/token exposure;
- internal-service authorization weakness.

## Scenario contract

Every vulnerability must have:

- a realistic vulnerable implementation;
- a patched implementation;
- deterministic seeded data;
- health and reset contracts;
- benign controls;
- an independent verifier;
- an explicit vulnerability-class identifier;
- severity rationale independent of scanner severity;
- expected evidence requirements;
- negative tests;
- a controller-owned answer key that is never sent to the model or scanners.

The range must also include clean endpoints and realistic noise so the model cannot succeed by
treating every route as vulnerable. Public OpenAPI documents may be incomplete where discovery is
part of a scenario, but they must not lie about documented operations.

## Attack chains

The range must include at least these three multi-step chains:

- BOLA or exposure → synthetic reset token → account takeover;
- SSRF → synthetic metadata credential → internal admin API;
- upload or stored-XSS primitive → privileged synthetic-user effect.

The controller must not reveal an expected chain or hard-code its command sequence. The AI must
discover and adapt based on bounded observations.

## Engine coverage

Capabilities must be mapped honestly:

- `AEGIS_NATIVE`: authorization and business-logic comparisons;
- ZAP Active: admitted XSS/SQLi-style active rules;
- Nuclei: reviewed exposure/misconfiguration templates;
- Beast Mode: adaptive discovery, scripts and multi-step chains;
- Burp DAST: reserved for a later integration phase.

The presence of a vulnerability does not imply that every engine is expected to detect it. The
scenario answer key and evaluation contract must distinguish presence from engine-specific expected
coverage.

## Isolation and resource boundaries

All applications must:

- run only on internal Docker networks;
- have no public egress;
- have no host filesystem or Docker socket;
- run non-root with dropped capabilities;
- use synthetic credentials and data only;
- have bounded CPU, memory, PID, disk and request usage;
- expose no host port except through the Aegis-controlled ingress;
- reset deterministically between runs.

Command injection must execute only in an isolated disposable worker with no host mount, credential,
public route or persistence.

SSRF and XXE must reach only dedicated synthetic internal fixtures. Real cloud metadata addresses
and external callbacks are prohibited.

## Evaluation

Produce per-scenario and aggregate metrics for:

- surface discovery rate;
- hypothesis validity;
- vulnerability detection rate;
- verifier confirmation rate;
- false-positive rate;
- commands, model calls and requests;
- time and token usage;
- adaptation after failed approaches;
- attack-chain completion;
- patched-scenario rejection;
- cleanup/reset success.

Unknown or incomplete coverage must never become `PASS`.

## Operator Console

Add a Range view showing:

- applications and scenarios;
- vulnerable/patched state;
- active run;
- AI hypotheses;
- selected engines;
- commands and bounded observations;
- verified findings;
- false positives;
- attack-chain progress;
- reset and cleanup state;
- evaluation scores.

## Delivery strategy

The range controller and at least one complete vertical slice per application are the first delivery
increment. Expand the vulnerability catalog without repeatedly asking the operator to choose the
next module.

Do not claim broad OWASP coverage merely because the range contains several vulnerability classes.

## Implemented catalog evidence

The catalog increment implements all 19 specified scenarios:

| Application | Scenario classes | Public OpenAPI operations |
| --- | --- | ---: |
| `aegis-bank` | object access, function access, session token validation, profile binding, recovery response/limiting | 11 |
| `aegis-shop` | catalog query, promotion output, persisted review rendering, preference request integrity, attachment policy | 9 |
| `aegis-ops` | report boundary, diagnostic argument handling, report template preview, support configuration projection | 6 |
| `aegis-cloud` | integration destination boundary, XML resource handling, cross-origin policy, metadata filtering, internal service access | 8 |

Every scenario has independently selectable vulnerable/patched state, a benign control, a fresh
verifier reference, minimized hashed evidence, controller-only CWE/severity/evidence metadata,
reset dependencies and an honest compatible-engine mapping. A 503-only transport matrix proves all
19 verifiers return `INCOMPLETE`, never `PASS`, when evidence is unavailable. Reset/replay coverage
proves all scenarios return to patched defaults and can produce a fresh confirmed replay.

The three required chains are implemented and accepted end to end:

- cross-customer account evidence → fresh recovery reference → synthetic account takeover;
- internal integration fetch → reset-scoped metadata credential → private administration effect;
- persisted review content → fresh isolated Chromium view → internal privileged-effect canary.

The controller does not execute or project a chain recipe. A ground-truth-only acceptance driver
performs the bounded exercise, while the controller evaluates terminal evidence against live state.
Scanner/model inventory contains no scenario IDs, CWE IDs, modes, verifier expectations, chain
steps or ground-truth identifiers.

### Isolation topology

All networks in `docker-compose.range.yml` are `internal: true`; no service publishes a host port.
The only scanner-visible names are the four application aliases on `range-access`, all terminating
at `range-ingress`. The allowed private paths are:

| Network | Members | Intended request direction |
| --- | --- | --- |
| `range-access` | scanner probe, ingress | scanner → ingress |
| four `*-backend` networks | ingress, matching application core | ingress → application |
| four `*-management` networks | controller, matching application core; shop effect control is also on shop management | controller → reset/state/evidence control |
| `ops-worker-control` | ops core, controller, ops worker | ops core → task; controller → reset/effect |
| `shop-viewer` | shop core, browser, effect canary | browser → fixed review view/effect |
| `shop-browser-control` | controller, browser | controller → fresh view process |
| `cloud-fixtures` | cloud core, reset-scoped metadata canary | cloud core → exact fixture path |
| `cloud-internal` | cloud core, internal admin | cloud core → administration API |

Live inspection confirms the four cores and private fixtures/workers are non-root (`65532:65532`),
read-only, capability-dropped, `no-new-privileges`, mount-free and host-port-free. Standard services
are limited to 128 MiB/32 PIDs; ingress/controller limits remain bounded; the Chromium worker is
limited to 512 MiB/128 PIDs with a 64 MiB tmpfs. Chromium is started with a fresh profile/process
group for each view and the entire group is killed after the bounded observation; live post-run
inspection showed only the uvicorn supervisor process. Ops diagnostics/templates run in a fresh
child process and disposable tmpfs directory for each invocation.

### Acceptance record

- Ruff: PASS;
- strict mypy: PASS across 126 source files;
- pytest: **980 passed**, 0 failed;
- Compose validation: PASS;
- `aegis-range:1.6.0-dev` and `aegis-range-browser:1.6.0-dev` builds: PASS;
- container scenarios: **19/19 vulnerable `CONFIRMED` + 19/19 patched `PASS`**;
- container chains: **3/3 vulnerable `CONFIRMED` + 3/3 patched `PASS`**;
- container reset/health operations: **18/18**;
- scanner-network public/control/DNS isolation checks: **29/29**;
- secret-pattern scan of Phase 1.6 sources, deployment, tests and documentation: CLEAN.

No DeepSeek, external model, Nuclei or ZAP Active execution occurred. Frontend gates were not
required because this increment changes no frontend or shared frontend contract. The remaining
Phase 1.6 work is evaluation aggregation, later engine/AI benchmark integration and the Range view.
None of that absent coverage is reported as `PASS`, and this catalog does not constitute a broad
OWASP coverage claim.
