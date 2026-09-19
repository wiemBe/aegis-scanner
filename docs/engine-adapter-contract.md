# Engine adapter contract (Phase 1.1)

Every security engine is integrated behind one interface, `SecurityEngineAdapter`
(`src/aegis/engine/adapters.py`). This document is the contract an adapter must satisfy and the
connector/network/credential boundary each planned engine will run behind.

## The interface

```python
class SecurityEngineAdapter(ABC):
    engine: SecurityEngine
    adapter_version: str
    enabled: bool
    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult: ...
    def health(self) -> EngineHealth: ...
```

- `execute` receives a fully typed, controller-constructed `EngineJob`. It must **fail closed with
  zero traffic** on any scope, budget or enable error, returning an `EngineExecution` with
  `status=FAILED` and a structured `EngineError`.
- `execute` must never widen scope. It re-validates every request against the safety controller
  (defense in depth) before any network action.
- `execute` must never read a command, flag, template or raw URL from the job — there are no such
  fields on `EngineJob`.
- `health` returns honest, independent `configured`, `reachable`, `enabled` and `authorized` states.
  A disabled adapter reports `enabled=False`, `state="DISABLED"` and `reachable=None`.

## The typed job

`EngineJob` is built only by the deterministic controller through `build_engine_job`
(`src/aegis/engine/policy.py`). It carries: `job_id`, `engine`, `profile_id`, `capability_id`,
`adapter_version`, `run_id`, `environment`, `activity`, a `TargetReference` (approved origin +
operation + method + optional object ref), approved `credential_profile_refs` (labels only, never
values), a list of controller-compiled read-only `EngineJobRequest`s, and an `EngineBudget`.

There is deliberately **no** `command`, `args`, `flags`, `raw_url`, `headers`, `template`,
`scan_config` or `credential` field. `extra="forbid"` makes any such key a hard validation error.

## Rejection policy

`build_engine_job` rejects (structured `EngineError`, zero traffic) on: unknown
engine/profile/capability; disabled adapter; disallowed environment; out-of-scope origin/operation;
unapproved state-changing behaviour or non-read-only method; missing authentication context;
unsupported method; arbitrary command/flag/config field (`guard_no_raw_command_fields`); and budget
excess. The controller records the rejection as `ENGINE_JOB_REJECTED`.

## The AEGIS_NATIVE adapter

`AegisNativeAdapter` wraps the existing Phase 0.8 executor + safety controller with no behaviour
change: the same safety controller authorizes each request, the same `TestExecutor` issues the
read-only reads (resolving synthetic credentials only inside the executor connector boundary), and
the same deterministic verifier remains the sole finding authority. The adapter reports a raw
cross-owner `200` as an untrusted `EngineReportedFinding`; it never confirms.

Adapter version: `aegis-native/1.1.0`. Isolation boundary: in-process; the control plane holds no
credential and reaches only the allowlisted lab origin with deny-all egress otherwise.

## Disabled adapters (Nuclei / ZAP / Burp DAST)

Each is a `DisabledEngineAdapter`. It installs nothing, opens no network, mounts no credential,
invokes no MCP and runs no subprocess. Every `execute` returns `ENGINE_DISABLED` with zero traffic.
Their catalog profiles are `enabled=False` and document the **future** connector/network/credential
isolation boundary:

- **Nuclei** — a separate, non-privileged sidecar on an isolated network segment; egress restricted
  to the approved synthetic origin; a pinned, reviewed template set (no remote template fetch); no
  credential unless a reviewed synthetic profile is provisioned into the sidecar boundary; no shell
  passthrough — the adapter builds the invocation from the typed job only.
- **ZAP** — *superseded in Phase 1.3 (see below).* Originally planned as an isolated daemon reached
  over a pinned internal API with active scan disabled.
- **Burp DAST** — its own connector with credentials confined to that boundary; the Burp MCP surface
  is **not** invoked; egress restricted to the approved origin; passive audit only, active scan
  stays disabled.

## Adding a real adapter (future)

1. Add its capability + an `enabled=True` profile to `catalog.py` **only** once a deterministic
   verifier or a documented human-review path exists for it.
2. Implement `SecurityEngineAdapter.execute` translating the typed job — never model prose — into the
   engine invocation, inside the connector boundary.
3. Keep `verification_policy=HUMAN_REVIEW_REQUIRED` until a deterministic Aegis verifier is written;
   a human-review capability can only reach `REVIEW_REQUIRED`, never `VERIFIED`, automatically.
4. Add acceptance evidence under a new phase and a fresh, immutable matrix.

## Phase 1.3: the ZAP adapter

`ZapAdapter` (`src/aegis/engine/zap.py`, `zap-adapter/1.3.0`) is enabled only when the operator sets
`ZAP_ENABLED`. It does not run ZAP as a daemon or use the ZAP API (no API key exists): the controller
builds a typed `ZapEngineJob` through `build_zap_job` — which projects the controller-owned OpenAPI
inventory and rejects before any runner call — and the adapter sends a strict `ZapRunRequest` to the
isolated zap-runner, which runs one fixed Automation Framework plan in `-cmd` mode behind the scope
guard. The adapter re-validates the runner attestation (pinned version, jar, JVM, add-on inventory
digest, profile/parser/projection versions, rule manifest, guard) and the untrusted response (ids,
nonce, projection and allowlist digests, alert rule/path allowlist, request budget, coverage
consistency). A generic kernel `EngineJob` is refused with `UNSUPPORTED_JOB_TYPE`. New error codes:
`PROJECTION_REJECTED`, `ACTIVE_SCAN_FORBIDDEN`. See
[Phase 1.3](phase-1.3-zap-passive-openapi.md).
