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
- **ZAP** — an isolated daemon reached over a pinned internal API; egress restricted to the approved
  origin; the ZAP API key confined to the ZAP connector boundary; active scan disabled (passive
  analysis of controller-driven traffic only).
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
