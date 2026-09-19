# ZAP runner isolation (Phase 1.3)

ZAP runs in two dedicated containers. Neither publishes a port, mounts a host path or the Docker
socket, or holds a credential of any kind.

```text
control-plane --[zap-rpc]--> zap-runner --[zap-egress]--> zap-scope-guard --[zap-target]--> lab-api
```

All three ZAP networks are `internal: true` (no gateway, no internet, no host). `zap-rpc` is shared
only with the control plane — it is deliberately **not** the Phase 1.2 `engine-rpc` network, so the
ZAP runner cannot reach the Nuclei runner. `zap-egress` contains nothing but the scope guard.
`zap-target` contains only the guard and the synthetic lab. The control plane binds its API only to
its fixed `security-lab` address, so no control-plane listener exists on `zap-rpc`.

## Why a separate scope guard

Real-ZAP experiments during this phase showed that ZAP 2.17.0's OpenAPI importer **follows
redirects** (a 302 produced a second, unapproved request) and **retries a request three times**
when a connection closes without a response. ZAP's own limits (`maxMessages`, stats tests) are
therefore not a security boundary. The boundary is the network plus an independent guard:

- the runner container has **no route** to the target; ZAP is configured
  (`network.connection.httpProxy.*`) to send every request to the guard, and it has nothing else to
  talk to;
- the guard forwards **nothing** until the runner arms it for one execution with the exact
  projected `(method, path)` set, the approved origin (which must also be in the guard's own
  hard-coded allowlist `http://lab-api:8001`) and a hard budget equal to the operation count;
- it refuses — never forwards — any other method, origin, scheme, path, query string, user-info or
  `CONNECT` tunnel, and any request beyond the budget (the slot is reserved atomically before
  forwarding);
- it forwards only `User-Agent` and `Accept`, never cookies or `Authorization`;
- it counts received, forwarded, blocked-by-reason, redirects, upstream failures and upstream
  timeouts independently of ZAP; the runner polls these counters every 0.5 s and kills ZAP's
  process group on the first refused request;
- the control port requires a one-time arm token; re-arming while armed is refused. ZAP never sees
  the token and runs only while the guard is armed.

The live acceptance additionally reconciles the target's own access log (attributed by source IP)
against the guard's forwarded set, so "zero unauthorized traffic" is measured three independent
ways: guard counters, runner classification and the target log.

## Container controls (both containers)

| Control | zap-runner | zap-scope-guard |
| --- | --- | --- |
| Base | pinned `zaproxy/zap-stable` index digest (derived image) | pinned `python:3.12-slim` digest |
| User | UID/GID 10002 | UID/GID 10003 |
| Root filesystem | read-only | read-only |
| Writable storage | `/work` tmpfs 256 MiB, `0700`, `nosuid,nodev,noexec` | none |
| Capabilities | all dropped, `no-new-privileges` | all dropped, `no-new-privileges` |
| Limits | 2 CPUs, 1536 MiB, 256 PIDs, 1024 fds | 0.5 CPU, 96 MiB, 32 PIDs, 256 fds |
| Shell / pip | removed | removed |
| Environment | empty (compose `environment: {}`) | empty |
| Logs | json-file, 2 × 1 MiB | json-file, 2 × 1 MiB |

The derived runner image also deletes every non-admitted add-on, the Webswing UI, the scan wrapper
scripts and purges Firefox/Xvfb/x11vnc/openbox. ZAP runs as `java -jar` directly (no launcher
script, no shell).

### Read-only root filesystem and ephemeral writes

ZAP runs with a fully read-only root filesystem. Its only write locations are inside a
per-execution directory on the `/work` tmpfs: the ZAP home (`-dir`), `user.home`, the JVM temp dir
(`-Djava.io.tmpdir`), the session database, the projected OpenAPI file, the plan, the report and
captured stdout. JVM perf data is disabled (`-XX:-UsePerfData`). The directory is deleted after
every execution; `session_destroyed` is reported only after the deletion is observed. The tmpfs
itself disappears when the container stops. No raw HTTP history, session database, report or
ZAP log ever leaves the container.

One compatibility note: ZAP copies its default configuration into the home directory preserving
file modes, so the root-owned install files keep owner-write (`0644`). They remain unwritable by the
runtime user and are additionally protected by the read-only root filesystem.

## Runtime switches

`-cmd -silent -notel` plus `callhome.tel.enabled=false`, `start.checkForUpdates=false`,
`start.checkAddonUpdates=false`, `start.installAddonUpdates=false`,
`start.installScannerRules=false` and the `start.report*Addons=false` keys. `callhome` is a
mandatory core add-on in 2.17.0 and cannot be removed; each execution must log ZAP's own
`Shh! Silent mode or telemetry turned off` line or it fails closed. `-cmd` mode starts no API
listener and no local proxy. No MCP or LLM add-on exists in the image and both ids are forbidden by
the manifest.

## Verified live topology

From inside `zap-runner`: the guard's proxy and control ports are reachable; the synthetic target,
control-plane listener (by name and IP), Nuclei runner, LLM gateway, Ollama, dashboard, a public
IP and a public DNS name are all blocked. From inside `zap-scope-guard`: only the synthetic target
is reachable. See `artifacts/topology-phase-1.3.txt`.

Residual notes: the guard's control port is reachable from the runner (by design) and the runner's
RPC port is reachable from the guard (they share `zap-egress`); ZAP itself cannot reach either
through its proxy because the guard only forwards the armed origin. Docker internal networks are
the lab enforcement boundary; they are not claimed as a production-grade egress firewall or
workload sandbox.
