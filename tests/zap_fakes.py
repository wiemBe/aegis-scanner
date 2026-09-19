"""Test doubles for the Phase 1.3 ZAP integration.

``make_fake_install`` builds a throwaway ZAP install tree (jar, plugin directory, JVM home) whose
``bin/java`` is a scripted executable impersonating the pinned JVM + ZAP CLI. It is driven through
the REAL runner subprocess path (fixed argv, constructed environment, no shell) and sends its HTTP
requests through the REAL scope guard, which forwards to the REAL synthetic lab app served on a
loopback port. Every fail-closed branch of the runner, guard, parser and controller is therefore
exercised offline. The live acceptance harness uses the real pinned ZAP image instead.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from aegis_zap.contracts import ZapRunRequest
from aegis_zap.manifest import MANIFEST_PATH, ZapManifest, load_manifest, manifest_digest
from lab_api.main import app as lab_app
from zap_guard.guard import GuardState
from zap_guard.guard import serve as serve_guard
from zap_runner.attestation import RunnerPaths, RunnerState, attest, machine_arch
from zap_runner.execution import Executor
from zap_runner.guard_client import GuardClient

REPO = Path(__file__).resolve().parent.parent

_SCRIPT = r"""#!{python}
import http.client, json, os, pathlib, socket, sys, time
from urllib.parse import urlsplit

here = pathlib.Path(__file__).resolve().parent
cfg = json.loads((here / "mode.json").read_text())
mode = cfg.get("mode", "normal")
args = sys.argv[1:]
with (here / "calls.jsonl").open("a") as log:
    log.write(json.dumps({{"argv": sys.argv, "env": sorted(os.environ)}}) + "\n")

if args == ["-version"]:
    sys.stdout.write('openjdk version "' + cfg.get("java", "17.0.20") + '" 2026-07-21\n')
    runtime = cfg.get("runtime", "17.0.20+8-1-deb12u1-Debian")
    sys.stdout.write("OpenJDK Runtime Environment (build " + runtime + ")\n")
    sys.exit(0)

def value(flag):
    return args[args.index(flag) + 1]

configs = [args[i + 1] for i, a in enumerate(args) if a == "-config"]
home = pathlib.Path(value("-dir"))
home.mkdir(parents=True, exist_ok=True)
addons = cfg["addons"] + cfg.get("extra_addons", [])
installed = ", ".join(f"[id={{i}}, version={{v}}]" for i, v, _ in sorted(addons))
stamp = "2026-09-19 12:00:00,000 [main ] INFO  "
lines = [stamp + "ExtensionFactory - Installed add-ons: [" + installed + "]"]
if mode != "not_silent":
    lines.append(stamp + "ExtensionCallHome - Shh! Silent mode or telemetry turned off")
if mode == "active_rules":
    lines.append(stamp + "ScanRuleManager - Loaded active scan rule: SQL Injection")
(home / "zap.log").write_text("\n".join(lines) + "\n")

if "-addonlist" in args:
    for i, v, s in sorted(addons):
        sys.stdout.write(f"{{i.title()}}\t{{i}}\tv{{v}}\t{{s}}\tdescription\n")
    sys.exit(0)

plan = json.loads(pathlib.Path(value("-autorun")).read_text())
def setting(key):
    return next(c.split("=", 1)[1] for c in configs if c.startswith(key + "="))

proxy_host = setting("network.connection.httpProxy.host")
proxy_port = int(setting("network.connection.httpProxy.port"))
timeout = int(setting("network.connection.timeoutInSecs"))
jobs = {{j["type"]: j for j in plan["jobs"]}}
out = []
def say(line):
    out.append(line)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()

if mode == "hang":
    time.sleep(120)
if mode == "huge_stdout":
    sys.stdout.write("A" * 1_200_000)
    sys.stdout.flush()
    time.sleep(5)

rules = [(r["id"], r["threshold"].upper()) for r in jobs["passiveScan-config"]["rules"]]
if mode == "rule_drift":
    rules.append((10038, "MEDIUM"))
say("Job passiveScan-config started")
for rid, level in rules:
    say(f"Job passiveScan-config set rule {{rid}} threshold to {{level}}")
say("Job passiveScan-config finished, time taken: 00:00:00")

openapi = jobs["openapi"]["parameters"]
spec = json.loads(pathlib.Path(openapi["apiFile"]).read_text())
origin = openapi["targetUrl"]
urls = []
for template, item in sorted(spec["paths"].items()):
    for method, op in item.items():
        path = template
        for p in op.get("parameters", []):
            path = path.replace("{{" + p["name"] + "}}", p["example"])
        urls.append((method.upper(), origin + path))
if mode == "escape_path":
    urls.append(("GET", origin + "/lab/zap/vulnerable/secret"))
if mode == "extra_request":
    urls.append(urls[0])

def fetch(method, url, depth=0):
    for attempt in range(4):  # ZAP retries a request whose connection closed without a response
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        try:
            headers = {{"User-Agent": "Aegis-ZAP-Passive-Lab/1.3.0", "Accept": "*/*"}}
            conn.request(method, url, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            headers = {{k.lower(): v for k, v in resp.getheaders()}}
        except socket.timeout:
            return None, "Read timed out"
        except (http.client.RemoteDisconnected, ConnectionResetError, http.client.BadStatusLine):
            continue
        finally:
            conn.close()
        if 300 <= resp.status < 400 and "location" in headers and depth < 2:
            loc = headers["location"]
            target = loc if "://" in loc else origin + loc
            follow, error = fetch("GET", target, depth + 1)
            return (resp.status, headers, follow), error
        return (resp.status, headers, None), None
    return None, "org.apache.hc.core5.http.NoHttpResponseException : failed to respond"

say("Job openapi started")
responses = []
for method, url in urls:
    result, error = fetch(method, url)
    if error is not None:
        say(f"Job openapi target: {{origin}} error: Failed to access URL: {{url}} : {{error}}")
        continue
    responses.append((method, url, result))
added = len(responses) if mode != "wrong_count" else len(responses) + 1
expected = jobs["openapi"]["tests"][0]["value"]
say(f"Job openapi added {{added}} URLs")
verdict = "passed" if added == expected else "failed"
op = "==" if added == expected else "!="
name = "projected-operations-imported"
say(f"Job openapi test of type stats {{verdict}}: {{name}} [{{added}} {{op}} {{expected}}]")
say("Job openapi finished, time taken: 00:00:00")
failed = added != expected or mode == "nonzero"

if not failed:
    say("Job passiveScan-wait started")
    if mode != "no_drain":
        say("Job passiveScan-wait finished, time taken: 00:00:01")

alerts = []
for method, url, result in responses:
    status, headers, _ = result
    missing = headers.get("x-content-type-options", "").strip().lower() != "nosniff"
    force = mode == "force_alert" and url.endswith("/catalog/synthetic-catalog-1")
    control = mode == "control_alert" and url.endswith("/status")
    if mode == "suppress_alerts":
        continue
    if missing or force or control:
        alerts.append((method, url))
report_cfg = jobs["report"]["parameters"]
report_path = pathlib.Path(report_cfg["reportDir"]) / (report_cfg["reportFile"] + ".json")

def instance(method, url, **extra):
    base = {{"id": "0", "uri": url, "nodeName": url, "method": method,
             "param": "x-content-type-options", "attack": "", "evidence": "",
             "otherinfo": "<p>This issue still applies to error pages.</p>"}}
    base.update(extra)
    return base

def alert(plugin, name, items, risk="1"):
    return {{"pluginid": str(plugin), "alertRef": str(plugin), "alert": name, "name": name,
             "riskcode": risk, "confidence": "2", "riskdesc": "Low (Medium)",
             "desc": "<p>The Anti-MIME-Sniffing header <script>alert(1)</script> was not set.</p>",
             "instances": items, "count": str(len(items)), "systemic": False,
             "solution": "<p>Set the header.</p>", "otherinfo": "<p>x</p>",
             "reference": "<p>https://owasp.org</p>", "cweid": "693", "wascid": "15",
             "sourceid": "1"}}

name = "X-Content-Type-Options Header Missing"
site_alerts = []
if alerts:
    items = [instance(m, u) for m, u in alerts]
    if mode == "duplicate_alert":
        items = items + items
    if mode == "html_evidence":
        items = [instance(m, u, evidence="<img src=x onerror=alert(1)>") for m, u in alerts]
    site_alerts.append(alert(10021, name, items, risk="3" if mode == "claims_high" else "1"))
if mode == "unadmitted_rule" and responses:
    site_alerts.append(alert(10038, "Content Security Policy (CSP) Header Not Set",
                             [instance(responses[0][0], responses[0][1], param="")]))
report = {{"@programName": "ZAP", "@version": cfg.get("zap_version", "2.17.0"),
           "@generated": "Sat, 19 Sept 2026 12:00:00", "created": "2026-09-19T12:00:00Z",
           "site": [{{"@name": origin, "@host": urlsplit(origin).hostname,
                     "@port": str(urlsplit(origin).port), "@ssl": "false",
                     "alerts": site_alerts}}]}}
text = json.dumps(report, indent=1)
if mode == "malformed_report":
    text = '{{"@programName": "ZAP", "@version": "2.17.0", "site": [}}'
if mode == "truncated_report":
    text = text[: len(text) // 2]
if mode == "oversized_report":
    text = text[:-1] + "," + '"insights": "' + "x" * 200_000 + '"}}'
if not failed:
    say("Job report started")
    if mode != "no_report":
        report_path.write_text(text)
        say(f"Job report generated report {{report_path}}")
    say("Job report finished, time taken: 00:00:00")
if failed:
    say("Automation plan failures:")
    sys.exit(1)
say("Automation plan succeeded!")
sys.exit(0)
"""


def fake_script() -> str:
    return _SCRIPT.format(python=sys.executable)


@dataclass
class FakeZap:
    root: Path
    paths: RunnerPaths
    manifest: ZapManifest

    @property
    def java_dir(self) -> Path:
        return self.paths.java_home / "bin"

    def set(self, mode: str = "normal", **options: Any) -> None:
        addons = [[a.id, a.version, a.status] for a in self.manifest.add_ons]
        payload = {"mode": mode, "addons": addons, **options}
        (self.java_dir / "mode.json").write_text(json.dumps(payload))

    def calls(self) -> list[dict[str, Any]]:
        path = self.java_dir / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    def run_calls(self) -> list[dict[str, Any]]:
        return [c for c in self.calls() if "-autorun" in c["argv"]]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_fake_install(root: Path, guard: GuardHarness, mode: str = "normal") -> FakeZap:
    """A pinned-looking install tree plus the manifest that pins exactly its bytes."""

    manifest = load_manifest()
    zap_root, java_home, work = root / "zap", root / "jvm", root / "work"
    plugin_dir = zap_root / "plugin"
    for directory in (plugin_dir, java_home / "bin", java_home / "lib" / "server", work):
        directory.mkdir(parents=True, exist_ok=True)
    jar = zap_root / manifest.engine.jar.path
    jar.write_bytes(b"fake zap jar 2.17.0\n")
    (java_home / "lib" / "server" / "libjvm.so").write_bytes(b"fake libjvm\n")
    (java_home / "release").write_text('JAVA_VERSION="17.0.20"\n')
    java = java_home / "bin" / "java"
    java.write_text(fake_script())
    java.chmod(0o755)
    add_ons = []
    for pin in manifest.add_ons:
        path = plugin_dir / pin.file
        path.write_bytes(f"fake add-on {pin.id} {pin.version}\n".encode())
        add_ons.append(pin.model_copy(update={"sha256": _sha(path)}))
    arch = machine_arch()
    java_pins = dict(manifest.engine.java.platforms)
    current = java_pins.get(arch) or next(iter(java_pins.values()))  # type: ignore[call-overload]
    java_pins[arch] = current.model_copy(  # type: ignore[index]
        update={
            "java_sha256": _sha(java),
            "libjvm_sha256": _sha(java_home / "lib" / "server" / "libjvm.so"),
            "release_sha256": _sha(java_home / "release"),
        }
    )
    engine = manifest.engine.model_copy(
        update={
            "jar": manifest.engine.jar.model_copy(update={"sha256": _sha(jar)}),
            "java": manifest.engine.java.model_copy(update={"platforms": java_pins}),
        }
    )
    pinned = manifest.model_copy(update={"engine": engine, "add_ons": tuple(add_ons)})
    paths = RunnerPaths(
        zap_root=zap_root,
        jar=jar,
        plugin_dir=plugin_dir,
        java_home=java_home,
        work_root=work,
        guard_control_url=guard.control_url,
        guard_proxy_host="127.0.0.1",
        guard_proxy_port=guard.proxy_port,
    )
    fake = FakeZap(root, paths, pinned)
    fake.set(mode)
    return fake


def ready_state(fake: FakeZap, guard: GuardHarness) -> RunnerState:
    state = RunnerState(
        manifest=fake.manifest,
        manifest_digest=manifest_digest(MANIFEST_PATH),
        paths=fake.paths,
        guard=GuardClient(guard.control_url),
    )
    return attest(state, environ={})


class LabServer:
    """The REAL synthetic lab app on a loopback port, counting every request path it serves."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        outer = self

        async def counting(scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                outer.paths.append(scope["path"])
            await lab_app(scope, receive, send)

        self.server = uvicorn.Server(
            uvicorn.Config(
                counting,
                host="127.0.0.1",
                port=0,
                log_level="critical",
                lifespan="off",
                timeout_graceful_shutdown=1,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def port(self) -> int:
        sockets = self.server.servers[0].sockets
        return int(sockets[0].getsockname()[1])

    def __enter__(self) -> LabServer:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:  # pragma: no cover - environment failure
                raise RuntimeError("lab server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *_: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


class GuardHarness:
    """The REAL scope guard on loopback ports; the fixed inventory origin resolves to the lab."""

    def __init__(self, lab: LabServer, upstream_timeout: float = 5.0) -> None:
        self.state = GuardState(
            upstream_timeout=upstream_timeout,
            resolver=lambda host, port: ("127.0.0.1", lab.port),
        )
        self.proxy, self.control = serve_guard(self.state, "127.0.0.1", 0, 0)
        self.threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (self.proxy, self.control)
        ]

    @property
    def proxy_port(self) -> int:
        return int(self.proxy.server_address[1])

    @property
    def control_url(self) -> str:
        return f"http://127.0.0.1:{self.control.server_address[1]}"

    def __enter__(self) -> GuardHarness:
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        for server in (self.proxy, self.control):
            server.shutdown()
            server.server_close()


class ExecutorTransport(httpx.AsyncBaseTransport):
    """An in-process runner transport: routes the controller's RPC straight into a real Executor
    (so the controller flow is tested without an RPC socket) and counts calls per route."""

    def __init__(self, executor: Executor | None) -> None:
        self.executor = executor
        self.calls: dict[str, int] = {"attestation": 0, "run": 0}
        self.override_run: Any = None
        self.override_attestation: Any = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.executor is None:
            raise httpx.ConnectError("runner unreachable")
        if request.url.path == "/v1/attestation":
            self.calls["attestation"] += 1
            if self.override_attestation is not None:
                return httpx.Response(200, content=self.override_attestation(self.executor))
            return httpx.Response(200, content=self.executor.state.attestation().model_dump_json())
        if request.url.path == "/v1/run":
            self.calls["run"] += 1
            body = await request.aread()
            parsed = ZapRunRequest.model_validate_json(body)
            if self.override_run is not None:
                return httpx.Response(200, content=self.override_run(self.executor, parsed))
            import anyio.to_thread

            response = await anyio.to_thread.run_sync(self.executor.run, parsed)
            return httpx.Response(200, content=response.model_dump_json())
        return httpx.Response(404)


class CountingTransport(httpx.AsyncBaseTransport):
    """Wraps the in-process lab app for the controller's verifier and counts request paths."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.paths: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        return await self.inner.handle_async_request(request)
