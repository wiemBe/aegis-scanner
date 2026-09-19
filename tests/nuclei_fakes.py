"""Test doubles for the Phase 1.2 Nuclei integration.

``FakeNuclei`` writes a small executable that impersonates the pinned Nuclei CLI. It is driven
through the REAL runner subprocess path (fixed argv, constructed environment, no shell, bounded
files), so every fail-closed branch of the runner and the controller is exercised offline. The
fake records each invocation's argv and environment KEYS so tests can assert what Nuclei received.

It is used only by the offline suite; the live acceptance harness uses the real pinned binary.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aegis_nuclei.contracts import NucleiRunRequest
from aegis_nuclei.manifest import MANIFEST_PATH, TemplateManifest, load_manifest, manifest_digest
from aegis_nuclei.targets import NucleiTarget
from nuclei_runner.attestation import RunnerState, machine_arch
from nuclei_runner.execution import Executor
from nuclei_runner.server import serve

REPO = Path(__file__).resolve().parent.parent
TEMPLATE_ROOT = REPO / "deploy" / "nuclei-runner" / "templates"
GIT_CONFIG_TEMPLATE = TEMPLATE_ROOT / "http/exposures/configs/git-config.yaml"

_SCRIPT = r"""#!{python}
import json, os, pathlib, sys, time
from urllib.parse import urlsplit

here = pathlib.Path(__file__).resolve().parent
cfg = json.loads((here / "mode.json").read_text())
args = sys.argv[1:]
with (here / "calls.jsonl").open("a") as log:
    log.write(json.dumps({{"argv": sys.argv, "env": sorted(os.environ)}}) + "\n")

if "-version" in args:
    sys.stderr.write("[INF] Nuclei Engine Version: " + cfg.get("version", "v3.11.1") + "\n")
    sys.exit(0)
if "-validate" in args:
    if cfg.get("validate", True):
        sys.stderr.write("[INF] All templates validated successfully\n")
        sys.exit(0)
    sys.stderr.write("[FTL] validation failed\n")
    sys.exit(1)

templates = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
url = args[args.index("-u") + 1]
out = pathlib.Path(args[args.index("-o") + 1])
parsed = urlsplit(url)
signed = cfg.get("signed", True)
if signed:
    sys.stderr.write(
        f"[INF] Executing {{len(templates)}} signed templates "
        "from projectdiscovery/nuclei-templates\n"
    )
else:
    sys.stderr.write(f"[WRN] Skipping {{len(templates)}} unsigned template[s]\n")
    sys.stderr.write("[FTL] Could not run nuclei: no templates provided for scan\n")
    sys.exit(1)
if url.startswith("http://127.0.0.1:9"):
    sys.exit(0)  # signature probe on the loopback sink

mode = cfg["mode"]
if mode == "timeout":
    time.sleep(60)
if mode == "nonzero":
    sys.stderr.write("[FTL] Could not run nuclei: synthetic failure\n")
    sys.exit(2)
sys.stderr.write(f"[INF] HTTP connections: {{cfg.get('connections', 1)}} total, 1 new, 0 reused\n")

def record(match, **extra):
    r = {{
        "template-id": "git-config",
        "template-path": templates[0],
        "info": {{"name": "Git Configuration - Detect", "author": ["pdteam"], "tags": ["git"],
                 "description": "d", "severity": "medium", "metadata": {{"max-request": 1}},
                 "classification": {{"cve-id": None, "cwe-id": ["cwe-200"]}}}},
        "type": "http", "host": parsed.hostname, "port": str(parsed.port), "scheme": parsed.scheme,
        "url": url, "path": parsed.path, "ip": "172.27.0.3",
        "timestamp": "2026-09-19T10:10:47.417982712Z", "matcher-status": match,
    }}
    if match:
        r["matched-at"] = url + "/.git/config"
        r["template-url"] = "https://cloud.projectdiscovery.io/public/git-config"
        r["curl-command"] = "curl -X 'GET' -H 'User-Agent: Mozilla/5.0' '" + url + "/.git/config'"
    r.update(extra)
    return json.dumps(r)

lines = []
if mode == "match":
    lines = [record(True)]
elif mode == "nomatch":
    lines = [record(False)]
elif mode == "duplicate":
    lines = [record(True), record(True, timestamp="2026-09-19T10:10:48.1Z")]
elif mode == "conflict":
    lines = [record(True), record(False)]
elif mode == "unreachable":
    lines = [record(False, error="port closed or filtered")]
elif mode == "malformed":
    lines = ['{{"template-id": "git-config", "matcher-status": tru']
elif mode == "raw_leak":
    lines = [record(True, response="HTTP/1.1 200 OK\r\nSet-Cookie: s=1\r\n\r\n[core]")]
elif mode == "unknown_template":
    lines = [record(True, **{{"template-id": "community-mass-scan"}})]
elif mode == "redirect_escape":
    lines = [record(True, **{{"matched-at": "http://evil.example/.git/config"}})]
elif mode == "unexpected_key":
    lines = [record(True, **{{"global-matchers": True}})]
elif mode == "oversized":
    lines = [record(False, error="x" * 900) for _ in range(20)]
elif mode == "huge_stdout":
    sys.stdout.write("A" * 400000)
    lines = [record(False)]
text = "".join(line + "\n" for line in lines)
if mode == "truncated":
    text = record(True)
if mode == "empty":
    text = ""
out.write_text(text)
sys.exit(0)
"""


@dataclass
class FakeNuclei:
    directory: Path

    @property
    def binary(self) -> Path:
        return self.directory / "nuclei"

    def set(self, mode: str, **options: Any) -> None:
        (self.directory / "mode.json").write_text(json.dumps({"mode": mode, **options}))

    def calls(self) -> list[dict[str, Any]]:
        path = self.directory / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line]

    def run_calls(self) -> list[dict[str, Any]]:
        """Invocations that were real executions (not version/validate/loopback probe)."""
        return [
            call
            for call in self.calls()
            if "-u" in call["argv"]
            and not call["argv"][call["argv"].index("-u") + 1].startswith("http://127.0.0.1:9")
        ]

    def sha256(self) -> str:
        return hashlib.sha256(self.binary.read_bytes()).hexdigest()


def fake_script() -> str:
    return _SCRIPT.format(python=sys.executable)


def fake_binary_sha256() -> str:
    """The fake's digest is deterministic (its text only depends on the interpreter path)."""
    return hashlib.sha256(fake_script().encode()).hexdigest()


def make_fake_nuclei(directory: Path, mode: str = "match", **options: Any) -> FakeNuclei:
    directory.mkdir(parents=True, exist_ok=True)
    fake = FakeNuclei(directory)
    fake.binary.write_text(fake_script())
    fake.binary.chmod(0o755)
    fake.set(mode, **options)
    return fake


def manifest_pinning(binary_sha256: str) -> TemplateManifest:
    """The real manifest with this architecture's binary pin replaced (fake binary only)."""

    manifest = load_manifest()
    arch = machine_arch()
    artifacts = dict(manifest.engine.artifacts)
    current = artifacts.get(arch) or next(iter(artifacts.values()))  # type: ignore[call-overload]
    artifacts[arch] = current.model_copy(update={"binary_sha256": binary_sha256})  # type: ignore[index]
    engine = manifest.engine.model_copy(update={"artifacts": artifacts})
    return manifest.model_copy(update={"engine": engine})


def local_targets(origin: str) -> dict[str, NucleiTarget]:
    """The fixed inventory, re-homed onto a test origin (the runner's own inventory is fixed)."""

    return {
        "synthetic-scm-vulnerable": NucleiTarget(
            "synthetic-scm-vulnerable",
            origin,
            "/lab/nuclei/vulnerable",
            "vulnerable",
            "labScmMetadataVulnerable",
        ),
        "synthetic-scm-patched": NucleiTarget(
            "synthetic-scm-patched",
            origin,
            "/lab/nuclei/patched",
            "patched",
            "labScmMetadataPatched",
        ),
    }


def ready_state(
    fake: FakeNuclei, work_root: Path, template_root: Path = TEMPLATE_ROOT
) -> RunnerState:
    from nuclei_runner.attestation import attest

    work_root.mkdir(parents=True, exist_ok=True)
    state = RunnerState(
        manifest=manifest_pinning(fake.sha256()),
        manifest_digest=manifest_digest(MANIFEST_PATH),
        binary=fake.binary,
        template_root=template_root,
        work_root=work_root,
    )
    return attest(state, environ={})


class RunnerServer:
    """The REAL runner HTTP server on an ephemeral loopback port, in a background thread."""

    def __init__(self, executor: Executor) -> None:
        self.executor = executor
        self.server = serve(executor, "127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> RunnerServer:
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.server.server_close()


class ExecutorTransport(httpx.AsyncBaseTransport):
    """An in-process runner transport: routes the controller's RPC straight into a real Executor
    (so the controller flow is tested without sockets) and counts calls per route."""

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
            parsed = NucleiRunRequest.model_validate_json(body)
            if self.override_run is not None:
                return httpx.Response(200, content=self.override_run(self.executor, parsed))
            return httpx.Response(200, content=self.executor.run(parsed).model_dump_json())
        return httpx.Response(404)


class CountingTransport(httpx.AsyncBaseTransport):
    """Wraps the in-process lab app and counts every target request by path."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.paths: list[str] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.paths.append(request.url.path)
        return await self.inner.handle_async_request(request)
