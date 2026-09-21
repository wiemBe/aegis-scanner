"""Test doubles for the Phase 1.5 controlled ZAP ACTIVE reflected-XSS integration.

``make_fake_active_install`` builds a throwaway install tree (jar, plugin directory with the eleven
admitted add-ons, JVM home) whose ``bin/java`` is a scripted executable impersonating the pinned JVM
and the ZAP CLI running the fixed ACTIVE Automation Framework plan. It is driven through the REAL
active runner subprocess path (fixed argv, constructed environment, no shell); its import and
active-scan requests go through the REAL scope guard armed in ACTIVE mode, which forwards them to
the REAL synthetic lab app on a loopback port. The fake decides its alerts the way ZAP does — by
looking for its own payload in the response body — so the vulnerable variant yields an alert and the
patched variant yields none without either outcome being hard-coded.

The loopback lab server and the guard harness are shared with the passive Phase 1.3 doubles. The
live 1+1 synthetic smoke against the real pinned ``aegis-zap-active-runner:1.5.0`` image is the
authority for real engine behaviour; these doubles exercise every fail-closed branch offline.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError
from zap_fakes import REPO, GuardHarness  # noqa: F401 - re-exported for the test module

from aegis_zap_active.contracts import (
    ZapActiveErrorCode,
    ZapActiveLeaseStatusResponse,
    ZapActiveRunRequest,
)
from aegis_zap_active.countersign import CountersignStatus
from aegis_zap_active.lease import AUDIENCE, LeaseClaims, LeaseRejected, sign_lease
from aegis_zap_active.manifest import MANIFEST_PATH, ZapActiveManifest, load_manifest
from aegis_zap_active.manifest import manifest_digest as active_manifest_digest
from zap_active_admission.contracts import ConsumeRequest
from zap_active_admission.registry import AdmissionRegistry
from zap_active_runner.admission_client import AdmissionRejected
from zap_active_runner.attestation import ActiveRunnerState, attest
from zap_active_runner.execution import Executor
from zap_runner.attestation import RunnerPaths, machine_arch
from zap_runner.guard_client import GuardClient

DEFAULT_PAYLOADS = (
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
)

_SCRIPT = r"""#!{python}
import http.client, json, os, pathlib, sys, time
from urllib.parse import quote, urlsplit

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
stamp = "2026-09-20 12:00:00,000 [main ] INFO  "
lines = [stamp + "ExtensionFactory - Installed add-ons: [" + installed + "]"]
if mode != "not_silent":
    lines.append(stamp + "ExtensionCallHome - Shh! Silent mode or telemetry turned off")
for name in ("Cross Site Scripting (Reflected)", "Path Traversal"):
    lines.append(stamp + "ScanRuleManager - Loaded active scan rule: " + name)
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

def fetch(method, url):
    for _ in range(3):  # a connection closed without a response is retried, as ZAP does
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        try:
            headers = {{"User-Agent": "Aegis-ZAP-Active-Lab/1.5.0", "Accept": "*/*"}}
            conn.request(method, url, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
        except TimeoutError:
            return None, ""
        except (http.client.RemoteDisconnected, ConnectionResetError, http.client.BadStatusLine):
            continue
        finally:
            conn.close()
        return resp.status, body.decode("utf-8", errors="replace")
    return None, ""

say("Job passiveScan-config started")
say("Job passiveScan-config finished, time taken: 00:00:00")

openapi = jobs["openapi"]["parameters"]
spec = json.loads(pathlib.Path(openapi["apiFile"]).read_text())
origin = openapi["targetUrl"]
path = next(iter(spec["paths"]))
param = spec["paths"][path]["get"]["parameters"][0]["name"]
example = spec["paths"][path]["get"]["parameters"][0]["example"]

say("Job openapi started")
fetch("GET", f"{{origin}}{{path}}?{{param}}={{quote(example, safe='')}}")
added = 1 if mode != "wrong_count" else 2
expected = jobs["openapi"]["tests"][0]["value"]
say(f"Job openapi added {{added}} URLs")
verdict = "passed" if added == expected else "failed"
op = "==" if added == expected else "!="
say(f"Job openapi test of type stats {{verdict}}: projected-operations-imported "
    f"[{{added}} {{op}} {{expected}}]")
say("Job openapi finished, time taken: 00:00:00")
if added != expected:
    say("Automation plan failures:")
    sys.exit(1)

def drain():
    say("Job passiveScan-wait started")
    if mode != "no_drain":
        say("Job passiveScan-wait finished, time taken: 00:00:01")

drain()

if mode == "hang":
    say("Job activeScan started")
    time.sleep(120)

hits = []
if mode != "no_active_scan":
    say("Job activeScan started")
    payloads = cfg.get("payloads", [])
    if mode == "budget":
        payloads = payloads * 40
    for payload in payloads:
        query = f"{{param}}={{quote(payload, safe='')}}"
        if mode == "escape_param":
            query += "&debug=1"
        target = f"{{origin}}{{path}}?{{query}}"
        if mode == "escape_path":
            target = f"{{origin}}/lab/zap-active/vulnerable/admin?{{query}}"
        method = "POST" if mode == "escape_method" else "GET"
        status, body = fetch(method, target)
        if status == 200 and payload in body:
            hits.append((f"{{origin}}{{path}}?{{query}}", payload))
    if mode != "active_scan_unfinished":
        say("Job activeScan finished, time taken: 00:00:02")
    drain()

report_cfg = jobs["report"]["parameters"]
report_path = pathlib.Path(report_cfg["reportDir"]) / (report_cfg["reportFile"] + ".json")

def instance(uri, payload, **extra):
    base = {{"id": "0", "uri": uri, "nodeName": uri.split("?")[0], "method": "GET",
             "param": param, "attack": payload, "evidence": payload,
             "otherinfo": "<p>Raw reflection in a script context.</p>"}}
    base.update(extra)
    return base

def alert(plugin, name, items, **extra):
    body = {{"pluginid": str(plugin), "alertRef": str(plugin), "alert": name, "name": name,
             "riskcode": "3", "confidence": "2", "riskdesc": "High (Medium)",
             "desc": "<p>Cross-site scripting <script>alert(1)</script> was found.</p>",
             "instances": items, "count": str(len(items)), "systemic": False,
             "solution": "<p>Encode output.</p>", "otherinfo": "<p>x</p>",
             "reference": "<p>https://owasp.org</p>", "cweid": "79", "wascid": "8",
             "sourceid": "1"}}
    body.update(extra)
    return body

rule_name = "Cross Site Scripting (Reflected)"
site_alerts = []
if hits and mode != "suppress_alerts":
    items = [instance(uri, payload) for uri, payload in hits]
    if mode == "duplicate_alert":
        items = items + items
    if mode == "alert_off_path":
        items = [instance(f"{{origin}}/lab/zap-active/other/search?q=1", hits[0][1])]
    if mode == "alert_bad_param":
        items = [instance(uri, payload, param="debug") for uri, payload in hits[:1]]
    if mode == "alert_bad_method":
        items = [instance(uri, payload, method="POST") for uri, payload in hits[:1]]
    plugin = 40014 if mode == "unadmitted_rule" else 40012
    name = "Other Rule" if mode == "unadmitted_rule" else rule_name
    site_alerts.append(alert(plugin, name, items))

report = {{"@programName": "ZAP", "@version": cfg.get("zap_version", "2.17.0"),
           "@generated": "Sun, 20 Sept 2026 12:00:00", "created": "2026-09-20T12:00:00Z",
           "site": [{{"@name": origin, "@host": urlsplit(origin).hostname,
                     "@port": str(urlsplit(origin).port), "@ssl": "false",
                     "alerts": site_alerts}}]}}
text = json.dumps(report, indent=1)
if mode == "malformed_report":
    text = '{{"@programName": "ZAP", "@version": "2.17.0", "site": [}}'
if mode == "oversized_report":
    text = text[:-1] + "," + '"insights": "' + "x" * 300_000 + '"}}'

say("Job report started")
if mode != "no_report":
    report_path.write_text(text)
    say(f"Job report generated report {{report_path}}")
say("Job report finished, time taken: 00:00:00")
if mode == "nonzero":
    say("Automation plan failures:")
    sys.exit(1)
say("Automation plan succeeded!")
sys.exit(0)
"""


def fake_active_script() -> str:
    return _SCRIPT.format(python=sys.executable)


@dataclass
class FakeActiveZap:
    root: Path
    paths: RunnerPaths
    manifest: ZapActiveManifest

    @property
    def java_dir(self) -> Path:
        return self.paths.java_home / "bin"

    def set(self, mode: str = "normal", **options: Any) -> None:
        addons = [[a.id, a.version, a.status] for a in self.manifest.add_ons]
        payload = {
            "mode": mode,
            "addons": addons,
            "payloads": list(DEFAULT_PAYLOADS),
            **options,
        }
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


def make_fake_active_install(
    root: Path, guard: GuardHarness, mode: str = "normal"
) -> FakeActiveZap:
    """A pinned-looking active install tree plus the manifest that pins exactly its bytes."""

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
    java.write_text(fake_active_script())
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
    fake = FakeActiveZap(root, paths, pinned)
    fake.set(mode)
    return fake


def ready_active_state(fake: FakeActiveZap, guard: GuardHarness) -> ActiveRunnerState:
    state = ActiveRunnerState(
        manifest=fake.manifest,
        manifest_digest=active_manifest_digest(MANIFEST_PATH),
        paths=fake.paths,
        guard=GuardClient(guard.control_url),
    )
    return attest(state, environ={})


class ActiveExecutorTransport(httpx.AsyncBaseTransport):
    """Routes the controller's active RPC straight into a real Executor and counts the calls."""

    def __init__(self, executor: Executor | None) -> None:
        self.executor = executor
        self.calls: dict[str, int] = {
            "attestation": 0,
            "run": 0,
            "stop": 0,
            "arm": 0,
            "revoke": 0,
            "status": 0,
        }
        self.override_run: Any = None
        self.override_attestation: Any = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.executor is None:
            raise httpx.ConnectError("active runner unreachable")
        if request.url.path == "/v1/attestation":
            self.calls["attestation"] += 1
            if self.override_attestation is not None:
                return httpx.Response(200, content=self.override_attestation(self.executor))
            return httpx.Response(200, content=self.executor.state.attestation().model_dump_json())
        if request.url.path == "/v1/emergency-stop":
            self.calls["stop"] += 1
            steps = self.executor.emergency_stop()
            return httpx.Response(200, content=json.dumps({"status": "STOPPING", "steps": steps}))
        if request.url.path == "/v1/lease/arm":
            self.calls["arm"] += 1
            token = json.loads(await request.aread())["lease_token"]
            outcome = self.executor.arm_lease(token)
            if isinstance(outcome, ZapActiveErrorCode):
                return httpx.Response(403, content=json.dumps({"error_code": outcome.value}))
            return httpx.Response(200, content=outcome.model_dump_json())
        if request.url.path == "/v1/lease/revoke":
            self.calls["revoke"] += 1
            body = json.loads(await request.aread())
            record = self.executor.revoke_lease(body["lease_id"], body.get("reason", "revoked"))
            if record is None:
                return httpx.Response(404, content=json.dumps({"error_code": "LEASE_NOT_ARMED"}))
            return httpx.Response(200, content=record.model_dump_json())
        if request.url.path == "/v1/lease/status":
            self.calls["status"] += 1
            return httpx.Response(200, content=self.executor.lease_status().model_dump_json())
        if request.url.path == "/v1/run":
            self.calls["run"] += 1
            body = await request.aread()
            parsed = ZapActiveRunRequest.model_validate_json(body)
            if self.override_run is not None:
                return httpx.Response(200, content=self.override_run(self.executor, parsed))
            import anyio.to_thread

            response = await anyio.to_thread.run_sync(self.executor.run, parsed)
            return httpx.Response(200, content=response.model_dump_json())
        return httpx.Response(404)


# --- lease admission doubles -------------------------------------------------------------------
#
# The registry below is the REAL :class:`AdmissionRegistry`; only the HTTP hop is removed. That is
# deliberate: the security-relevant behaviour (signature verification, canonical decoding, exact
# claim set, audience, lifetime, single-use nonce, armed-registry requirement, atomic consume,
# revocation, restart revocation) is exactly the code that runs in the container, and the transport
# in front of it is covered separately by the admission-server tests.

ADMISSION_TEST_SECRET = "phase-1.5-offline-admission-signing-key-0123456789"  # noqa: S105


def verify_countersign_offline(manifest: ZapActiveManifest) -> CountersignStatus:
    """The offline structural stand-in for :func:`aegis_zap_active.countersign.verify_countersign`.

    A fake install tree pins fake add-on bytes, so its SHA-256s can never equal the countersigned
    real digests and the REAL check must fail on it — that is the fail-closed behaviour working.
    End-to-end offline tests therefore use this stand-in, which enforces the same structural
    bindings the countersign exists to freeze — profile, capability, the single admitted rule's
    id/name/strength/threshold, and the presence of the three countersigned forced-dependency
    pins — while the real byte-digest check is exercised directly by the countersign tests.

    It fails closed on every drift, exactly like the real check; it simply cannot compare byte
    digests that a fake install cannot possess."""

    if manifest.profile_id != "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1":
        return CountersignStatus(valid=False, code="PROFILE_MISMATCH")
    rules = manifest.rules_for_capability("zap_active_reflected_xss_v1")
    if len(rules) != 1:
        return CountersignStatus(valid=False, code="RULE_MISMATCH")
    rule = rules[0]
    if rule.plugin_id != 40012 or rule.name != "Cross Site Scripting (Reflected)":
        return CountersignStatus(valid=False, code="RULE_MISMATCH")
    if rule.strength != "LOW" or rule.threshold != "MEDIUM":
        return CountersignStatus(valid=False, code="STRENGTH_OR_THRESHOLD_MISMATCH")
    for add_on_id in ("ascanrules", "oast", "database"):
        if manifest.add_on(add_on_id) is None:
            return CountersignStatus(valid=False, code="ADDON_DIGEST_MISMATCH")
    return CountersignStatus(
        valid=True,
        code="VALID",
        record_id="offline-test-countersign",
        countersigned_on="1970-01-01",
        countersigned_by="TEST_ONLY",
        capability_id="zap_active_reflected_xss_v1",
        profile_id="ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        rule_id=rule.plugin_id,
        rule_name=rule.name,
        strength=rule.strength,
        threshold=rule.threshold,
        environment="SYNTHETIC_LAB",
        manifest_sha256="0" * 64,
        scope_statement="offline structural test",
        accepted_residual_risk="test only",
        countersigned_add_on_ids=("ascanrules", "database", "oast"),
    )


class InProcessAdmission:
    """A real ``AdmissionRegistry`` behind the runner's ``AdmissionClient`` method surface."""

    def __init__(self, state_file: Path, secret: str = ADMISSION_TEST_SECRET) -> None:
        self.registry = AdmissionRegistry(secret, state_file=state_file)
        self.secret = secret
        self.reachable_flag = True
        self.calls: dict[str, int] = {"arm": 0, "consume": 0, "revoke": 0, "status": 0}

    def reachable(self) -> bool:
        return self.reachable_flag

    def arm(self, lease_token: str) -> Any:
        self.calls["arm"] += 1
        if not self.reachable_flag:
            return AdmissionRejected("LEASE_REGISTRY_UNAVAILABLE")
        try:
            return self.registry.arm(lease_token)
        except LeaseRejected as rejected:
            return AdmissionRejected(rejected.code)

    def consume(self, **fields: Any) -> Any:
        self.calls["consume"] += 1
        if not self.reachable_flag:
            return AdmissionRejected("LEASE_REGISTRY_UNAVAILABLE")
        token = fields.pop("lease_token")
        try:
            return self.registry.consume(ConsumeRequest(token=token, **fields))
        except LeaseRejected as rejected:
            return AdmissionRejected(rejected.code)
        except ValidationError:
            return AdmissionRejected("LEASE_MALFORMED")

    def revoke(self, lease_id: str, reason: str = "revoked") -> Any:
        self.calls["revoke"] += 1
        record = self.registry.revoke(lease_id, reason)
        return record if record is not None else AdmissionRejected("LEASE_NOT_ARMED")

    def status(self) -> ZapActiveLeaseStatusResponse:
        self.calls["status"] += 1
        if not self.reachable_flag:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)
        snapshot = self.registry.snapshot()
        return ZapActiveLeaseStatusResponse(
            admission_reachable=True,
            state_root_owned=snapshot["state_root_owned"],
            armed=snapshot["armed"],
            recent=snapshot["recent"],
            armed_total=snapshot["armed_total"],
            consumed_total=snapshot["consumed_total"],
            revoked_total=snapshot["revoked_total"],
            rejected_total=snapshot["rejected_total"],
            restart_revoked_total=snapshot["restart_revoked_total"],
        )

    def restart(self) -> InProcessAdmission:
        """A fresh process over the same persisted state: nothing stays armed across a restart."""

        return InProcessAdmission(self.registry._state_file, self.secret)  # noqa: SLF001


def signed_lease_token(
    *,
    secret: str = ADMISSION_TEST_SECRET,
    lease_id: str | None = None,
    target: Any = None,
    projection: Any = None,
    manifest_digest_value: str | None = None,
    lifetime: int = 600,
    offset: int = 0,
    **claim_overrides: Any,
) -> tuple[str, LeaseClaims]:
    """Mint one signed lease for the offline tests, with every claim individually overridable."""

    now = int(datetime.now(UTC).timestamp()) + offset
    claims = LeaseClaims(
        lease_id=lease_id or f"lease-{secrets.token_hex(8)}",
        capability_id=claim_overrides.pop("capability_id", "zap_active_reflected_xss_v1"),
        profile_id=claim_overrides.pop("profile_id", "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"),
        target_ref=claim_overrides.pop("target_ref", target.target_ref if target else ""),
        target_origin=claim_overrides.pop("target_origin", target.origin if target else ""),
        projection_digest=claim_overrides.pop(
            "projection_digest", projection.digest if projection else "0" * 64
        ),
        allowlist_digest=claim_overrides.pop(
            "allowlist_digest", projection.allowlist_digest if projection else "0" * 64
        ),
        manifest_digest=claim_overrides.pop(
            "manifest_digest", manifest_digest_value or active_manifest_digest(MANIFEST_PATH)
        ),
        issued_at=claim_overrides.pop("issued_at", now),
        not_before=claim_overrides.pop("not_before", now),
        expires_at=claim_overrides.pop("expires_at", now + lifetime),
        nonce=claim_overrides.pop("nonce", secrets.token_hex(16)),
        audience=claim_overrides.pop("audience", AUDIENCE),
        budget_id=claim_overrides.pop("budget_id", f"budget-{secrets.token_hex(6)}"),
    )
    assert not claim_overrides, f"unknown claim override: {sorted(claim_overrides)}"
    return sign_lease(claims, secret), claims
