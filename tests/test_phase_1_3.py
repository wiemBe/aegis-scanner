"""Phase 1.3 — Controlled ZAP passive OpenAPI integration: offline acceptance tests.

These prove, without network access, that ZAP is pinned and drift fails closed; that the plan,
argv and projection are controller-owned, passive-only and read-only; that the scope guard is the
only traffic path and refuses every escape before it reaches the target; that reports are parsed
fail-closed without propagating prose; that ZAP never self-confirms and zero alerts is never PASS
without complete coverage; and that AEGIS_NATIVE, Nuclei and the console remain compatible. The
live matrix against the real pinned ZAP image is in ``scripts/phase_1_3_acceptance.py``.
"""

from __future__ import annotations

import copy
import http.client
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import ValidationError
from zap_fakes import (
    REPO,
    CountingTransport,
    ExecutorTransport,
    FakeZap,
    GuardHarness,
    LabServer,
    make_fake_install,
    ready_state,
)

import aegis.engine.zap as controller
import aegis.main as main_module
from aegis.engine.adapters import DisabledEngineAdapter
from aegis.engine.catalog import PROFILE_CATALOG, get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineActivity,
    EngineEnvironment,
    EngineErrorCode,
    EngineExecutionStatus,
    FindingLifecycleState,
    SecurityEngine,
    VerifierConclusion,
)
from aegis.engine.lifecycle import correlate_reported_finding, record_verifier_conclusion
from aegis.engine.policy import EnginePolicyRejection
from aegis.engine.zap import ZapAdapter, ZapEngineJob, ZapProjectionRejection, build_zap_job
from aegis.models import ScanCreate, ScanStatus
from aegis.planner import DemoPlanner
from aegis.safety import SafetyController, SafetyViolation
from aegis.service import ScanService
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis.zap_verifier import ZapProbeFacts, evaluate, header_state, probe_plan
from aegis_zap.contracts import ZapRunnerErrorCode, ZapRunRequest, ZapRunResponse
from aegis_zap.inventory import ZAP_TARGETS, source_bytes
from aegis_zap.manifest import MANIFEST_PATH, load_manifest, manifest_digest
from aegis_zap.parser import parse_report
from aegis_zap.profile import (
    FIXED_CONFIG,
    FORBIDDEN_JOB_TYPES,
    JOB_SEQUENCE,
    PROFILE_ID,
    assert_argv_safe,
    build_argv,
    build_plan,
    child_environment,
    plan_bytes,
    validate_plan,
)
from aegis_zap.projection import (
    ProjectionErrorCode,
    ProjectionRejected,
    project,
    projection_ref,
)
from lab_api.main import app as lab_app
from zap_guard.guard import GuardState
from zap_runner.attestation import attest, dangerous_environment
from zap_runner.execution import Executor
from zap_runner.server import serve as serve_runner

CAPABILITY = "zap_passive_header_openapi_v1"
MANIFEST = load_manifest()
VULN = ZAP_TARGETS["synthetic-zap-vulnerable"]
PATCHED = ZAP_TARGETS["synthetic-zap-patched"]
VULN_PROJECTION = project(VULN)
PATCHED_PROJECTION = project(PATCHED)
RULE = MANIFEST.passive_rules[0]
ZAP_FILES = (
    "docker-compose.zap.yml",
    "deploy/zap-runner/Dockerfile",
    "deploy/zap-guard/Dockerfile",
)


# --- fixtures and helpers -------------------------------------------------------------------


@pytest.fixture
def lab() -> Iterator[LabServer]:
    with LabServer() as server:
        yield server


@pytest.fixture
def guard(lab: LabServer) -> Iterator[GuardHarness]:
    with GuardHarness(lab) as harness:
        yield harness


def _fake(tmp_path: Path, guard: GuardHarness, mode: str = "normal", **options: Any) -> FakeZap:
    fake = make_fake_install(tmp_path / "install", guard)
    fake.set(mode, **options)
    return fake


def _executor(
    tmp_path: Path,
    guard: GuardHarness,
    mode: str = "normal",
    *,
    cap: float | None = None,
    **opts: Any,
) -> tuple[FakeZap, Executor]:
    fake = _fake(tmp_path, guard, mode, **opts)
    state = ready_state(fake, guard)
    assert state.ready, state.failure_codes
    return fake, Executor(state, wall_clock_cap_seconds=cap)


def _request(target_ref: str = VULN.target_ref, **overrides: Any) -> ZapRunRequest:
    try:
        projection = project(ZAP_TARGETS[target_ref])
    except (KeyError, ProjectionRejected):
        projection = VULN_PROJECTION
    suffix = overrides.pop("suffix", "aa")
    payload: dict[str, Any] = {
        "engine_execution_id": f"exec-0000000000{suffix}",
        "job_id": f"job-0000000000{suffix}",
        "run_id": f"scan-0000000000{suffix}",
        "scan_id": f"scan-0000000000{suffix}",
        "target_ref": target_ref,
        "profile_id": PROFILE_ID,
        "projection_ref": projection_ref(target_ref),
        "projection_digest": projection.digest,
        "operation_allowlist_digest": projection.allowlist_digest,
        "budgets": {
            "max_requests": projection.operation_count,
            "time_budget_ms": 120_000,
            "max_report_bytes": 131_072,
            "max_alerts": 8,
        },
        "nonce": "0" * 30 + suffix,
        "correlation_id": "corr-00000000000000" + suffix,
    }
    payload.update(overrides)
    return ZapRunRequest.model_validate(payload)


def _zap_service(
    tmp_path: Path,
    guard: GuardHarness,
    monkeypatch: pytest.MonkeyPatch,
    mode: str = "normal",
    *,
    runner: bool = True,
    enabled: bool = True,
    cap: float | None = None,
    **options: Any,
) -> tuple[ScanService, FakeZap, ExecutorTransport, CountingTransport]:
    fake, executor = _executor(tmp_path, guard, mode, cap=cap, **options)
    # The controller refuses any runner whose attested inventory is not the manifest's; offline,
    # the manifest pins the fake install's (deterministic) bytes. The live acceptance uses the
    # real pins.
    monkeypatch.setattr(controller, "load_manifest", lambda: fake.manifest)
    runner_transport = ExecutorTransport(executor if runner else None)
    lab_transport = CountingTransport(httpx.ASGITransport(app=lab_app))
    settings = Settings(database_path=str(tmp_path / "scans.db"), zap_enabled=enabled)
    store = ScanStore(settings.database_path)
    store.initialize()
    service = ScanService(
        settings,
        store=store,
        planner=DemoPlanner(),
        safety=SafetyController(settings),
        transport=lab_transport,
        zap_transport=runner_transport,
    )
    return service, fake, runner_transport, lab_transport


async def _run(service: ScanService, **create: Any) -> Any:
    create.setdefault("capability", CAPABILITY)
    scan = service.create(ScanCreate(**create))
    await service.run(scan.id)
    result = service.store.get(scan.id)
    assert result is not None
    return result


def _events(service: ScanService, scan_id: str) -> list[str]:
    return [str(row["event"]) for row in service.store.audit(scan_id)]


def _report(alerts: list[dict[str, Any]] | None = None, **top: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "@generated": "Sat, 19 Sept 2026 12:39:25",
        "created": "2026-09-19T12:39:25Z",
        "site": [
            {
                "@name": "http://lab-api:8001",
                "@host": "lab-api",
                "@port": "8001",
                "@ssl": "false",
                "alerts": alerts if alerts is not None else [_alert()],
            }
        ],
    }
    report.update(top)
    return report


def _alert(**overrides: Any) -> dict[str, Any]:
    uri = "http://lab-api:8001/lab/zap/vulnerable/catalog/synthetic-catalog-1"
    alert: dict[str, Any] = {
        "pluginid": "10021",
        "alertRef": "10021",
        "alert": RULE.name,
        "name": RULE.name,
        "riskcode": "1",
        "confidence": "2",
        "riskdesc": "Low (Medium)",
        "desc": "<p>The Anti-MIME-Sniffing header <script>alert(1)</script></p>",
        "instances": [
            {
                "id": "0",
                "uri": uri,
                "nodeName": uri,
                "method": "GET",
                "param": "x-content-type-options",
                "attack": "",
                "evidence": "",
                "otherinfo": "<p>At High threshold ...</p>",
            }
        ],
        "count": "1",
        "systemic": False,
        "solution": "<p>Ensure ...</p>",
        "otherinfo": "<p>...</p>",
        "reference": "<p>https://owasp.org/www-community/Security_Headers</p>",
        "cweid": "693",
        "wascid": "15",
        "sourceid": "1",
    }
    alert.update(overrides)
    return alert


def _parse(report: dict[str, Any] | bytes | None, **overrides: Any) -> Any:
    data = report if isinstance(report, bytes) or report is None else json.dumps(report).encode()
    options: dict[str, Any] = {
        "engine_version": "2.17.0",
        "projection": VULN_PROJECTION,
        "rules": MANIFEST.passive_rules,
        "max_report_bytes": 131_072,
        "max_alerts": 8,
    }
    options.update(overrides)
    return parse_report(data, **options)


# --- 1. frozen supply chain -------------------------------------------------------------------


def test_zap_release_image_and_add_ons_are_exactly_pinned() -> None:
    engine = MANIFEST.engine
    assert engine.version == "2.17.0"
    assert engine.image.index_digest == (
        "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
    )
    assert set(engine.image.platforms) == {"linux_arm64", "linux_amd64"}
    assert engine.jar.sha256 == "015dda4709b5ef79736086bb41e8e2a4e95b04cf6625f14d6bcc02b197c99c0c"
    assert engine.java.runtime_version == "17.0.20+8-1-deb12u1-Debian"
    assert {(a.id, a.version) for a in MANIFEST.add_ons} == {
        ("automation", "0.60.0"),
        ("callhome", "0.23.0"),
        ("commonlib", "1.43.0"),
        ("network", "0.29.0"),
        ("openapi", "57.0.0"),
        ("pscan", "0.6.0"),
        ("pscanrules", "75.0.0"),
        ("reports", "0.46.0"),
    }
    forbidden = set(MANIFEST.forbidden_add_on_ids)
    assert {
        "ascanrules",
        "spider",
        "spiderAjax",
        "scripts",
        "graaljs",
        "zest",
        "fuzz",
        "oast",
        "replacer",
        "requester",
        "sequence",
        "graphql",
        "soap",
        "postman",
        "mcp",
        "llm",
        "client",
    } <= forbidden
    assert manifest_digest() == manifest_digest(MANIFEST_PATH)
    assert [(r.plugin_id, r.quality, r.threshold) for r in MANIFEST.passive_rules] == [
        (10021, "release", "MEDIUM")
    ]


def test_no_floating_image_tags_and_hash_locked_dependencies() -> None:
    runner = (REPO / "deploy/zap-runner/Dockerfile").read_text()
    guard = (REPO / "deploy/zap-guard/Dockerfile").read_text()
    assert f"zaproxy/zap-stable@{MANIFEST.engine.image.index_digest}" in runner
    assert "python:3.12-slim@sha256:" in guard
    for text in (runner, guard, (REPO / "docker-compose.zap.yml").read_text()):
        references = [
            line.split("=", 1)[-1].split()[-1]
            for line in text.splitlines()
            if re.match(r"^\s*(ARG|FROM)\s", line) and ("/" in line or ":" in line)
        ]
        for reference in references:
            if reference.startswith("${"):
                continue
            assert "@sha256:" in reference, reference
        assert ":latest" not in text and "zap-weekly" not in text
    lock = (REPO / "deploy/zap-runner/requirements.lock").read_text()
    pins = [line for line in lock.splitlines() if "==" in line]
    assert pins and all("\\" in line for line in pins) and lock.count("--hash=sha256:") >= 6
    assert "--require-hashes" in runner and "addoninstall" not in runner.replace(
        "no add-on install/update", ""
    )


def test_compose_topology_and_runner_hardening_are_fail_closed() -> None:
    compose = yaml.safe_load((REPO / "docker-compose.zap.yml").read_text())
    services, networks = compose["services"], compose["networks"]
    runner, guard = services["zap-runner"], services["zap-scope-guard"]
    assert runner["networks"] == ["zap-rpc", "zap-egress"]
    assert guard["networks"] == ["zap-egress", "zap-target"]
    assert "zap-target" in services["lab-api"]["networks"]
    for name in ("zap-rpc", "zap-egress", "zap-target"):
        assert networks[name]["internal"] is True
    # The ZAP runner never shares a network with the Nuclei runner (engine-rpc) or the planner.
    nuclei = yaml.safe_load((REPO / "docker-compose.nuclei.yml").read_text())
    assert not set(runner["networks"]) & set(nuclei["services"]["nuclei-runner"]["networks"])
    assert not set(runner["networks"]) & {"security-lab", "planner-rpc", "model-egress"}
    assert "zap-egress" not in services["control-plane"]["networks"]
    assert "zap-target" not in services["control-plane"]["networks"]
    for service in (runner, guard):
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert "ports" not in service and "volumes" not in service
        assert service["environment"] == {}
        assert int(service["user"].split(":")[0]) >= 10000
        assert service["pids_limit"] and service["mem_limit"] and service["cpus"]
    assert runner["tmpfs"] == ["/work:size=256m,mode=0700,uid=10002,gid=10002,nosuid,nodev,noexec"]
    assert "tmpfs" not in guard


# --- 2. drift fails closed --------------------------------------------------------------------


def test_runner_boot_attestation_ready_with_exact_inventory(
    tmp_path: Path, guard: GuardHarness
) -> None:
    fake = _fake(tmp_path, guard)
    state = ready_state(fake, guard)
    assert state.ready and state.failure_codes == []
    attestation = state.attestation()
    assert attestation.engine.pinned and attestation.engine.zap_version == "2.17.0"
    assert attestation.addonlist_verified and attestation.java_verified
    assert attestation.guard.reachable and attestation.guard.state == "IDLE"
    assert attestation.admitted_rule_ids == (10021,)
    assert all(a.pinned for a in attestation.add_ons) and not attestation.unexpected_plugin_files


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda f: (f.paths.plugin_dir / "ascanrules-release-83.zap").write_bytes(b"x"),
            "ADDON_INVENTORY_DRIFT",
        ),
        (
            lambda f: (f.paths.plugin_dir / "llm-alpha-0.1.0.zap").write_bytes(b"x"),
            "ADDON_INVENTORY_DRIFT",
        ),
        (
            lambda f: (f.paths.plugin_dir / "mcp-alpha-0.1.0.zap").write_bytes(b"x"),
            "ADDON_INVENTORY_DRIFT",
        ),
        (
            lambda f: (f.paths.plugin_dir / "openapi-beta-57.zap").write_bytes(b"tampered"),
            "ADDON_INVENTORY_DRIFT",
        ),
        (
            lambda f: (f.paths.plugin_dir / "pscanrules-release-75.zap").unlink(),
            "ADDON_INVENTORY_DRIFT",
        ),
        (lambda f: f.paths.jar.write_bytes(b"zap 2.18.0"), "ENGINE_INTEGRITY_FAILURE"),
        (
            lambda f: (f.paths.java_home / "release").write_text("JAVA_VERSION=21"),
            "ENGINE_INTEGRITY_FAILURE",
        ),
    ],
)
def test_image_and_add_on_drift_fails_closed(
    tmp_path: Path, guard: GuardHarness, mutate: Any, code: str
) -> None:
    fake = _fake(tmp_path, guard)
    mutate(fake)
    state = ready_state(fake, guard)
    assert not state.ready and code in state.failure_codes
    if "ascanrules" in str(list(fake.paths.plugin_dir.iterdir())):
        assert "ascanrules" in state.forbidden_add_ons_present
    assert fake.run_calls() == []


@pytest.mark.parametrize(
    ("options", "code"),
    [
        ({"extra_addons": [["llm", "0.1.0", "alpha"]]}, "ADDON_RUNTIME_MISMATCH"),
        ({"extra_addons": [["ascanrules", "83.0.0", "release"]]}, "ADDON_RUNTIME_MISMATCH"),
        ({"mode": "not_silent"}, "SILENT_MODE_NOT_CONFIRMED"),
        ({"mode": "active_rules"}, "ACTIVE_RULES_LOADED"),
        ({"java": "21.0.1"}, "JAVA_VERSION_MISMATCH"),
    ],
)
def test_runtime_inventory_drift_fails_closed(
    tmp_path: Path, guard: GuardHarness, options: dict[str, Any], code: str
) -> None:
    fake = _fake(tmp_path, guard)
    mode = options.pop("mode", "normal")
    fake.set(mode, **options)
    state = ready_state(fake, guard)
    assert not state.ready and code in state.failure_codes


def test_dangerous_environment_and_missing_guard_block_readiness(
    tmp_path: Path, guard: GuardHarness
) -> None:
    fake = _fake(tmp_path, guard)
    state = ready_state(fake, guard)
    for bad in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "HTTP_PROXY", "AI_AUTH_TOKEN", "LD_PRELOAD"):
        assert dangerous_environment({bad: "x"}) == [bad]
    assert not attest(state, environ={"JAVA_TOOL_OPTIONS": "-javaagent:x"}).ready
    state.guard.control_url = "http://127.0.0.1:9"
    assert "GUARD_NOT_ATTESTED" in attest(state, environ={}).failure_codes


def test_drift_after_boot_makes_runner_not_ready_with_zero_traffic(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    (fake.paths.plugin_dir / "spider-release-0.20.0.zap").write_bytes(b"spider")
    response = executor.run(_request())
    assert response.status == "REJECTED"
    assert response.error_code is ZapRunnerErrorCode.ADDON_INVENTORY_DRIFT
    assert not executor.state.ready and fake.run_calls() == [] and lab.paths == []


# --- 3. fixed Automation Framework profile ----------------------------------------------------


def _plan() -> dict[str, Any]:
    return build_plan(
        projection=VULN_PROJECTION,
        api_file=Path("/work/exec-0000000000aa/projection.json"),
        report_dir=Path("/work/exec-0000000000aa/out"),
        rules=MANIFEST.passive_rules,
    )


def test_plan_is_the_fixed_passive_sequence() -> None:
    plan = _plan()
    assert tuple(job["type"] for job in plan["jobs"]) == JOB_SEQUENCE
    config, openapi, wait, report = plan["jobs"]
    assert config["parameters"]["disableAllRules"] is True
    assert config["parameters"]["scanOnlyInScope"] is True
    assert config["rules"] == [{"id": 10021, "name": RULE.name, "threshold": "medium"}]
    assert set(openapi["parameters"]) == {"apiFile", "targetUrl", "context"}
    assert "apiUrl" not in json.dumps(plan)
    assert openapi["tests"][0]["value"] == VULN_PROJECTION.operation_count
    assert wait["parameters"] == {"maxDuration": 0}
    assert report["parameters"]["template"] == "traditional-json"
    context = plan["env"]["contexts"][0]
    assert context["urls"] == list(VULN_PROJECTION.urls)
    assert all(p.startswith("\\Q") and p.endswith("\\E") for p in context["includePaths"])
    assert not any(t in JOB_SEQUENCE for t in FORBIDDEN_JOB_TYPES)
    assert validate_plan(json.loads(plan_bytes(plan)), plan) == []


@pytest.mark.parametrize("job_type", sorted(FORBIDDEN_JOB_TYPES))
def test_injected_jobs_are_rejected(job_type: str) -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["jobs"].insert(2, {"type": job_type, "parameters": {}})
    violations = validate_plan(tampered, plan)
    assert f"FORBIDDEN_JOB:{job_type}" in violations and "JOB_SEQUENCE" in violations


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (
            ("jobs", 1, "parameters", "apiUrl"),
            "http://evil.example/openapi.json",
            "FORBIDDEN_KEY:apiUrl",
        ),
        (("env", "contexts", 0, "users"), [{"name": "u"}], "FORBIDDEN_KEY:users"),
        (
            ("env", "contexts", 0, "authentication"),
            {"method": "http"},
            "FORBIDDEN_KEY:authentication",
        ),
        (("env", "vars"), {"x": "y"}, "FORBIDDEN_KEY:vars"),
        (("jobs", 0, "parameters", "disableAllRules"), False, "PLAN_MISMATCH"),
        (("jobs", 0, "rules", 0, "id"), 10038, "PLAN_MISMATCH"),
        (("jobs", 1, "parameters", "apiFile"), "/etc/passwd", "PLAN_MISMATCH"),
        (("jobs", 3, "parameters", "template"), "traditional-json-plus", "REPORT_TEMPLATE"),
    ],
)
def test_tampered_plan_keys_are_rejected(path: tuple[Any, ...], value: Any, code: str) -> None:
    plan = _plan()
    tampered = copy.deepcopy(plan)
    node: Any = tampered
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    assert code in validate_plan(tampered, plan)


def test_argv_is_fixed_passive_and_safe() -> None:
    argv = build_argv(
        java=Path("/usr/lib/jvm/java-17-openjdk-arm64/bin/java"),
        jar=Path("/zap/zap-2.17.0.jar"),
        zap_home=Path("/work/exec-0000000000aa/home"),
        tmp_dir=Path("/work/exec-0000000000aa/tmp"),
        plan_file=Path("/work/exec-0000000000aa/plan.yaml"),
        guard_host="zap-scope-guard",
        guard_port=3128,
    )
    assert {"-cmd", "-silent", "-notel", "-autorun"} <= set(argv)
    for forbidden in ("-daemon", "-host", "-port", "-addoninstall", "-addonupdate", "-script"):
        assert forbidden not in argv
    configs = [argv[i + 1] for i, item in enumerate(argv) if item == "-config"]
    assert set(FIXED_CONFIG) <= set(configs)
    assert "network.connection.httpProxy.host=zap-scope-guard" in configs
    assert "callhome.tel.enabled=false" in configs and "start.checkForUpdates=false" in configs
    assert not any("mcp" in token.lower() or "llm" in token.lower() for token in argv)


@pytest.mark.parametrize(
    "extra",
    [
        ["-addoninstall", "ascanrules"],
        ["-addonupdate"],
        ["-daemon"],
        ["-script", "/tmp/x.js"],  # noqa: S108 - hostile input under test
        ["-openapiurl", "http://evil.example/openapi.json"],
        ["-config", "api.disablekey=true"],
        ["-config", "network.localServers.mainProxy.address=0.0.0.0"],
        ["-dir", "/tmp;rm -rf /"],  # noqa: S108 - hostile input under test
        ["-autorun", "/work/plan.yaml$(id)"],
    ],
)
def test_injected_zap_flags_are_refused(extra: list[str]) -> None:
    base = [
        "/usr/bin/java",
        "-Xmx768m",
        "-jar",
        "/zap/zap-2.17.0.jar",
        "-cmd",
        "-silent",
        "-notel",
    ]
    with pytest.raises(ValueError):
        assert_argv_safe(base + extra)


def test_child_environment_is_constructed_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:evil.jar")
    monkeypatch.setenv("HTTP_PROXY", "http://evil")
    env = child_environment(Path("/work/x/home"))
    assert set(env) == {"PATH", "LANG", "LC_ALL", "HOME"}


# --- 4. safe OpenAPI projection -----------------------------------------------------------------


def test_projection_is_deterministic_minimal_and_read_only() -> None:
    again = project(VULN)
    assert again.document == VULN_PROJECTION.document and again.digest == VULN_PROJECTION.digest
    doc = json.loads(VULN_PROJECTION.document)
    assert set(doc) == {"openapi", "info", "servers", "paths"}
    assert doc["servers"] == [{"url": "http://lab-api:8001"}]
    methods = {m for item in doc["paths"].values() for m in item}
    assert methods == {"get"}
    text = VULN_PROJECTION.document.decode()
    for stripped in (
        "Synthetic lab route",
        "Controller-owned inventory",
        "summary",
        "security",
        "tags",
        "x-aegis",
        "externalDocs",
        "bearer",
        "contact",
        "components",
        "requestBody",
        "labZapAdminPurge",
        '"put"',
        '"delete"',
        "LabMarker",
    ):
        assert stripped not in text
    responses = [op["responses"] for item in doc["paths"].values() for op in item.values()]
    assert responses == [{"200": {"description": "Synthetic response"}}] * 2
    assert VULN_PROJECTION.operation_count == 2 and VULN_PROJECTION.path_count == 2
    assert VULN_PROJECTION.removed_operations == 8
    assert VULN_PROJECTION.redaction_status == "REDACTED"
    param = doc["paths"]["/lab/zap/vulnerable/catalog/{catalog_id}"]["get"]["parameters"][0]
    assert param == {
        "example": "synthetic-catalog-1",
        "in": "path",
        "name": "catalog_id",
        "required": True,
        "schema": {"enum": ["synthetic-catalog-1"], "type": "string"},
    }
    assert {op.method for op in PATCHED_PROJECTION.operations} == {"GET"}
    assert VULN_PROJECTION.digest != PATCHED_PROJECTION.digest


def _source() -> dict[str, Any]:
    return json.loads(source_bytes(VULN))


def _mutated(mutator: Any) -> bytes:
    doc = _source()
    mutator(doc)
    return json.dumps(doc).encode()


_VULN_OP = ("/lab/zap/vulnerable/status", "get")


def _op(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["paths"][_VULN_OP[0]][_VULN_OP[1]]


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda d: d["paths"][_VULN_OP[0]].update(post=d["paths"][_VULN_OP[0]].pop("get")),
            ProjectionErrorCode.STATE_CHANGING_OPERATION,
        ),
        (
            lambda d: d["paths"][_VULN_OP[0]].update(delete=d["paths"][_VULN_OP[0]].pop("get")),
            ProjectionErrorCode.STATE_CHANGING_OPERATION,
        ),
        (
            lambda d: d["paths"][_VULN_OP[0]].update(patch=d["paths"][_VULN_OP[0]].pop("get")),
            ProjectionErrorCode.STATE_CHANGING_OPERATION,
        ),
        (
            lambda d: d["paths"][_VULN_OP[0]].update(trace=d["paths"][_VULN_OP[0]].pop("get")),
            ProjectionErrorCode.METHOD_NOT_ALLOWED,
        ),
        (
            lambda d: d["paths"][_VULN_OP[0]].update(connect={"operationId": "c"}),
            ProjectionErrorCode.CUSTOM_METHOD,
        ),
        (lambda d: _op(d).update(callbacks={"cb": {}}), ProjectionErrorCode.CALLBACKS_PRESENT),
        (lambda d: d.update(webhooks={"hook": {}}), ProjectionErrorCode.WEBHOOKS_PRESENT),
        (
            lambda d: _op(d)["responses"]["200"].update(links={"l": {"operationId": "x"}}),
            ProjectionErrorCode.LINKS_PRESENT,
        ),
        (
            lambda d: _op(d)["responses"]["200"].update({"$ref": "https://evil.example/r.json"}),
            ProjectionErrorCode.EXTERNAL_REFERENCE,
        ),
        (
            lambda d: _op(d)["responses"]["200"].update({"$ref": "file:///etc/passwd"}),
            ProjectionErrorCode.EXTERNAL_REFERENCE,
        ),
        (
            lambda d: _op(d)["responses"]["200"].update({"$ref": "other.json#/x"}),
            ProjectionErrorCode.EXTERNAL_REFERENCE,
        ),
        (
            lambda d: _op(d).update(examples={"e": {"externalValue": "http://x"}}),
            ProjectionErrorCode.EXTERNAL_REFERENCE,
        ),
        (
            lambda d: d.update(servers=[{"url": "https://api.production.example"}]),
            ProjectionErrorCode.ALTERNATE_SERVER,
        ),
        (
            lambda d: d["servers"].append({"url": "http://lab-api:9999"}),
            ProjectionErrorCode.ALTERNATE_SERVER,
        ),
        (
            lambda d: d.update(
                servers=[
                    {"url": "http://{host}:8001", "variables": {"host": {"default": "lab-api"}}}
                ]
            ),
            ProjectionErrorCode.SERVER_VARIABLES,
        ),
        (
            lambda d: _op(d).update(servers=[{"url": "http://evil.example"}]),
            ProjectionErrorCode.ALTERNATE_SERVER,
        ),
        (
            lambda d: d["paths"][_VULN_OP[0]].update({"$ref": "#/components/pathItems/x"}),
            ProjectionErrorCode.PATH_ITEM_REFERENCE,
        ),
        (
            lambda d: _op(d).update(description="Use Authorization: Bearer abcdefghijklmnop"),
            ProjectionErrorCode.CREDENTIAL_MATERIAL,
        ),
        (
            lambda d: _op(d).update(example="lab-token-user-a"),
            ProjectionErrorCode.CREDENTIAL_MATERIAL,
        ),
        (
            lambda d: _op(d).update(
                parameters=[{"name": "Authorization", "in": "header", "required": True}]
            ),
            ProjectionErrorCode.UNAPPROVED_PARAMETER,
        ),
        (lambda d: d.update(openapi="2.0"), ProjectionErrorCode.UNSUPPORTED_VERSION),
        (
            lambda d: d["paths"].update({f"/lab/zap/x{i}": {} for i in range(70)}),
            ProjectionErrorCode.TOO_MANY_PATHS,
        ),
        (
            lambda d: _op(d).update(deep=json.loads("[" * 30 + "]" * 30)),
            ProjectionErrorCode.EXCESSIVE_NESTING,
        ),
        (lambda d: _op(d).update(summary="x" * 5000), ProjectionErrorCode.SOURCE_OVERSIZED),
        (
            lambda d: d["paths"]["/lab/zap/patched/status"]["get"].update(
                operationId="labZapVulnerableStatus"
            ),
            ProjectionErrorCode.DUPLICATE_OPERATION_ID,
        ),
        (lambda d: d["paths"].pop(_VULN_OP[0]), ProjectionErrorCode.OPERATION_NOT_FOUND),
    ],
)
def test_projection_rejects_hostile_sources(mutator: Any, code: ProjectionErrorCode) -> None:
    with pytest.raises(ProjectionRejected) as rejected:
        project(VULN, _mutated(mutator))
    assert rejected.value.code is code


def test_projection_rejects_oversized_and_duplicate_key_documents() -> None:
    with pytest.raises(ProjectionRejected) as rejected:
        project(VULN, b"{" + b" " * 140_000 + b"}")
    assert rejected.value.code is ProjectionErrorCode.SOURCE_OVERSIZED
    with pytest.raises(ProjectionRejected) as rejected:
        project(VULN, b'{"openapi": "3.0.3", "openapi": "3.0.3", "paths": {}}')
    assert rejected.value.code is ProjectionErrorCode.SOURCE_MALFORMED


@pytest.mark.parametrize(
    ("ref", "code"),
    [
        ("synthetic-zap-negative-state-changing", ProjectionErrorCode.STATE_CHANGING_OPERATION),
        ("synthetic-zap-negative-alternate-server", ProjectionErrorCode.ALTERNATE_SERVER),
        ("synthetic-zap-negative-external-ref", ProjectionErrorCode.EXTERNAL_REFERENCE),
    ],
)
def test_inventory_negative_controls_are_refused_by_projection(
    ref: str, code: ProjectionErrorCode
) -> None:
    with pytest.raises(ProjectionRejected) as rejected:
        project(ZAP_TARGETS[ref])
    assert rejected.value.code is code


# --- 5. strict runner RPC -------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "url",
        "origin",
        "target_url",
        "openapi_url",
        "api_url",
        "openapi",
        "spec",
        "plan",
        "automation_plan",
        "jobs",
        "zap_options",
        "options",
        "flags",
        "argv",
        "headers",
        "cookies",
        "credentials",
        "script",
        "add_ons",
        "rules",
        "report_template",
        "output_path",
    ],
)
def test_rpc_request_forbids_arbitrary_fields(field: str) -> None:
    payload = json.loads(_request().model_dump_json())
    payload[field] = "http://evil.example/x"
    with pytest.raises(ValidationError):
        ZapRunRequest.model_validate_json(json.dumps(payload))


def test_rpc_request_is_strict_about_types_and_references() -> None:
    payload = json.loads(_request().model_dump_json())
    for key, bad in (
        ("budgets", {**payload["budgets"], "max_requests": "2"}),
        ("budgets", {**payload["budgets"], "max_requests": 9}),
        ("projection_ref", "https://evil.example/openapi.json"),
        ("target_ref", "http://lab-api:8001"),
        ("profile_id", "zap-full-scan"),
    ):
        with pytest.raises(ValidationError):
            ZapRunRequest.model_validate_json(json.dumps({**payload, key: bad}))


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"projection_digest": "0" * 64}, ZapRunnerErrorCode.PROJECTION_DIGEST_MISMATCH),
        ({"operation_allowlist_digest": "0" * 64}, ZapRunnerErrorCode.ALLOWLIST_DIGEST_MISMATCH),
        (
            {"projection_ref": "synthetic-zap-patched/1.3.0"},
            ZapRunnerErrorCode.PROJECTION_REF_MISMATCH,
        ),
        ({"target_ref": "synthetic-zap-unknown"}, ZapRunnerErrorCode.UNKNOWN_TARGET),
        (
            {
                "target_ref": "synthetic-zap-negative-external-ref",
                "projection_ref": "synthetic-zap-negative-external-ref/1.3.0",
            },
            ZapRunnerErrorCode.PROJECTION_REJECTED,
        ),
        ({"profile_id": "ZAP_FULL_ACTIVE_SCAN"}, ZapRunnerErrorCode.UNKNOWN_PROFILE),
        (
            {
                "budgets": {
                    "max_requests": 3,
                    "time_budget_ms": 120_000,
                    "max_report_bytes": 131_072,
                    "max_alerts": 8,
                }
            },
            ZapRunnerErrorCode.BUDGET_OUT_OF_BOUNDS,
        ),
    ],
)
def test_runner_revalidates_before_starting_zap(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, overrides: dict[str, Any], code: Any
) -> None:
    fake, executor = _executor(tmp_path, guard)
    target = overrides.pop("target_ref", VULN.target_ref)
    response = executor.run(_request(target, **overrides))
    assert response.status == "REJECTED" and response.error_code is code
    assert fake.run_calls() == [] and lab.paths == [] and guard.state.forwarded_total == 0


def test_runner_rejects_replayed_nonce_and_is_serialized(
    tmp_path: Path, guard: GuardHarness
) -> None:
    fake, executor = _executor(tmp_path, guard)
    first = executor.run(_request())
    assert first.status == "COMPLETED"
    replay = executor.run(_request())
    assert replay.error_code is ZapRunnerErrorCode.REPLAYED_NONCE
    assert len(fake.run_calls()) == 1


def test_runner_http_server_is_strict(tmp_path: Path, guard: GuardHarness) -> None:
    _, executor = _executor(tmp_path, guard)
    server = serve_runner(executor, "127.0.0.1", 0)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]

        def call(method: str, path: str, body: bytes | None, ctype: str) -> int:
            conn = http.client.HTTPConnection(str(host), int(port), timeout=10)
            conn.request(method, path, body=body, headers={"Content-Type": ctype})
            status = conn.getresponse().status
            conn.close()
            return status

        assert call("GET", "/health", None, "application/json") == 200
        assert call("POST", "/v1/run", b"x", "text/plain") == 415
        assert call("POST", "/v1/run", b"{" + b" " * 5000 + b"}", "application/json") == 413
        payload = json.loads(_request().model_dump_json())
        payload["automation_plan"] = "jobs: [{type: activeScan}]"
        assert call("POST", "/v1/run", json.dumps(payload).encode(), "application/json") == 400
        assert call("DELETE", "/v1/run", None, "application/json") == 405
        assert call("GET", "/v1/plan", None, "application/json") == 404
    finally:
        server.shutdown()
        server.server_close()


def test_host_clock_jump_is_clamped_not_a_runner_crash(
    tmp_path: Path, guard: GuardHarness
) -> None:
    from datetime import UTC, datetime, timedelta

    _, executor = _executor(tmp_path, guard)
    started = datetime.now(UTC) - timedelta(minutes=17)  # e.g. the lab host slept mid-run
    response = executor._response(
        _request(), status="FAILED", started=started, error=ZapRunnerErrorCode.EXECUTION_TIMEOUT
    )
    assert response.duration_ms == 600_000 and not response.coverage_complete


def test_runner_server_returns_a_typed_error_when_execution_raises(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    _, executor = _executor(tmp_path, guard)

    def boom(_: ZapRunRequest) -> ZapRunResponse:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(executor, "run", boom)
    server = serve_runner(executor, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        conn = http.client.HTTPConnection(str(host), int(port), timeout=10)
        conn.request(
            "POST",
            "/v1/run",
            body=_request().model_dump_json().encode(),
            headers={"Content-Type": "application/json"},
        )
        reply = conn.getresponse()
        body = json.loads(reply.read())
        conn.close()
        assert reply.status == 500
        assert body == {
            "schema_version": "aegis.zap.rpc/1",
            "status": "REJECTED",
            "error_code": "SPAWN_FAILED",
        }
    finally:
        server.shutdown()
        server.server_close()


# --- 6. execution through the real guard against the real lab app -------------------------------


def test_vulnerable_execution_reports_one_alert_on_the_scenario_route(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    response = executor.run(_request())
    assert response.status == "COMPLETED" and response.coverage_complete
    assert [(a.plugin_id, a.path, a.param) for a in response.alerts] == [
        (10021, "/lab/zap/vulnerable/catalog/synthetic-catalog-1", "x-content-type-options")
    ]
    assert response.traffic and response.traffic.forwarded == 2 and response.traffic.blocked == 0
    assert sorted(lab.paths) == sorted(op.path for op in VULN_PROJECTION.operations)
    assert response.stages.pscan_drained and response.stages.installed_add_ons_match
    assert response.stages.silent_mode and response.plan.validated
    assert set(response.parse.stripped_fields) >= {"desc", "solution", "otherinfo", "reference"}
    assert response.session_destroyed and not any(executor.state.paths.work_root.iterdir())
    argv = fake.run_calls()[0]["argv"]
    assert "-autorun" in argv and "-silent" in argv and "-notel" in argv
    assert set(fake.run_calls()[0]["env"]) <= {"PATH", "LANG", "LC_ALL", "HOME"}


def test_patched_execution_has_complete_coverage_and_zero_alerts(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    _, executor = _executor(tmp_path, guard)
    response = executor.run(_request(PATCHED.target_ref))
    assert response.status == "COMPLETED" and response.coverage_complete
    assert response.alerts == () and response.parse.status == "PARSED"
    assert sorted(lab.paths) == sorted(op.path for op in PATCHED_PROJECTION.operations)


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("nonzero", ZapRunnerErrorCode.PLAN_FAILED),
        ("malformed_report", ZapRunnerErrorCode.REPORT_MALFORMED),
        ("oversized_report", ZapRunnerErrorCode.REPORT_OVERSIZED),
        ("truncated_report", ZapRunnerErrorCode.REPORT_TRUNCATED),
        ("no_report", ZapRunnerErrorCode.REPORT_MISSING),
        ("no_drain", ZapRunnerErrorCode.PASSIVE_QUEUE_NOT_DRAINED),
        ("unadmitted_rule", ZapRunnerErrorCode.UNADMITTED_RULE),
        ("not_silent", ZapRunnerErrorCode.SILENT_MODE_NOT_CONFIRMED),
        ("active_rules", ZapRunnerErrorCode.ADDON_RUNTIME_MISMATCH),
        ("rule_drift", ZapRunnerErrorCode.RULE_SET_MISMATCH),
        ("wrong_count", ZapRunnerErrorCode.PLAN_FAILED),
        ("huge_stdout", ZapRunnerErrorCode.OUTPUT_OVERSIZED),
    ],
)
def test_bad_engine_behaviour_fails_closed(
    tmp_path: Path, guard: GuardHarness, mode: str, code: ZapRunnerErrorCode
) -> None:
    fake = _fake(tmp_path, guard)
    state = ready_state(fake, guard)
    assert state.ready
    fake.set(mode)  # misbehave only at execution time, after a clean boot attestation
    response = Executor(state).run(_request(PATCHED.target_ref))
    assert response.status == "FAILED" and response.error_code is code
    assert not response.coverage_complete and response.alerts == ()
    assert response.session_destroyed


def test_extra_addon_at_runtime_fails_closed(tmp_path: Path, guard: GuardHarness) -> None:
    fake, executor = _executor(tmp_path, guard)
    fake.set("normal", extra_addons=[["llm", "0.1.0", "alpha"]])
    response = executor.run(_request())
    assert response.error_code is ZapRunnerErrorCode.ADDON_RUNTIME_MISMATCH
    assert response.alerts == ()


@pytest.mark.parametrize(
    ("mode", "target", "code", "reason"),
    [
        ("escape_path", VULN.target_ref, ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED, "PATH"),
        ("extra_request", VULN.target_ref, ZapRunnerErrorCode.REQUEST_BUDGET_EXCEEDED, "BUDGET"),
        (
            "normal",
            "synthetic-zap-negative-redirect",
            ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED,
            "PATH",
        ),
        (
            "normal",
            "synthetic-zap-negative-unstable",
            ZapRunnerErrorCode.REQUEST_BUDGET_EXCEEDED,
            "BUDGET",
        ),
    ],
)
def test_scope_and_budget_escapes_never_reach_the_target(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    mode: str,
    target: str,
    code: Any,
    reason: str,
) -> None:
    fake, executor = _executor(tmp_path, guard)
    fake.set(mode)
    response = executor.run(_request(target))
    assert response.status == "FAILED" and response.error_code is code
    assert response.traffic and dict(response.traffic.blocked_reasons).get(reason, 0) >= 1
    approved = {op.path for op in project(ZAP_TARGETS[target]).operations}
    # The lab saw only approved paths, each at most once: blocked requests were never forwarded.
    assert set(lab.paths) <= approved and len(lab.paths) == len(set(lab.paths))
    assert "/lab/zap/redirect/elsewhere" not in lab.paths
    assert "/lab/zap/vulnerable/secret" not in lab.paths
    if target == "synthetic-zap-negative-redirect":
        assert response.traffic.redirects == 1


def test_slow_target_times_out_and_never_passes(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    _, executor = _executor(tmp_path, guard)
    response = executor.run(_request("synthetic-zap-negative-slow"))
    assert response.status == "FAILED" and response.error_code is ZapRunnerErrorCode.TARGET_TIMEOUT
    assert not response.coverage_complete


def test_hung_engine_is_killed_by_the_wall_clock(tmp_path: Path, guard: GuardHarness) -> None:
    fake, executor = _executor(tmp_path, guard, cap=6.0)
    fake.set("hang")
    response = executor.run(_request())
    assert response.exit_class == "TIMEOUT"
    assert response.error_code is ZapRunnerErrorCode.EXECUTION_TIMEOUT
    assert response.session_destroyed and not response.coverage_complete


# --- 7. safe report parser -----------------------------------------------------------------------


def test_parser_accepts_a_report_and_never_propagates_prose() -> None:
    outcome = _parse(_report())
    assert outcome.summary.status == "PARSED" and len(outcome.records) == 1
    record = outcome.records[0]
    assert record.rule_name == RULE.name and record.claimed_risk == "low"
    dumped = record.model_dump_json()
    for prose in ("<p>", "<script>", "Anti-MIME", "owasp.org", "Ensure"):
        assert prose not in dumped
    assert set(outcome.summary.stripped_fields) >= {"desc", "solution", "otherinfo", "reference"}
    again = _parse(
        _report(),
    )
    assert again.records[0].record_digest == record.record_digest


def test_genuine_pinned_zap_report_fixture_parses() -> None:
    fixture = REPO / "tests/fixtures/zap-2.17.0-traditional-json-vulnerable.json"
    outcome = _parse(fixture.read_bytes())
    assert outcome.summary.status == "PARSED"
    assert [(r.plugin_id, r.path) for r in outcome.records] == [
        (10021, "/lab/zap/vulnerable/catalog/synthetic-catalog-1")
    ]


def test_parser_collapses_identical_duplicates_and_rejects_conflicts() -> None:
    alert = _alert()
    alert["instances"] = [copy.deepcopy(alert["instances"][0]) for _ in range(2)]
    alert["count"] = "2"
    outcome = _parse(_report([alert]))
    assert outcome.summary.status == "PARSED" and outcome.summary.duplicates_collapsed == 1
    conflicting = copy.deepcopy(alert)
    conflicting["instances"][1]["evidence"] = "different"
    assert _parse(_report([conflicting])).summary.status == "MALFORMED"


def _instance_override(**extra: Any) -> dict[str, Any]:
    alert = _alert()
    alert["instances"][0].update(extra)
    return _report([alert])


@pytest.mark.parametrize(
    ("data", "status", "code"),
    [
        (None, "MISSING", ZapRunnerErrorCode.REPORT_MISSING),
        (b"", "EMPTY", ZapRunnerErrorCode.REPORT_MISSING),
        (b'{"@programName": "ZAP", "site": [', "TRUNCATED", ZapRunnerErrorCode.REPORT_TRUNCATED),
        (b"{not json}", "MALFORMED", ZapRunnerErrorCode.REPORT_MALFORMED),
        (
            b'{"@programName": "ZAP", "@programName": "ZAP"}',
            "MALFORMED",
            ZapRunnerErrorCode.REPORT_MALFORMED,
        ),
        (b"{" + b" " * 140_000 + b"}", "OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED),
        (
            _report(**{"@version": "2.18.0"}),
            "MALFORMED",
            ZapRunnerErrorCode.ENGINE_INTEGRITY_FAILURE,
        ),
        (_report(extra_top="x"), "MALFORMED", ZapRunnerErrorCode.REPORT_MALFORMED),
        (
            _report([_alert(pluginid="40012", alertRef="40012")]),
            "MALFORMED",
            ZapRunnerErrorCode.UNADMITTED_RULE,
        ),
        (_report([_alert(name="Something Else")]), "MALFORMED", ZapRunnerErrorCode.UNADMITTED_RULE),
        (
            _instance_override(uri="http://lab-api:8001/lab/zap/vulnerable/secret"),
            "MALFORMED",
            ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED,
        ),
        (
            _instance_override(uri="https://evil.example/lab/zap/vulnerable/status"),
            "MALFORMED",
            ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED,
        ),
        (_instance_override(method="POST"), "MALFORMED", ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED),
        (
            _instance_override(attack="' OR 1=1 --"),
            "MALFORMED",
            ZapRunnerErrorCode.REPORT_MALFORMED,
        ),
        (_instance_override(evidence="x" * 2000), "OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED),
        (_instance_override(param="x" * 200), "MALFORMED", ZapRunnerErrorCode.REPORT_MALFORMED),
        (
            _instance_override(requestHeader="Cookie: s=1"),
            "MALFORMED",
            ZapRunnerErrorCode.REPORT_MALFORMED,
        ),
        (_report([_alert(count="3")]), "MALFORMED", ZapRunnerErrorCode.REPORT_MALFORMED),
        (_report([_alert()] * 9), "OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED),
        (_report([_alert(desc="x" * 9000)]), "OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED),
    ],
)
def test_parser_fails_closed(data: Any, status: str, code: ZapRunnerErrorCode) -> None:
    outcome = _parse(data)
    assert outcome.summary.status == status and outcome.summary.failure_code is code
    assert outcome.records == ()


def test_parser_site_origin_escape_fails_closed() -> None:
    report = _report()
    report["site"].append(
        {
            "@name": "https://evil.example",
            "@host": "evil.example",
            "@port": "443",
            "@ssl": "true",
            "alerts": [],
        }
    )
    assert _parse(report).summary.failure_code is ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED


def test_html_evidence_is_reduced_to_a_digest() -> None:
    outcome = _parse(_instance_override(evidence="<img src=x onerror=alert(1)>"))
    record = outcome.records[0]
    assert record.evidence_length == 28 and "<img" not in record.model_dump_json()


# --- 8. the scope guard ---------------------------------------------------------------------------


def _proxy(
    guard: GuardHarness, method: str, url: str, headers: dict[str, str] | None = None
) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", guard.proxy_port, timeout=10)
    try:
        conn.request(method, url, headers=headers or {})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def _arm(guard: GuardHarness, paths: list[str], max_requests: int | None = None) -> str:
    status, body = guard.state.arm(
        {
            "schema_version": "aegis.zap.guard/1",
            "execution_id": "exec-0000000000ab",
            "origin": "http://lab-api:8001",
            "allowlist": [{"method": "GET", "path": p} for p in paths],
            "max_requests": max_requests or len(paths),
            "ttl_ms": 30_000,
        }
    )
    assert status == 200, body
    return str(body["token"])


def test_guard_forwards_nothing_while_idle(guard: GuardHarness, lab: LabServer) -> None:
    assert _proxy(guard, "GET", "http://lab-api:8001/lab/zap/vulnerable/status") == 403
    assert lab.paths == [] and guard.state.blocked_while_idle == 1


def test_guard_enforces_origin_path_method_query_and_budget(
    guard: GuardHarness, lab: LabServer
) -> None:
    status_path = "/lab/zap/vulnerable/status"
    token = _arm(guard, [status_path])
    assert _proxy(guard, "GET", "http://evil.example:8001" + status_path) == 403
    assert _proxy(guard, "GET", "http://lab-api:8002" + status_path) == 403
    assert _proxy(guard, "GET", "https://lab-api:8001" + status_path) == 403
    assert _proxy(guard, "GET", "http://lab-api:8001" + status_path + "?x=1") == 403
    assert _proxy(guard, "GET", "http://lab-api:8001/lab/zap/patched/status") == 403
    assert _proxy(guard, "POST", "http://lab-api:8001" + status_path) == 403
    assert _proxy(guard, "CONNECT", "lab-api:8001") == 403
    assert _proxy(guard, "GET", "http://user:pw@lab-api:8001" + status_path) == 403
    assert lab.paths == []
    headers = {"Cookie": "session=1", "Authorization": "Bearer abcdefghijklmnop", "X-Evil": "1"}
    assert _proxy(guard, "GET", "http://lab-api:8001" + status_path, headers) == 200
    assert _proxy(guard, "GET", "http://lab-api:8001" + status_path) == 403  # budget exhausted
    assert lab.paths == [status_path]
    status, body = guard.state.counters({"token": token}, disarm=True)
    counters = body["counters"]
    assert counters["forwarded"] == 1 and counters["budget_exceeded"] is True
    reasons = dict(counters["blocked_reasons"])
    assert reasons["ORIGIN"] >= 2 and reasons["PATH"] == 1 and reasons["BUDGET"] == 1
    assert reasons["METHOD"] == 2 and reasons["MALFORMED_TARGET"] >= 2


def test_guard_control_requires_the_token_and_refuses_rearming(guard: GuardHarness) -> None:
    token = _arm(guard, ["/lab/zap/vulnerable/status"])
    assert guard.state.counters({"token": "0" * 32}, disarm=False)[0] == 403
    assert guard.state.counters({"token": token, "x": 1}, disarm=False)[0] == 400
    status, _ = guard.state.arm(
        {
            "schema_version": "aegis.zap.guard/1",
            "execution_id": "exec-0000000000ac",
            "origin": "http://lab-api:8001",
            "allowlist": [{"method": "GET", "path": "/lab/zap/vulnerable/status"}],
            "max_requests": 1,
            "ttl_ms": 30_000,
        }
    )
    assert status == 409
    assert guard.state.counters({"token": token}, disarm=True)[0] == 200
    assert guard.state.counters({"token": token}, disarm=True)[0] == 403


@pytest.mark.parametrize(
    "override",
    [
        {"origin": "http://evil.example:8001"},
        {"origin": "http://127.0.0.1:8001"},
        {"allowlist": [{"method": "POST", "path": "/lab/zap/vulnerable/status"}]},
        {"allowlist": [{"method": "GET", "path": "/lab/zap/../etc/passwd"}]},
        {"max_requests": 5},
        {"ttl_ms": 999_999},
        {"extra": True},
    ],
)
def test_guard_refuses_invalid_arming(override: dict[str, Any]) -> None:
    payload: dict[str, Any] = {
        "schema_version": "aegis.zap.guard/1",
        "execution_id": "exec-0000000000ad",
        "origin": "http://lab-api:8001",
        "allowlist": [{"method": "GET", "path": "/lab/zap/vulnerable/status"}],
        "max_requests": 1,
        "ttl_ms": 30_000,
    }
    payload.update(override)
    assert GuardState().arm(payload)[0] == 400


# --- 9. controller policy, correlation and independent verification ----------------------------


def test_controller_builds_job_from_catalog_inventory_and_projection() -> None:
    job, projection = build_zap_job(
        profile_id=PROFILE_ID,
        capability_id=CAPABILITY,
        run_id="scan-0000000000aa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        target_ref=VULN.target_ref,
        remaining_requests=8,
        allowed_origins=["http://lab-api:8001"],
        adapter_enabled=True,
    )
    assert job.activity is EngineActivity.PASSIVE and job.rule_ids == (10021,)
    assert job.projection_digest == projection.digest == VULN_PROJECTION.digest
    assert job.budget.max_requests == 2 and job.operation_count == 2
    assert job.target.operation_id == "labZapVulnerableCatalog"
    capability = get_engine_capability(CAPABILITY)
    assert capability and capability.verified_severity == "LOW"
    profile = get_engine_profile(PROFILE_ID)
    assert profile and profile.enabled and profile.capability_ids == (CAPABILITY,)
    zap_profiles = [p for p in PROFILE_CATALOG if p.engine is SecurityEngine.ZAP and p.enabled]
    assert [p.profile_id for p in zap_profiles] == [PROFILE_ID]


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"capability_id": "zap_active_scan_v0"}, EngineErrorCode.ACTIVE_SCAN_FORBIDDEN),
        ({"capability_id": "zap_passive_scan_v0"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"capability_id": "nuclei_scm_metadata_exposure_v1"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"capability_id": "bola_object_read_v1"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"adapter_enabled": False}, EngineErrorCode.ENGINE_DISABLED),
        ({"target_ref": "synthetic-zap-unknown"}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        ({"allowed_origins": ["http://other:8001"]}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        ({"remaining_requests": 1}, EngineErrorCode.BUDGET_EXCEEDED),
        ({"profile_id": "zap-passive-synthetic"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"profile_id": "NUCLEI_LAB_SAFE_HTTP_V1"}, EngineErrorCode.UNKNOWN_ENGINE),
        ({"environment": EngineEnvironment.PRODUCTION}, EngineErrorCode.DISALLOWED_ENVIRONMENT),
        (
            {"target_ref": "synthetic-zap-negative-external-ref"},
            EngineErrorCode.PROJECTION_REJECTED,
        ),
    ],
)
def test_controller_policy_rejects_before_runner(
    overrides: dict[str, Any], code: EngineErrorCode
) -> None:
    options: dict[str, Any] = {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY,
        "run_id": "scan-0000000000aa",
        "environment": EngineEnvironment.SYNTHETIC_LAB,
        "target_ref": VULN.target_ref,
        "remaining_requests": 8,
        "allowed_origins": ["http://lab-api:8001"],
        "adapter_enabled": True,
    }
    options.update(overrides)
    with pytest.raises(EnginePolicyRejection) as rejected:
        build_zap_job(**options)
    assert rejected.value.error.code is code
    if code is EngineErrorCode.PROJECTION_REJECTED:
        assert isinstance(rejected.value, ZapProjectionRejection)


@pytest.mark.parametrize(
    "field", ["command", "argv", "plan", "jobs", "url", "apiUrl", "headers", "script", "options"]
)
def test_zap_job_has_no_plan_url_or_option_fields(field: str) -> None:
    job, _ = build_zap_job(
        profile_id=PROFILE_ID,
        capability_id=CAPABILITY,
        run_id="scan-0000000000aa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        target_ref=VULN.target_ref,
        remaining_requests=8,
        allowed_origins=["http://lab-api:8001"],
        adapter_enabled=True,
    )
    with pytest.raises(ValidationError):
        ZapEngineJob.model_validate({**job.model_dump(), field: "x"})


@pytest.mark.parametrize(
    "field",
    ["openapi_url", "api_url", "openapi", "plan", "jobs", "tool", "url", "headers", "rules"],
)
def test_scan_request_cannot_supply_openapi_plan_or_tool(field: str) -> None:
    with pytest.raises(ValidationError):
        ScanCreate.model_validate({"capability": CAPABILITY, field: "http://evil.example/x"})


def _facts(
    *, control: dict[str, Any] | None = None, probe: dict[str, Any] | None = None
) -> list[ZapProbeFacts]:
    base = {
        "method": "GET",
        "status_code": 200,
        "content_class": "JSON",
        "body_bytes": 90,
        "synthetic_marker_ok": True,
    }
    return [
        ZapProbeFacts(
            name="c",
            role="BASE_CONTROL",
            path="/lab/zap/vulnerable/status",
            **{**base, "nosniff_header": "PRESENT_NOSNIFF", **(control or {})},
        ),
        ZapProbeFacts(
            name="p",
            role="HEADER_PROBE",
            path="/lab/zap/vulnerable/catalog/synthetic-catalog-1",
            **{**base, "nosniff_header": "ABSENT", **(probe or {})},
        ),
    ]


def test_verifier_verdicts_are_independent_of_zap() -> None:
    assert evaluate(_facts()).status == "CONFIRMED"
    assert evaluate(_facts(probe={"nosniff_header": "PRESENT_NOSNIFF"})).status == "PASS"
    for control, probe in (
        ({"nosniff_header": "ABSENT"}, None),
        ({"synthetic_marker_ok": False}, None),
        ({"transport_error": True}, None),
        (None, {"nosniff_header": "INVALID"}),
        (None, {"redirect": True}),
        (None, {"content_class": "HTML"}),
        (None, {"synthetic_marker_ok": False}),
    ):
        assert evaluate(_facts(control=control, probe=probe)).status == "INSUFFICIENT"
    assert header_state([]) == "ABSENT" and header_state(["NoSniff "]) == "PRESENT_NOSNIFF"
    assert header_state(["nosniff", "nosniff"]) == "INVALID" and header_state(["x"]) == "INVALID"
    assert probe_plan(ZAP_TARGETS["synthetic-zap-negative-redirect"], "scan-x") == []
    import aegis.zap_verifier as verifier_module

    source = Path(verifier_module.__file__).read_text()
    assert "claimed_risk" not in source and "ZapRunResponse" not in source


def test_safety_permits_only_fixed_zap_verifier_paths() -> None:
    safety = SafetyController(Settings())
    for _, _, path in probe_plan(VULN, "scan-x") + probe_plan(PATCHED, "scan-x"):
        assert safety.approve_zap_verification("http://lab-api:8001", path)
    for bad in (
        "/lab/zap/redirect/status",
        "/lab/zap/vulnerable/catalog/other",
        "/lab/zap/admin/purge",
        "/api/v1/accounts/A-100",
    ):
        with pytest.raises(SafetyViolation):
            safety.approve_zap_verification("http://lab-api:8001", bad)


def test_zap_alert_cannot_become_verified_without_the_verifier() -> None:
    from aegis.engine.contracts import EngineReportedFinding

    job, _ = build_zap_job(
        profile_id=PROFILE_ID,
        capability_id=CAPABILITY,
        run_id="scan-0000000000aa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        target_ref=VULN.target_ref,
        remaining_requests=8,
        allowed_origins=["http://lab-api:8001"],
        adapter_enabled=True,
    )
    reported = EngineReportedFinding(
        report_key=f"{CAPABILITY}:10021:{VULN.target_ref}:labZapVulnerableCatalog",
        engine=SecurityEngine.ZAP,
        capability_id=CAPABILITY,
        claimed_category="tool claim",
        target_operation_id="labZapVulnerableCatalog",
        principal_profile="anonymous",
        observation_names=["zap-10021-x"],
        signal="Passive rule 10021 flagged (unverified).",
    )
    normalized = correlate_reported_finding(reported, job, ai_hypothesis="none", in_scope=True)
    assert normalized.lifecycle_state is FindingLifecycleState.AEGIS_CORRELATED
    assert normalized.severity is None and normalized.confidence is None
    for status, state in (
        ("PASS", FindingLifecycleState.REJECTED),
        ("INSUFFICIENT", FindingLifecycleState.REVIEW_REQUIRED),
        ("CONFIRMED", FindingLifecycleState.VERIFIED),
    ):
        conclusion = VerifierConclusion(status=status, summary="verifier said so")  # type: ignore[arg-type]
        promoted = record_verifier_conclusion(
            normalized, conclusion, inconclusive_state=FindingLifecycleState.REVIEW_REQUIRED
        )
        assert promoted.lifecycle_state is state
    assert promoted.severity == "LOW" and promoted.confidence == "CONFIRMED"


# --- 10. end-to-end controller flows -----------------------------------------------------------


_EXPECTED_ORDER = [
    "ZAP_PROJECTION_CREATED",
    "ZAP_JOB_ADMITTED",
    "ZAP_RUNNER_STARTED",
    "ZAP_PLAN_VALIDATED",
    "ZAP_OPENAPI_IMPORT_STARTED",
    "ZAP_OPENAPI_IMPORT_COMPLETED",
    "ZAP_PASSIVE_SCAN_WAIT_STARTED",
    "ZAP_PASSIVE_SCAN_DRAINED",
    "ZAP_EXECUTION_COMPLETED",
]


async def test_vulnerable_flow_is_verifier_owned(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, runner, lab_transport = _zap_service(tmp_path, guard, monkeypatch, "claims_high")
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.FAIL and result.terminal_reason == "DETERMINISTIC_CONFIRMED"
    assert len(result.findings) == 1
    finding = result.findings[0]
    # ZAP claimed HIGH risk; the Aegis-owned severity from the catalog is LOW.
    assert finding.severity == "LOW" and finding.confidence == "CONFIRMED"
    assert [n["lifecycle_state"] for n in result.normalized_findings] == ["VERIFIED"]
    assert result.verification.status == "CONFIRMED"
    events = _events(service, result.id)
    positions = [events.index(event) for event in _EXPECTED_ORDER]
    assert positions == sorted(positions)
    for event in (
        "ZAP_ALERT_REPORTED",
        "ZAP_ALERT_CORRELATED",
        "ZAP_VERIFICATION_STARTED",
        "ZAP_VERIFICATION_COMPLETED",
    ):
        assert event in events
    assert runner.calls["run"] == 1
    assert sorted(lab_transport.paths) == sorted(p for _, _, p in probe_plan(VULN, result.id))
    provenance = result.zap_provenance
    assert provenance["coverage_complete"] and provenance["traffic"]["forwarded"] == 2
    assert provenance["projection"]["digest"] == VULN_PROJECTION.digest
    assert provenance["alerts"][0]["claimed_risk"] == "high"


async def test_patched_flow_passes_only_with_complete_coverage(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch)
    vulnerable = await _run(service, variant="vulnerable")
    patched = await _run(service, variant="patched", retest_of=vulnerable.id)
    assert patched.status is ScanStatus.PASS and patched.terminal_reason == "COVERAGE_COMPLETE"
    assert not patched.findings and not patched.normalized_findings
    assert patched.verification.status == "PASS"
    assert patched.zap_provenance["coverage_complete"] is True


@pytest.mark.parametrize("mode", ["no_drain", "nonzero", "no_report", "truncated_report"])
async def test_zero_alerts_without_complete_coverage_is_never_pass(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    service, fake, _, lab_transport = _zap_service(tmp_path, guard, monkeypatch)
    fake.set(mode)
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.INCOMPLETE and not result.findings
    assert result.terminal_reason.startswith("ZAP_EXECUTION_INCOMPLETE_")
    assert "ZAP_EXECUTION_FAILED" in _events(service, result.id)
    assert lab_transport.paths == []  # no verifier traffic after a failed execution


async def test_zap_cannot_self_confirm(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, "force_alert")
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == "TOOL_FINDING_REJECTED_BY_VERIFIER"
    assert not result.findings
    assert [n["lifecycle_state"] for n in result.normalized_findings] == ["REJECTED"]


async def test_missing_tool_alert_on_vulnerable_target_is_not_pass(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, "suppress_alerts")
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == "ENGINE_VERIFIER_DISAGREEMENT" and not result.findings


async def test_unrelated_alert_cannot_satisfy_acceptance(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, "control_alert")
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == "UNCORRELATED_TOOL_ALERT" and not result.findings
    assert [n["lifecycle_state"] for n in result.normalized_findings] == ["REJECTED"]


async def test_duplicate_alerts_normalize_deterministically(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, "duplicate_alert")
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.FAIL
    assert len(result.normalized_findings) == 1
    assert result.zap_provenance["counts"]["duplicates_collapsed"] == 1


@pytest.mark.parametrize(
    ("ref", "code"),
    [
        ("synthetic-zap-negative-state-changing", "STATE_CHANGING_OPERATION"),
        ("synthetic-zap-negative-alternate-server", "ALTERNATE_SERVER"),
        ("synthetic-zap-negative-external-ref", "EXTERNAL_REFERENCE"),
    ],
)
async def test_projection_negative_controls_have_zero_runner_and_target_traffic(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    monkeypatch: pytest.MonkeyPatch,
    ref: str,
    code: str,
) -> None:
    service, fake, runner, lab_transport = _zap_service(tmp_path, guard, monkeypatch)
    result = await _run(service, target_ref=ref)
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == f"ZAP_PROJECTION_REJECTED_{code}"
    assert runner.calls == {"attestation": 0, "run": 0}
    assert fake.run_calls() == [] and lab.paths == [] and lab_transport.paths == []
    events = _events(service, result.id)
    assert "ZAP_PROJECTION_REJECTED" in events and "ZAP_JOB_ADMITTED" not in events


@pytest.mark.parametrize(
    ("ref", "detail"),
    [
        ("synthetic-zap-negative-redirect", "SCOPE_ESCAPE_BLOCKED"),
        ("synthetic-zap-negative-unstable", "REQUEST_BUDGET_EXCEEDED"),
    ],
)
async def test_runtime_negative_controls_fail_closed(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    monkeypatch: pytest.MonkeyPatch,
    ref: str,
    detail: str,
) -> None:
    service, _, _, lab_transport = _zap_service(tmp_path, guard, monkeypatch)
    result = await _run(service, target_ref=ref)
    assert result.status is ScanStatus.INCOMPLETE and not result.findings
    assert result.terminal_reason == f"ZAP_EXECUTION_INCOMPLETE_{detail}"
    assert "/lab/zap/redirect/elsewhere" not in lab.paths and lab_transport.paths == []


async def test_denied_active_scan_and_retired_placeholder(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, fake, runner, _ = _zap_service(tmp_path, guard, monkeypatch)
    result = await _run(service, capability="zap_active_scan_v0")
    assert result.terminal_reason == "ZAP_JOB_REJECTED_ACTIVE_SCAN_FORBIDDEN"
    assert runner.calls["run"] == 0 and fake.run_calls() == []
    with pytest.raises(ValueError):
        service.create(ScanCreate(capability="zap_passive_scan_v0"))


def _tamper(field: str) -> Any:
    def override(executor: Executor, request: ZapRunRequest) -> str:
        response = executor.run(request)
        data = json.loads(response.model_dump_json())
        if field == "alert_path":
            data["alerts"][0]["path"] = "/lab/zap/vulnerable/secret"
        elif field == "alert_plugin":
            data["alerts"][0]["plugin_id"] = 40012
        elif field == "forwarded":
            data["traffic"]["forwarded"] = 7
        elif field == "blocked_but_complete":
            data["traffic"]["blocked"] = 1
        elif field == "digest":
            data["projection"]["digest"] = "0" * 64
        elif field == "nonce":
            data["nonce"] = "f" * 32
        elif field == "not_drained":
            data["stages"]["pscan_drained"] = False
        elif field == "unexpected_path":
            data["traffic"]["per_path"].append(["GET", "/lab/zap/admin/purge", 1])
        return json.dumps(data)

    return override


@pytest.mark.parametrize(
    "field",
    [
        "alert_path",
        "alert_plugin",
        "forwarded",
        "blocked_but_complete",
        "digest",
        "nonce",
        "not_drained",
        "unexpected_path",
    ],
)
async def test_hostile_runner_responses_fail_closed(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    service, _, runner, _ = _zap_service(tmp_path, guard, monkeypatch)
    runner.override_run = _tamper(field)
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.INCOMPLETE and not result.findings


def _attestation_tamper(mutation: str) -> Any:
    def override(executor: Executor) -> str:
        data = json.loads(executor.state.attestation().model_dump_json())
        if mutation == "not_ready":
            data["ready"] = False
        elif mutation == "version":
            data["engine"]["zap_version"] = "2.18.0"
        elif mutation == "inventory":
            data["engine"]["add_on_inventory_digest"] = "0" * 64
        elif mutation == "guard":
            data["guard"]["reachable"] = False
        elif mutation == "extra_files":
            data["unexpected_plugin_files"] = 1
        elif mutation == "llm":
            data["forbidden_add_ons_present"] = ["llm"]
        elif mutation == "rules":
            data["admitted_rule_ids"] = [10021, 10038]
        elif mutation == "java":
            data["engine"]["java_runtime_version"] = "21.0.4+7"
        return json.dumps(data)

    return override


@pytest.mark.parametrize(
    "mutation",
    ["not_ready", "version", "inventory", "guard", "extra_files", "llm", "rules", "java"],
)
async def test_attestation_mismatch_blocks_execution(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    service, fake, runner, _ = _zap_service(tmp_path, guard, monkeypatch)
    runner.override_attestation = _attestation_tamper(mutation)
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.INCOMPLETE
    assert result.terminal_reason.startswith("ZAP_EXECUTION_INCOMPLETE_")
    assert runner.calls["run"] == 0 and fake.run_calls() == [] and lab.paths == []


async def test_unreachable_runner_is_incomplete(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, runner=False)
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.INCOMPLETE
    assert result.terminal_reason == "ZAP_EXECUTION_INCOMPLETE_RUNNER_UNAVAILABLE_OR_INVALID"


async def test_disabled_zap_rejects_and_is_a_zero_traffic_skeleton(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, fake, runner, _ = _zap_service(tmp_path, guard, monkeypatch, enabled=False)
    result = await _run(service, variant="vulnerable")
    assert result.terminal_reason == "ZAP_JOB_REJECTED_ENGINE_DISABLED"
    assert runner.calls == {"attestation": 0, "run": 0} and fake.run_calls() == []
    default = ScanService(
        Settings(database_path=str(tmp_path / "d.db")),
        store=ScanStore(str(tmp_path / "d.db")),
        planner=DemoPlanner(),
        safety=SafetyController(Settings()),
    )
    for engine in (SecurityEngine.ZAP, SecurityEngine.BURP_DAST):
        adapter = default.dispatcher.adapter_for(engine)
        assert isinstance(adapter, DisabledEngineAdapter) and not adapter.enabled
        assert adapter.health().state == "DISABLED"


async def test_zap_adapter_refuses_generic_kernel_jobs() -> None:
    from test_phase_1_1 import _job as native_job

    adapter = ZapAdapter("http://zap-runner:8092", enabled=True)
    result = await adapter.execute(native_job(), "vulnerable")
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert result.execution.error and result.execution.error.code is (
        EngineErrorCode.UNSUPPORTED_JOB_TYPE
    )


async def test_no_raw_http_or_alert_prose_is_persisted_or_projected(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch, "html_evidence")
    result = await _run(service, variant="vulnerable")
    blob = result.model_dump_json() + json.dumps(service.store.audit(result.id), default=str)
    for forbidden in (
        "<p>",
        "<script",
        "<img",
        "onerror",
        "Anti-MIME-Sniffing",
        "Mozilla",
        "Set-Cookie",
        'otherinfo": "<',
        'zap-passive-header", "variant',
        "Authorization",
    ):
        assert forbidden not in blob
    from aegis.operator import evidence_cards, safe_metadata

    for card in evidence_cards(result):
        assert "<" not in json.dumps(card)
    for row in service.store.audit(result.id):
        assert "<" not in json.dumps(safe_metadata(row.get("details")))


async def test_console_exposes_zap_provenance_coverage_and_responsibility(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _zap_service(tmp_path, guard, monkeypatch)
    vulnerable = await _run(service, variant="vulnerable")
    patched = await _run(service, variant="patched", retest_of=vulnerable.id)
    monkeypatch.setattr(main_module, "service", service)
    monkeypatch.setattr(main_module, "store", service.store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        engines = (await client.get("/api/console/engines")).json()
        integrations = (await client.get("/api/console/integrations")).json()
        run = (await client.get(f"/api/console/runs/{vulnerable.id}")).json()
        findings = (await client.get("/api/console/findings")).json()
        audit = (
            await client.get("/api/console/audit", params={"engine": "ZAP", "limit": 100})
        ).json()
        config = (await client.get("/api/console/config")).json()
    card = next(item for item in engines["items"] if item["engine"] == "ZAP")
    assert (
        card["enabled"] and card["authorized"] and card["reachable"] and card["state"] == "ENABLED"
    )
    provenance = card["provenance"]
    assert provenance["pinned_engine_version"] == "2.17.0"
    assert provenance["pinned_image_index_digest"] == MANIFEST.engine.image.index_digest
    assert (
        provenance["approved_rule_count"] == 1
        and provenance["manifest_digest"] == manifest_digest()
    )
    latest = provenance["latest_execution"]
    assert latest["scan_id"] == patched.id and latest["coverage_state"] == "COMPLETE"
    assert latest["passive_queue_drained"] is True and latest["observed_requests"] == 2
    assert provenance["responsibility"] == (
        "ZAP passively analyzes responses from controller-approved read-only API operations. "
        "ZAP alerts are independently correlated and verified by Aegis."
    )
    assert "ZAP" in engines["operational_engines"] and "ZAP" in config["operational_engines"]
    assert {i["engine"]: i["state"] for i in integrations["items"]}["ZAP"] == "CONNECTED"
    types = {c["artifact_type"] for c in run["evidence"]}
    assert types == {"ZAP_EXECUTION_CARD", "ZAP_ALERT_CARD", "VERIFIER_PROBE_CARD"}
    zap = run["run"]["zap"]
    assert zap["tool_reported_alerts"] == 1 and zap["verifier_confirmed"] == 1
    assert zap["correlated_alerts"] == 1 and zap["coverage_state"] == "COMPLETE"
    assert zap["expected_requests"] == zap["observed_requests"] == 2
    zap_findings = [f for f in findings["items"] if f["source_engine"] == "ZAP"]
    assert len(zap_findings) == 1 and zap_findings[0]["provenance"] == "VERIFIER"
    assert zap_findings[0]["status"] == "REMEDIATED" and zap_findings[0]["severity"] == "LOW"
    items = audit["items"]
    assert items and all(item["engine"] == "ZAP" for item in items)
    actors = {i["event_type"]: i["actor_type"] for i in items}
    assert actors["ZAP_PROJECTION_CREATED"] == "CONTROLLER"
    assert actors["ZAP_JOB_ADMITTED"] == "CONTROLLER"
    assert actors["ZAP_RUNNER_STARTED"] == "SYSTEM"
    assert actors["ZAP_OPENAPI_IMPORT_COMPLETED"] == "TOOL_RUNNER"
    assert actors["ZAP_PASSIVE_SCAN_DRAINED"] == "TOOL_RUNNER"
    assert actors["ZAP_ALERT_REPORTED"] == "TOOL_RUNNER"
    assert actors["ZAP_ALERT_CORRELATED"] == "CONTROLLER"
    assert actors["ZAP_VERIFICATION_COMPLETED"] == "VERIFIER"
    assert "AI_PLANNER" not in actors.values()
    stages = {i["stage"] for i in items}
    assert {"OPENAPI_PROJECTION", "PLAN_VALIDATION", "OPENAPI_IMPORT", "PASSIVE_SCAN"} <= stages


# --- 11. regressions ------------------------------------------------------------------------------


async def test_native_behaviour_unchanged_with_zap_enabled(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, fake, runner, _ = _zap_service(tmp_path, guard, monkeypatch)
    from test_agent_loop import make_service

    baseline = make_service(tmp_path / "native")
    scan_a = baseline.create()
    await baseline.run(scan_a.id)
    scan_b = service.create()
    await service.run(scan_b.id)
    a, b = baseline.store.get(scan_a.id), service.store.get(scan_b.id)
    assert a and b and b.status is ScanStatus.FAIL and b.engine == "AEGIS_NATIVE"
    assert _events(baseline, a.id) == _events(service, b.id)
    shape = lambda s: [(e.method, e.path, e.credential_profile, e.status_code) for e in s.evidence]  # noqa: E731
    assert shape(a) == shape(b) and a.terminal_reason == b.terminal_reason
    retest = service.create(ScanCreate(variant="patched", retest_of=b.id))
    await service.run(retest.id)
    fixed = service.store.get(retest.id)
    assert fixed and fixed.status is ScanStatus.PASS
    assert [e.status_code for e in fixed.evidence] == [200, 200, 403]
    assert runner.calls == {"attestation": 0, "run": 0} and fake.run_calls() == []
    assert not any(e.startswith("ZAP_") for e in _events(service, b.id))


async def test_nuclei_still_operational_alongside_zap(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    import test_phase_1_2 as nuclei_tests
    from nuclei_fakes import fake_binary_sha256, manifest_pinning

    import aegis.engine.nuclei as nuclei_controller

    monkeypatch.setattr(
        nuclei_controller, "load_manifest", lambda: manifest_pinning(fake_binary_sha256())
    )
    service, _, runner, _ = nuclei_tests._nuclei_service(tmp_path / "n", "match")
    service.settings.zap_enabled = True
    result = await nuclei_tests._run(service, variant="vulnerable")
    assert result.status is ScanStatus.FAIL and result.engine == "NUCLEI"
    assert runner.calls["run"] == 1


async def test_lab_openapi_surface_and_zap_routes() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=lab_app), base_url="http://lab"
    ) as client:
        schema = (await client.get("/openapi.json")).json()
        vulnerable = await client.get("/lab/zap/vulnerable/catalog/synthetic-catalog-1")
        patched = await client.get("/lab/zap/patched/catalog/synthetic-catalog-1")
        status = await client.get("/lab/zap/vulnerable/status")
        other = await client.get("/lab/zap/vulnerable/catalog/other")
    assert not any(path.startswith("/lab/") for path in schema["paths"])
    assert "x-content-type-options" not in vulnerable.headers
    assert patched.headers["x-content-type-options"] == "nosniff"
    assert status.headers["x-content-type-options"] == "nosniff"
    assert other.status_code == 404
    body_v, body_p = vulnerable.json(), patched.json()
    assert {k: v for k, v in body_v.items() if k != "variant"} == {
        k: v for k, v in body_p.items() if k != "variant"
    }


def test_no_active_scan_spider_script_mcp_or_oast_is_reachable() -> None:
    zap_caps = [c for c in (get_engine_capability(i) for i in (CAPABILITY,)) if c]
    assert all(c.activity is EngineActivity.PASSIVE for c in zap_caps)
    profile = get_engine_profile(PROFILE_ID)
    assert profile and profile.capability_ids == (CAPABILITY,)
    admitted = {a.id for a in MANIFEST.add_ons}
    assert not admitted & {
        "ascanrules",
        "spider",
        "spiderAjax",
        "scripts",
        "graaljs",
        "zest",
        "oast",
        "mcp",
        "llm",
        "client",
        "requester",
        "replacer",
        "fuzz",
    }
    plan_text = json.dumps(_plan())
    for token in ("activeScan", "spider", "script", "oast", "mcp", "llm", "requestor"):
        assert token not in plan_text
