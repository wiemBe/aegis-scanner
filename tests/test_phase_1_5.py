"""Phase 1.5 — Controlled ZAP active reflected-XSS integration: offline acceptance tests.

These prove, without network access, that the Phase 1.5 active profile is a SEPARATE, narrower
addition that never widens Phase 1.3: the active add-on set and the single admitted release rule
(40012) are digest-pinned and drift fails closed; the plan, argv and projection stay controller-
owned with exactly one GET operation and one bounded query parameter; the scope guard's ACTIVE mode
permits a query string only on that parameter, keeps the passive path byte-identical and remains the
only route to the target; the report parser reduces ZAP's ``attack`` payload to a class and a digest
and never propagates raw attack text or prose; a run requires a single-use, phrase-confirmed,
target-bound activation lease and an emergency stop can always kill it; and only the deterministic
Aegis XSS verifier — never ZAP — can CONFIRM a finding or grant a patched PASS.

The authority for real engine behaviour is the live 1+1 synthetic smoke against the pinned
``aegis-zap-active-runner:1.5.0`` image (one vulnerable + one patched execution), recorded in
``docs/phase-1.5-zap-active-reflected-xss.md``. It is deliberately NOT a 5/5 matrix.
"""

from __future__ import annotations

import copy
import hashlib
import http.client
import json
import re
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import ValidationError
from zap_active_fakes import (
    ADMISSION_TEST_SECRET,
    ActiveExecutorTransport,
    FakeActiveZap,
    InProcessAdmission,
    make_fake_active_install,
    ready_active_state,
    signed_lease_token,
    verify_countersign_offline,
)
from zap_fakes import REPO, CountingTransport, GuardHarness, LabServer

import aegis.engine.zap_active as controller
from aegis.engine.catalog import PROFILE_CATALOG, get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineActivity,
    EngineEnvironment,
    EngineErrorCode,
    EngineExecutionStatus,
    EngineReportedFinding,
    FindingLifecycleState,
    SecurityEngine,
    VerifierConclusion,
)
from aegis.engine.lifecycle import correlate_reported_finding, record_verifier_conclusion
from aegis.engine.policy import EnginePolicyRejection
from aegis.engine.zap_active import (
    ACTIVE_CAPABILITY_ID,
    ACTIVE_PROFILE_ID,
    ZapActiveAdapter,
    ZapActiveEngineJob,
    build_zap_active_job,
)
from aegis.safety import SafetyController, SafetyViolation
from aegis.settings import Settings
from aegis.zap_active_lease import (
    CONFIRMATION_PHRASE,
    ActiveLeaseBinding,
    ActiveScanActivationRequest,
    ActiveScanLeaseStore,
    LeaseError,
    new_budget_id,
)
from aegis.zap_active_test_env import (
    ADMITTED_RULE_IDS,
    HARD_REQUEST_CEILING,
    MAX_WALL_CLOCK_MS,
    TEST_ENV_PROFILE_ID,
    PreflightInputs,
    preflight,
    required_configuration,
)
from aegis.zap_active_verifier import (
    VERIFIER_VERSION,
    ZapXssProbeFacts,
    classify_reflection,
    collect,
    evaluate,
    fresh_marker,
    probe_plan,
)
from aegis_zap.contracts import GuardCounters
from aegis_zap.facts import AutomationFacts, ZapLogFacts
from aegis_zap.manifest import load_manifest as load_passive_manifest
from aegis_zap.projection import ProjectionErrorCode, ProjectionRejected
from aegis_zap_active.contracts import (
    ZapActiveAlertRecord,
    ZapActiveBudgets,
    ZapActiveErrorCode,
    ZapActiveRunRequest,
    ZapActiveRunResponse,
)
from aegis_zap_active.inventory import (
    LAB_ORIGIN,
    QUERY_PARAM,
    ZAP_ACTIVE_TARGETS,
    source_bytes,
    target_for_variant,
)
from aegis_zap_active.manifest import (
    MANIFEST_PATH,
    add_on_inventory_digest,
    load_manifest,
    manifest_digest,
)
from aegis_zap_active.parser import PARSER_VERSION, classify_attack, parse_report
from aegis_zap_active.profile import (
    FORBIDDEN_JOB_TYPES,
    JOB_SEQUENCE,
    PROFILE_ID,
    PROFILE_VERSION,
    assert_argv_safe,
    build_argv,
    build_plan,
    child_environment,
    plan_bytes,
    validate_plan,
)
from aegis_zap_active.projection import PROJECTION_VERSION, project, projection_ref
from lab_api.main import app as lab_app
from zap_active_runner.admission_client import AdmissionRejected
from zap_active_runner.execution import Executor, classify
from zap_guard.guard import ACTIVE_MAX_REQUESTS, GUARD_SCHEMA, GuardState
from zap_runner.guard_client import GuardClient

CAPABILITY = "zap_active_reflected_xss_v1"
MANIFEST = load_manifest()
RULE = MANIFEST.active_rules[0]
VULN = target_for_variant("vulnerable")
PATCHED = target_for_variant("patched")
VULN_PROJECTION = project(VULN)
PATCHED_PROJECTION = project(PATCHED)
ACTIVE_FILES = (
    "docker-compose.zap-active.yml",
    "deploy/zap-runner-active/Dockerfile",
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


def _fake(
    tmp_path: Path, guard: GuardHarness, mode: str = "normal", **options: Any
) -> FakeActiveZap:
    fake = make_fake_active_install(tmp_path / "install", guard)
    fake.set(mode, **options)
    return fake


def _admission(tmp_path: Path) -> InProcessAdmission:
    return InProcessAdmission(tmp_path / "admission" / "leases.json")


def _executor(
    tmp_path: Path,
    guard: GuardHarness,
    mode: str = "normal",
    *,
    cap: float | None = 90.0,
    admission: InProcessAdmission | None = None,
    **options: Any,
) -> tuple[FakeActiveZap, Executor]:
    # Boot attestation always runs against a well-behaved install; the scenario mode is applied
    # afterwards so that misbehaviour during the scan is what the test observes.
    fake = _fake(tmp_path, guard)
    state = ready_active_state(fake, guard)
    assert state.ready, state.failure_codes
    fake.set(mode, **options)
    executor = Executor(
        state, wall_clock_cap_seconds=cap, admission=admission or _admission(tmp_path)
    )
    return fake, executor


def _armed_token(executor: Executor, target_ref: str = VULN.target_ref, **overrides: Any) -> str:
    """Mint a signed lease for ``target_ref`` and arm it in the executor's admission registry."""

    target = ZAP_ACTIVE_TARGETS[target_ref]
    try:
        projection = project(target)
    except ProjectionRejected:
        projection = VULN_PROJECTION
    token, _ = signed_lease_token(target=target, projection=projection, **overrides)
    assert executor.admission is not None
    armed = executor.admission.arm(token)
    assert not isinstance(armed, AdmissionRejected), armed
    return token


def _request(target_ref: str = VULN.target_ref, **overrides: Any) -> ZapActiveRunRequest:
    try:
        projection = project(ZAP_ACTIVE_TARGETS[target_ref])
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
        "capability_id": CAPABILITY,
        "projection_ref": projection_ref(target_ref),
        "projection_digest": projection.digest,
        "operation_allowlist_digest": projection.allowlist_digest,
        "query_param": projection.query_param,
        "budgets": {
            "max_requests": 32,
            "time_budget_ms": 60_000,
            "max_report_bytes": 131_072,
            "max_alerts": 8,
            "delay_ms": 0,
        },
        "lease_token": overrides.pop("lease_token", None) or _unarmed_token(target_ref),
        "nonce": "0" * 30 + suffix,
        "correlation_id": "corr-00000000000000" + suffix,
    }
    payload.update(overrides)
    return ZapActiveRunRequest.model_validate(payload)


def _job(**overrides: Any) -> ZapActiveEngineJob:
    options: dict[str, Any] = {
        "profile_id": ACTIVE_PROFILE_ID,
        "capability_id": CAPABILITY,
        "run_id": "scan-0000000000aa",
        "environment": EngineEnvironment.SYNTHETIC_LAB,
        "target_ref": VULN.target_ref,
        "allowed_origins": [LAB_ORIGIN],
        "adapter_enabled": True,
    }
    options.update(overrides)
    job, _ = build_zap_active_job(**options)
    return job


def _unarmed_token(target_ref: str = VULN.target_ref) -> str:
    """A syntactically valid, correctly signed token that nothing has armed.

    Requests that override the target reference to an unknown or malformed value are rejected by
    policy before any lease is read, so the placeholder token may describe the known vulnerable
    target in those cases."""

    target = ZAP_ACTIVE_TARGETS.get(target_ref, VULN)
    try:
        projection = project(target)
    except ProjectionRejected:
        projection = VULN_PROJECTION
    token, _ = signed_lease_token(target=target, projection=projection)
    return token


def _binding(job: ZapActiveEngineJob) -> ActiveLeaseBinding:
    return ActiveLeaseBinding(
        projection_digest=job.projection_digest,
        allowlist_digest=job.allowlist_digest,
        manifest_digest=job.manifest_digest,
        budget_id=new_budget_id(),
    )


def _dummy_binding() -> ActiveLeaseBinding:
    """A well-formed binding for lease-store unit tests that never touch a runner.

    The digests are the real pinned ones (the real manifest and the real vulnerable projection),
    which is what the controller would bind a real lease to."""

    return ActiveLeaseBinding(
        projection_digest=VULN_PROJECTION.digest,
        allowlist_digest=VULN_PROJECTION.allowlist_digest,
        manifest_digest=manifest_digest(),
        budget_id=new_budget_id(),
    )


def _lease_store(job: ZapActiveEngineJob | None = None) -> ActiveScanLeaseStore:
    job = job or _job()
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    store.issue(_activation(target_ref=job.target_ref), binding=_binding(job))
    return store


def _activation(**overrides: Any) -> ActiveScanActivationRequest:
    payload: dict[str, Any] = {
        "target_ref": VULN.target_ref,
        "origin": LAB_ORIGIN,
        "classification": "SYNTHETIC_LAB",
        "profile_id": ACTIVE_PROFILE_ID,
        "capability_id": CAPABILITY,
        "allowed_methods": ("GET", "HEAD"),
        "allowed_path": VULN.search_path,
        "query_param": QUERY_PARAM,
        "max_requests": 200,
        "rate_per_second": 4.0,
        "confirmation_phrase": CONFIRMATION_PHRASE,
    }
    payload.update(overrides)
    return ActiveScanActivationRequest.model_validate(payload)


def _instance(**overrides: Any) -> dict[str, Any]:
    uri = f"{LAB_ORIGIN}{VULN_PROJECTION.path}?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    instance: dict[str, Any] = {
        "id": "0",
        "uri": uri,
        "nodeName": uri.split("?")[0],
        "method": "GET",
        "param": "q",
        "attack": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>",
        "otherinfo": "<p>Raw reflection.</p>",
    }
    instance.update(overrides)
    return instance


def _alert(**overrides: Any) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "pluginid": "40012",
        "alertRef": "40012",
        "alert": RULE.name,
        "name": RULE.name,
        "riskcode": "3",
        "confidence": "2",
        "riskdesc": "High (Medium)",
        "desc": "<p>Cross-site scripting <script>alert(1)</script> was found.</p>",
        "instances": [_instance()],
        "count": "1",
        "systemic": False,
        "solution": "<p>Encode output.</p>",
        "otherinfo": "<p>...</p>",
        "reference": "<p>https://owasp.org</p>",
        "cweid": "79",
        "wascid": "8",
        "sourceid": "1",
    }
    alert.update(overrides)
    return alert


def _report(alerts: list[dict[str, Any]] | None = None, **top: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "@generated": "Sun, 20 Sept 2026 12:00:00",
        "created": "2026-09-20T12:00:00Z",
        "site": [
            {
                "@name": LAB_ORIGIN,
                "@host": "lab-api",
                "@port": "8001",
                "@ssl": "false",
                "alerts": alerts if alerts is not None else [_alert()],
            }
        ],
    }
    report.update(top)
    return report


def _parse(report: dict[str, Any] | bytes | None, **overrides: Any) -> Any:
    data = report if isinstance(report, bytes) or report is None else json.dumps(report).encode()
    options: dict[str, Any] = {
        "engine_version": "2.17.0",
        "projection": VULN_PROJECTION,
        "rule": RULE,
        "max_report_bytes": 131_072,
        "max_alerts": 8,
    }
    options.update(overrides)
    return parse_report(data, **options)


# --- 1. the frozen active supply chain ---------------------------------------------------------


def test_active_manifest_pins_the_image_eleven_add_ons_and_one_release_rule() -> None:
    engine = MANIFEST.engine
    passive = load_passive_manifest()
    # The base image, jar and JVM are byte-identical to Phase 1.3: only the add-on set differs.
    assert engine.version == "2.17.0"
    assert engine.image.index_digest == (
        "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
    )
    assert engine.image.index_digest == passive.engine.image.index_digest
    assert engine.jar.sha256 == passive.engine.jar.sha256
    assert engine.java.runtime_version == passive.engine.java.runtime_version
    active_set = {(a.id, a.version) for a in MANIFEST.add_ons}
    passive_set = {(a.id, a.version) for a in passive.add_ons}
    assert passive_set < active_set  # a strict superset: the eight passive add-ons are unchanged
    assert active_set - passive_set == {
        ("ascanrules", "83.0.0"),
        ("oast", "0.24.0"),
        ("database", "0.9.0"),
    }
    assert len(MANIFEST.add_ons) == 11
    files = {a.id: a.file for a in MANIFEST.add_ons}
    assert files["ascanrules"] == "ascanrules-release-83.zap"
    assert files["oast"] == "oast-beta-0.24.0.zap"
    assert files["database"] == "database-alpha-0.9.0.zap"
    # oast/database exist only as the admitted rule's forced dependency chain, declared as such.
    assert set(MANIFEST.neutralised_dependency_ids) == {"oast", "database"}
    assert MANIFEST.add_on("ascanrules") is not None
    assert manifest_digest() == manifest_digest(MANIFEST_PATH)
    assert (
        manifest_digest() != {a.id for a in passive.add_ons}
        and manifest_digest(MANIFEST_PATH) == hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    )


def test_exactly_one_admitted_active_rule_is_reflected_xss_40012() -> None:
    assert len(MANIFEST.active_rules) == 1
    assert (RULE.plugin_id, RULE.quality, RULE.threshold, RULE.strength) == (
        40012,
        "release",
        "MEDIUM",
        "LOW",
    )
    assert RULE.name == "Cross Site Scripting (Reflected)"
    assert RULE.add_on_id == "ascanrules" and RULE.add_on_version == "83.0.0"
    assert RULE.implementation.endswith("CrossSiteScriptingScanRule")
    assert RULE.cwe_id == 79 and RULE.expected_param == QUERY_PARAM
    assert RULE.capability_id == CAPABILITY
    assert RULE.verification_policy == "DETERMINISTIC_AEGIS_VERIFIER"
    assert RULE.verifier == VERIFIER_VERSION
    assert RULE.attack_field_policy == (
        "REDACTED_CLASSIFICATION_AND_DIGEST_ONLY_NEVER_RAW_ATTACK_TEXT"
    )
    assert RULE.risk_confidence_policy.startswith("UNTRUSTED_TOOL_METADATA")
    # An AI-assisted admission review that is NOT operator-countersigned must say so.
    assert RULE.review.operator_countersigned is False
    assert MANIFEST.rules_for_capability(CAPABILITY) == (RULE,)
    assert MANIFEST.rules_for_capability("zap_active_scan_v0") == ()


@pytest.mark.parametrize(
    "add_on_id",
    [
        "spider",
        "spiderAjax",
        "scripts",
        "graaljs",
        "zest",
        "fuzz",
        "replacer",
        "requester",
        "sequence",
        "graphql",
        "soap",
        "postman",
        "mcp",
        "llm",
        "client",
        "ascanrulesAlpha",
        "ascanrulesBeta",
        "domxss",
        "retire",
        "selenium",
        "websocket",
    ],
)
def test_expansion_add_ons_remain_forbidden_in_the_active_image(add_on_id: str) -> None:
    assert add_on_id in MANIFEST.forbidden_add_on_ids
    assert MANIFEST.add_on(add_on_id) is None


def test_active_manifest_rejects_a_second_or_non_release_rule() -> None:
    from aegis_zap_active.manifest import parse_manifest

    raw = json.loads(MANIFEST_PATH.read_bytes())
    assert parse_manifest(MANIFEST_PATH.read_bytes()).profile_id == PROFILE_ID
    duplicate = copy.deepcopy(raw)
    duplicate["active_rules"] = [raw["active_rules"][0], copy.deepcopy(raw["active_rules"][0])]
    with pytest.raises(ValidationError):  # the same rule twice
        parse_manifest(json.dumps(duplicate).encode())
    unpinned = copy.deepcopy(raw)
    unpinned["active_rules"][0]["add_on_id"] = "pscanrules"
    with pytest.raises(ValidationError):  # a rule must reference its own pinned add-on version
        parse_manifest(json.dumps(unpinned).encode())
    drifted = copy.deepcopy(raw)
    drifted["active_rules"][0]["add_on_version"] = "84.0.0"
    with pytest.raises(ValidationError):
        parse_manifest(json.dumps(drifted).encode())
    beta = copy.deepcopy(raw)
    beta["active_rules"][0]["quality"] = "beta"
    with pytest.raises(ValidationError):  # only release-quality rules may be admitted
        parse_manifest(json.dumps(beta).encode())
    conflicted = copy.deepcopy(raw)
    conflicted["forbidden_add_on_ids"] = [*raw["forbidden_add_on_ids"], "ascanrules"]
    with pytest.raises(ValidationError):
        parse_manifest(json.dumps(conflicted).encode())
    unaccounted = copy.deepcopy(raw)
    unaccounted["neutralised_dependency_ids"] = ["oast", "database", "spider"]
    with pytest.raises(ValidationError):
        parse_manifest(json.dumps(unaccounted).encode())


def test_active_image_and_compose_are_digest_pinned_and_fail_closed() -> None:
    dockerfile = (REPO / "deploy/zap-runner-active/Dockerfile").read_text()
    assert f"zaproxy/zap-stable@{MANIFEST.engine.image.index_digest}" in dockerfile
    assert ":latest" not in dockerfile and "zap-weekly" not in dockerfile
    # The build verifies every pin and prunes the plugin directory to exactly the manifest set.
    assert "--require-hashes" in dockerfile and "addoninstall" not in dockerfile
    assert 'assert sorted(os.listdir("/zap/plugin")) == sorted(keep)' in dockerfile
    assert "ascanrules-release-78" not in dockerfile.replace(
        "ascanrules-release-78 and every other add-on", ""
    )
    # No shell survives in the active runner image.
    removed = dockerfile.split("rm -f", 1)[1]
    for shell in ("/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash"):
        assert shell in removed, shell
    assert "USER 10002:10002" in dockerfile
    assert 'ENTRYPOINT ["python3", "-m", "zap_active_runner"]' in dockerfile
    compose = yaml.safe_load((REPO / "docker-compose.zap-active.yml").read_text())
    services, networks = compose["services"], compose["networks"]
    runner, guard_service = services["zap-active-runner"], services["zap-active-scope-guard"]
    admission = services["zap-active-admission"]
    # The runner is NOT on the target network: it has no route around the guard. It reaches the
    # lease admission component and nothing else beyond the guard.
    assert runner["networks"] == ["active-rpc", "active-egress", "active-admission"]
    assert guard_service["networks"] == ["active-egress", "active-target"]
    # The admission component is reachable ONLY from the runner container, and has no route to the
    # target, the guard, the control plane or the internet.
    assert admission["networks"] == ["active-admission"]
    assert "active-target" in services["lab-api"]["networks"]
    assert "active-egress" not in services["control-plane"]["networks"]
    assert "active-target" not in services["control-plane"]["networks"]
    assert "active-admission" not in services["control-plane"]["networks"]
    for name in ("active-rpc", "active-egress", "active-target", "active-admission"):
        assert networks[name]["internal"] is True
    for service in (runner, guard_service, admission):
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert "ports" not in service
        assert service["pids_limit"] and service["mem_limit"] and service["cpus"]
    # Admission state must survive a container restart; the named root-owned volume is not a
    # host mount and is deliberately unavailable to the runner/ZAP container.
    assert admission["volumes"] == ["admission-state:/admission"]
    assert "volumes" not in runner and "volumes" not in guard_service
    # Guard control has a separate credential. It is absent from ZAP's child environment and the
    # lease signing key remains absent from both guard and runner.
    assert set(guard_service["environment"]) == {"AEGIS_ZAP_GUARD_CONTROL_SECRET"}
    assert set(runner["environment"]) == {
        "AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT",
        "AEGIS_ZAP_ACTIVE_ADMISSION_URL",
        "AEGIS_ZAP_ACTIVE_RUNNER_CLIENT",
        "AEGIS_ZAP_GUARD_CONTROL_SECRET",
    }
    assert int(guard_service["user"].split(":")[0]) >= 10000
    assert int(runner["user"].split(":")[0]) >= 10000
    # The admission component is deliberately root so its registry can be root-owned; every other
    # privilege is dropped and its only writable path is the root-owned named admission volume.
    assert admission["user"] == "0:0"
    assert runner["image"] == "aegis-zap-active-runner:1.5.0"
    assert admission["image"] == "aegis-zap-active-admission:1.5.0"
    # The Phase 1.3 passive image stays on its own tag and its own networks.
    assert guard_service["image"] == "aegis-zap-scope-guard:1.5.0"
    passive = yaml.safe_load((REPO / "docker-compose.zap.yml").read_text())
    assert passive["services"]["zap-runner"]["image"] != runner["image"]
    assert not set(runner["networks"]) & set(passive["services"]["zap-runner"]["networks"])
    assert not set(runner["networks"]) & {"security-lab", "planner-rpc", "model-egress"}


def test_phase_1_3_passive_profile_and_image_are_untouched() -> None:
    passive = load_passive_manifest()
    assert passive.profile_id == "ZAP_LAB_PASSIVE_OPENAPI_V1"
    assert len(passive.add_ons) == 8
    assert "ascanrules" in passive.forbidden_add_on_ids
    assert [r.plugin_id for r in passive.passive_rules] == [10021]
    from aegis_zap.manifest import MANIFEST_PATH as PASSIVE_PATH
    from aegis_zap.manifest import manifest_digest as passive_digest

    assert passive_digest(PASSIVE_PATH) == (
        "94933d15c53dea51591573b4959f4f4655fbc54586b43a5da03427a78dcf2ba3"
    )
    from aegis_zap.profile import PROFILE_ID as PASSIVE_PROFILE

    assert PASSIVE_PROFILE == "ZAP_LAB_PASSIVE_OPENAPI_V1" and PASSIVE_PROFILE != PROFILE_ID


# --- 2. the active OpenAPI projection ----------------------------------------------------------


def test_active_projection_is_one_get_operation_with_one_bounded_query_parameter() -> None:
    projection = VULN_PROJECTION
    document = json.loads(projection.document)
    assert projection.method == "GET" and projection.operation_count == 1
    assert projection.path == "/lab/zap-active/vulnerable/search"
    assert projection.query_param == QUERY_PARAM and projection.query_params == ("q",)
    assert document["servers"] == [{"url": LAB_ORIGIN}]  # never the source's own servers block
    assert list(document["paths"]) == [projection.path]
    operation = document["paths"][projection.path]["get"]
    assert list(document["paths"][projection.path]) == ["get"]
    assert [p["name"] for p in operation["parameters"]] == ["q"]
    assert operation["parameters"][0]["in"] == "query"
    assert operation["parameters"][0]["schema"] == {"type": "string", "maxLength": 32}
    assert operation["parameters"][0]["example"] == "aegis-probe"
    assert list(operation["responses"]) == ["200"]
    # The state-changing operation in the same source document is projected away.
    assert projection.removed_operations == 2 and projection.redaction_status == "REDACTED"
    assert "admin" not in projection.document.decode()
    assert projection.digest == hashlib.sha256(projection.document).hexdigest()
    assert project(VULN).document == projection.document  # deterministic, byte-for-byte
    assert projection_ref(VULN.target_ref) == f"{VULN.target_ref}/{PROJECTION_VERSION}"
    assert PATCHED_PROJECTION.digest != projection.digest
    assert PATCHED_PROJECTION.allowlist_digest != projection.allowlist_digest


@pytest.mark.parametrize(
    ("target_ref", "code"),
    [
        (
            "synthetic-zap-active-negative-state-changing",
            ProjectionErrorCode.STATE_CHANGING_OPERATION,
        ),
        ("synthetic-zap-active-negative-alternate-server", ProjectionErrorCode.ALTERNATE_SERVER),
        ("synthetic-zap-active-negative-external-ref", ProjectionErrorCode.EXTERNAL_REFERENCE),
    ],
)
def test_active_inventory_negative_controls_are_refused(
    target_ref: str, code: ProjectionErrorCode
) -> None:
    target = ZAP_ACTIVE_TARGETS[target_ref]
    assert target.purpose == "NEGATIVE_CONTROL"
    with pytest.raises(ProjectionRejected) as rejected:
        project(target)
    assert rejected.value.code is code


def _mutate(path: tuple[Any, ...], value: Any) -> bytes:
    document = json.loads(source_bytes(VULN))
    node = document
    for key in path[:-1]:
        node = node[key]
    if value is None:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda: _mutate(("openapi",), "2.0"), ProjectionErrorCode.UNSUPPORTED_VERSION),
        (lambda: _mutate(("webhooks",), {"x": {}}), ProjectionErrorCode.WEBHOOKS_PRESENT),
        (
            lambda: _mutate(("servers",), [{"url": "http://evil.example:8001"}]),
            ProjectionErrorCode.ALTERNATE_SERVER,
        ),
        (
            lambda: _mutate(
                ("paths", "/lab/zap-active/vulnerable/search", "get", "parameters"),
                [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "debug", "in": "query", "schema": {"type": "string"}},
                ],
            ),
            ProjectionErrorCode.UNAPPROVED_PARAMETER,
        ),
        (
            lambda: _mutate(
                ("paths", "/lab/zap-active/vulnerable/search", "get", "parameters"),
                [{"name": "x-key", "in": "header", "schema": {"type": "string"}}],
            ),
            ProjectionErrorCode.UNAPPROVED_PARAMETER,
        ),
        (
            lambda: _mutate(
                ("paths", "/lab/zap-active/vulnerable/search"),
                {"$ref": "#/components/pathItems/x"},
            ),
            ProjectionErrorCode.PATH_ITEM_REFERENCE,
        ),
        (lambda: b"{ not json", ProjectionErrorCode.SOURCE_MALFORMED),
        (
            lambda: json.dumps({**json.loads(source_bytes(VULN)), "paths": {}}).encode(),
            ProjectionErrorCode.SOURCE_MALFORMED,
        ),
    ],
)
def test_active_projection_rejects_hostile_sources(mutator: Any, code: ProjectionErrorCode) -> None:
    with pytest.raises(ProjectionRejected) as rejected:
        project(VULN, mutator())
    assert rejected.value.code is code


def test_active_projection_rejects_duplicate_keys_and_oversized_documents() -> None:
    duplicated = b'{"openapi": "3.0.3", "openapi": "3.0.3", "paths": {}}'
    with pytest.raises(ProjectionRejected) as rejected:
        project(VULN, duplicated)
    assert rejected.value.code is ProjectionErrorCode.SOURCE_MALFORMED
    with pytest.raises(ProjectionRejected) as oversized:
        project(VULN, b"x" * 2_000_000)
    assert oversized.value.code is ProjectionErrorCode.SOURCE_OVERSIZED


# --- 3. the fixed active Automation Framework plan ---------------------------------------------


def _plan(**overrides: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "projection": VULN_PROJECTION,
        "rule": RULE,
        "api_file": Path("/work/projection.json"),
        "report_dir": Path("/work/out"),
    }
    options.update(overrides)
    return build_plan(**options)


def test_plan_is_the_fixed_active_sequence_with_only_rule_40012_enabled() -> None:
    plan = _plan()
    assert JOB_SEQUENCE == (
        "passiveScan-config",
        "openapi",
        "passiveScan-wait",
        "activeScan",
        "passiveScan-wait",
        "report",
    )
    assert tuple(job["type"] for job in plan["jobs"]) == JOB_SEQUENCE
    assert plan["env"]["contexts"][0]["urls"] == [VULN_PROJECTION.url]
    assert plan["env"]["parameters"]["failOnError"] is True
    active = next(j for j in plan["jobs"] if j["type"] == "activeScan")
    policy = active["policyDefinition"]
    # Everything is thresholded OFF by default; exactly the admitted rule is re-enabled.
    assert policy["defaultThreshold"] == "off"
    assert policy["defaultStrength"] == "medium"
    assert [r["id"] for r in policy["rules"]] == [40012]
    assert policy["rules"][0]["strength"] == "low"
    assert policy["rules"][0]["threshold"] == "medium"
    assert active["parameters"]["threadPerHost"] == 1
    assert active["parameters"]["addQueryParam"] is False
    assert active["parameters"]["scanHeadersAllRequests"] is False
    assert active["parameters"]["handleAntiCSRFTokens"] is False
    assert active["parameters"]["policy"] == ""
    openapi = next(j for j in plan["jobs"] if j["type"] == "openapi")
    assert set(openapi["parameters"]) == {"apiFile", "targetUrl", "context"}
    assert "apiUrl" not in json.dumps(plan)  # a remote OpenAPI source is never expressible
    report = next(j for j in plan["jobs"] if j["type"] == "report")
    assert report["parameters"]["template"] == "traditional-json"
    assert report["parameters"]["displayReport"] is False
    assert validate_plan(plan, plan, rule=RULE) == []
    assert plan_bytes(plan) == plan_bytes(_plan())  # deterministic


@pytest.mark.parametrize(
    "job_type",
    [
        "spider",
        "spiderAjax",
        "script",
        "requestor",
        "replacer",
        "graphql",
        "soap",
        "postman",
        "addOns",
        "sequence-activeScan",
        "activeScan-config",
        "activeScan-policy",
        "oast",
        "llm",
        "mcp",
        "import",
        "alertFilter",
    ],
)
def test_injected_jobs_are_rejected_by_the_active_profile(job_type: str) -> None:
    assert job_type in FORBIDDEN_JOB_TYPES
    plan = _plan()
    tampered = copy.deepcopy(plan)
    tampered["jobs"].insert(1, {"type": job_type, "parameters": {}})
    violations = validate_plan(tampered, plan, rule=RULE)
    assert f"FORBIDDEN_JOB:{job_type}" in violations


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda p: p["jobs"][3]["policyDefinition"]["rules"].append(
                {"id": 40018, "name": "SQL Injection", "strength": "low", "threshold": "medium"}
            ),
            "ACTIVESCAN_RULE_SET",
        ),
        (
            lambda p: p["jobs"][3]["policyDefinition"]["rules"][0].__setitem__("id", 40018),
            "ACTIVESCAN_UNADMITTED_RULE",
        ),
        (
            lambda p: p["jobs"][3]["policyDefinition"]["rules"][0].__setitem__(
                "strength", "insane"
            ),
            "ACTIVESCAN_STRENGTH_OR_THRESHOLD",
        ),
        (
            lambda p: p["jobs"][3]["policyDefinition"]["rules"][0].__setitem__("threshold", "low"),
            "ACTIVESCAN_STRENGTH_OR_THRESHOLD",
        ),
        (
            lambda p: p["jobs"][3]["policyDefinition"].__setitem__("defaultThreshold", "medium"),
            "ACTIVESCAN_DEFAULT_NOT_OFF",
        ),
        (
            lambda p: p["jobs"][3]["policyDefinition"].__setitem__("defaultStrength", "insane"),
            "ACTIVESCAN_DEFAULT_NOT_OFF",
        ),
        (
            lambda p: p["jobs"][3]["parameters"].__setitem__("threadPerHost", 8),
            "ACTIVESCAN_PARAMETERS",
        ),
        (
            lambda p: p["jobs"][3]["parameters"].__setitem__("addQueryParam", True),
            "ACTIVESCAN_PARAMETERS",
        ),
        (
            lambda p: p["jobs"][3]["parameters"].__setitem__("scanHeadersAllRequests", True),
            "ACTIVESCAN_PARAMETERS",
        ),
        (
            lambda p: p["jobs"][3]["parameters"].__setitem__("policy", "Default Policy"),
            "ACTIVESCAN_PARAMETERS",
        ),
        (
            lambda p: p["jobs"][1]["parameters"].__setitem__(
                "apiUrl", "http://evil.example/o.json"
            ),
            "FORBIDDEN_KEY:apiUrl",
        ),
        (
            lambda p: p["jobs"][5]["parameters"].__setitem__("template", "traditional-html"),
            "REPORT_TEMPLATE",
        ),
        (lambda p: p["jobs"].pop(3), "JOB_SEQUENCE"),
        (
            lambda p: p["env"]["contexts"][0].__setitem__("urls", ["http://evil.example:8001/x"]),
            "PLAN_MISMATCH",
        ),
    ],
)
def test_tampered_active_plans_are_rejected(mutate: Any, code: str) -> None:
    expected = _plan()
    tampered = copy.deepcopy(expected)
    mutate(tampered)
    violations = validate_plan(tampered, expected, rule=RULE)
    assert code in violations, violations


def test_plan_shape_and_unknown_jobs_fail_closed() -> None:
    expected = _plan()
    assert validate_plan({"jobs": []}, expected, rule=RULE) == ["PLAN_SHAPE"]
    assert validate_plan("not a plan", expected, rule=RULE) == ["PLAN_SHAPE"]
    tampered = copy.deepcopy(expected)
    tampered["jobs"].append({"type": "somethingNew", "parameters": {}})
    assert "UNKNOWN_JOB:somethingNew" in validate_plan(tampered, expected, rule=RULE)


def test_active_argv_is_the_fixed_passive_argv_and_stays_safe(tmp_path: Path) -> None:
    argv = build_argv(
        java=tmp_path / "java",
        jar=tmp_path / "zap.jar",
        zap_home=tmp_path / "home",
        tmp_dir=tmp_path / "tmp",
        plan_file=tmp_path / "plan.yaml",
        guard_host="zap-active-scope-guard",
        guard_port=3128,
    )
    assert argv[-2:] == ["-autorun", str(tmp_path / "plan.yaml")]
    assert "-cmd" in argv and "-silent" in argv and "-notel" in argv
    for forbidden in ("-daemon", "-port", "-host", "-addoninstall", "-addonupdate", "-script"):
        assert forbidden not in argv
    assert "network.connection.httpProxy.host=zap-active-scope-guard" in argv
    assert_argv_safe(argv)
    with pytest.raises(ValueError):
        build_argv(
            java=tmp_path / "java",
            jar=tmp_path / "zap.jar",
            zap_home=tmp_path / "home",
            tmp_dir=tmp_path / "tmp",
            plan_file=tmp_path / "plan.yaml",
            guard_host="evil host; rm -rf /",
            guard_port=3128,
        )


def test_child_environment_is_constructed_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_AUTH_TOKEN", "secret-token-value")
    monkeypatch.setenv("HTTP_PROXY", "http://evil.example:3128")
    environment = child_environment(Path("/work/home"))
    assert set(environment) == {"PATH", "LANG", "LC_ALL", "HOME"}
    assert "secret-token-value" not in json.dumps(environment)


# --- 4. the strict active RPC contract ----------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "plan",
        "jobs",
        "argv",
        "command",
        "url",
        "apiUrl",
        "payload",
        "payloads",
        "rules",
        "strength",
        "headers",
        "script",
    ],
)
def test_active_rpc_request_forbids_arbitrary_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        ZapActiveRunRequest.model_validate({**_request().model_dump(), field: "x"})


def test_active_budgets_are_hard_capped() -> None:
    assert ZapActiveBudgets(
        max_requests=512,
        time_budget_ms=660_000,
        max_report_bytes=262_144,
        max_alerts=16,
        delay_ms=5_000,
    )
    for override in (
        {"max_requests": 513},
        {"max_requests": 0},
        {"time_budget_ms": 660_001},
        {"time_budget_ms": 1_000},
        {"max_report_bytes": 262_145},
        {"max_alerts": 17},
        {"delay_ms": 5_001},
    ):
        with pytest.raises(ValidationError):
            ZapActiveBudgets.model_validate(
                {
                    "max_requests": 32,
                    "time_budget_ms": 60_000,
                    "max_report_bytes": 131_072,
                    "max_alerts": 8,
                    "delay_ms": 0,
                    **override,
                }
            )


def test_alert_record_cannot_carry_a_raw_attack_or_evidence_string() -> None:
    fields = set(ZapActiveAlertRecord.model_fields)
    assert "attack" not in fields and "evidence" not in fields
    assert {"attack_class", "attack_sha256", "attack_length"} <= fields
    assert {"evidence_sha256", "evidence_length"} <= fields
    with pytest.raises(ValidationError):
        ZapActiveAlertRecord.model_validate(
            {
                "plugin_id": 40012,
                "rule_name": RULE.name,
                "method": "GET",
                "path": VULN_PROJECTION.path,
                "param": "q",
                "claimed_risk": "high",
                "claimed_confidence": "medium",
                "evidence_sha256": "a" * 64,
                "evidence_length": 1,
                "attack": "<script>alert(1)</script>",
                "attack_class": "SCRIPT_ELEMENT",
                "attack_sha256": "b" * 64,
                "attack_length": 25,
                "record_digest": "c" * 64,
            }
        )


def test_run_request_rejects_a_state_changing_or_unbounded_reference() -> None:
    for override in (
        {"target_ref": "SYNTHETIC-ZAP-ACTIVE-VULNERABLE"},
        {"query_param": "Q"},
        {"query_param": "*"},
        {"projection_digest": "z" * 64},
        {"lease_token": "short"},
        {"profile_id": "zap lab active"},
    ):
        with pytest.raises(ValidationError):
            _request(**override)


# --- 5. the scope guard's ACTIVE mode ------------------------------------------------------------


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


ACTIVE_ARM_LEASE_ID = "lease-0123456789abcdef"


def _active_arm_payload(
    path: str = "/lab/zap-active/vulnerable/search",
    *,
    max_requests: int = 4,
    params: list[str] | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": GUARD_SCHEMA,
        "execution_id": "exec-0000000000ab",
        "origin": LAB_ORIGIN,
        "allowlist": [{"method": "GET", "path": path}],
        "max_requests": max_requests,
        "ttl_ms": 60_000,
        "mode": "ACTIVE",
        "allowed_query_params": params if params is not None else ["q"],
        # Phase 1.5 lease binding: the guard records the consumed lease and stops at its expiry.
        "lease_id": ACTIVE_ARM_LEASE_ID,
        "lease_expires_at": int(datetime.now(UTC).timestamp()) + 600,
        "projection_digest": VULN_PROJECTION.digest,
        "allowlist_digest": VULN_PROJECTION.allowlist_digest,
    }
    payload.update(overrides)
    return payload


def _arm_active(
    guard: GuardHarness,
    path: str = "/lab/zap-active/vulnerable/search",
    *,
    max_requests: int = 4,
    params: list[str] | None = None,
) -> str:
    status, body = guard.state.arm(
        _active_arm_payload(path, max_requests=max_requests, params=params)
    )
    assert status == 200, body
    # The guard echoes the binding so the runner can confirm both sides agree.
    assert body["lease_id"] == ACTIVE_ARM_LEASE_ID
    assert body["projection_digest"] == VULN_PROJECTION.digest
    assert body["allowlist_digest"] == VULN_PROJECTION.allowlist_digest
    assert body["max_requests"] == max_requests
    return str(body["token"])


def _arm_passive(guard: GuardHarness, path: str) -> str:
    status, body = guard.state.arm(
        {
            "schema_version": GUARD_SCHEMA,
            "execution_id": "exec-0000000000ac",
            "origin": LAB_ORIGIN,
            "allowlist": [{"method": "GET", "path": path}],
            "max_requests": 1,
            "ttl_ms": 30_000,
        }
    )
    assert status == 200, body
    return str(body["token"])


def test_passive_guard_mode_is_byte_for_byte_preserved(guard: GuardHarness, lab: LabServer) -> None:
    path = "/lab/zap/vulnerable/status"
    token = _arm_passive(guard, path)
    assert guard.state.mode == "PASSIVE" and guard.state.allowed_params == frozenset()
    # A query string is still refused outright on the passive path.
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?q=1") == 403
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}") == 200
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}") == 403  # budget is still exactly one
    assert lab.paths == [path]
    _, body = guard.state.counters({"token": token}, disarm=True)
    reasons = dict(body["counters"]["blocked_reasons"])
    assert reasons["MALFORMED_TARGET"] == 1 and reasons["BUDGET"] == 1


def test_active_mode_allows_a_query_only_on_the_projected_parameter(
    guard: GuardHarness, lab: LabServer
) -> None:
    path = VULN_PROJECTION.path
    token = _arm_active(guard, path, max_requests=3)
    assert guard.state.mode == "ACTIVE" and guard.state.allowed_params == frozenset({"q"})
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?q=%3Cscript%3E") == 200
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}") == 200  # no query is still fine
    # Every escape is refused before a byte reaches the target.
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?q=1&debug=1") == 403
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?debug=1") == 403
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}/lab/zap-active/patched/search?q=1") == 403
    assert _proxy(guard, "GET", f"http://evil.example:8001{path}?q=1") == 403
    assert _proxy(guard, "GET", f"https://lab-api:8001{path}?q=1") == 403
    assert _proxy(guard, "POST", f"{LAB_ORIGIN}{path}?q=1") == 403
    assert _proxy(guard, "CONNECT", "lab-api:8001") == 403
    assert _proxy(guard, "GET", f"http://user:pw@lab-api:8001{path}?q=1") == 403
    assert lab.paths == [path, path]
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?q=3") == 200
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{path}?q=4") == 403  # budget exhausted
    _, body = guard.state.counters({"token": token}, disarm=True)
    counters = body["counters"]
    reasons = dict(counters["blocked_reasons"])
    assert counters["forwarded"] == 3 and counters["budget_exceeded"] is True
    assert reasons["PARAM"] == 2 and reasons["PATH"] == 1 and reasons["BUDGET"] == 1
    assert reasons["ORIGIN"] >= 1 and reasons["METHOD"] >= 2
    # Traffic accounting stays on the bare path: the payload never widens the allowlist.
    assert counters["per_path"] == [["GET", path, 3]]


def test_active_arming_is_bounded_and_refuses_widening() -> None:
    def arm(**override: Any) -> int:
        payload = _active_arm_payload(
            VULN_PROJECTION.path, max_requests=8, execution_id="exec-0000000000ad"
        )
        payload.update(override)
        return GuardState().arm(payload)[0]

    assert arm() == 200
    # The lease binding is mandatory and exactly shaped: a missing, malformed or already-expired
    # lease is never armed, so an expired lease cannot start a scan at all.
    for missing in ("lease_id", "lease_expires_at", "projection_digest", "allowlist_digest"):
        payload = _active_arm_payload(VULN_PROJECTION.path, max_requests=8)
        payload.pop(missing)
        assert GuardState().arm(payload)[0] == 400, missing
    assert arm(lease_id="lease-not-hex") == 400
    assert arm(lease_expires_at=int(datetime.now(UTC).timestamp()) - 1) == 400
    assert arm(projection_digest="z" * 64) == 400
    assert arm(allowlist_digest="short") == 400
    assert ACTIVE_MAX_REQUESTS == 512
    assert arm(max_requests=ACTIVE_MAX_REQUESTS) == 200
    assert arm(max_requests=ACTIVE_MAX_REQUESTS + 1) == 400
    assert arm(max_requests=0) == 400
    assert arm(ttl_ms=660_001) == 400
    assert arm(origin="http://evil.example:8001") == 400
    assert arm(origin="http://127.0.0.1:8001") == 400
    assert arm(allowed_query_params=[]) == 400
    assert arm(allowed_query_params=["q", "w", "e", "r", "t"]) == 400
    assert arm(allowed_query_params=["Q"]) == 400
    assert arm(allowed_query_params=["*"]) == 400
    assert arm(allowlist=[{"method": "POST", "path": VULN_PROJECTION.path}]) == 400
    assert arm(allowlist=[{"method": "GET", "path": "/lab/../etc/passwd"}]) == 400
    assert arm(extra=True) == 400
    assert arm(mode="AGGRESSIVE") == 400  # an unknown mode falls through to the passive shape


def test_active_guard_forwards_nothing_while_idle(guard: GuardHarness, lab: LabServer) -> None:
    assert _proxy(guard, "GET", f"{LAB_ORIGIN}{VULN_PROJECTION.path}?q=1") == 403
    assert lab.paths == [] and guard.state.blocked_while_idle == 1


def test_guard_never_logs_a_raw_attack_payload() -> None:
    source = (REPO / "src/zap_guard/guard.py").read_text()
    forwarded = [line for line in source.splitlines() if "guard FORWARDED" in line]
    assert forwarded and all("{path}" not in line for line in forwarded)
    assert 'logged = path.split("?", 1)[0]' in source


# --- 6. the fail-closed active report parser ------------------------------------------------------


def test_parser_reduces_the_attack_payload_to_a_class_and_a_digest() -> None:
    outcome = _parse(_report())
    assert outcome.summary.status == "PARSED" and outcome.summary.records == 1
    record = outcome.records[0]
    payload = "<script>alert(1)</script>"
    assert record.plugin_id == 40012 and record.rule_name == RULE.name
    assert record.method == "GET" and record.path == VULN_PROJECTION.path
    assert record.param == "q"
    assert record.attack_class == "SCRIPT_ELEMENT"
    assert record.attack_length == len(payload)
    assert record.attack_sha256 == hashlib.sha256(payload.encode()).hexdigest()
    assert record.evidence_sha256 == hashlib.sha256(payload.encode()).hexdigest()
    # ZAP's own risk/confidence survive only as untrusted claims.
    assert record.claimed_risk == "high" and record.claimed_confidence == "medium"
    serialized = record.model_dump_json()
    assert payload not in serialized and "alert(1)" not in serialized and "<" not in serialized
    assert "Cross-site scripting" not in serialized  # no scanner prose
    assert {"desc", "solution", "otherinfo", "reference", "riskdesc"} <= set(
        outcome.summary.stripped_fields
    )
    assert "instance.attack" in outcome.summary.stripped_fields
    assert "instance.evidence" in outcome.summary.stripped_fields


@pytest.mark.parametrize(
    ("attack", "expected"),
    [
        ("<script>alert(1)</script>", "SCRIPT_ELEMENT"),
        ("javascript:alert(1)", "JS_URI"),
        ("<img src=x onerror=alert(1)>", "EVENT_HANDLER"),
        ('"><b>x</b>', "ATTRIBUTE_BREAKOUT"),
        ("<b>x</b>", "MARKUP_INJECTION"),
        ("plain", "OTHER"),
        ("", "NONE"),
    ],
)
def test_attack_classification_is_structural_only(attack: str, expected: str) -> None:
    assert classify_attack(attack) == expected


def test_parser_collapses_identical_duplicates_and_rejects_conflicts() -> None:
    duplicated = _parse(_report([_alert(instances=[_instance(), _instance()], count="2")]))
    assert duplicated.summary.status == "PARSED"
    assert duplicated.summary.records == 1 and duplicated.summary.duplicates_collapsed == 1
    distinct = _parse(
        _report(
            [
                _alert(
                    instances=[_instance(), _instance(attack="javascript:alert(1)")],
                    count="2",
                )
            ]
        )
    )
    assert distinct.summary.records == 2
    miscounted = _parse(_report([_alert(count="9")]))
    assert miscounted.summary.status == "MALFORMED"
    assert miscounted.summary.failure_code is ZapActiveErrorCode.REPORT_MALFORMED


@pytest.mark.parametrize(
    ("build", "status", "code"),
    [
        (lambda: None, "MISSING", ZapActiveErrorCode.REPORT_MISSING),
        (lambda: b"", "EMPTY", ZapActiveErrorCode.REPORT_MISSING),
        (lambda: b'{"@programName": "ZAP"', "TRUNCATED", ZapActiveErrorCode.REPORT_TRUNCATED),
        (lambda: b"{ not json }", "MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED),
        (
            lambda: json.dumps(_report(**{"@version": "2.16.1"})).encode(),
            "MALFORMED",
            ZapActiveErrorCode.ENGINE_INTEGRITY_FAILURE,
        ),
        (
            lambda: json.dumps(_report(**{"@programName": "NotZAP"})).encode(),
            "MALFORMED",
            ZapActiveErrorCode.REPORT_MALFORMED,
        ),
        (
            lambda: json.dumps(_report([_alert(pluginid="40014", alertRef="40014")])).encode(),
            "MALFORMED",
            ZapActiveErrorCode.UNADMITTED_RULE,
        ),
        (
            lambda: json.dumps(_report([_alert(name="Renamed Rule")])).encode(),
            "MALFORMED",
            ZapActiveErrorCode.UNADMITTED_RULE,
        ),
        (
            lambda: json.dumps(_report([_alert(instances=[_instance(param="debug")])])).encode(),
            "MALFORMED",
            ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM,
        ),
        (
            lambda: json.dumps(
                _report(
                    [
                        _alert(
                            instances=[
                                _instance(uri=f"{LAB_ORIGIN}{VULN_PROJECTION.path}?q=1&debug=1")
                            ]
                        )
                    ]
                )
            ).encode(),
            "MALFORMED",
            ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM,
        ),
        (
            lambda: json.dumps(
                _report(
                    [_alert(instances=[_instance(uri=f"{LAB_ORIGIN}/lab/zap-active/x/search")])]
                )
            ).encode(),
            "MALFORMED",
            ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED,
        ),
        (
            lambda: json.dumps(
                _report([_alert(instances=[_instance(uri="http://evil.example:8001/lab/x?q=1")])])
            ).encode(),
            "MALFORMED",
            ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED,
        ),
        (
            lambda: json.dumps(_report([_alert(instances=[_instance(method="POST")])])).encode(),
            "MALFORMED",
            ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED,
        ),
        (
            lambda: json.dumps(_report([_alert(instances=[_instance(injected="x")])])).encode(),
            "MALFORMED",
            ZapActiveErrorCode.REPORT_MALFORMED,
        ),
        (
            lambda: json.dumps(_report([_alert(instances=[])])).encode(),
            "OVERSIZED",
            ZapActiveErrorCode.REPORT_OVERSIZED,
        ),
        (
            lambda: json.dumps(
                _report([_alert(instances=[_instance(attack="x" * 9_000)])])
            ).encode(),
            "OVERSIZED",
            ZapActiveErrorCode.REPORT_OVERSIZED,
        ),
        (
            lambda: b'{"@programName": "ZAP", "@programName": "ZAP", "site": []}',
            "MALFORMED",
            ZapActiveErrorCode.REPORT_MALFORMED,
        ),
    ],
)
def test_active_parser_fails_closed(build: Any, status: str, code: ZapActiveErrorCode) -> None:
    outcome = _parse(build())
    assert outcome.summary.status == status
    assert outcome.summary.failure_code is code
    assert outcome.records == ()


def test_parser_refuses_a_second_site_or_an_unapproved_origin() -> None:
    off_origin = _report()
    off_origin["site"][0]["@name"] = "http://evil.example:8001"
    assert _parse(off_origin).summary.failure_code is ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    oversized = _parse(json.dumps(_report()).encode(), max_report_bytes=64)
    assert oversized.summary.failure_code is ZapActiveErrorCode.REPORT_OVERSIZED
    too_many = _parse(_report([_alert(), _alert()]), max_alerts=1)
    assert too_many.summary.failure_code is ZapActiveErrorCode.REPORT_OVERSIZED
    assert PARSER_VERSION == "zap-active-traditional-json-parser/1.5.0"


def test_zero_alerts_is_parsed_but_is_not_itself_a_verdict() -> None:
    outcome = _parse(_report([]))
    assert outcome.summary.status == "PARSED" and outcome.records == ()
    assert outcome.summary.failure_code is None


# --- 7. runner execution through the real guard against the real lab app --------------------------


def _arm_for(executor: Executor, request: ZapActiveRunRequest) -> ZapActiveRunRequest:
    """Arm the request's lease in the executor's admission registry, as the controller would.

    Real runs are always preceded by an explicit arm call, so the offline execution tests do the
    same. Tests that want an UNARMED, expired, replayed or tampered lease bypass this helper and
    hand ``executor.run`` the token directly."""

    assert executor.admission is not None
    armed = executor.admission.registry.armed_record()
    if armed is not None:
        executor.admission.revoke(armed.lease_id, "test_reset")
    outcome = executor.admission.arm(request.lease_token)
    assert not isinstance(outcome, AdmissionRejected), outcome
    return request


def _run(
    executor: Executor, request: ZapActiveRunRequest, *, arm: bool = True
) -> ZapActiveRunResponse:
    if arm:
        _arm_for(executor, request)
    return executor.run(request)


def test_vulnerable_execution_reports_redacted_alerts_within_budget(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    response = _run(executor, _request())
    assert response.status == "COMPLETED" and response.error_code is None
    assert response.coverage_complete is True and response.parse.status == "PARSED"
    assert response.stages.active_scan_started and response.stages.active_scan_completed
    assert response.stages.installed_add_ons_match and response.stages.silent_mode
    assert response.plan.admitted_rule_ids == (40012,)
    assert response.plan.job_types == JOB_SEQUENCE and response.plan.validated
    assert response.alerts and all(a.plugin_id == 40012 for a in response.alerts)
    assert all(a.path == VULN_PROJECTION.path and a.param == "q" for a in response.alerts)
    assert response.traffic is not None
    assert response.traffic.blocked == 0 and response.traffic.forwarded >= 1
    assert response.traffic.forwarded <= 32
    assert response.traffic.per_path == (("GET", VULN_PROJECTION.path, response.traffic.forwarded),)
    assert set(lab.paths) == {VULN_PROJECTION.path}
    assert response.session_destroyed is True
    assert len(fake.run_calls()) == 1
    payload = response.model_dump_json()
    assert "alert(1)" not in payload and "<script" not in payload


def test_patched_execution_has_complete_coverage_and_zero_alerts(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    _, executor = _executor(tmp_path, guard)
    response = _run(executor, _request(PATCHED.target_ref, suffix="ab"))
    assert response.status == "COMPLETED" and response.alerts == ()
    assert response.coverage_complete is True
    assert response.traffic is not None and response.traffic.blocked == 0
    assert set(lab.paths) == {PATCHED_PROJECTION.path}


@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("escape_param", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED),
        ("escape_path", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED),
        ("escape_method", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED),
        ("budget", ZapActiveErrorCode.REQUEST_BUDGET_EXCEEDED),
        ("active_scan_unfinished", ZapActiveErrorCode.ACTIVE_SCAN_INCOMPLETE),
        ("no_active_scan", ZapActiveErrorCode.PLAN_FAILED),
        ("no_drain", ZapActiveErrorCode.PASSIVE_QUEUE_NOT_DRAINED),
        ("not_silent", ZapActiveErrorCode.SILENT_MODE_NOT_CONFIRMED),
        ("nonzero", ZapActiveErrorCode.PLAN_FAILED),
        ("wrong_count", ZapActiveErrorCode.PLAN_FAILED),
        ("no_report", ZapActiveErrorCode.REPORT_MISSING),
        ("malformed_report", ZapActiveErrorCode.REPORT_MALFORMED),
        ("oversized_report", ZapActiveErrorCode.REPORT_OVERSIZED),
        ("unadmitted_rule", ZapActiveErrorCode.UNADMITTED_RULE),
        ("alert_off_path", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED),
        ("alert_bad_param", ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM),
        ("alert_bad_method", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED),
    ],
)
def test_bad_engine_behaviour_never_completes(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, mode: str, code: ZapActiveErrorCode
) -> None:
    _, executor = _executor(tmp_path, guard, mode, cap=45.0)
    request = _request(
        budgets={
            "max_requests": 8,
            "time_budget_ms": 60_000,
            "max_report_bytes": 131_072,
            "max_alerts": 8,
            "delay_ms": 0,
        }
    )
    response = _run(executor, request)
    assert response.status == "FAILED"
    assert response.error_code is code, response.error_code
    assert response.alerts == () and response.coverage_complete is False
    # Whatever the engine did, nothing outside the projected path ever reached the target.
    assert set(lab.paths) <= {VULN_PROJECTION.path}


def test_emergency_stop_kills_an_in_flight_scan(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    _, executor = _executor(tmp_path, guard, "hang", cap=60.0)
    result: dict[str, ZapActiveRunResponse] = {}

    def run() -> None:
        result["response"] = _run(executor, _request())

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = datetime.now(UTC) + timedelta(seconds=30)
    while not guard.state.is_armed() and datetime.now(UTC) < deadline:
        pass
    steps = executor.emergency_stop()
    thread.join(timeout=60)
    response = result["response"]
    # The ordered kill switch: revoke the lease, disarm the guard, kill the engine, mark STOPPED.
    assert steps["lease_revoked"] and steps["guard_disarmed"] and steps["engine_killed"]
    assert steps["marked_stopped"] is True
    # STOPPED is terminal and is never overwritten by an in-flight completion.
    assert response.status == "STOPPED"
    assert response.error_code is ZapActiveErrorCode.EMERGENCY_STOP
    assert response.exit_class == "KILLED_BY_GUARD"
    assert response.alerts == () and response.coverage_complete is False
    assert guard.state.is_armed() is False  # the guard is always disarmed afterwards
    assert guard.state.lease_revoked is True  # revoked before the kill, not after
    assert executor.admission is not None
    assert executor.admission.registry.armed_record() is None


def test_wall_clock_cap_kills_a_hung_engine(tmp_path: Path, guard: GuardHarness) -> None:
    _, executor = _executor(tmp_path, guard, "hang", cap=6.0)
    response = _run(executor, _request())
    assert response.status == "FAILED"
    assert response.error_code is ZapActiveErrorCode.EXECUTION_TIMEOUT
    assert response.exit_class == "TIMEOUT" and response.coverage_complete is False


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"target_ref": "synthetic-zap-active-unknown"}, ZapActiveErrorCode.UNKNOWN_TARGET),
        (
            {"target_ref": "synthetic-zap-active-negative-alternate-server"},
            ZapActiveErrorCode.UNKNOWN_TARGET,
        ),
        ({"profile_id": "ZAP_LAB_PASSIVE_OPENAPI_V1"}, ZapActiveErrorCode.UNKNOWN_PROFILE),
        (
            {"projection_digest": "a" * 64},
            ZapActiveErrorCode.PROJECTION_DIGEST_MISMATCH,
        ),
        (
            {"operation_allowlist_digest": "b" * 64},
            ZapActiveErrorCode.ALLOWLIST_DIGEST_MISMATCH,
        ),
        ({"query_param": "debug"}, ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM),
        (
            {"projection_ref": "synthetic-zap-active-vulnerable/9.9.9"},
            ZapActiveErrorCode.PROJECTION_REF_MISMATCH,
        ),
    ],
)
def test_runner_revalidates_before_starting_zap(
    tmp_path: Path,
    guard: GuardHarness,
    lab: LabServer,
    overrides: dict[str, Any],
    code: ZapActiveErrorCode,
) -> None:
    fake, executor = _executor(tmp_path, guard)
    response = _run(executor, _request(**overrides))
    assert response.status == "REJECTED" and response.error_code is code
    assert fake.run_calls() == [] and lab.paths == []
    assert guard.state.forwarded_total == 0 and guard.state.is_armed() is False


def test_runner_rejects_a_replayed_nonce_and_stays_serialized(
    tmp_path: Path, guard: GuardHarness
) -> None:
    _, executor = _executor(tmp_path, guard)
    first = _run(executor, _request())
    assert first.status == "COMPLETED"
    replay = _run(executor, _request())
    assert replay.status == "REJECTED"
    assert replay.error_code is ZapActiveErrorCode.REPLAYED_NONCE


def test_drift_after_boot_makes_the_runner_reject_with_zero_traffic(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    (fake.paths.plugin_dir / "ascanrules-release-83.zap").write_bytes(b"tampered\n")
    response = _run(executor, _request())
    assert response.status == "REJECTED"
    assert response.error_code is ZapActiveErrorCode.ADDON_INVENTORY_DRIFT
    assert executor.state.ready is False and fake.run_calls() == [] and lab.paths == []


def test_boot_attestation_requires_the_exact_eleven_add_ons(
    tmp_path: Path, guard: GuardHarness
) -> None:
    fake = _fake(tmp_path, guard)
    state = ready_active_state(fake, guard)
    attestation = state.attestation()
    assert attestation.ready and attestation.failure_codes == ()
    assert attestation.engine.pinned and attestation.addonlist_verified
    assert attestation.admitted_rule_ids == (40012,)
    assert set(attestation.neutralised_dependency_ids) == {"oast", "database"}
    assert len(attestation.add_ons) == 11 and all(a.pinned for a in attestation.add_ons)
    assert attestation.unexpected_plugin_files == 0
    assert attestation.forbidden_add_ons_present == ()
    assert attestation.profile_id == PROFILE_ID
    assert attestation.parser_version == PARSER_VERSION
    assert attestation.guard.reachable and attestation.guard.guard_version.startswith("zap-scope")
    # An extra add-on file on disk is drift, not an upgrade.
    (fake.paths.plugin_dir / "spider-release-0.13.0.zap").write_bytes(b"extra\n")
    drifted = ready_active_state(fake, guard)
    assert drifted.ready is False
    assert "ADDON_INVENTORY_DRIFT" in drifted.failure_codes
    assert drifted.attestation().unexpected_plugin_files == 1


def test_forbidden_add_on_present_on_disk_blocks_readiness(
    tmp_path: Path, guard: GuardHarness
) -> None:
    fake = _fake(tmp_path, guard)
    (fake.paths.plugin_dir / "scripts-release-45.zap").write_bytes(b"forbidden\n")
    state = ready_active_state(fake, guard)
    assert state.ready is False
    assert state.attestation().forbidden_add_ons_present == ("scripts",)


def _counters(**overrides: Any) -> GuardCounters:
    payload: dict[str, Any] = {
        "received": 4,
        "forwarded": 4,
        "blocked": 0,
        "blocked_reasons": (),
        "redirects": 0,
        "upstream_failures": 0,
        "upstream_timeouts": 0,
        "budget_exceeded": False,
        "per_path": (("GET", VULN_PROJECTION.path, 4),),
        "statuses": (("200", 4),),
    }
    payload.update(overrides)
    return GuardCounters.model_validate(payload)


def _auto(**overrides: Any) -> AutomationFacts:
    defaults: dict[str, Any] = {
        "plan_succeeded": True,
        "jobs_started": JOB_SEQUENCE,
        "jobs_finished": JOB_SEQUENCE,
        "urls_added": 1,
        "urls_test_passed": True,
        "pscan_wait_started": True,
        "pscan_wait_finished": True,
        "report_paths": ("/work/out/aegis-zap-active-report.json",),
    }
    defaults.update(overrides)
    return AutomationFacts(**defaults)


def _stages(**overrides: Any) -> Any:
    from aegis_zap_active.contracts import ActiveStageFacts

    defaults: dict[str, Any] = {
        "plan_validated": True,
        "zap_started": True,
        "import_started": True,
        "import_completed": True,
        "urls_added": 1,
        "urls_test_passed": True,
        "active_scan_started": True,
        "active_scan_completed": True,
        "pscan_drained": True,
        "report_generated": True,
        "plan_succeeded": True,
        "silent_mode": True,
        "installed_add_ons_match": True,
    }
    defaults.update(overrides)
    return ActiveStageFacts(**defaults)


def _classify(**overrides: Any) -> ZapActiveErrorCode | None:
    options: dict[str, Any] = {
        "exit_class": "OK",
        "exit_code": 0,
        "oversized": False,
        "traffic": _counters(),
        "auto": _auto(),
        "log": ZapLogFacts(silent_mode=True, installed_line_seen=True),
        "stages": _stages(),
        "projection": VULN_PROJECTION,
        "rule": RULE,
    }
    options.update(overrides)
    return classify(**options)


def test_classify_accepts_only_complete_in_scope_coverage() -> None:
    assert _classify() is None
    assert _classify(traffic=None) is ZapActiveErrorCode.GUARD_UNAVAILABLE
    assert _classify(exit_class="TIMEOUT") is ZapActiveErrorCode.EXECUTION_TIMEOUT
    assert (
        _classify(traffic=_counters(blocked=1, blocked_reasons=(("PARAM", 1),)))
        is ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    )
    assert (
        _classify(traffic=_counters(budget_exceeded=True))
        is ZapActiveErrorCode.REQUEST_BUDGET_EXCEEDED
    )
    assert _classify(traffic=_counters(redirects=1)) is ZapActiveErrorCode.REDIRECT_OBSERVED
    assert _classify(traffic=_counters(upstream_timeouts=1)) is ZapActiveErrorCode.TARGET_TIMEOUT
    assert (
        _classify(traffic=_counters(upstream_failures=1)) is ZapActiveErrorCode.TARGET_UNREACHABLE
    )
    assert _classify(oversized=True) is ZapActiveErrorCode.OUTPUT_OVERSIZED
    assert (
        _classify(stages=_stages(installed_add_ons_match=False))
        is ZapActiveErrorCode.ADDON_RUNTIME_MISMATCH
    )
    assert (
        _classify(log=ZapLogFacts(silent_mode=False))
        is ZapActiveErrorCode.SILENT_MODE_NOT_CONFIRMED
    )
    assert _classify(exit_code=1) is ZapActiveErrorCode.NONZERO_EXIT
    assert _classify(auto=_auto(unknown_rule=True)) is ZapActiveErrorCode.RULE_SET_MISMATCH
    assert _classify(auto=_auto(urls_added=2)) is ZapActiveErrorCode.IMPORT_INCOMPLETE
    assert (
        _classify(stages=_stages(active_scan_completed=False))
        is ZapActiveErrorCode.ACTIVE_SCAN_INCOMPLETE
    )
    assert (
        _classify(traffic=_counters(forwarded=0, received=0, per_path=(), statuses=()))
        is ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    )
    assert (
        _classify(traffic=_counters(per_path=(("GET", "/lab/zap-active/other/search", 4),)))
        is ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    )
    assert (
        _classify(traffic=_counters(statuses=(("302", 4),)))
        is ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    )
    assert (
        _classify(auto=_auto(pscan_wait_finished=False))
        is ZapActiveErrorCode.PASSIVE_QUEUE_NOT_DRAINED
    )
    assert _classify(stages=_stages(report_generated=False)) is ZapActiveErrorCode.REPORT_MISSING


# --- 8. the single-use activation lease -----------------------------------------------------------


def test_lease_requires_the_exact_phrase_and_an_authorized_classification() -> None:
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    with pytest.raises(LeaseError) as wrong_phrase:
        store.issue(
            _activation(confirmation_phrase="activate active scan"), binding=_dummy_binding()
        )
    assert wrong_phrase.value.code == "CONFIRMATION_PHRASE_MISMATCH"
    for classification in ("STAGING", "PRODUCTION"):
        with pytest.raises(LeaseError) as refused:
            store.issue(_activation(classification=classification), binding=_dummy_binding())
        assert refused.value.code == "ENVIRONMENT_NOT_AUTHORISED"
    assert store.current() is None
    lease = store.issue(_activation(), binding=_dummy_binding())
    assert lease.state == "ISSUED" and lease.is_live()
    assert lease.classification == "SYNTHETIC_LAB"
    # The console projection never exposes the token.
    assert "token" not in lease.redacted() and lease.token not in json.dumps(lease.redacted())
    with pytest.raises(LeaseError) as busy:
        store.issue(_activation(), binding=_dummy_binding())
    assert busy.value.code == "LEASE_ALREADY_ACTIVE"


def test_lease_is_single_use_and_bound_to_one_target_profile_and_capability() -> None:
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    lease = store.issue(_activation(), binding=_dummy_binding())
    binding = {
        "target_ref": VULN.target_ref,
        "profile_id": ACTIVE_PROFILE_ID,
        "capability_id": CAPABILITY,
    }
    with pytest.raises(LeaseError) as mismatch:
        store.consume(token="f" * 32, **binding)
    assert mismatch.value.code == "LEASE_TOKEN_MISMATCH"
    for override in (
        {"target_ref": PATCHED.target_ref},
        {"profile_id": "ZAP_LAB_PASSIVE_OPENAPI_V1"},
        {"capability_id": "zap_passive_header_openapi_v1"},
    ):
        with pytest.raises(LeaseError) as bound:
            store.consume(token=lease.token, **{**binding, **override})
        assert bound.value.code == "LEASE_BINDING_MISMATCH"
    consumed = store.consume(token=lease.token, **binding)
    assert consumed.state == "CONSUMED" and consumed.consumed_at is not None
    with pytest.raises(LeaseError) as reused:  # single use: there is no second execution
        store.consume(token=lease.token, **binding)
    assert reused.value.code == "NO_LIVE_LEASE"
    store.complete(lease.lease_id)
    current = store.current()
    assert current is not None and current.state == "COMPLETED"


def test_lease_expires_and_is_never_renewable() -> None:
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    lease = store.issue(_activation(ttl_seconds=30), binding=_dummy_binding())
    store._lease = lease.model_copy(  # noqa: SLF001 - simulate the clock passing the expiry
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    current = store.current()
    assert current is not None and current.state == "EXPIRED"
    with pytest.raises(LeaseError):
        store.consume(
            token=lease.token,
            target_ref=VULN.target_ref,
            profile_id=ACTIVE_PROFILE_ID,
            capability_id=CAPABILITY,
        )
    assert not hasattr(store, "extend") and not hasattr(store, "renew")
    with pytest.raises(ValidationError):
        _activation(ttl_seconds=3_600)


def test_emergency_stop_revokes_the_lease_and_fires_the_kill_switch() -> None:
    fired: list[str] = []
    store = ActiveScanLeaseStore(
        ADMISSION_TEST_SECRET, on_emergency_stop=lambda: fired.append("stop")
    )
    lease = store.issue(_activation(), binding=_dummy_binding())
    assert store.emergency_stop("operator_pressed_stop") is True
    assert fired == ["stop"]
    current = store.current()
    assert current is not None
    assert current.state == "REVOKED" and current.termination_reason == "operator_pressed_stop"
    assert current.lease_id == lease.lease_id
    # A stop with nothing live still fires the kill switch and never raises.
    assert store.emergency_stop() is False and fired == ["stop", "stop"]


# --- 9. controller policy, adapter and correlation ---------------------------------------------


def test_controller_builds_the_active_job_from_catalog_inventory_and_projection() -> None:
    job, projection = build_zap_active_job(
        profile_id=ACTIVE_PROFILE_ID,
        capability_id=CAPABILITY,
        run_id="scan-0000000000aa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        target_ref=VULN.target_ref,
        allowed_origins=[LAB_ORIGIN],
        adapter_enabled=True,
    )
    assert job.activity is EngineActivity.ACTIVE and job.rule_id == 40012
    assert job.method == "GET" and job.path == VULN_PROJECTION.path
    assert job.query_param == "q" and job.strength == "low" and job.threshold == "medium"
    assert job.projection_digest == projection.digest == VULN_PROJECTION.digest
    assert job.manifest_digest == manifest_digest()
    assert job.add_on_inventory_digest == add_on_inventory_digest(MANIFEST)
    assert job.max_requests == 200 and job.time_budget_ms == 300_000
    assert job.created_by == "CONTROLLER"
    capability = get_engine_capability(CAPABILITY)
    assert capability is not None
    assert capability.activity is EngineActivity.ACTIVE
    assert capability.verified_severity == "HIGH"
    assert capability.state_changing_possible is False
    assert capability.requires_authentication is False
    assert set(capability.supported_methods) <= {"GET", "HEAD"}
    assert capability.allowed_environments == (EngineEnvironment.SYNTHETIC_LAB,)
    assert "OPERATOR_ACTIVE_SCAN_LEASE" in capability.required_approvals
    profile = get_engine_profile(ACTIVE_PROFILE_ID)
    assert profile is not None and profile.enabled
    assert profile.capability_ids == (CAPABILITY,)
    assert profile.environment is EngineEnvironment.SYNTHETIC_LAB
    zap_profiles = [p for p in PROFILE_CATALOG if p.engine is SecurityEngine.ZAP and p.enabled]
    enabled = [p.profile_id for p in zap_profiles]
    assert sorted(enabled) == ["ZAP_LAB_ACTIVE_REFLECTED_XSS_V1", "ZAP_LAB_PASSIVE_OPENAPI_V1"]
    assert ACTIVE_CAPABILITY_ID == CAPABILITY


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"capability_id": "zap_active_scan_v0"}, EngineErrorCode.UNAPPROVED_STATE_CHANGE),
        ({"capability_id": "zap_passive_header_openapi_v1"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"capability_id": "nuclei_scm_metadata_exposure_v1"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"profile_id": "ZAP_LAB_PASSIVE_OPENAPI_V1"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"profile_id": "NUCLEI_LAB_SAFE_HTTP_V1"}, EngineErrorCode.UNKNOWN_PROFILE),
        ({"adapter_enabled": False}, EngineErrorCode.ENGINE_DISABLED),
        ({"environment": EngineEnvironment.PRODUCTION}, EngineErrorCode.DISALLOWED_ENVIRONMENT),
        ({"environment": EngineEnvironment.STAGING}, EngineErrorCode.DISALLOWED_ENVIRONMENT),
        ({"target_ref": "synthetic-zap-active-unknown"}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        (
            {"target_ref": "synthetic-zap-active-negative-external-ref"},
            EngineErrorCode.OUT_OF_SCOPE_ORIGIN,
        ),
        ({"allowed_origins": ["http://other:8001"]}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
    ],
)
def test_controller_policy_rejects_before_any_runner_contact(
    overrides: dict[str, Any], code: EngineErrorCode
) -> None:
    options: dict[str, Any] = {
        "profile_id": ACTIVE_PROFILE_ID,
        "capability_id": CAPABILITY,
        "run_id": "scan-0000000000aa",
        "environment": EngineEnvironment.SYNTHETIC_LAB,
        "target_ref": VULN.target_ref,
        "allowed_origins": [LAB_ORIGIN],
        "adapter_enabled": True,
    }
    options.update(overrides)
    with pytest.raises(EnginePolicyRejection) as rejected:
        build_zap_active_job(**options)
    assert rejected.value.error.code is code


@pytest.mark.parametrize(
    "field",
    [
        "command",
        "argv",
        "plan",
        "jobs",
        "url",
        "apiUrl",
        "headers",
        "script",
        "options",
        "payload",
        "rules",
    ],
)
def test_active_job_has_no_plan_url_payload_or_option_fields(field: str) -> None:
    job = _job()
    with pytest.raises(ValidationError):
        ZapActiveEngineJob.model_validate({**job.model_dump(), field: "x"})


def test_denied_broad_active_scan_capability_is_still_never_buildable() -> None:
    denied = get_engine_capability("zap_active_scan_v0")
    assert denied is not None
    assert denied.required_approvals == ("NEVER_APPROVED",)
    assert denied.request_budget == 0 and denied.state_changing_possible is True
    assert not any("zap_active_scan_v0" in p.capability_ids for p in PROFILE_CATALOG)
    from aegis.engine.zap import build_zap_job

    with pytest.raises(EnginePolicyRejection) as passive_path:
        build_zap_job(
            profile_id="ZAP_LAB_PASSIVE_OPENAPI_V1",
            capability_id="zap_active_scan_v0",
            run_id="scan-0000000000aa",
            environment=EngineEnvironment.SYNTHETIC_LAB,
            target_ref="synthetic-zap-vulnerable",
            remaining_requests=8,
            allowed_origins=[LAB_ORIGIN],
            adapter_enabled=True,
        )
    assert passive_path.value.error.code is EngineErrorCode.ACTIVE_SCAN_FORBIDDEN
    # The passive builder never produces the active profile either.
    with pytest.raises(EnginePolicyRejection):
        build_zap_job(
            profile_id=ACTIVE_PROFILE_ID,
            capability_id=CAPABILITY,
            run_id="scan-0000000000aa",
            environment=EngineEnvironment.SYNTHETIC_LAB,
            target_ref="synthetic-zap-vulnerable",
            remaining_requests=8,
            allowed_origins=[LAB_ORIGIN],
            adapter_enabled=True,
        )


def _response(job: ZapActiveEngineJob, request: ZapActiveRunRequest, **overrides: Any) -> Any:
    from aegis_zap_active.contracts import (
        ActivePlanFacts,
        ActiveProjectionFacts,
        ActiveStageFacts,
        ZapActiveParseSummary,
    )

    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "engine_execution_id": request.engine_execution_id,
        "job_id": job.job_id,
        "nonce": request.nonce,
        "runner_version": "zap-active-runner/1.5.0",
        "profile_id": job.profile_id,
        "profile_version": PROFILE_VERSION,
        "status": "COMPLETED",
        "exit_class": "OK",
        "exit_code": 0,
        "engine": {
            "zap_version": "2.17.0",
            "jar_sha256": MANIFEST.engine.jar.sha256,
            "arch": "linux_arm64",
            "add_on_inventory_digest": job.add_on_inventory_digest,
            "pinned": True,
        },
        "projection": ActiveProjectionFacts(
            projection_ref=job.projection_ref,
            projection_version=PROJECTION_VERSION,
            digest=job.projection_digest,
            allowlist_digest=job.allowlist_digest,
            source_sha256=job.source_sha256,
            operation_count=1,
            path_count=1,
            query_param="q",
            redaction_status="REDACTED",
        ),
        "plan": ActivePlanFacts(validated=True, admitted_rule_ids=(40012,)),
        "stages": ActiveStageFacts(active_scan_completed=True, plan_succeeded=True),
        "traffic": _counters(),
        "started_at": now,
        "completed_at": now,
        "duration_ms": 1000,
        "stdout_bytes": 10,
        "report_bytes": 10,
        "session_destroyed": True,
        "parse": ZapActiveParseSummary(
            parser_version=PARSER_VERSION,
            status="PARSED",
            sites=1,
            alerts=1,
            instances=1,
            records=1,
            duplicates_collapsed=0,
        ),
        "alerts": (),
        "coverage_complete": True,
    }
    payload.update(overrides)
    return ZapActiveRunResponse.model_validate(payload, strict=False)


def _record(**overrides: Any) -> ZapActiveAlertRecord:
    payload: dict[str, Any] = {
        "plugin_id": 40012,
        "rule_name": RULE.name,
        "method": "GET",
        "path": VULN_PROJECTION.path,
        "param": "q",
        "claimed_risk": "high",
        "claimed_confidence": "confirmed",
        "evidence_sha256": "a" * 64,
        "evidence_length": 10,
        "attack_class": "SCRIPT_ELEMENT",
        "attack_sha256": "b" * 64,
        "attack_length": 25,
        "record_digest": "c" * 64,
    }
    payload.update(overrides)
    return ZapActiveAlertRecord.model_validate(payload)


def test_adapter_revalidates_every_runner_response_as_untrusted() -> None:
    adapter = ZapActiveAdapter("http://runner", enabled=True, adapter_version="x")
    job = _job()
    request = adapter.build_request(job, "scan-0000000000aa", "exec-0000000000aa", _unarmed_token())
    assert adapter.validate_response(job, request, _response(job, request)) is None
    checks = {
        "CORRELATION_MISMATCH": {"nonce": "0" * 32},
        "PROFILE_MISMATCH": {"profile_version": "9.9.9"},
        "PROJECTION_MISMATCH": None,
        "ALERT_BUDGET_EXCEEDED": {"alerts": tuple(_record() for _ in range(9))},
        "REQUEST_BUDGET_EXCEEDED": {"traffic": _counters(forwarded=501, received=501)},
        "UNEXPECTED_ORIGIN_OR_PATH": {
            "traffic": _counters(per_path=(("GET", "/lab/zap-active/other/search", 1),))
        },
        "UNADMITTED_RULE": {"alerts": (_record(plugin_id=40014),)},
        "UNEXPECTED_PARAMETER": {"alerts": (_record(param="debug"),)},
        "COMPLETED_WITHOUT_COMPLETE_COVERAGE": {"coverage_complete": False},
        "RESULTS_ON_FAILED_EXECUTION": {
            "status": "FAILED",
            "alerts": (_record(),),
            "error_code": ZapActiveErrorCode.PLAN_FAILED,
        },
        "PARSER_VERSION_MISMATCH": None,
    }
    for code, override in checks.items():
        if code == "PROJECTION_MISMATCH":
            response = _response(job, request)
            response = response.model_copy(
                update={
                    "projection": response.projection.model_copy(update={"digest": "e" * 64})  # type: ignore[union-attr]
                }
            )
        elif code == "PARSER_VERSION_MISMATCH":
            response = _response(job, request)
            response = response.model_copy(
                update={
                    "parse": response.parse.model_copy(update={"parser_version": "other/9.9.9"})
                }
            )
        else:
            response = _response(job, request, **(override or {}))
        assert adapter.validate_response(job, request, response) == code, code
    # A rejection carries no results and is accepted as a terminal, non-PASS outcome.
    rejected = _response(
        job,
        request,
        status="REJECTED",
        error_code=ZapActiveErrorCode.UNKNOWN_TARGET,
        coverage_complete=False,
        alerts=(),
    )
    assert adapter.validate_response(job, request, rejected) is None


async def test_active_execution_consumes_exactly_one_lease_end_to_end(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, executor = _executor(tmp_path, guard)
    monkeypatch.setattr(controller, "load_manifest", lambda: fake.manifest)
    # The real countersign check must fail on a fake install (its add-on bytes cannot carry the
    # countersigned digests); the offline end-to-end path substitutes the structural stand-in.
    monkeypatch.setattr(
        controller,
        "verify_countersign",
        lambda **kwargs: verify_countersign_offline(kwargs["manifest"]),
    )
    job, _ = build_zap_active_job(
        profile_id=ACTIVE_PROFILE_ID,
        capability_id=CAPABILITY,
        run_id="scan-0000000000aa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        target_ref=VULN.target_ref,
        allowed_origins=[LAB_ORIGIN],
        adapter_enabled=True,
        manifest=fake.manifest,
    )
    transport = ActiveExecutorTransport(executor)
    adapter = ZapActiveAdapter(
        "http://zap-active-runner:8093",
        enabled=True,
        adapter_version=job.adapter_version,
        transport=transport,
    )
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    lease = store.issue(_activation(), binding=_binding(job))
    # The activation ceremony arms the lease at the runner; execution only consumes it.
    armed = await adapter.arm_lease(lease.token)
    assert not isinstance(armed, str), armed
    result = await adapter.run(
        job, "scan-0000000000aa", execution_id="exec-0000000000aa", lease_store=store
    )
    assert result.execution.status is EngineExecutionStatus.COMPLETED
    assert result.response is not None and result.response.status == "COMPLETED"
    assert result.response.alerts and result.validation_code is None
    assert result.lease is not None
    current = store.current()
    assert current is not None and current.state == "COMPLETED"
    assert set(lab.paths) == {VULN_PROJECTION.path}
    # A second run cannot reuse the spent lease: no lease, no traffic.
    repeat = await adapter.run(
        job, "scan-0000000000aa", execution_id="exec-0000000000ab", lease_store=store
    )
    assert repeat.execution.status is EngineExecutionStatus.FAILED
    assert repeat.validation_code == "LEASE:NO_LIVE_LEASE"
    assert transport.calls["run"] == 1


class _RoutingTransport(httpx.AsyncBaseTransport):
    """Routes the controller's runner RPC to the in-process executor and its lab/verifier
    requests to the lab app — the same split the compose topology enforces by network."""

    def __init__(self, runner: httpx.AsyncBaseTransport, lab: httpx.AsyncBaseTransport) -> None:
        self.runner = runner
        self.lab = lab

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "zap-active-runner":
            return await self.runner.handle_async_request(request)
        if request.url.host == "lab-api":
            return await self.lab.handle_async_request(request)
        return httpx.Response(404, request=request)


async def test_controller_activation_arms_once_and_execution_only_consumes(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The activate -> execute controller flow: exactly ONE arm (at the ceremony), one consume,
    a verifier-owned verdict, and a second arm can never slip in between."""

    from pydantic import SecretStr

    from aegis.zap_active_controller import ZapActiveActivation, ZapActiveController

    fake, executor = _executor(tmp_path, guard)
    monkeypatch.setattr(controller, "load_manifest", lambda: fake.manifest)
    monkeypatch.setattr(
        controller,
        "verify_countersign",
        lambda **kwargs: verify_countersign_offline(kwargs["manifest"]),
    )
    routing = _RoutingTransport(ActiveExecutorTransport(executor), httpx.ASGITransport(app=lab_app))
    settings = Settings(
        zap_active_enabled=True,
        zap_active_lease_secret=SecretStr(ADMISSION_TEST_SECRET),
        zap_active_runner_client_secret=SecretStr(ADMISSION_TEST_SECRET),
    )
    zap = ZapActiveController(settings, SafetyController(settings), transport=routing)
    session = await zap.activate(
        ZapActiveActivation(
            scenario="scenario-a",
            confirmation_phrase=CONFIRMATION_PHRASE,
            operator_id="offline-operator",
        )
    )
    assert session.state == "ARMED" and session.armed_lease is not None
    admission = executor.admission
    assert admission is not None
    assert admission.calls["arm"] == 1  # the ceremony armed exactly once
    await zap.execute()
    view = zap.view()
    assert view["state"] == "COMPLETED"
    assert view["verdict"]["outcome"] == "VERIFIED_VULNERABLE"
    assert view["verdict"]["owner"] == "AEGIS_VERIFIER"
    assert view["progress"]["coverage_complete"] is True
    # Browser projections expose no route/fixture ground truth or bearer material. The verifier's
    # final conclusion is intentionally visible, but the browser cannot choose or inspect either
    # underlying fixture directly.
    projected = json.dumps(view)
    assert "AZL1." not in projected
    assert "synthetic-zap-active-vulnerable" not in projected
    assert "synthetic-zap-active-patched" not in projected
    assert "http://lab-api:8001/lab/zap-active" not in projected
    assert "<script>" not in projected
    assert admission.calls["arm"] == 1  # execution never re-arms
    assert admission.calls["consume"] == 1
    assert admission.calls["revoke"] >= 1
    current = zap.lease_store().current()
    assert current is not None and current.state == "COMPLETED"
    # The runner-side registry is empty afterwards: the lease was terminal after one execution.
    assert admission.registry.armed_record() is None


async def test_unattested_or_unreachable_runner_never_consumes_a_lease(
    tmp_path: Path, guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, executor = _executor(tmp_path, guard)
    monkeypatch.setattr(controller, "load_manifest", lambda: fake.manifest)
    monkeypatch.setattr(
        controller,
        "verify_countersign",
        lambda **kwargs: verify_countersign_offline(kwargs["manifest"]),
    )
    job = _job()
    job = job.model_copy(update={"add_on_inventory_digest": add_on_inventory_digest(fake.manifest)})
    unreachable = ZapActiveAdapter(
        "http://zap-active-runner:8093",
        enabled=True,
        adapter_version=job.adapter_version,
        transport=ActiveExecutorTransport(None),
    )
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    store.issue(_activation(), binding=_binding(job))
    result = await unreachable.run(
        job, "scan-0000000000aa", execution_id="exec-0000000000aa", lease_store=store
    )
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert result.execution.error is not None
    assert result.execution.error.code is EngineErrorCode.RUNNER_NOT_ATTESTED
    current = store.current()
    assert current is not None and current.state == "ISSUED"  # the lease was never spent
    transport = ActiveExecutorTransport(executor)
    transport.override_attestation = (
        lambda ex: ex.state.attestation()
        .model_copy(update={"admitted_rule_ids": (40012, 40018)})
        .model_dump_json()
    )
    widened = ZapActiveAdapter(
        "http://zap-active-runner:8093",
        enabled=True,
        adapter_version=job.adapter_version,
        transport=transport,
    )
    result = await widened.run(
        job, "scan-0000000000aa", execution_id="exec-0000000000ab", lease_store=store
    )
    assert result.validation_code == "RULE_MANIFEST_MISMATCH"
    assert transport.calls["run"] == 0


async def test_disabled_active_adapter_is_a_zero_traffic_skeleton(lab: LabServer) -> None:
    adapter = ZapActiveAdapter("http://runner", enabled=False, adapter_version="x")
    store = ActiveScanLeaseStore(ADMISSION_TEST_SECRET)
    store.issue(_activation(), binding=_dummy_binding())
    result = await adapter.run(
        _job(), "scan-0000000000aa", execution_id="exec-0000000000aa", lease_store=store
    )
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert result.execution.error is not None
    assert result.execution.error.code is EngineErrorCode.ENGINE_DISABLED
    assert await adapter.attest() is None
    assert lab.paths == []
    current = store.current()
    assert current is not None and current.state == "ISSUED"


def test_active_alert_cannot_become_verified_without_the_verifier() -> None:
    job = _job()
    reported = EngineReportedFinding(
        report_key=f"{CAPABILITY}:40012:{VULN.target_ref}:{VULN.operation_id}",
        engine=SecurityEngine.ZAP,
        capability_id=CAPABILITY,
        claimed_category="tool claim",
        target_operation_id=VULN.operation_id,
        principal_profile="anonymous",
        observation_names=["zap-active-40012-x"],
        signal="Active rule 40012 flagged (unverified).",
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
    assert promoted.severity == "HIGH" and promoted.confidence == "CONFIRMED"


# --- 10. the independent deterministic XSS verifier ---------------------------------------------


def _xss_facts(
    *, control: dict[str, Any] | None = None, probe: dict[str, Any] | None = None
) -> list[ZapXssProbeFacts]:
    marker = "AEGIS0123456789ab"
    base = {
        "marker": marker,
        "status_code": 200,
        "content_class": "HTML",
        "body_bytes": 200,
        "variant_marker_ok": True,
    }
    return [
        ZapXssProbeFacts(
            name="c", role="BASE_CONTROL", path=VULN.search_path, **{**base, **(control or {})}
        ),
        ZapXssProbeFacts(
            name="p",
            role="XSS_PROBE",
            path=VULN.search_path,
            **{**base, "reflection": "RAW_EXECUTABLE", **(probe or {})},
        ),
    ]


def test_verifier_verdicts_are_independent_of_zap() -> None:
    assert evaluate(_xss_facts()).status == "CONFIRMED"
    assert evaluate(_xss_facts(probe={"reflection": "ENTITY_ENCODED"})).status == "PASS"
    for control, probe in (
        ({"variant_marker_ok": False}, None),
        ({"transport_error": True}, None),
        ({"redirect": True}, None),
        (None, {"variant_marker_ok": False}),
        (None, {"transport_error": True}),
        (None, {"redirect": True}),
        (None, {"reflection": "ABSENT"}),
        (None, {"reflection": "AMBIGUOUS"}),
        (None, {"reflection": "NOT_OBSERVED"}),
        (None, {"marker": "AEGISdifferent00"}),
    ):
        assert evaluate(_xss_facts(control=control, probe=probe)).status == "INSUFFICIENT"
    assert evaluate([]).status == "INSUFFICIENT"
    assert evaluate(_xss_facts()[:1]).status == "INSUFFICIENT"
    # The verifier proves an executable context, never browser execution.
    confirmed = evaluate(_xss_facts())
    assert "no browser execution" in confirmed.summary
    assert confirmed.verifier_version == VERIFIER_VERSION
    marker = fresh_marker()
    assert marker != fresh_marker() and marker.startswith("AEGIS")
    negative = ZAP_ACTIVE_TARGETS["synthetic-zap-active-negative-alternate-server"]
    assert probe_plan(negative, "scan-x") == []
    assert [role for _, role in probe_plan(VULN, "scan-x")] == ["BASE_CONTROL", "XSS_PROBE"]


def test_reflection_classification_is_deterministic() -> None:
    marker = "AEGISdeadbeefdead"
    raw = f"<div>You searched for: <script>{marker}</script></div>"
    encoded = f"<div>You searched for: &lt;script&gt;{marker}&lt;/script&gt;</div>"
    assert classify_reflection(raw, marker) == "RAW_EXECUTABLE"
    assert classify_reflection(encoded, marker) == "ENTITY_ENCODED"
    assert classify_reflection(f"<div>{marker}</div>", marker) == "AMBIGUOUS"
    assert classify_reflection("<div>nothing</div>", marker) == "ABSENT"


async def test_verifier_confirms_the_vulnerable_and_passes_the_patched_lab_route() -> None:
    safety = SafetyController(Settings())
    for target, expected in ((VULN, "CONFIRMED"), (PATCHED, "PASS")):
        transport = CountingTransport(httpx.ASGITransport(app=lab_app))
        marker = fresh_marker()
        facts = await collect(
            target=target,
            scan_id="scan-0000000000aa",
            marker=marker,
            safety=safety,
            transport=transport,
            timeout_seconds=10.0,
        )
        verdict = evaluate(facts)
        assert verdict.status == expected, (target.variant, verdict.summary)
        assert verdict.marker == marker
        # Exactly two fresh read-only requests, both on the one projected search path.
        assert transport.paths == [target.search_path, target.search_path]
        assert all(fact.method == "GET" for fact in facts)
        assert [f.role for f in facts] == ["BASE_CONTROL", "XSS_PROBE"]
        probe = facts[1]
        reflected = "RAW_EXECUTABLE" if expected == "CONFIRMED" else "ENTITY_ENCODED"
        assert probe.reflection == reflected
        assert probe.content_class == "HTML" and probe.variant_marker_ok
        # Only body-free facts are persisted.
        serialized = json.dumps([f.model_dump() for f in facts])
        assert "<script" not in serialized and "You searched for" not in serialized


async def test_verifier_uses_a_fresh_marker_that_zap_never_supplied() -> None:
    safety = SafetyController(Settings())
    markers = set()
    for _ in range(3):
        transport = CountingTransport(httpx.ASGITransport(app=lab_app))
        marker = fresh_marker()
        facts = await collect(
            target=VULN,
            scan_id="scan-0000000000aa",
            marker=marker,
            safety=safety,
            transport=transport,
            timeout_seconds=10.0,
        )
        assert evaluate(facts).status == "CONFIRMED"
        markers.add(marker)
    assert len(markers) == 3
    source = (REPO / "src/aegis/zap_active_verifier.py").read_text()
    # The verifier never reads a scanner claim or its payload.
    assert "ZapActiveRunResponse" not in source and "claimed_risk" not in source
    assert "attack_sha256" not in source and "ZapActiveAlertRecord" not in source


def test_safety_permits_only_the_fixed_active_verifier_path() -> None:
    safety = SafetyController(Settings())
    for target in (VULN, PATCHED):
        assert safety.approve_zap_active_verification(LAB_ORIGIN, target.search_path)
    for bad in (
        "/lab/zap-active/negative/search",
        "/lab/zap-active/vulnerable",
        "/lab/zap-active/vulnerable/reset",
        "/lab/zap-active/vulnerable/admin/purge",
        "/lab/zap/vulnerable/status",
        "/api/v1/accounts/A-100",
    ):
        with pytest.raises(SafetyViolation):
            safety.approve_zap_active_verification(LAB_ORIGIN, bad)
    with pytest.raises(SafetyViolation):
        safety.approve_zap_active_verification("http://evil.example:8001", VULN.search_path)


# --- 11. the inert controlled test-environment profile ------------------------------------------


def test_test_env_profile_is_inert_until_the_operator_registers_a_target() -> None:
    required = required_configuration()
    assert set(required) == {"TARGET_ORIGIN", "OPENAPI_FILE", "ALLOWED_PATH_PREFIX"}
    assert required["TARGET_ORIGIN"].startswith("required")
    assert required["OPENAPI_FILE"].startswith("required")
    assert required["ALLOWED_PATH_PREFIX"].startswith("optional")
    # No credential, token or secret is ever requested by this profile.
    joined = " ".join(required.values()).lower()
    for word in ("password", "credential", "secret", "token", "api key", "cookie"):
        assert word not in joined
    assert TEST_ENV_PROFILE_ID == "ZAP_TEST_ENV_ACTIVE_V1"
    assert ADMITTED_RULE_IDS == (40012,)
    assert HARD_REQUEST_CEILING == 500 and MAX_WALL_CLOCK_MS == 600_000
    # This repository ships no test-environment target, so nothing can run.
    assert not any(t.origin != LAB_ORIGIN for t in ZAP_ACTIVE_TARGETS.values())


def _preflight(**overrides: Any) -> list[str]:
    options: dict[str, Any] = {
        "resolved_origin": "http://closed-test-env.internal:8443",
        "registered_origin": "http://closed-test-env.internal:8443",
        "classification": "CONTROLLED_TEST_ENV",
        "guard_armed": True,
        "kill_switch_ok": True,
        "request_budget_installed": True,
        "guard_route_isolated": True,
        "secrets_absent_from_zap_and_guard": True,
        "max_requests": 200,
        "rate_per_second": 2.0,
        "wall_clock_ms": 300_000,
        "admitted_rule_ids": (40012,),
        "allowed_methods": ("GET", "HEAD"),
    }
    options.update(overrides)
    return preflight(PreflightInputs(**options))


def test_test_env_preflight_fails_closed_on_every_missing_control() -> None:
    assert _preflight() == []
    assert _preflight(resolved_origin="http://other.internal:8443") == [
        "ORIGIN_NOT_REGISTERED_TARGET"
    ]
    for classification in ("PRODUCTION", "STAGING", "SYNTHETIC_LAB", ""):
        assert "CLASSIFICATION_NOT_CONTROLLED_TEST_ENV" in _preflight(classification=classification)
    assert "SCOPE_GUARD_NOT_ARMED" in _preflight(guard_armed=False)
    assert "KILL_SWITCH_NOT_VERIFIED" in _preflight(kill_switch_ok=False)
    assert "REQUEST_BUDGET_NOT_INSTALLED" in _preflight(request_budget_installed=False)
    assert "GUARD_BYPASS_ROUTE_PRESENT" in _preflight(guard_route_isolated=False)
    assert "SECRETS_PRESENT" in _preflight(secrets_absent_from_zap_and_guard=False)
    assert "REQUEST_CEILING_OUT_OF_BOUNDS" in _preflight(max_requests=501)
    assert "REQUEST_CEILING_OUT_OF_BOUNDS" in _preflight(max_requests=0)
    assert "RATE_OUT_OF_BOUNDS" in _preflight(rate_per_second=2.5)
    assert "WALL_CLOCK_OUT_OF_BOUNDS" in _preflight(wall_clock_ms=600_001)
    assert "RULE_SUBSET_MISMATCH" in _preflight(admitted_rule_ids=(40012, 40018))
    assert "NON_READ_ONLY_METHOD" in _preflight(allowed_methods=("GET", "POST"))
    # Several failures are reported together; a preflight is never partially satisfied.
    assert len(_preflight(guard_armed=False, kill_switch_ok=False, max_requests=900)) == 3


def test_test_env_profile_forbids_spiders_auth_oast_and_any_model_call() -> None:
    from aegis.zap_active_test_env import (
        CONCURRENCY,
        EXCLUDED_METHODS,
        FORBIDDEN_FEATURES,
        MAX_RATE_PER_SECOND,
        STRENGTH,
        THRESHOLD,
    )

    assert (STRENGTH, THRESHOLD, CONCURRENCY, MAX_RATE_PER_SECOND) == ("low", "medium", 1, 2.0)
    assert set(EXCLUDED_METHODS) == {"POST", "PUT", "PATCH", "DELETE"}
    assert {"spider", "ajaxSpider", "oastCallbacks", "authentication", "scripts"} <= set(
        FORBIDDEN_FEATURES
    )
    assert {"publicModelCall", "deepseekCall"} <= set(FORBIDDEN_FEATURES)


# --- 12. regressions ----------------------------------------------------------------------------


def test_synthetic_active_routes_are_excluded_from_the_published_openapi() -> None:
    from fastapi.testclient import TestClient

    with TestClient(lab_app) as client:
        schema = client.get("/openapi.json").json()
        assert not [p for p in schema["paths"] if p.startswith("/lab/zap-active")]
        # The Phase 1.3 passive lab surface is unchanged by Phase 1.5.
        vulnerable = client.get("/lab/zap-active/vulnerable/search", params={"q": "<b>x</b>"})
        patched = client.get("/lab/zap-active/patched/search", params={"q": "<b>x</b>"})
        assert vulnerable.status_code == patched.status_code == 200
        assert "<b>x</b>" in vulnerable.text  # raw reflection: the intentional lab defect
        assert "&lt;b&gt;x&lt;/b&gt;" in patched.text and "<b>x</b>" not in patched.text
        assert vulnerable.headers["x-content-type-options"] == "nosniff"
        assert client.get("/lab/zap-active/unknown/search").status_code == 404
        reset = client.get("/lab/zap-active/vulnerable/reset").json()
        assert reset["stateful"] is False and reset["synthetic"] is True


def test_no_spider_script_oast_or_model_call_is_reachable_from_the_active_path() -> None:
    from aegis_zap_active.profile import FORBIDDEN_PLAN_KEYS

    plan = json.dumps(_plan())
    # Not expressible in the plan the runner actually executes.
    for forbidden in (
        "spider",
        "spiderAjax",
        "script",
        "oast",
        "requestor",
        "replacer",
        "authentication",
        "users",
        "apiUrl",
        "headers",
    ):
        assert forbidden not in plan
    assert {"apiUrl", "script", "users", "authentication", "headers"} <= FORBIDDEN_PLAN_KEYS
    assert {"spider", "spiderAjax", "script", "oast"} <= FORBIDDEN_JOB_TYPES
    # OAST is present in the image only as a neutralised forced dependency and is never a job.
    assert "oast" in MANIFEST.neutralised_dependency_ids
    assert "oast" in MANIFEST.prohibited_jobs
    assert "oastCallbacks" in MANIFEST.prohibited_features
    assert "llmOrMcp" in MANIFEST.prohibited_features
    assert "operatorOrModelPayloads" in MANIFEST.prohibited_features
    assert "stateChangingMethods" in MANIFEST.prohibited_features


def test_active_modules_never_import_a_model_provider_or_the_planner() -> None:
    for module in (
        REPO / "src/aegis_zap_active/profile.py",
        REPO / "src/aegis_zap_active/parser.py",
        REPO / "src/zap_active_runner/execution.py",
        REPO / "src/aegis/zap_active_verifier.py",
        REPO / "src/aegis/zap_active_lease.py",
    ):
        source = module.read_text()
        imports = re.findall(r"^\s*(?:from|import)\s+([A-Za-z0-9_.]+)", source, re.M)
        for name in imports:
            assert not name.startswith(("aegis.planner", "aegis.llm", "aegis.providers")), name


def test_secret_material_is_absent_from_every_new_phase_1_5_file() -> None:
    patterns = [
        re.compile(r"sk-[A-Za-z0-9]{16,}"),
        re.compile(r"AI_AUTH_TOKEN\s*=\s*['\"][^'\"]+['\"]"),
        re.compile(r"(?i)\bpassword\s*=\s*['\"][^'\"]{3,}['\"]"),
        re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+\S+"),
    ]
    files = [
        *(REPO / "src/aegis_zap_active").rglob("*.py"),
        *(REPO / "src/zap_active_runner").rglob("*.py"),
        REPO / "src/aegis/zap_active_lease.py",
        REPO / "src/aegis/zap_active_verifier.py",
        REPO / "src/aegis/zap_active_test_env.py",
        REPO / "src/aegis/engine/zap_active.py",
        REPO / "deploy/zap-runner-active/Dockerfile",
        REPO / "docker-compose.zap-active.yml",
    ]
    for path in files:
        text = path.read_text()
        for pattern in patterns:
            assert not pattern.search(text), f"{path}: {pattern.pattern}"


def test_phase_1_5_files_exist_and_are_checked_in() -> None:
    for name in ACTIVE_FILES:
        assert (REPO / name).is_file(), name
    assert (REPO / "src/aegis_zap_active/manifest.json").is_file()
    assert (REPO / "docs/phase-1.5-zap-active-reflected-xss.md").is_file()


# --- 11. runner-enforced lease: the executor refuses what the registry does not arm ------------


def test_unarmed_valid_token_is_rejected_with_zero_traffic(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    """A valid signature alone is never permission to scan: nothing was armed, nothing runs."""
    fake, executor = _executor(tmp_path, guard)
    response = _run(executor, _request(), arm=False)
    assert response.status == "REJECTED"
    assert response.error_code is ZapActiveErrorCode.LEASE_NOT_ARMED
    assert response.lease.presented and not response.lease.consumed
    assert fake.run_calls() == [] and lab.paths == []
    assert guard.state.forwarded_total == 0 and guard.state.is_armed() is False


def test_expired_and_tampered_leases_are_rejected_with_zero_traffic(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    expired, _ = signed_lease_token(
        target=VULN, projection=VULN_PROJECTION, offset=-2_000, lifetime=600
    )
    response = executor.run(_request(lease_token=expired))
    assert response.status == "REJECTED"
    assert response.error_code is ZapActiveErrorCode.LEASE_EXPIRED
    tampered, _ = signed_lease_token(target=VULN, projection=VULN_PROJECTION)
    prefix, payload, signature = tampered.split(".")
    tampered = f"{prefix}.{payload}.{signature[:-1]}x"
    response = executor.run(_request(lease_token=tampered, suffix="ab"))
    assert response.status == "REJECTED"
    assert response.error_code is ZapActiveErrorCode.LEASE_SIGNATURE_INVALID
    assert fake.run_calls() == [] and lab.paths == []
    assert guard.state.forwarded_total == 0 and guard.state.is_armed() is False


def test_a_second_execution_with_the_same_lease_is_rejected(
    tmp_path: Path, guard: GuardHarness, lab: LabServer
) -> None:
    fake, executor = _executor(tmp_path, guard)
    request = _request()
    response = _run(executor, request)
    assert response.status == "COMPLETED" and response.lease.revoked_after_execution is True
    first_paths = list(lab.paths)
    assert set(first_paths) == {VULN_PROJECTION.path}
    # Same lease token, fresh nonce: the lease is terminal after exactly one execution.
    second = executor.run(request.model_copy(update={"nonce": "1" * 32}))
    assert second.status == "REJECTED"
    assert second.error_code is ZapActiveErrorCode.LEASE_ALREADY_CONSUMED
    assert lab.paths == first_paths  # zero new traffic
    assert len(fake.run_calls()) == 1


def test_guard_binding_disagreement_fails_before_spawn(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner must reject execution if the guard cannot confirm the same binding."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        return None  # the guard rejected the arm: the runner must not proceed

    monkeypatch.setattr(GuardClient, "arm_active", refuse)
    fake, executor = _executor(tmp_path, guard)
    response = _run(executor, _request())
    assert response.status == "FAILED"
    assert response.error_code is ZapActiveErrorCode.GUARD_BINDING_MISMATCH
    assert response.stages.zap_started is False
    assert fake.run_calls() == [] and lab.paths == []
    assert guard.state.forwarded_total == 0 and guard.state.is_armed() is False


def test_guard_client_disarms_when_the_guard_echoes_a_different_binding(
    guard: GuardHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The arm call compares the guard's echoed binding field-by-field and disarms on any drift."""

    client = GuardClient(guard.control_url)
    real_call = GuardClient._call  # noqa: SLF001 - the unbound method, called with self below

    def tampered(self: Any, path: str, payload: Any, model: Any) -> Any:
        response = real_call(self, path, payload, model)
        if path == "/v1/arm" and response is not None:
            response = response.model_copy(update={"projection_digest": "f" * 64})
        return response

    monkeypatch.setattr(GuardClient, "_call", tampered)
    armed = client.arm_active(
        execution_id="exec-0000000000aa",
        origin=LAB_ORIGIN,
        method="GET",
        path=VULN_PROJECTION.path,
        allowed_params=("q",),
        max_requests=8,
        ttl_ms=60_000,
        lease_id=ACTIVE_ARM_LEASE_ID,
        lease_expires_at=int(datetime.now(UTC).timestamp()) + 600,
        projection_digest=VULN_PROJECTION.digest,
        allowlist_digest=VULN_PROJECTION.allowlist_digest,
    )
    assert armed is None
    assert guard.state.is_armed() is False  # the disagreement disarmed the guard, never ran


def test_emergency_stop_between_guard_arm_and_spawn_never_starts_the_engine(
    tmp_path: Path, guard: GuardHarness, lab: LabServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stop landing in the window between guard arm and engine spawn wins: the engine is never
    started, the lease is revoked and the run reports STOPPED."""

    monkeypatch.setattr("zap_active_runner.execution.PENDING_SPAWN_WAIT_SECONDS", 1.0)
    fake, executor = _executor(tmp_path, guard)
    original = GuardClient.arm_active

    def stop_on_arm(self: Any, **kwargs: Any) -> Any:
        armed = original(self, **kwargs)
        if armed is not None:
            executor.emergency_stop()  # the stop lands while the guard is armed, before spawn
        return armed

    monkeypatch.setattr(GuardClient, "arm_active", stop_on_arm)
    request = _request()
    _arm_for(executor, request)
    response = executor.run(request)
    assert response.status == "STOPPED"
    assert response.error_code is ZapActiveErrorCode.EMERGENCY_STOP
    assert response.exit_class == "KILLED_BY_GUARD"
    assert response.coverage_complete is False and response.alerts == ()
    assert fake.run_calls() == []  # the engine was never started
    assert lab.paths == []  # and never reached the target
    assert guard.state.is_armed() is False
    assert executor.admission is not None
    assert executor.admission.registry.armed_record() is None
