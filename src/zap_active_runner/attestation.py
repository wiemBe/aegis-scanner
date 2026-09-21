"""Boot-time and per-execution integrity attestation for the active zap-runner (Phase 1.5).

Mirrors the passive runner's attestation but for the 11-add-on active manifest and the active
profile. The only behavioural differences are:

- the expected add-on set is the 11 active add-ons (the 8 passive add-ons plus ``ascanrules`` and
  its neutralised forced dependencies ``oast`` and ``database``);
- at boot the pinned ZAP DOES load active scan rules (ascanrules is present), so a non-zero active
  rule count is expected rather than a failure. The 40012-only restriction is applied at scan time
  by the fixed activeScan policy, not by the absence of the add-on;
- the neutralised dependency ids are attested so the console can show why oast/database exist.

Generic, state-free helpers (subprocess launch, bounded reads, arch, dangerous-env, file digests)
are reused from the passive runner and the manifest module unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegis_zap.facts import (
    add_on_list_facts,
    java_version_facts,
    normalize_add_on_version,
    zap_log_facts,
)
from aegis_zap.manifest import file_sha256
from aegis_zap_active.contracts import (
    RUNNER_VERSION,
    AddOnAttestation,
    RunnerGuardState,
    ZapActiveRunnerAttestation,
    ZapEngineAttestation,
)
from aegis_zap_active.manifest import ZapActiveManifest
from aegis_zap_active.parser import PARSER_VERSION
from aegis_zap_active.profile import PROFILE_ID, PROFILE_VERSION
from aegis_zap_active.projection import PROJECTION_VERSION
from zap_runner.attestation import (
    EXPECTED_GUARD_VERSION,
    MAX_CAPTURE_BYTES,
    RunnerPaths,
    dangerous_environment,
    machine_arch,
    read_bounded,
    run_fixed,
)
from zap_runner.guard_client import GuardClient

ACTIVE_ORIGINS = ("http://lab-api:8001",)


@dataclass
class ActiveRunnerState:
    manifest: ZapActiveManifest
    manifest_digest: str
    paths: RunnerPaths
    guard: GuardClient
    booted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ready: bool = False
    failure_codes: list[str] = field(default_factory=list)
    jar_sha256: str | None = None
    java_version: str | None = None
    java_runtime_version: str | None = None
    java_verified: bool = False
    add_ons: list[AddOnAttestation] = field(default_factory=list)
    unexpected_plugin_files: int = 0
    forbidden_add_ons_present: list[str] = field(default_factory=list)
    addonlist_verified: bool = False
    executions_total: int = 0
    rejections_total: int = 0
    last_execution_at: datetime | None = None

    def inventory_digest(self) -> str | None:
        if (
            not self.add_ons
            or not all(a.pinned for a in self.add_ons)
            or self.unexpected_plugin_files
        ):
            return None
        rows = sorted((a.id, a.version, a.sha256) for a in self.add_ons)
        return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()

    def engine(self) -> ZapEngineAttestation:
        pinned = bool(
            self.jar_sha256 == self.manifest.engine.jar.sha256
            and self.java_verified
            and self.inventory_digest() is not None
            and self.addonlist_verified
        )
        return ZapEngineAttestation(
            zap_version=self.manifest.engine.version if pinned else "unverified",
            jar_sha256=self.jar_sha256,
            java_version=self.java_version,
            java_runtime_version=self.java_runtime_version,
            arch=machine_arch(),
            add_on_inventory_digest=self.inventory_digest(),
            pinned=pinned,
        )

    def guard_state(self) -> RunnerGuardState:
        attestation = self.guard.attestation()
        if attestation is None:
            return RunnerGuardState(reachable=False)
        return RunnerGuardState(
            reachable=True,
            guard_version=attestation.guard_version,
            state=attestation.state,
            allowed_origins=attestation.allowed_origins,
            forwarded_total=attestation.forwarded_total,
            blocked_total=attestation.blocked_total,
        )

    def attestation(self) -> ZapActiveRunnerAttestation:
        return ZapActiveRunnerAttestation(
            runner_version=RUNNER_VERSION,
            ready=self.ready,
            failure_codes=tuple(self.failure_codes[:32]),
            engine=self.engine(),
            profile_id=PROFILE_ID,
            profile_version=PROFILE_VERSION,
            parser_version=PARSER_VERSION,
            projection_version=PROJECTION_VERSION,
            manifest_version=self.manifest.manifest_version,
            manifest_digest=self.manifest_digest,
            add_ons=tuple(self.add_ons),
            unexpected_plugin_files=self.unexpected_plugin_files,
            forbidden_add_ons_present=tuple(self.forbidden_add_ons_present[:64]),
            neutralised_dependency_ids=self.manifest.neutralised_dependency_ids,
            addonlist_verified=self.addonlist_verified,
            java_verified=self.java_verified,
            admitted_rule_ids=tuple(r.plugin_id for r in self.manifest.active_rules),
            guard=self.guard_state(),
            booted_at=self.booted_at,
            executions_total=self.executions_total,
            rejections_total=self.rejections_total,
            last_execution_at=self.last_execution_at,
        )


def verify_engine_files(state: ActiveRunnerState) -> bool:
    paths, pins = state.paths, state.manifest.engine
    try:
        state.jar_sha256 = file_sha256(paths.jar)
    except OSError:
        state.jar_sha256 = None
    java_pin = pins.java.platforms.get(machine_arch())  # type: ignore[call-overload]
    if java_pin is None:
        return False
    try:
        jvm_ok = (
            file_sha256(paths.java.resolve()) == java_pin.java_sha256
            and file_sha256((paths.java_home / "lib" / "server" / "libjvm.so").resolve())
            == java_pin.libjvm_sha256
            and file_sha256(paths.java_home / "release") == java_pin.release_sha256
        )
    except OSError:
        jvm_ok = False
    return state.jar_sha256 == pins.jar.sha256 and jvm_ok


def verify_add_on_files(state: ActiveRunnerState) -> bool:
    manifest, plugin_dir = state.manifest, state.paths.plugin_dir
    expected = {a.file: a for a in manifest.add_ons}
    forbidden = set(manifest.forbidden_add_on_ids)
    attestations: list[AddOnAttestation] = []
    unexpected = 0
    forbidden_present: list[str] = []
    try:
        entries = sorted(plugin_dir.iterdir())
    except OSError:
        entries = []
    present = {entry.name for entry in entries}
    for entry in entries:
        add_on_id = entry.name.split("-", 1)[0]
        if add_on_id in forbidden:
            forbidden_present.append(add_on_id)
        if entry.name not in expected or entry.is_symlink() or not entry.is_file():
            unexpected += 1
    for name, pin in sorted(expected.items()):
        path = plugin_dir / name
        digest: str | None = None
        if name in present and path.is_file() and not path.is_symlink():
            try:
                digest = file_sha256(path)
            except OSError:
                digest = None
        attestations.append(
            AddOnAttestation(
                id=pin.id,
                version=pin.version,
                file=name,
                sha256=digest,
                pinned=digest == pin.sha256,
            )
        )
    state.add_ons = attestations
    state.unexpected_plugin_files = unexpected
    state.forbidden_add_ons_present = sorted(set(forbidden_present))
    return all(a.pinned for a in attestations) and not unexpected and not forbidden_present


def _addonlist_argv(state: ActiveRunnerState, home: Path) -> list[str]:
    return [
        str(state.paths.java),
        "-Xmx512m",
        "-XX:-UsePerfData",
        "-Djava.awt.headless=true",
        f"-Djava.io.tmpdir={home}",
        f"-Duser.home={home}",
        "-jar",
        str(state.paths.jar),
        "-cmd",
        "-silent",
        "-notel",
        "-dir",
        str(home / "zap"),
        "-config",
        "callhome.tel.enabled=false",
        "-addonlist",
    ]


def verify_runtime_inventory(state: ActiveRunnerState) -> list[str]:
    """Ask the pinned JVM and ZAP what they load. Active rules ARE expected to load at boot."""

    failures: list[str] = []
    home = Path(tempfile.mkdtemp(prefix="attest-active-", dir=state.paths.work_root))
    try:
        _, out = run_fixed([str(state.paths.java), "-version"], home=home, timeout=30)
        version, runtime = java_version_facts(out)
        state.java_version, state.java_runtime_version = version, runtime
        java_pin = state.manifest.engine.java
        state.java_verified = version == java_pin.version and runtime == java_pin.runtime_version
        if not state.java_verified:
            failures.append("JAVA_VERSION_MISMATCH")
            return failures
        code, out = run_fixed(_addonlist_argv(state, home), home=home, timeout=120)
        listed = {(i, normalize_add_on_version(v)) for i, v, _ in add_on_list_facts(out).add_ons}
        log = zap_log_facts(read_bounded(home / "zap" / "zap.log", MAX_CAPTURE_BYTES) or b"")
        logged = {(i, normalize_add_on_version(v)) for i, v in log.installed_add_ons}
        expected = state.manifest.add_on_set
        state.addonlist_verified = code == 0 and listed == expected and logged == expected
        if not state.addonlist_verified:
            failures.append("ADDON_RUNTIME_MISMATCH")
        if not log.silent_mode:
            failures.append("SILENT_MODE_NOT_CONFIRMED")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return failures


def verify_guard(state: ActiveRunnerState) -> bool:
    attestation = state.guard.attestation()
    return bool(
        attestation is not None
        and attestation.guard_version == EXPECTED_GUARD_VERSION
        and set(attestation.allowed_origins) == set(ACTIVE_ORIGINS)
    )


def attest(state: ActiveRunnerState, environ: dict[str, str] | None = None) -> ActiveRunnerState:
    failures: list[str] = []
    if dangerous_environment(dict(os.environ if environ is None else environ)):
        failures.append("DANGEROUS_ENVIRONMENT")
    if not verify_engine_files(state):
        failures.append("ENGINE_INTEGRITY_FAILURE")
    if not verify_add_on_files(state):
        failures.append("ADDON_INVENTORY_DRIFT")
    if not failures:
        failures.extend(verify_runtime_inventory(state))
    if not verify_guard(state):
        failures.append("GUARD_NOT_ATTESTED")
    state.failure_codes = failures
    state.ready = not failures
    return state
