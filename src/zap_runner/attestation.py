"""Boot-time and per-execution integrity attestation for the zap-runner.

The runner becomes READY only when every check passes:

1. its own process environment carries none of the variables that could inject JVM options,
   proxies, libraries or credentials;
2. the ZAP jar SHA-256 equals the manifest pin;
3. the JVM launcher, ``libjvm.so`` and ``release`` file equal the pins for this CPU architecture,
   and ``java -version`` reports exactly the pinned version and runtime build;
4. the install plugin directory contains EXACTLY the manifest add-on files (no extra file, no
   directory, no symlink), each byte-identical to its pin, and no forbidden add-on id;
5. the pinned ZAP itself, started headless with ``-silent -notel`` in a throwaway home, lists
   exactly the manifest add-ons at the pinned versions (``-addonlist``), logs the same installed
   set, and confirms silent mode (no update, news or telemetry calls);
6. the scope guard answers with the pinned guard version, IDLE state and the same origin allowlist.

A failure in any step leaves the runner NOT_READY; every run request is then rejected before ZAP is
started and before any target traffic. Drift is never "upgraded" at runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegis_zap.contracts import (
    RUNNER_VERSION,
    AddOnAttestation,
    RunnerGuardState,
    ZapEngineAttestation,
    ZapRunnerAttestation,
)
from aegis_zap.facts import (
    add_on_list_facts,
    java_version_facts,
    normalize_add_on_version,
    zap_log_facts,
)
from aegis_zap.inventory import ZAP_TARGETS
from aegis_zap.manifest import ZapManifest, file_sha256
from aegis_zap.parser import PARSER_VERSION
from aegis_zap.profile import (
    DANGEROUS_ENV_NAMES,
    DANGEROUS_ENV_PREFIXES,
    PROFILE_ID,
    PROFILE_VERSION,
    child_environment,
)
from aegis_zap.projection import PROJECTION_VERSION
from zap_runner.guard_client import GuardClient

EXPECTED_GUARD_VERSION = "zap-scope-guard/1.3.0"
MAX_CAPTURE_BYTES = 262_144


def machine_arch() -> str:
    machine = platform.machine().lower()
    return {"aarch64": "linux_arm64", "arm64": "linux_arm64", "x86_64": "linux_amd64"}.get(
        machine, f"unsupported:{machine}"[:24]
    )


@dataclass(frozen=True)
class RunnerPaths:
    """Fixed filesystem and network locations. Tests re-point them at scripted doubles."""

    zap_root: Path
    jar: Path
    plugin_dir: Path
    java_home: Path
    work_root: Path
    guard_control_url: str
    guard_proxy_host: str
    guard_proxy_port: int

    @property
    def java(self) -> Path:
        return self.java_home / "bin" / "java"


def dangerous_environment(environ: dict[str, str]) -> list[str]:
    return sorted(
        name
        for name in environ
        if name in DANGEROUS_ENV_NAMES or name.upper().startswith(DANGEROUS_ENV_PREFIXES)
    )


def run_fixed(argv: list[str], *, home: Path, timeout: float) -> tuple[int | None, bytes]:
    """Run a fixed argv with a constructed environment; return (exit code, bounded output)."""

    with tempfile.TemporaryFile(dir=home) as out:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False, clean env
                argv,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                env=child_environment(home),
                cwd=home,
                timeout=timeout,
                check=False,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
            code: int | None = completed.returncode
        except (OSError, subprocess.TimeoutExpired):
            code = None
        out.seek(0)
        return code, out.read(MAX_CAPTURE_BYTES)


def read_bounded(path: Path, limit: int) -> bytes | None:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


@dataclass
class RunnerState:
    manifest: ZapManifest
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

    def attestation(self) -> ZapRunnerAttestation:
        return ZapRunnerAttestation(
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
            addonlist_verified=self.addonlist_verified,
            java_verified=self.java_verified,
            admitted_rule_ids=tuple(r.plugin_id for r in self.manifest.passive_rules),
            guard=self.guard_state(),
            booted_at=self.booted_at,
            executions_total=self.executions_total,
            rejections_total=self.rejections_total,
            last_execution_at=self.last_execution_at,
        )


def verify_engine_files(state: RunnerState) -> bool:
    """Jar + per-architecture JVM file pins. Cheap enough to repeat before every execution."""

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


def verify_add_on_files(state: RunnerState) -> bool:
    """The install plugin directory must contain exactly the pinned add-on files."""

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


def _addonlist_argv(state: RunnerState, home: Path) -> list[str]:
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


def verify_runtime_inventory(state: RunnerState) -> list[str]:
    """Ask the pinned JVM and the pinned ZAP what they actually load. Returns failure codes."""

    failures: list[str] = []
    home = Path(tempfile.mkdtemp(prefix="attest-", dir=state.paths.work_root))
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
        if log.active_rules_loaded:
            failures.append("ACTIVE_RULES_LOADED")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return failures


def verify_guard(state: RunnerState) -> bool:
    attestation = state.guard.attestation()
    origins = {target.origin for target in ZAP_TARGETS.values()}
    return bool(
        attestation is not None
        and attestation.guard_version == EXPECTED_GUARD_VERSION
        and set(attestation.allowed_origins) == origins
    )


def attest(state: RunnerState, environ: dict[str, str] | None = None) -> RunnerState:
    """Run the full boot attestation. Idempotent; records failure codes, never raises."""

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
