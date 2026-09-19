"""Boot-time and per-execution integrity attestation for the nuclei-runner.

The runner becomes READY only when every check passes:

1. its own process environment carries none of the variables that could redirect or weaken Nuclei
   (``NUCLEI_ARGS``, ``NUCLEI_SIGNATURE_PUBLIC_KEY``, ``PDCP_API_KEY``, proxies, AI credentials);
2. the Nuclei binary's SHA-256 equals the manifest pin for this CPU architecture;
3. the binary reports exactly the pinned version;
4. every manifest template is present, byte-identical and passes static admission, the template
   tree contains nothing else, and the upstream license file matches its pin;
5. the pinned binary validates the admitted template set (``-validate``);
6. a signature probe — the full fixed profile, including ``-disable-unsigned-templates``, aimed at
   a closed LOOPBACK port so no packet leaves the container — reports that exactly the admitted
   templates execute as signed ProjectDiscovery templates.

A failure in any step leaves the runner NOT_READY; every run request is then rejected before any
target traffic.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegis_nuclei.admission import TemplateAdmission, admit_manifest, unexpected_template_files
from aegis_nuclei.contracts import (
    RUNNER_VERSION,
    EngineAttestation,
    RunnerAttestation,
    TemplateAttestation,
)
from aegis_nuclei.manifest import TemplateManifest, file_sha256
from aegis_nuclei.parser import PARSER_VERSION
from aegis_nuclei.profile import (
    DANGEROUS_ENV_NAMES,
    DANGEROUS_ENV_PREFIXES,
    PROFILE_ID,
    PROFILE_VERSION,
    build_argv,
    child_environment,
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VERSION_LINE = re.compile(r"Nuclei Engine Version: (v\d+\.\d+\.\d+)")
_SIGNED_LINE = re.compile(
    r"Executing (\d+) signed templates from projectdiscovery/nuclei-templates"
)
_UNSIGNED_LINE = re.compile(r"Skipping (\d+) unsigned template")
_LOADED_LINE = re.compile(r"Templates loaded for current scan: (\d+)")
_CONNECTIONS_LINE = re.compile(r"HTTP connections: (\d+) total")
_FATAL_LINE = re.compile(r"\[FTL\]")
_VALIDATED_LINE = re.compile(r"All templates validated successfully")

# Signature probe target: a closed port on the runner's own loopback interface.
SIGNATURE_PROBE_URL = "http://127.0.0.1:9"
MAX_STDERR_SCAN_BYTES = 65_536


@dataclass(frozen=True)
class StderrFacts:
    """The only facts ever derived from Nuclei stderr. The text itself is never returned."""

    version: str | None = None
    templates_loaded: int | None = None
    signed_executed: int | None = None
    unsigned_skipped: int | None = None
    http_connections: int | None = None
    fatal: bool = False
    validated: bool = False


def stderr_facts(data: bytes) -> StderrFacts:
    text = _ANSI.sub("", data[:MAX_STDERR_SCAN_BYTES].decode("utf-8", errors="replace"))

    def number(pattern: re.Pattern[str]) -> int | None:
        found = pattern.search(text)
        return int(found.group(1)) if found else None

    version = _VERSION_LINE.search(text)
    return StderrFacts(
        version=version.group(1) if version else None,
        templates_loaded=number(_LOADED_LINE),
        signed_executed=number(_SIGNED_LINE),
        unsigned_skipped=number(_UNSIGNED_LINE),
        http_connections=number(_CONNECTIONS_LINE),
        fatal=bool(_FATAL_LINE.search(text)),
        validated=bool(_VALIDATED_LINE.search(text)),
    )


def machine_arch() -> str:
    machine = platform.machine().lower()
    return {"aarch64": "linux_arm64", "arm64": "linux_arm64", "x86_64": "linux_amd64"}.get(
        machine, f"unsupported:{machine}"[:16]
    )


def dangerous_environment(environ: dict[str, str]) -> list[str]:
    return sorted(
        name
        for name in environ
        if name in DANGEROUS_ENV_NAMES or name.upper().startswith(DANGEROUS_ENV_PREFIXES)
    )


def run_fixed(argv: list[str], *, home: Path, timeout: float) -> tuple[int | None, bytes]:
    """Run a fixed argv with a constructed environment; return (exit code, bounded stderr)."""

    with tempfile.TemporaryFile() as err:
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False, clean env
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=err,
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
        err.seek(0)
        return code, err.read(MAX_STDERR_SCAN_BYTES)


@dataclass
class RunnerState:
    manifest: TemplateManifest
    manifest_digest: str
    binary: Path
    template_root: Path
    work_root: Path
    booted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ready: bool = False
    failure_codes: list[str] = field(default_factory=list)
    engine: EngineAttestation | None = None
    admissions: list[TemplateAdmission] = field(default_factory=list)
    unexpected_files: int = 0
    signature_probe: str = "NOT_RUN"
    executions_total: int = 0
    last_execution_at: datetime | None = None

    def template_attestations(self) -> tuple[TemplateAttestation, ...]:
        verified = self.signature_probe == "SIGNED_VERIFIED"
        items = []
        for admission in self.admissions:
            if not admission.admitted:
                status = "REJECTED"
            elif verified:
                status = "SIGNED_VERIFIED"
            else:
                status = "SIGNATURE_LINE_PRESENT"
            items.append(
                TemplateAttestation(
                    template_id=admission.template_id,
                    path=admission.path,
                    sha256=admission.sha256,
                    admitted=admission.admitted,
                    signature_status=status,  # type: ignore[arg-type]
                    violations=admission.violations[:32],
                )
            )
        return tuple(items)

    def attestation(self) -> RunnerAttestation:
        return RunnerAttestation(
            runner_version=RUNNER_VERSION,
            ready=self.ready,
            failure_codes=tuple(self.failure_codes[:32]),
            engine=self.engine
            or EngineAttestation(nuclei_version="unknown", arch=machine_arch(), pinned=False),
            profile_id=PROFILE_ID,
            profile_version=PROFILE_VERSION,
            parser_version=PARSER_VERSION,
            template_set_id=self.manifest.template_set_id,
            manifest_version=self.manifest.manifest_version,
            manifest_digest=self.manifest_digest,
            templates=self.template_attestations(),
            unexpected_template_files=self.unexpected_files,
            signature_probe=self.signature_probe,  # type: ignore[arg-type]
            booted_at=self.booted_at,
            executions_total=self.executions_total,
            last_execution_at=self.last_execution_at,
        )


def verify_binary(state: RunnerState) -> bool:
    arch = machine_arch()
    artifact = state.manifest.engine.artifacts.get(arch)  # type: ignore[call-overload]
    try:
        digest = file_sha256(state.binary)
    except OSError:
        digest = None
    pinned = artifact is not None and digest == artifact.binary_sha256
    state.engine = EngineAttestation(
        nuclei_version=state.engine.nuclei_version if state.engine else "unknown",
        binary_sha256=digest,
        arch=arch,
        pinned=pinned,
    )
    return pinned


def verify_templates(state: RunnerState) -> bool:
    state.admissions = admit_manifest(state.template_root, state.manifest)
    state.unexpected_files = len(unexpected_template_files(state.template_root, state.manifest))
    license_path = state.template_root / state.manifest.upstream_templates.license_file
    try:
        license_ok = file_sha256(license_path) == state.manifest.upstream_templates.license_sha256
    except OSError:
        license_ok = False
    return all(a.admitted for a in state.admissions) and state.unexpected_files == 0 and license_ok


def admitted_paths(state: RunnerState) -> list[Path]:
    return [state.template_root / entry.path for entry in state.manifest.templates]


def attest(state: RunnerState, environ: dict[str, str] | None = None) -> RunnerState:
    """Run the full boot attestation. Idempotent; records failure codes, never raises."""

    failures: list[str] = []
    if dangerous_environment(dict(os.environ if environ is None else environ)):
        failures.append("DANGEROUS_ENVIRONMENT")
    if not verify_binary(state):
        failures.append("ENGINE_INTEGRITY_FAILURE")
    if not verify_templates(state):
        failures.append("TEMPLATE_INTEGRITY_FAILURE")

    home = Path(tempfile.mkdtemp(prefix="attest-", dir=state.work_root))
    try:
        if "ENGINE_INTEGRITY_FAILURE" not in failures:
            _, err = run_fixed([str(state.binary), "-version"], home=home, timeout=30)
            version = stderr_facts(err).version
            assert state.engine is not None
            state.engine = state.engine.model_copy(update={"nuclei_version": version or "unknown"})
            if version != state.manifest.engine.version:
                failures.append("ENGINE_VERSION_MISMATCH")
        if not failures:
            argv = [str(state.binary), "-duc", "-validate"]
            for path in admitted_paths(state):
                argv += ["-t", str(path)]
            code, err = run_fixed(argv, home=home, timeout=60)
            if code != 0 or not stderr_facts(err).validated:
                failures.append("TEMPLATE_VALIDATION_FAILED")
        state.signature_probe = "NOT_RUN"
        if not failures:
            argv = build_argv(
                binary=state.binary,
                template_paths=admitted_paths(state),
                target_url=SIGNATURE_PROBE_URL,
                output_file=home / "probe.jsonl",
                max_time_seconds=20,
            )
            _, err = run_fixed(argv, home=home, timeout=40)
            facts = stderr_facts(err)
            expected = len(state.manifest.templates)
            if facts.signed_executed == expected and not facts.unsigned_skipped:
                state.signature_probe = "SIGNED_VERIFIED"
            else:
                state.signature_probe = "FAILED"
                failures.append("SIGNATURE_NOT_VERIFIED")
    finally:
        shutil.rmtree(home, ignore_errors=True)

    state.failure_codes = failures
    state.ready = not failures
    return state


def templates_unchanged(state: RunnerState) -> bool:
    """Per-execution re-check of every admitted template's bytes (defense in depth)."""

    try:
        return all(
            file_sha256(state.template_root / entry.path) == entry.sha256
            for entry in state.manifest.templates
        )
    except OSError:
        return False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
