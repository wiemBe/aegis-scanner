"""Execute one validated run request with the fixed profile, bounded in every dimension."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path

from aegis_nuclei.contracts import (
    RUNNER_VERSION,
    EngineAttestation,
    NucleiRunRequest,
    NucleiRunResponse,
    ParseSummary,
    RunnerErrorCode,
)
from aegis_nuclei.parser import PARSER_VERSION, AdmittedTemplate, parse_jsonl
from aegis_nuclei.profile import PROFILE_ID, PROFILE_VERSION, build_argv, child_environment
from aegis_nuclei.targets import NUCLEI_TARGETS, NucleiTarget
from nuclei_runner.attestation import (
    MAX_STDERR_SCAN_BYTES,
    RunnerState,
    machine_arch,
    stderr_facts,
    templates_unchanged,
    verify_binary,
)

MAX_STDOUT_BYTES = 262_144
_NONCE_MEMORY = 1024


def _file_digest_and_size(path: Path) -> tuple[str | None, int]:
    if not path.exists():
        return None, 0
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest(), size


class Executor:
    """Serializes executions (concurrency 1) and enforces every runner-side check."""

    def __init__(
        self,
        state: RunnerState,
        *,
        targets: dict[str, NucleiTarget] | None = None,
    ) -> None:
        self.state = state
        self.targets = targets if targets is not None else NUCLEI_TARGETS
        self._lock = threading.Lock()
        self._nonces: OrderedDict[str, None] = OrderedDict()
        self._nonce_lock = threading.Lock()

    # --- response helpers ------------------------------------------------------------------

    def _engine(self) -> EngineAttestation:
        return self.state.engine or EngineAttestation(
            nuclei_version="unknown", arch=machine_arch(), pinned=False
        )

    def _response(
        self,
        request: NucleiRunRequest,
        *,
        status: str,
        started: datetime,
        error: RunnerErrorCode | None = None,
        exit_class: str = "NOT_RUN",
        **extra: object,
    ) -> NucleiRunResponse:
        completed = datetime.now(UTC)
        payload: dict[str, object] = {
            "engine_execution_id": request.engine_execution_id,
            "job_id": request.job_id,
            "nonce": request.nonce,
            "runner_version": RUNNER_VERSION,
            "profile_id": PROFILE_ID,
            "profile_version": PROFILE_VERSION,
            "status": status,
            "error_code": error,
            "exit_class": exit_class,
            "engine": self._engine(),
            "template_set_id": self.state.manifest.template_set_id,
            "manifest_digest": self.state.manifest_digest,
            "templates": self.state.template_attestations(),
            "started_at": started,
            "completed_at": completed,
            "duration_ms": max(0, int((completed - started).total_seconds() * 1000)),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_bytes": 0,
            "parse": ParseSummary(
                parser_version=PARSER_VERSION,
                status="NOT_PARSED",
                lines=0,
                records=0,
                matched=0,
                unmatched=0,
                errored=0,
                duplicates_collapsed=0,
            ),
            "coverage_complete": False,
        }
        payload.update(extra)
        return NucleiRunResponse.model_validate(payload, strict=False)

    def _reject(
        self, request: NucleiRunRequest, code: RunnerErrorCode, started: datetime
    ) -> NucleiRunResponse:
        return self._response(request, status="REJECTED", started=started, error=code)

    # --- policy -------------------------------------------------------------------------------

    def _remember_nonce(self, nonce: str) -> bool:
        with self._nonce_lock:
            if nonce in self._nonces:
                return False
            self._nonces[nonce] = None
            while len(self._nonces) > _NONCE_MEMORY:
                self._nonces.popitem(last=False)
            return True

    def _policy_error(self, request: NucleiRunRequest) -> RunnerErrorCode | None:
        manifest = self.state.manifest
        if not self.state.ready:
            return RunnerErrorCode.RUNNER_NOT_READY
        if request.profile_id != PROFILE_ID:
            return RunnerErrorCode.UNKNOWN_PROFILE
        if request.template_set_id != manifest.template_set_id:
            return RunnerErrorCode.UNKNOWN_TEMPLATE_SET
        if request.manifest_digest != self.state.manifest_digest:
            return RunnerErrorCode.MANIFEST_DIGEST_MISMATCH
        target = self.targets.get(request.target_ref)
        if target is None:
            return RunnerErrorCode.UNKNOWN_TARGET
        if request.origin != target.origin:
            return RunnerErrorCode.ORIGIN_MISMATCH
        budgets = request.budgets
        if budgets.max_requests < manifest.total_max_requests or budgets.max_results < len(
            manifest.templates
        ):
            return RunnerErrorCode.BUDGET_OUT_OF_BOUNDS
        return None

    # --- execution ----------------------------------------------------------------------------

    def run(self, request: NucleiRunRequest) -> NucleiRunResponse:
        started = datetime.now(UTC)
        error = self._policy_error(request)
        if error is not None:
            return self._reject(request, error, started)
        if not self._remember_nonce(request.nonce):
            return self._reject(request, RunnerErrorCode.REPLAYED_NONCE, started)
        if not self._lock.acquire(blocking=False):
            return self._reject(request, RunnerErrorCode.BUSY, started)
        try:
            # Defense in depth: re-verify binary and template bytes immediately before exec.
            if not verify_binary(self.state):
                self.state.ready = False
                self.state.failure_codes.append("ENGINE_INTEGRITY_FAILURE")
                return self._reject(request, RunnerErrorCode.ENGINE_INTEGRITY_FAILURE, started)
            if not templates_unchanged(self.state):
                self.state.ready = False
                self.state.failure_codes.append("TEMPLATE_INTEGRITY_FAILURE")
                return self._reject(request, RunnerErrorCode.TEMPLATE_INTEGRITY_FAILURE, started)
            try:
                return self._execute(request, self.targets[request.target_ref], started)
            except Exception:  # unexpected runner fault: typed failure, never exception prose
                return self._response(
                    request,
                    status="FAILED",
                    started=started,
                    error=RunnerErrorCode.SPAWN_FAILED,
                    exit_class="SPAWN_FAILED",
                )
        finally:
            self._lock.release()

    def _execute(
        self, request: NucleiRunRequest, target: NucleiTarget, started: datetime
    ) -> NucleiRunResponse:
        state = self.state
        workdir = state.work_root / request.engine_execution_id
        home = workdir / "home"
        output = workdir / "results.jsonl"
        stdout_path = workdir / "stdout.bin"
        stderr_path = workdir / "stderr.bin"
        admitted = {
            entry.template_id: AdmittedTemplate(entry, state.template_root / entry.path)
            for entry in state.manifest.templates
        }
        budgets = request.budgets
        timeout_s = budgets.time_budget_ms / 1000
        max_time = max(5, min(120, int(timeout_s) - 2))
        exit_code: int | None = None
        exit_class = "OK"
        try:
            home.mkdir(parents=True, mode=0o700)
            argv = build_argv(
                binary=state.binary,
                template_paths=[a.absolute_path for a in admitted.values()],
                target_url=target.target_url,
                output_file=output,
                max_time_seconds=max_time,
            )
            with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
                try:
                    process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, clean env
                        argv,
                        stdin=subprocess.DEVNULL,
                        stdout=out,
                        stderr=err,
                        env=child_environment(home),
                        cwd=workdir,
                        shell=False,
                        close_fds=True,
                        start_new_session=True,
                    )
                except OSError:
                    return self._response(
                        request,
                        status="FAILED",
                        started=started,
                        error=RunnerErrorCode.SPAWN_FAILED,
                        exit_class="SPAWN_FAILED",
                    )
                try:
                    exit_code = process.wait(timeout=timeout_s)
                    exit_class = "OK" if exit_code == 0 else "NONZERO_EXIT"
                except subprocess.TimeoutExpired:
                    exit_class = "TIMEOUT"
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                    exit_code = None

            stdout_digest, stdout_bytes = _file_digest_and_size(stdout_path)
            stderr_digest, stderr_bytes = _file_digest_and_size(stderr_path)
            output_digest, output_bytes = _file_digest_and_size(output)
            with stderr_path.open("rb") as handle:
                facts = stderr_facts(handle.read(MAX_STDERR_SCAN_BYTES))
            metadata: dict[str, object] = {
                "exit_code": exit_code if exit_code is None or -128 <= exit_code <= 255 else None,
                "templates_loaded": facts.templates_loaded,
                "signed_templates_executed": facts.signed_executed,
                "unsigned_templates_skipped": facts.unsigned_skipped,
                "http_connections": facts.http_connections,
                "stdout_bytes": stdout_bytes,
                "stderr_bytes": stderr_bytes,
                "output_bytes": output_bytes,
                "output_sha256": output_digest,
                "stderr_sha256": stderr_digest,
            }
            del stdout_digest  # stdout mirrors findings; only its size is recorded

            def failed(code: RunnerErrorCode, cls: str, **more: object) -> NucleiRunResponse:
                return self._response(
                    request,
                    status="FAILED",
                    started=started,
                    error=code,
                    exit_class=cls,
                    **{**metadata, **more},
                )

            if exit_class == "TIMEOUT":
                return failed(RunnerErrorCode.EXECUTION_TIMEOUT, "TIMEOUT")
            if stdout_bytes > MAX_STDOUT_BYTES or output_bytes > budgets.max_output_bytes:
                return failed(RunnerErrorCode.OUTPUT_OVERSIZED, "OUTPUT_OVERSIZED")
            if facts.unsigned_skipped:
                return failed(RunnerErrorCode.UNSIGNED_TEMPLATE_SKIPPED, exit_class)
            if exit_class != "OK":
                code = RunnerErrorCode.ENGINE_FATAL if facts.fatal else RunnerErrorCode.NONZERO_EXIT
                return failed(code, "NONZERO_EXIT")
            if facts.signed_executed != len(admitted):
                return failed(RunnerErrorCode.SIGNATURE_NOT_VERIFIED, exit_class)
            if facts.http_connections is not None and facts.http_connections > budgets.max_requests:
                return failed(RunnerErrorCode.REQUEST_BUDGET_EXCEEDED, exit_class)

            data = output.read_bytes() if output.exists() else b""
            outcome = parse_jsonl(
                data,
                admitted=admitted,
                target=target,
                max_results=budgets.max_results,
                max_output_bytes=budgets.max_output_bytes,
            )
            if outcome.summary.status not in {"PARSED"}:
                code = outcome.summary.failure_code or RunnerErrorCode.OUTPUT_MALFORMED
                return failed(code, exit_class, parse=outcome.summary)
            return self._response(
                request,
                status="COMPLETED",
                started=started,
                error=None if outcome.coverage_complete else RunnerErrorCode.COVERAGE_INCOMPLETE,
                exit_class=exit_class,
                parse=outcome.summary,
                results=outcome.results,
                coverage_complete=outcome.coverage_complete,
                **metadata,
            )
        finally:
            state.executions_total += 1
            state.last_execution_at = datetime.now(UTC)
            shutil.rmtree(workdir, ignore_errors=True)
