"""Execute one validated run request with the fixed profile, bounded in every dimension.

Order of operations (every step fails closed; ZAP is started only after all pre-checks):

1. revalidate the request: READY, profile, known target, projection REF, independently re-derived
   projection digest and operation-allowlist digest, budgets equal to the projection, nonce;
2. re-verify the jar, JVM and add-on file pins (drift makes the runner NOT READY);
3. write the projected OpenAPI bytes and generate the fixed plan; read the plan back from disk and
   validate it against the profile (byte-equal, no forbidden job/key);
4. ARM the scope guard for exactly the projected (method, path) set and the hard request budget;
5. start ZAP (fixed argv, constructed environment, no shell) and poll the guard: any blocked
   request, budget excess, wall-clock excess or oversized output kills ZAP's process group;
6. DISARM the guard and take its independent counters as the authoritative traffic record;
7. derive typed facts from ZAP stdout/zap.log, classify, and only then parse the report;
8. destroy the whole per-execution directory (ZAP home, session database, projection, plan,
   report and logs) — nothing raw survives the execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_zap.contracts import (
    RUNNER_VERSION,
    GuardCounters,
    PlanFacts,
    ProjectionFacts,
    StageFacts,
    ZapParseSummary,
    ZapRunnerErrorCode,
    ZapRunRequest,
    ZapRunResponse,
)
from aegis_zap.facts import (
    AutomationFacts,
    ZapLogFacts,
    automation_facts,
    normalize_add_on_version,
    zap_log_facts,
)
from aegis_zap.inventory import SOURCES_DIR, ZAP_TARGETS, ZapTarget, source_bytes
from aegis_zap.parser import PARSER_VERSION, parse_report
from aegis_zap.profile import (
    JOB_SEQUENCE,
    PROFILE_ID,
    PROFILE_VERSION,
    REPORT_FILE,
    build_argv,
    build_plan,
    child_environment,
    plan_bytes,
    plan_digest,
    validate_plan,
)
from aegis_zap.projection import (
    ProjectionRejected,
    ProjectionResult,
    project,
    projection_ref,
)
from zap_runner.attestation import (
    MAX_CAPTURE_BYTES,
    RunnerState,
    read_bounded,
    verify_add_on_files,
    verify_engine_files,
)

MAX_STDOUT_BYTES = 1_048_576
MAX_DURATION_MS = 600_000
POLL_SECONDS = 0.2
GUARD_POLL_SECONDS = 0.5
_NONCE_MEMORY = 1024
_SCOPE_REASONS = frozenset({"PATH", "ORIGIN", "METHOD", "MALFORMED_TARGET", "NOT_ARMED"})


def _digest_and_size(path: Path) -> tuple[str | None, int]:
    if not path.exists():
        return None, 0
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL is not ignorable
        pass


class Executor:
    """Serializes executions (concurrency 1) and enforces every runner-side check."""

    def __init__(
        self,
        state: RunnerState,
        *,
        targets: dict[str, ZapTarget] | None = None,
        sources_dir: Path = SOURCES_DIR,
        wall_clock_cap_seconds: float | None = None,
    ) -> None:
        self.state = state
        self.targets = targets if targets is not None else ZAP_TARGETS
        self.sources_dir = sources_dir
        # Only ever LOWERS the controller's time budget (the offline suite uses it to exercise the
        # timeout path quickly); it can never extend it.
        self.wall_clock_cap_seconds = wall_clock_cap_seconds
        self._lock = threading.Lock()
        self._nonces: OrderedDict[str, None] = OrderedDict()
        self._nonce_lock = threading.Lock()

    # --- response helpers ------------------------------------------------------------------

    def _response(
        self,
        request: ZapRunRequest,
        *,
        status: str,
        started: datetime,
        error: ZapRunnerErrorCode | None = None,
        exit_class: str = "NOT_RUN",
        **extra: Any,
    ) -> ZapRunResponse:
        completed = datetime.now(UTC)
        payload: dict[str, Any] = {
            "engine_execution_id": request.engine_execution_id,
            "job_id": request.job_id,
            "nonce": request.nonce,
            "runner_version": RUNNER_VERSION,
            "profile_id": PROFILE_ID,
            "profile_version": PROFILE_VERSION,
            "status": status,
            "error_code": error,
            "exit_class": exit_class,
            "engine": self.state.engine(),
            "plan": PlanFacts(validated=False),
            "stages": StageFacts(),
            "started_at": started,
            "completed_at": completed,
            # Wall-clock based, so a host clock jump (e.g. the lab host sleeping mid-run) can
            # exceed the contract bound; clamp instead of failing to report the typed outcome.
            "duration_ms": min(
                MAX_DURATION_MS, max(0, int((completed - started).total_seconds() * 1000))
            ),
            "stdout_bytes": 0,
            "report_bytes": 0,
            "session_destroyed": True,
            "parse": ZapParseSummary(
                parser_version=PARSER_VERSION,
                status="NOT_PARSED",
                sites=0,
                alerts=0,
                instances=0,
                records=0,
                duplicates_collapsed=0,
            ),
            "coverage_complete": False,
        }
        payload.update(extra)
        return ZapRunResponse.model_validate(payload, strict=False)

    def _reject(
        self, request: ZapRunRequest, code: ZapRunnerErrorCode, started: datetime, **extra: Any
    ) -> ZapRunResponse:
        self.state.rejections_total += 1
        return self._response(request, status="REJECTED", started=started, error=code, **extra)

    # --- policy ----------------------------------------------------------------------------

    def _remember_nonce(self, nonce: str) -> bool:
        with self._nonce_lock:
            if nonce in self._nonces:
                return False
            self._nonces[nonce] = None
            while len(self._nonces) > _NONCE_MEMORY:
                self._nonces.popitem(last=False)
            return True

    def _policy(
        self, request: ZapRunRequest
    ) -> tuple[ZapRunnerErrorCode | None, ZapTarget | None, ProjectionResult | None]:
        if not self.state.ready:
            return ZapRunnerErrorCode.RUNNER_NOT_READY, None, None
        if request.profile_id != PROFILE_ID:
            return ZapRunnerErrorCode.UNKNOWN_PROFILE, None, None
        target = self.targets.get(request.target_ref)
        if target is None:
            return ZapRunnerErrorCode.UNKNOWN_TARGET, None, None
        if request.projection_ref != projection_ref(target.target_ref):
            return ZapRunnerErrorCode.PROJECTION_REF_MISMATCH, target, None
        try:
            # The runner re-derives the projection from ITS OWN copy of the inventory; it never
            # receives OpenAPI content from the caller.
            projection = project(target, source_bytes(target, self.sources_dir))
        except (ProjectionRejected, OSError, ValueError):
            return ZapRunnerErrorCode.PROJECTION_REJECTED, target, None
        if projection.digest != request.projection_digest:
            return ZapRunnerErrorCode.PROJECTION_DIGEST_MISMATCH, target, projection
        if projection.allowlist_digest != request.operation_allowlist_digest:
            return ZapRunnerErrorCode.ALLOWLIST_DIGEST_MISMATCH, target, projection
        budgets = request.budgets
        if (
            budgets.max_requests != projection.operation_count
            or budgets.max_requests != target.expected_requests
        ):
            return ZapRunnerErrorCode.BUDGET_OUT_OF_BOUNDS, target, projection
        return None, target, projection

    # --- execution -------------------------------------------------------------------------

    def run(self, request: ZapRunRequest) -> ZapRunResponse:
        started = datetime.now(UTC)
        error, target, projection = self._policy(request)
        if error is not None or target is None or projection is None:
            return self._reject(request, error or ZapRunnerErrorCode.INVALID_REQUEST, started)
        if not self._remember_nonce(request.nonce):
            return self._reject(request, ZapRunnerErrorCode.REPLAYED_NONCE, started)
        if not self._lock.acquire(blocking=False):
            return self._reject(request, ZapRunnerErrorCode.BUSY, started)
        try:
            # Defense in depth: re-verify engine and add-on bytes immediately before exec.
            if not verify_engine_files(self.state):
                self.state.ready = False
                self.state.failure_codes.append("ENGINE_INTEGRITY_FAILURE")
                return self._reject(request, ZapRunnerErrorCode.ENGINE_INTEGRITY_FAILURE, started)
            if not verify_add_on_files(self.state):
                self.state.ready = False
                self.state.failure_codes.append("ADDON_INVENTORY_DRIFT")
                return self._reject(request, ZapRunnerErrorCode.ADDON_INVENTORY_DRIFT, started)
            try:
                return self._execute(request, target, projection, started)
            except Exception:  # unexpected runner fault: typed failure, never exception prose
                return self._response(
                    request,
                    status="FAILED",
                    started=started,
                    error=ZapRunnerErrorCode.SPAWN_FAILED,
                    exit_class="SPAWN_FAILED",
                )
        finally:
            self._lock.release()

    def _projection_facts(self, projection: ProjectionResult) -> ProjectionFacts:
        return ProjectionFacts(
            projection_ref=projection_ref(projection.target_ref),
            projection_version=projection.projection_version,
            digest=projection.digest,
            allowlist_digest=projection.allowlist_digest,
            source_sha256=projection.source_sha256,
            operation_count=projection.operation_count,
            path_count=projection.path_count,
            redaction_status=projection.redaction_status,  # type: ignore[arg-type]
        )

    def _execute(
        self,
        request: ZapRunRequest,
        target: ZapTarget,
        projection: ProjectionResult,
        started: datetime,
    ) -> ZapRunResponse:
        workdir = self.state.paths.work_root / request.engine_execution_id
        armed: list[str] = []
        try:
            response = self._prepare_and_run(
                request, target, projection, started, workdir, armed
            )
        finally:
            if armed:
                self.state.guard.disarm(armed[0])  # safety net; the normal path disarms first
            shutil.rmtree(workdir, ignore_errors=True)
            self.state.last_execution_at = datetime.now(UTC)
        # Reported only after the fact: the ZAP home, session database, projection, plan, report
        # and logs are gone.
        return response.model_copy(update={"session_destroyed": not workdir.exists()})

    def _prepare_and_run(
        self,
        request: ZapRunRequest,
        target: ZapTarget,
        projection: ProjectionResult,
        started: datetime,
        workdir: Path,
        armed_tokens: list[str],
    ) -> ZapRunResponse:
        state = self.state
        paths = state.paths
        zap_home, tmp_dir, out_dir = workdir / "home", workdir / "tmp", workdir / "out"
        api_file, plan_file = workdir / "projection.json", workdir / "plan.yaml"
        stdout_path = workdir / "zap-stdout.bin"
        rules = state.manifest.passive_rules
        extra: dict[str, Any] = {"projection": self._projection_facts(projection)}
        workdir.mkdir(mode=0o700)
        for directory in (zap_home, tmp_dir, out_dir):
            directory.mkdir(mode=0o700)
        api_file.write_bytes(projection.document)
        plan = build_plan(projection=projection, api_file=api_file, report_dir=out_dir, rules=rules)
        plan_file.write_bytes(plan_bytes(plan))
        # Validate exactly what ZAP will read, not the in-memory object.
        try:
            on_disk = json.loads(plan_file.read_bytes())
        except ValueError:
            on_disk = None
        violations = validate_plan(on_disk, plan)
        extra["plan"] = PlanFacts(
            plan_digest=plan_digest(plan),
            validated=not violations,
            job_types=JOB_SEQUENCE,
            admitted_rule_ids=tuple(r.plugin_id for r in rules),
        )
        if violations:
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=ZapRunnerErrorCode.PLAN_INVALID,
                **extra,
            )
        argv = build_argv(
            java=paths.java,
            jar=paths.jar,
            zap_home=zap_home,
            tmp_dir=tmp_dir,
            plan_file=plan_file,
            guard_host=paths.guard_proxy_host,
            guard_port=paths.guard_proxy_port,
        )
        time_budget_s = min(request.budgets.time_budget_ms, 300_000) / 1000
        armed = state.guard.arm(
            execution_id=request.engine_execution_id,
            origin=target.origin,
            operations=projection.operations,
            ttl_ms=int(time_budget_s * 1000) + 10_000,
        )
        if armed is None:
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=ZapRunnerErrorCode.GUARD_UNAVAILABLE,
                stages=StageFacts(plan_validated=True),
                **extra,
            )
        armed_tokens.append(armed.token)
        return self._spawn_and_classify(
            request,
            projection,
            rules,
            argv,
            started,
            workdir,
            stdout_path,
            out_dir,
            zap_home,
            armed.token,
            time_budget_s,
            extra,
        )

    def _spawn_and_classify(
        self,
        request: ZapRunRequest,
        projection: ProjectionResult,
        rules: tuple[Any, ...],
        argv: list[str],
        started: datetime,
        workdir: Path,
        stdout_path: Path,
        out_dir: Path,
        zap_home: Path,
        token: str,
        time_budget_s: float,
        extra: dict[str, Any],
    ) -> ZapRunResponse:
        state = self.state
        exit_code: int | None = None
        exit_class = "OK"
        with stdout_path.open("wb") as out:
            try:
                process = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False, clean env
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=subprocess.STDOUT,
                    env=child_environment(zap_home),
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
                    error=ZapRunnerErrorCode.SPAWN_FAILED,
                    exit_class="SPAWN_FAILED",
                    stages=StageFacts(plan_validated=True),
                    **extra,
                )
            state.executions_total += 1
            allowed = max(5.0, time_budget_s - 2.0)
            if self.wall_clock_cap_seconds is not None:
                allowed = min(allowed, self.wall_clock_cap_seconds)
            deadline = time.monotonic() + allowed
            next_guard_poll = time.monotonic()
            oversized = False
            while True:
                code = process.poll()
                if code is not None:
                    exit_code = code
                    exit_class = "OK" if code == 0 else "NONZERO_EXIT"
                    break
                now = time.monotonic()
                if now >= deadline:
                    exit_class = "TIMEOUT"
                    _kill(process)
                    break
                if stdout_path.stat().st_size > MAX_STDOUT_BYTES:
                    oversized = True
                    exit_class = "KILLED_BY_GUARD"
                    _kill(process)
                    break
                if now >= next_guard_poll:
                    next_guard_poll = now + GUARD_POLL_SECONDS
                    live = state.guard.counters(token)
                    if live is not None and (
                        live.counters.budget_exceeded or live.counters.blocked > 0
                    ):
                        # A refused request already means ZAP tried to leave its approved
                        # surface: stop it immediately instead of letting it continue.
                        exit_class = "KILLED_BY_GUARD"
                        _kill(process)
                        break
                time.sleep(POLL_SECONDS)

        final = state.guard.disarm(token)
        traffic = final.counters if final is not None else None
        stdout_digest, stdout_bytes = _digest_and_size(stdout_path)
        auto = automation_facts(read_bounded(stdout_path, MAX_CAPTURE_BYTES) or b"")
        log = zap_log_facts(read_bounded(zap_home / "zap.log", MAX_CAPTURE_BYTES) or b"")
        expected_report = out_dir / f"{REPORT_FILE}.json"
        report_digest, report_size = _digest_and_size(expected_report)
        installed = {(i, normalize_add_on_version(v)) for i, v in log.installed_add_ons}
        stages = StageFacts(
            plan_validated=True,
            zap_started=True,
            import_started="openapi" in auto.jobs_started,
            import_completed="openapi" in auto.jobs_finished,
            urls_added=auto.urls_added,
            urls_test_passed=auto.urls_test_passed,
            rules_set=auto.rules_set,
            pscan_wait_started=auto.pscan_wait_started,
            pscan_drained=auto.pscan_wait_finished,
            report_generated=auto.report_paths == (str(expected_report),),
            plan_succeeded=auto.plan_succeeded,
            silent_mode=log.silent_mode,
            installed_add_ons=tuple(sorted(installed)),
            installed_add_ons_match=log.installed_line_seen
            and installed == state.manifest.add_on_set,
            active_rules_loaded=log.active_rules_loaded,
            openapi_errors=auto.openapi_errors,
        )
        extra.update(
            exit_class=exit_class,
            exit_code=exit_code if exit_code is None or -128 <= exit_code <= 255 else None,
            stages=stages,
            traffic=traffic,
            stdout_bytes=stdout_bytes,
            stdout_sha256=stdout_digest,
            report_bytes=report_size,
            report_sha256=report_digest,
        )
        failure = classify(
            exit_class=exit_class,
            exit_code=exit_code,
            oversized=oversized,
            traffic=traffic,
            auto=auto,
            log=log,
            stages=stages,
            projection=projection,
            expected_rules=tuple(sorted((r.plugin_id, r.threshold) for r in rules)),
        )
        if failure is not None:
            return self._response(
                request, status="FAILED", started=started, error=failure, **extra
            )
        report = read_bounded(expected_report, request.budgets.max_report_bytes + 1)
        outcome = parse_report(
            report,
            engine_version=state.manifest.engine.version,
            projection=projection,
            rules=rules,
            max_report_bytes=request.budgets.max_report_bytes,
            max_alerts=request.budgets.max_alerts,
        )
        if outcome.summary.status != "PARSED":
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=outcome.summary.failure_code or ZapRunnerErrorCode.REPORT_MALFORMED,
                parse=outcome.summary,
                **extra,
            )
        return self._response(
            request,
            status="COMPLETED",
            started=started,
            parse=outcome.summary,
            alerts=outcome.records,
            coverage_complete=True,
            **extra,
        )


def classify(
    *,
    exit_class: str,
    exit_code: int | None,
    oversized: bool,
    traffic: GuardCounters | None,
    auto: AutomationFacts,
    log: ZapLogFacts,
    stages: StageFacts,
    projection: ProjectionResult,
    expected_rules: tuple[tuple[int, str], ...],
) -> ZapRunnerErrorCode | None:
    """The first failed completeness/scope condition, or None when coverage is complete.

    Scope and traffic conditions are checked first so an escape is always reported as such, even
    when ZAP also failed for a secondary reason. Zero alerts is never, by itself, success."""

    if traffic is None:
        return ZapRunnerErrorCode.GUARD_UNAVAILABLE
    reasons = dict(traffic.blocked_reasons)
    if exit_class == "TIMEOUT":
        return ZapRunnerErrorCode.EXECUTION_TIMEOUT
    if any(reason in _SCOPE_REASONS for reason in reasons):
        return ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED
    if traffic.budget_exceeded or "BUDGET" in reasons:
        return ZapRunnerErrorCode.REQUEST_BUDGET_EXCEEDED
    if traffic.redirects:
        return ZapRunnerErrorCode.REDIRECT_OBSERVED
    if traffic.upstream_timeouts or auto.target_timeouts:
        return ZapRunnerErrorCode.TARGET_TIMEOUT
    if traffic.upstream_failures or auto.target_unreachable:
        return ZapRunnerErrorCode.TARGET_UNREACHABLE
    if oversized:
        return ZapRunnerErrorCode.OUTPUT_OVERSIZED
    if not stages.installed_add_ons_match or log.active_rules_loaded:
        return ZapRunnerErrorCode.ADDON_RUNTIME_MISMATCH
    if not log.silent_mode:
        return ZapRunnerErrorCode.SILENT_MODE_NOT_CONFIRMED
    if exit_code != 0:
        return (
            ZapRunnerErrorCode.PLAN_FAILED
            if auto.plan_failures_reported
            else ZapRunnerErrorCode.NONZERO_EXIT
        )
    if not auto.plan_succeeded or auto.jobs_started != JOB_SEQUENCE:
        return ZapRunnerErrorCode.PLAN_FAILED
    if auto.unknown_rule or auto.rules_set != expected_rules:
        return ZapRunnerErrorCode.RULE_SET_MISMATCH
    expected_paths = sorted([op.method, op.path, 1] for op in projection.operations)
    if (
        auto.urls_added != projection.operation_count
        or not auto.urls_test_passed
        or auto.openapi_errors
        or traffic.forwarded != projection.operation_count
        or traffic.received != projection.operation_count
        or sorted(list(row) for row in traffic.per_path) != expected_paths
        or any(not status.startswith("2") for status, _ in traffic.statuses)
    ):
        return ZapRunnerErrorCode.IMPORT_INCOMPLETE
    if not auto.pscan_wait_started or not auto.pscan_wait_finished:
        return ZapRunnerErrorCode.PASSIVE_QUEUE_NOT_DRAINED
    if not stages.report_generated:
        return ZapRunnerErrorCode.REPORT_MISSING
    return None
