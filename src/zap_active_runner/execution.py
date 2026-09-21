"""Execute one validated active-scan request with the fixed active profile, bounded in every
dimension. Mirrors the passive executor's order of operations; the differences are the active plan,
the ACTIVE guard arming (query mutation on the projected parameter only, larger measured budget),
an emergency-stop event that kills ZAP mid-scan, and the active completeness classification.

Every step fails closed; ZAP is started only after all pre-checks. The per-execution directory
(ZAP home, session database, projection, plan, report, logs) is destroyed after every execution.
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

from aegis_zap.facts import (
    AutomationFacts,
    ZapLogFacts,
    automation_facts,
    normalize_add_on_version,
    zap_log_facts,
)
from aegis_zap.projection import ProjectionRejected
from aegis_zap_active.contracts import (
    RUNNER_VERSION,
    ActiveLeaseFacts,
    ActivePlanFacts,
    ActiveProjectionFacts,
    ActiveStageFacts,
    GuardCounters,
    LeaseState,
    RedactedLeaseRecord,
    ZapActiveErrorCode,
    ZapActiveLeaseStatusResponse,
    ZapActiveParseSummary,
    ZapActiveRunRequest,
    ZapActiveRunResponse,
)
from aegis_zap_active.inventory import (
    SOURCES_DIR,
    ZAP_ACTIVE_TARGETS,
    ZapActiveTarget,
    source_bytes,
)
from aegis_zap_active.lease import AUDIENCE
from aegis_zap_active.manifest import ActiveRule
from aegis_zap_active.parser import PARSER_VERSION, parse_report
from aegis_zap_active.profile import (
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
from aegis_zap_active.projection import (
    ActiveProjectionResult,
    project,
    projection_ref,
)
from zap_active_runner.admission_client import AdmissionClient, AdmissionRejected
from zap_active_runner.attestation import (
    ActiveRunnerState,
    verify_add_on_files,
    verify_engine_files,
)
from zap_runner.attestation import MAX_CAPTURE_BYTES, read_bounded

MAX_STDOUT_BYTES = 2_097_152
MAX_DURATION_MS = 660_000
POLL_SECONDS = 0.2
# How long the kill switch waits for an in-flight execution to reach its spawn before killing.
PENDING_SPAWN_WAIT_SECONDS = 15.0
GUARD_POLL_SECONDS = 0.5
_NONCE_MEMORY = 1024
_SCOPE_REASONS = frozenset({"PATH", "ORIGIN", "METHOD", "PARAM", "MALFORMED_TARGET", "NOT_ARMED"})


def _scan_mins(time_budget_ms: int) -> int:
    return max(1, min(10, time_budget_ms // 60_000))


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
    """Serializes active executions (concurrency 1) and enforces every runner-side check."""

    def __init__(
        self,
        state: ActiveRunnerState,
        *,
        targets: dict[str, ZapActiveTarget] | None = None,
        sources_dir: Path = SOURCES_DIR,
        wall_clock_cap_seconds: float | None = None,
        admission: AdmissionClient | None = None,
    ) -> None:
        self.state = state
        self.targets = targets if targets is not None else ZAP_ACTIVE_TARGETS
        self.sources_dir = sources_dir
        self.wall_clock_cap_seconds = wall_clock_cap_seconds
        # Without an admission client the runner cannot authenticate a lease, so it refuses to
        # execute at all. There is deliberately no "lease optional" mode.
        self.admission = admission
        self._lock = threading.Lock()
        # Serializes the kill switch against the run loop's spawn and stop observation, so the
        # emergency-stop order (revoke -> disarm guard -> kill -> STOPPED) can never be overtaken
        # by an in-flight completion.
        self._stop_lock = threading.Lock()
        self._nonces: OrderedDict[str, None] = OrderedDict()
        self._nonce_lock = threading.Lock()
        self._stop = threading.Event()
        self._inflight_lock = threading.Lock()
        self._inflight_lease: str | None = None
        self._inflight_guard_token: str | None = None
        self._inflight_process: subprocess.Popen[bytes] | None = None
        self.stops_total = 0

    def _track(self, **fields: Any) -> None:
        with self._inflight_lock:
            for name, value in fields.items():
                setattr(self, f"_inflight_{name}", value)

    def emergency_stop(self) -> dict[str, bool]:
        """The kill switch, executed in the one order that cannot leave a window open.

        1. revoke the runner lease, so nothing can consume or re-consume it;
        2. disarm the guard for that lease, so the very next ZAP request is refused *before* it
           reaches the target — even if the process takes a moment to die;
        3. kill the ZAP process tree;
        4. mark the run STOPPED (the wait loop observes the event and never returns COMPLETED);
        5. retain the bounded evidence already collected.

        Steps 1-3 run under the stop lock, and the run loop's spawn is serialized against the same
        lock, so a stop pressed between lease consumption and engine spawn cannot be overtaken:
        either the revocation lands first (the execution reports STOPPED without ever starting the
        engine) or the spawn lands first (the engine is killed with the guard already disarmed).
        Revoking before killing is the point: killing first would leave an armed guard and a live
        lease for however long the SIGKILL takes to land."""

        self.stops_total += 1
        with self._inflight_lock:
            lease_id = self._inflight_lease
            process = self._inflight_process
        if lease_id is not None and process is None:
            # An execution is in flight but has not reached the spawn yet. Waiting briefly here is
            # what makes step 3 real: without it a stop pressed a millisecond before the JVM starts
            # would report "engine not killed" and leave the kill to the wait loop. The stop lock
            # is deliberately NOT held while waiting, because the spawn path needs it to proceed.
            deadline = time.monotonic() + PENDING_SPAWN_WAIT_SECONDS
            while time.monotonic() < deadline:
                with self._inflight_lock:
                    process = self._inflight_process
                    still_running = self._inflight_lease == lease_id
                if process is not None or not still_running:
                    break
                time.sleep(POLL_SECONDS)
        steps = {
            "lease_revoked": False,
            "guard_disarmed": False,
            "engine_killed": False,
            "marked_stopped": True,
        }
        with self._stop_lock:
            if lease_id is not None:
                if self.admission is not None:
                    outcome = self.admission.revoke(lease_id, "emergency_stop")
                    steps["lease_revoked"] = not isinstance(outcome, AdmissionRejected)
                revoked = self.state.guard.revoke_lease(lease_id, "emergency_stop")
                if revoked is not None:
                    steps["guard_disarmed"] = True
                else:
                    # The guard may already have been disarmed by an in-flight completion. The
                    # step still reports the truth rather than a failure: it is only a failure
                    # when the guard is still armed (or unreachable) afterwards.
                    attestation = self.state.guard.attestation()
                    steps["guard_disarmed"] = (
                        attestation is not None and attestation.state == "IDLE"
                    )
            # Only now does the run loop observe the stop: the revocation and the guard disarm
            # have already landed, so a kill raced by the loop can never leave an armed guard.
            self._stop.set()
            if process is not None and process.poll() is None:
                _kill(process)
                steps["engine_killed"] = True
        return steps

    @property
    def rule(self) -> ActiveRule:
        return self.state.manifest.active_rules[0]

    # --- response helpers ------------------------------------------------------------------

    def _response(
        self,
        request: ZapActiveRunRequest,
        *,
        status: str,
        started: datetime,
        error: ZapActiveErrorCode | None = None,
        exit_class: str = "NOT_RUN",
        **extra: Any,
    ) -> ZapActiveRunResponse:
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
            "plan": ActivePlanFacts(validated=False),
            "stages": ActiveStageFacts(),
            "started_at": started,
            "completed_at": completed,
            "duration_ms": min(
                MAX_DURATION_MS, max(0, int((completed - started).total_seconds() * 1000))
            ),
            "stdout_bytes": 0,
            "report_bytes": 0,
            "session_destroyed": True,
            "parse": ZapActiveParseSummary(
                parser_version=PARSER_VERSION,
                status="NOT_PARSED",
                sites=0,
                alerts=0,
                instances=0,
                records=0,
                duplicates_collapsed=0,
            ),
            "coverage_complete": False,
            "lease": ActiveLeaseFacts(presented=bool(request.lease_token)),
        }
        payload.update(extra)
        return ZapActiveRunResponse.model_validate(payload, strict=False)

    def _reject(
        self,
        request: ZapActiveRunRequest,
        code: ZapActiveErrorCode,
        started: datetime,
        **extra: Any,
    ) -> ZapActiveRunResponse:
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
        self, request: ZapActiveRunRequest
    ) -> tuple[ZapActiveErrorCode | None, ZapActiveTarget | None, ActiveProjectionResult | None]:
        if not self.state.ready:
            return ZapActiveErrorCode.RUNNER_NOT_READY, None, None
        if request.profile_id != PROFILE_ID:
            return ZapActiveErrorCode.UNKNOWN_PROFILE, None, None
        target = self.targets.get(request.target_ref)
        if target is None or target.purpose != "ACCEPTANCE":
            return ZapActiveErrorCode.UNKNOWN_TARGET, None, None
        if request.projection_ref != projection_ref(target.target_ref):
            return ZapActiveErrorCode.PROJECTION_REF_MISMATCH, target, None
        try:
            projection = project(target, source_bytes(target, self.sources_dir))
        except (ProjectionRejected, OSError, ValueError):
            return ZapActiveErrorCode.PROJECTION_REJECTED, target, None
        if projection.digest != request.projection_digest:
            return ZapActiveErrorCode.PROJECTION_DIGEST_MISMATCH, target, projection
        if projection.allowlist_digest != request.operation_allowlist_digest:
            return ZapActiveErrorCode.ALLOWLIST_DIGEST_MISMATCH, target, projection
        if request.query_param != projection.query_param:
            return ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM, target, projection
        return None, target, projection

    # --- execution -------------------------------------------------------------------------

    def run(self, request: ZapActiveRunRequest) -> ZapActiveRunResponse:
        started = datetime.now(UTC)
        error, target, projection = self._policy(request)
        if error is not None or target is None or projection is None:
            return self._reject(request, error or ZapActiveErrorCode.INVALID_REQUEST, started)
        if not self._remember_nonce(request.nonce):
            return self._reject(request, ZapActiveErrorCode.REPLAYED_NONCE, started)
        if not self._lock.acquire(blocking=False):
            return self._reject(request, ZapActiveErrorCode.BUSY, started)
        try:
            self._stop.clear()
            if not verify_engine_files(self.state):
                self.state.ready = False
                self.state.failure_codes.append("ENGINE_INTEGRITY_FAILURE")
                return self._reject(request, ZapActiveErrorCode.ENGINE_INTEGRITY_FAILURE, started)
            if not verify_add_on_files(self.state):
                self.state.ready = False
                self.state.failure_codes.append("ADDON_INVENTORY_DRIFT")
                return self._reject(request, ZapActiveErrorCode.ADDON_INVENTORY_DRIFT, started)
            lease, rejection = self._consume_lease(request, target, projection)
            if lease is None:
                # A lease refusal is a pre-execution rejection: the guard was never armed and ZAP
                # was never started, so this path forwards exactly zero requests to the target.
                return self._reject(
                    request,
                    rejection or ZapActiveErrorCode.LEASE_INVALID,
                    started,
                    lease=ActiveLeaseFacts(
                        presented=True,
                        rejection_code=(rejection or ZapActiveErrorCode.LEASE_INVALID).value,
                    ),
                )
            self._track(lease=lease.lease_id)
            try:
                response = self._execute(request, target, projection, started, lease)
            except Exception:
                response = self._response(
                    request,
                    status="FAILED",
                    started=started,
                    error=ZapActiveErrorCode.SPAWN_FAILED,
                    exit_class="SPAWN_FAILED",
                    lease=ActiveLeaseFacts(presented=True, consumed=True, lease_id=lease.lease_id),
                )
            finally:
                # The lease is terminal after exactly one execution, whatever the outcome: a
                # second run with the same token has nothing armed to consume.
                revoked = self._revoke_lease(lease.lease_id, "execution_finished")
                self._track(lease=None, process=None, guard_token=None)
            return response.model_copy(
                update={
                    "lease": response.lease.model_copy(update={"revoked_after_execution": revoked})
                }
            )
        finally:
            self._lock.release()

    def _consume_lease(
        self,
        request: ZapActiveRunRequest,
        target: ZapActiveTarget,
        projection: ActiveProjectionResult,
    ) -> tuple[RedactedLeaseRecord | None, ZapActiveErrorCode | None]:
        """Authenticate and atomically consume the lease against facts THIS runner computed.

        The binding is deliberately not taken from the request: the origin comes from the runner's
        own pinned inventory, the digests from the projection it just rebuilt from its own source
        files, and the manifest digest from its own attested manifest. A caller therefore cannot
        make a lease fit an execution by describing that execution differently."""

        if self.admission is None:
            return None, ZapActiveErrorCode.LEASE_REGISTRY_UNAVAILABLE
        outcome = self.admission.consume(
            lease_token=request.lease_token,
            execution_id=request.engine_execution_id,
            capability_id=request.capability_id,
            profile_id=PROFILE_ID,
            target_ref=target.target_ref,
            target_origin=target.origin,
            projection_digest=projection.digest,
            allowlist_digest=projection.allowlist_digest,
            manifest_digest=self.state.manifest_digest,
        )
        if isinstance(outcome, AdmissionRejected):
            return None, _lease_error(outcome.code)
        if outcome.audience != AUDIENCE or outcome.state is not LeaseState.CONSUMED:
            return None, ZapActiveErrorCode.LEASE_INVALID
        return outcome, None

    def _revoke_lease(self, lease_id: str, reason: str) -> bool:
        if self.admission is None:
            return False
        return not isinstance(self.admission.revoke(lease_id, reason), AdmissionRejected)

    def lease_status(self) -> ZapActiveLeaseStatusResponse:
        if self.admission is None:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)
        return self.admission.status()

    def arm_lease(self, lease_token: str) -> RedactedLeaseRecord | ZapActiveErrorCode:
        """Admit a signed lease into the root-owned registry. Arming grants nothing by itself."""

        if self.admission is None:
            return ZapActiveErrorCode.LEASE_REGISTRY_UNAVAILABLE
        outcome = self.admission.arm(lease_token)
        if isinstance(outcome, AdmissionRejected):
            return _lease_error(outcome.code)
        return outcome

    def revoke_lease(self, lease_id: str, reason: str = "revoked") -> RedactedLeaseRecord | None:
        """Operator/controller revoke. Also disarms the guard, so traffic stops immediately."""

        self.state.guard.revoke_lease(lease_id, reason)
        if self.admission is None:
            return None
        outcome = self.admission.revoke(lease_id, reason)
        return None if isinstance(outcome, AdmissionRejected) else outcome

    def _projection_facts(self, projection: ActiveProjectionResult) -> ActiveProjectionFacts:
        return ActiveProjectionFacts(
            projection_ref=projection_ref(projection.target_ref),
            projection_version=projection.projection_version,
            digest=projection.digest,
            allowlist_digest=projection.allowlist_digest,
            source_sha256=projection.source_sha256,
            operation_count=projection.operation_count,
            path_count=projection.path_count,
            query_param=projection.query_param,
            redaction_status=projection.redaction_status,  # type: ignore[arg-type]
        )

    def _execute(
        self,
        request: ZapActiveRunRequest,
        target: ZapActiveTarget,
        projection: ActiveProjectionResult,
        started: datetime,
        lease: RedactedLeaseRecord,
    ) -> ZapActiveRunResponse:
        workdir = self.state.paths.work_root / request.engine_execution_id
        armed: list[str] = []
        try:
            response = self._prepare_and_run(
                request, target, projection, started, workdir, armed, lease
            )
        finally:
            if armed:
                self.state.guard.disarm(armed[0])
            # Raw engine output can contain attack strings, reflected bodies, credentials and
            # lease material. It is never retained outside this 0700 execution directory.
            shutil.rmtree(workdir, ignore_errors=True)
            self.state.last_execution_at = datetime.now(UTC)
        return response.model_copy(update={"session_destroyed": not workdir.exists()})

    def _prepare_and_run(
        self,
        request: ZapActiveRunRequest,
        target: ZapActiveTarget,
        projection: ActiveProjectionResult,
        started: datetime,
        workdir: Path,
        armed_tokens: list[str],
        lease: RedactedLeaseRecord,
    ) -> ZapActiveRunResponse:
        state = self.state
        paths = state.paths
        rule = self.rule
        zap_home, tmp_dir, out_dir = workdir / "home", workdir / "tmp", workdir / "out"
        api_file, plan_file = workdir / "projection.json", workdir / "plan.yaml"
        stdout_path = workdir / "zap-stdout.bin"
        budgets = request.budgets
        lease_expires_at = int(datetime.fromisoformat(lease.expires_at).timestamp())
        lease_facts = ActiveLeaseFacts(
            presented=True,
            consumed=True,
            lease_id=lease.lease_id,
            state=lease.state,
            expires_at=lease.expires_at,
            budget_id=lease.budget_id,
        )
        extra: dict[str, Any] = {
            "projection": self._projection_facts(projection),
            "lease": lease_facts,
        }
        workdir.mkdir(mode=0o700)
        for directory in (zap_home, tmp_dir, out_dir):
            directory.mkdir(mode=0o700)
        api_file.write_bytes(projection.document)
        plan = build_plan(
            projection=projection,
            rule=rule,
            api_file=api_file,
            report_dir=out_dir,
            delay_ms=budgets.delay_ms,
            max_scan_mins=_scan_mins(budgets.time_budget_ms),
        )
        plan_file.write_bytes(plan_bytes(plan))
        try:
            on_disk = json.loads(plan_file.read_bytes())
        except ValueError:
            on_disk = None
        violations = validate_plan(on_disk, plan, rule=rule)
        extra["plan"] = ActivePlanFacts(
            plan_digest=plan_digest(plan),
            validated=not violations,
            job_types=JOB_SEQUENCE,
            admitted_rule_ids=(rule.plugin_id,),
            strength=rule.strength.lower(),
            threshold=rule.threshold.lower(),
        )
        if violations:
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=ZapActiveErrorCode.PLAN_INVALID,
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
        time_budget_s = min(budgets.time_budget_ms, MAX_DURATION_MS) / 1000
        if lease.projection_digest != projection.digest or (
            lease.allowlist_digest != projection.allowlist_digest
        ):  # pragma: no cover - admission already enforced this; belt and braces before arming
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=ZapActiveErrorCode.LEASE_BINDING_MISMATCH,
                stages=ActiveStageFacts(plan_validated=True),
                **extra,
            )
        armed = state.guard.arm_active(
            execution_id=request.engine_execution_id,
            origin=target.origin,
            method=projection.method,
            path=projection.path,
            allowed_params=(projection.query_param,),
            max_requests=budgets.max_requests,
            ttl_ms=min(MAX_DURATION_MS, int(time_budget_s * 1000) + 20_000),
            lease_id=lease.lease_id,
            lease_expires_at=lease_expires_at,
            projection_digest=lease.projection_digest,
            allowlist_digest=lease.allowlist_digest,
        )
        if armed is None:
            # Either the guard is unreachable, or it confirmed a binding other than the lease's.
            # Both are refusals: ZAP is not started and nothing reaches the target.
            binding_seen = state.guard.attestation() is not None
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=(
                    ZapActiveErrorCode.GUARD_BINDING_MISMATCH
                    if binding_seen
                    else ZapActiveErrorCode.GUARD_UNAVAILABLE
                ),
                stages=ActiveStageFacts(plan_validated=True),
                **extra,
            )
        extra["lease"] = lease_facts.model_copy(update={"guard_binding_confirmed": True})
        armed_tokens.append(armed.token)
        self._track(guard_token=armed.token)
        return self._spawn_and_classify(
            request,
            projection,
            rule,
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
        request: ZapActiveRunRequest,
        projection: ActiveProjectionResult,
        rule: ActiveRule,
        argv: list[str],
        started: datetime,
        workdir: Path,
        stdout_path: Path,
        out_dir: Path,
        zap_home: Path,
        token: str,
        time_budget_s: float,
        extra: dict[str, Any],
    ) -> ZapActiveRunResponse:
        state = self.state
        exit_code: int | None = None
        exit_class = "OK"
        with stdout_path.open("wb") as out:
            # Spawn is serialized against the kill switch: a stop that lands first wins and this
            # execution reports STOPPED without ever starting the engine; a spawn that wins is
            # killed with the guard already disarmed by the stop path.
            with self._stop_lock:
                if self._stop.is_set():
                    return self._response(
                        request,
                        status="STOPPED",
                        started=started,
                        error=ZapActiveErrorCode.EMERGENCY_STOP,
                        exit_class="KILLED_BY_GUARD",
                        stages=ActiveStageFacts(plan_validated=True),
                        **extra,
                    )
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
                        error=ZapActiveErrorCode.SPAWN_FAILED,
                        exit_class="SPAWN_FAILED",
                        stages=ActiveStageFacts(plan_validated=True),
                        **extra,
                    )
                state.executions_total += 1
                self._track(process=process)
            allowed = max(5.0, time_budget_s)
            if self.wall_clock_cap_seconds is not None:
                allowed = min(allowed, self.wall_clock_cap_seconds)
            deadline = time.monotonic() + allowed
            next_guard_poll = time.monotonic()
            oversized = False
            while True:
                code = process.poll()
                if code is not None:
                    exit_code = code
                    # A process that died because the stop landed is KILLED_BY_GUARD, whatever
                    # exit status the SIGKILL produced: an in-flight completion must never
                    # overwrite the stop classification.
                    exit_class = (
                        "KILLED_BY_GUARD"
                        if self._stop.is_set()
                        else ("OK" if code == 0 else "NONZERO_EXIT")
                    )
                    break
                now = time.monotonic()
                if self._stop.is_set():
                    exit_class = "KILLED_BY_GUARD"
                    _kill(process)
                    break
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
                        exit_class = "KILLED_BY_GUARD"
                        _kill(process)
                        break
                time.sleep(POLL_SECONDS)

        final = state.guard.disarm(token)
        traffic = final.counters if final is not None else None
        emergency = self._stop.is_set()
        stdout_digest, stdout_bytes = _digest_and_size(stdout_path)
        auto = automation_facts(read_bounded(stdout_path, MAX_CAPTURE_BYTES) or b"")
        log = zap_log_facts(read_bounded(zap_home / "zap.log", MAX_CAPTURE_BYTES) or b"")
        expected_report = out_dir / f"{REPORT_FILE}.json"
        report_digest, report_size = _digest_and_size(expected_report)
        installed = {(i, normalize_add_on_version(v)) for i, v in log.installed_add_ons}
        stages = ActiveStageFacts(
            plan_validated=True,
            zap_started=True,
            import_started="openapi" in auto.jobs_started,
            import_completed="openapi" in auto.jobs_finished,
            urls_added=auto.urls_added,
            urls_test_passed=auto.urls_test_passed,
            passive_rules_disabled=True,
            active_scan_started="activeScan" in auto.jobs_started,
            active_scan_completed="activeScan" in auto.jobs_finished,
            active_rules_loaded=log.active_rules_loaded,
            admitted_active_rule_ran="activeScan" in auto.jobs_finished,
            pscan_drained=auto.pscan_wait_finished,
            report_generated=auto.report_paths == (str(expected_report),),
            plan_succeeded=auto.plan_succeeded,
            silent_mode=log.silent_mode,
            installed_add_ons=tuple(sorted(installed)),
            installed_add_ons_match=log.installed_line_seen
            and installed == state.manifest.add_on_set,
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
        if emergency:
            # Terminal and unconditional. Even if the process happened to exit 0 while the kill
            # was landing, a stopped run is STOPPED: a completion never overwrites it, and the
            # bounded evidence collected so far is still returned.
            return self._response(
                request,
                status="STOPPED",
                started=started,
                error=ZapActiveErrorCode.EMERGENCY_STOP,
                **extra,
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
            rule=rule,
        )
        if failure is not None:
            return self._response(request, status="FAILED", started=started, error=failure, **extra)
        report = read_bounded(expected_report, request.budgets.max_report_bytes + 1)
        outcome = parse_report(
            report,
            engine_version=state.manifest.engine.version,
            projection=projection,
            rule=rule,
            max_report_bytes=request.budgets.max_report_bytes,
            max_alerts=request.budgets.max_alerts,
        )
        if outcome.summary.status != "PARSED":
            return self._response(
                request,
                status="FAILED",
                started=started,
                error=outcome.summary.failure_code or ZapActiveErrorCode.REPORT_MALFORMED,
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


def _lease_error(code: str) -> ZapActiveErrorCode:
    """Map an admission refusal label onto the typed RPC error set, defaulting to LEASE_INVALID.

    Unknown labels collapse rather than propagate: a refusal never becomes free-form text on the
    wire, and no cryptographic detail escapes the admission boundary."""

    try:
        return ZapActiveErrorCode(code)
    except ValueError:
        return ZapActiveErrorCode.LEASE_INVALID


def classify(
    *,
    exit_class: str,
    exit_code: int | None,
    oversized: bool,
    traffic: GuardCounters | None,
    auto: AutomationFacts,
    log: ZapLogFacts,
    stages: ActiveStageFacts,
    projection: ActiveProjectionResult,
    rule: ActiveRule,
) -> ZapActiveErrorCode | None:
    """The first failed completeness/scope condition, or None when coverage is complete.

    Scope and traffic conditions are checked first so an escape is always reported as such. A zero
    alert count is never, by itself, success or failure — the verifier owns the verdict."""

    if traffic is None:
        return ZapActiveErrorCode.GUARD_UNAVAILABLE
    reasons = dict(traffic.blocked_reasons)
    if exit_class == "TIMEOUT":
        return ZapActiveErrorCode.EXECUTION_TIMEOUT
    if any(reason in _SCOPE_REASONS for reason in reasons):
        return ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    if traffic.budget_exceeded or "BUDGET" in reasons:
        return ZapActiveErrorCode.REQUEST_BUDGET_EXCEEDED
    if traffic.redirects:
        return ZapActiveErrorCode.REDIRECT_OBSERVED
    if traffic.upstream_timeouts or auto.target_timeouts:
        return ZapActiveErrorCode.TARGET_TIMEOUT
    if traffic.upstream_failures or auto.target_unreachable:
        return ZapActiveErrorCode.TARGET_UNREACHABLE
    if oversized:
        return ZapActiveErrorCode.OUTPUT_OVERSIZED
    if not stages.installed_add_ons_match:
        return ZapActiveErrorCode.ADDON_RUNTIME_MISMATCH
    if not log.silent_mode:
        return ZapActiveErrorCode.SILENT_MODE_NOT_CONFIRMED
    if exit_code != 0:
        return (
            ZapActiveErrorCode.PLAN_FAILED
            if auto.plan_failures_reported
            else ZapActiveErrorCode.NONZERO_EXIT
        )
    if not auto.plan_succeeded or auto.jobs_started != JOB_SEQUENCE:
        return ZapActiveErrorCode.PLAN_FAILED
    if auto.unknown_rule:
        return ZapActiveErrorCode.RULE_SET_MISMATCH
    if (
        auto.urls_added != projection.operation_count
        or not auto.urls_test_passed
        or auto.openapi_errors
    ):
        return ZapActiveErrorCode.IMPORT_INCOMPLETE
    if not stages.active_scan_started or not stages.active_scan_completed:
        return ZapActiveErrorCode.ACTIVE_SCAN_INCOMPLETE
    if (
        traffic.forwarded < 1
        or traffic.received != traffic.forwarded
        or any((m, p) != (projection.method, projection.path) for m, p, _ in traffic.per_path)
        or any(not status.startswith("2") for status, _ in traffic.statuses)
    ):
        return ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED
    if not auto.pscan_wait_started or not auto.pscan_wait_finished:
        return ZapActiveErrorCode.PASSIVE_QUEUE_NOT_DRAINED
    if not stages.report_generated:
        return ZapActiveErrorCode.REPORT_MISSING
    return None
