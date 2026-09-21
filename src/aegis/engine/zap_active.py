"""Controller side of the Phase 1.5 ZAP active reflected-XSS integration.

Responsibility split (same kernel invariants as the passive ZAP path, applied to active scanning):

- the operator requests the approved CAPABILITY and, separately, authorizes a single-use activation
  lease; the AI planner is never involved;
- :func:`build_zap_active_job` deterministically selects the fixed active profile, resolves the
  target REFERENCE through the fixed active inventory, builds the projected one-operation OpenAPI
  surface, and constructs a typed :class:`ZapActiveEngineJob` — or rejects with a structured
  :class:`EngineError` before any runner call;
- :class:`ZapActiveAdapter` consumes the lease, translates the job into the strict active runner RPC
  (adding the lease token), and re-validates the runner's typed response as UNTRUSTED input;
- ZAP alerts are TOOL_REPORTED only. Promotion belongs to :mod:`aegis.zap_active_verifier`.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis.engine.catalog import get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineActivity,
    EngineEnvironment,
    EngineError,
    EngineErrorCode,
    EngineExecution,
    EngineExecutionStatus,
    SecurityEngine,
    TargetReference,
)
from aegis.engine.policy import EnginePolicyRejection
from aegis.zap_active_lease import ActiveScanLease, ActiveScanLeaseStore, LeaseError
from aegis_zap.projection import ProjectionRejected
from aegis_zap_active.contracts import (
    MAX_RPC_RESPONSE_BYTES,
    RedactedLeaseRecord,
    ZapActiveBudgets,
    ZapActiveLeaseStatusResponse,
    ZapActiveRunnerAttestation,
    ZapActiveRunRequest,
    ZapActiveRunResponse,
)
from aegis_zap_active.countersign import verify_countersign
from aegis_zap_active.inventory import ZAP_ACTIVE_TARGETS, ZapActiveTarget
from aegis_zap_active.manifest import (
    ZapActiveManifest,
    add_on_inventory_digest,
    load_manifest,
    manifest_digest,
)
from aegis_zap_active.parser import PARSER_VERSION
from aegis_zap_active.profile import PROFILE_VERSION
from aegis_zap_active.projection import (
    PROJECTION_VERSION,
    ActiveProjectionResult,
    project,
    projection_ref,
)

ACTIVE_PROFILE_ID = "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"
ACTIVE_CAPABILITY_ID = "zap_active_reflected_xss_v1"
EXPECTED_GUARD_VERSION = "zap-scope-guard/1.3.0"
ZAP_MAX_ALERTS = 8
ZAP_MAX_REPORT_BYTES = 131_072
DEFAULT_DELAY_MS = 250
READ_ONLY = frozenset({"GET", "HEAD"})


class ZapActiveEngineJob(BaseModel):
    """The typed ZAP active job. Built ONLY by :func:`build_zap_active_job`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    engine: Literal[SecurityEngine.ZAP] = SecurityEngine.ZAP
    profile_id: Literal["ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"]
    capability_id: str = Field(min_length=3, max_length=100)
    adapter_version: str = Field(min_length=1, max_length=40)
    run_id: str = Field(pattern=r"^scan-[a-f0-9]{12}$")
    environment: EngineEnvironment
    activity: Literal[EngineActivity.ACTIVE]
    target: TargetReference
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    projection_ref: str = Field(max_length=80)
    projection_version: str = Field(max_length=16)
    projection_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowlist_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    method: Literal["GET"]
    path: str = Field(pattern=r"^/lab/zap-active/[A-Za-z0-9/_-]+$")
    operation_id: str = Field(min_length=3, max_length=80)
    query_param: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    add_on_inventory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    rule_id: int = Field(ge=10000, le=99999)
    threshold: str = Field(max_length=8)
    strength: str = Field(max_length=8)
    max_requests: int = Field(ge=1, le=512)
    time_budget_ms: int = Field(ge=30_000, le=660_000)
    delay_ms: int = Field(ge=0, le=5_000)
    max_report_bytes: int = Field(ge=4_096, le=262_144)
    max_alerts: int = Field(ge=1, le=16)
    created_by: Literal["CONTROLLER"] = "CONTROLLER"


def _json(payload: dict[str, object]) -> bytes:
    return json.dumps({"schema_version": "aegis.zap.active-rpc/1", **payload}).encode()


def _reject(code: EngineErrorCode, detail: str = "") -> EnginePolicyRejection:
    return EnginePolicyRejection(
        EngineError(engine=SecurityEngine.ZAP, code=code, detail=detail[:200])
    )


def build_zap_active_job(
    *,
    profile_id: str,
    capability_id: str,
    run_id: str,
    environment: EngineEnvironment,
    target_ref: str,
    allowed_origins: list[str],
    adapter_enabled: bool,
    manifest: ZapActiveManifest | None = None,
) -> tuple[ZapActiveEngineJob, ActiveProjectionResult]:
    """Construct a validated active job and its projection, or raise before any runner contact."""

    manifest = manifest or load_manifest()
    profile = get_engine_profile(profile_id)
    if profile is None or profile.engine is not SecurityEngine.ZAP:
        raise _reject(EngineErrorCode.UNKNOWN_PROFILE, profile_id)
    capability = get_engine_capability(capability_id)
    if capability is None or capability.engine is not SecurityEngine.ZAP:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    if capability.activity is not EngineActivity.ACTIVE:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    if capability.state_changing_possible or not set(capability.supported_methods) <= READ_ONLY:
        raise _reject(EngineErrorCode.UNAPPROVED_STATE_CHANGE, capability_id)
    if capability.requires_authentication:
        raise _reject(EngineErrorCode.MISSING_AUTH_CONTEXT, capability_id)
    if capability.protocol != "http":
        raise _reject(EngineErrorCode.UNSUPPORTED_PROTOCOL, capability.protocol)
    if capability_id not in profile.capability_ids:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    if not profile.enabled or not adapter_enabled:
        raise _reject(EngineErrorCode.ENGINE_DISABLED, profile_id)
    if environment not in capability.allowed_environments or profile.environment is not environment:
        raise _reject(EngineErrorCode.DISALLOWED_ENVIRONMENT, environment.value)
    if manifest.profile_id != profile_id:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, "manifest profile")
    target = ZAP_ACTIVE_TARGETS.get(target_ref)
    if target is None or target.purpose != "ACCEPTANCE":
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, "unknown active target reference")
    if target.origin.rstrip("/") not in {o.rstrip("/") for o in allowed_origins}:
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, target.origin)
    # Re-read and verify the offline operator signature for this exact inventory target before
    # a projection or runner request exists.  No cached JSON record can authorize another target.
    countersign = verify_countersign(
        capability_id=capability_id,
        profile_id=profile_id,
        environment=environment.value,
        target_ref=target_ref,
        manifest=manifest,
    )
    if not countersign.valid:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, countersign.code)

    rules = manifest.rules_for_capability(capability_id)
    if len(rules) != 1 or rules[0].verification_policy != capability.verification_policy.value:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, capability_id)
    rule = rules[0]

    try:
        projection = project(target)
    except ProjectionRejected as rejected:
        raise _reject(EngineErrorCode.PROJECTION_REJECTED, rejected.code.value) from None

    try:
        job = ZapActiveEngineJob(
            job_id=f"job-{uuid4().hex[:12]}",
            profile_id=ACTIVE_PROFILE_ID,  # type: ignore[arg-type]
            capability_id=capability_id,
            adapter_version=capability.adapter_version,
            run_id=run_id,
            environment=environment,
            activity=EngineActivity.ACTIVE,
            target=TargetReference(
                engine=SecurityEngine.ZAP,
                environment=environment,
                origin=target.origin,
                operation_id=projection.operation_id,
                method="GET",
                normalized_path=projection.path,
            ),
            target_ref=target.target_ref,
            projection_ref=projection_ref(target.target_ref),
            projection_version=projection.projection_version,
            projection_digest=projection.digest,
            allowlist_digest=projection.allowlist_digest,
            source_sha256=projection.source_sha256,
            method="GET",
            path=projection.path,
            operation_id=projection.operation_id,
            query_param=projection.query_param,
            manifest_digest=manifest_digest(),
            add_on_inventory_digest=add_on_inventory_digest(manifest),
            rule_id=rule.plugin_id,
            threshold=rule.threshold.lower(),
            strength=rule.strength.lower(),
            max_requests=capability.request_budget,
            time_budget_ms=capability.time_budget_ms,
            delay_ms=DEFAULT_DELAY_MS,
            max_report_bytes=ZAP_MAX_REPORT_BYTES,
            max_alerts=ZAP_MAX_ALERTS,
        )
    except ValidationError as exc:  # pragma: no cover - inputs are already typed
        raise _reject(EngineErrorCode.MALFORMED_ENGINE_OUTPUT, "job_validation") from exc
    return job, projection


def target_for(job: ZapActiveEngineJob) -> ZapActiveTarget:
    return ZAP_ACTIVE_TARGETS[job.target_ref]


@dataclass
class ZapActiveAdapterResult:
    execution: EngineExecution
    attestation: ZapActiveRunnerAttestation | None
    request: ZapActiveRunRequest | None
    response: ZapActiveRunResponse | None
    lease: ActiveScanLease | None
    validation_code: str | None
    armed: RedactedLeaseRecord | None = None
    stopped: bool = False


class ZapActiveAdapter:
    """RPC client for the isolated active zap-runner. Holds no credential and runs no subprocess."""

    engine = SecurityEngine.ZAP

    def __init__(
        self,
        runner_url: str,
        *,
        enabled: bool,
        adapter_version: str,
        timeout_seconds: float = 320.0,
        runner_client_token: str = "",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.runner_url = runner_url.rstrip("/")
        self.enabled = enabled
        self.adapter_version = adapter_version
        self.timeout_seconds = timeout_seconds
        self._runner_client_token = runner_client_token
        self._transport = transport
        self.last_attestation: ZapActiveRunnerAttestation | None = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        )

    async def _bounded(self, method: str, path: str, body: bytes | None = None) -> bytes | None:
        try:
            async with self._client() as client:
                headers = {
                    **({"Content-Type": "application/json"} if body is not None else {}),
                    **(
                        {"X-Aegis-Active-Runner-Client": self._runner_client_token}
                        if self._runner_client_token
                        else {}
                    ),
                }
                async with client.stream(
                    method, f"{self.runner_url}{path}", content=body, headers=headers
                ) as response:
                    # Typed refusals (400/403/404) carry a bounded error_code the caller needs,
                    # so they are read rather than collapsed into "unavailable".
                    if response.status_code not in {200, 400, 403, 404, 413, 415, 503}:
                        return None
                    data = b""
                    async for chunk in response.aiter_bytes():
                        data += chunk
                        if len(data) > MAX_RPC_RESPONSE_BYTES:
                            return None
                    return data
        except httpx.HTTPError:
            return None

    async def attest(self) -> ZapActiveRunnerAttestation | None:
        if not self.enabled:
            return None
        data = await self._bounded("GET", "/v1/attestation")
        if data is None:
            self.last_attestation = None
            return None
        try:
            self.last_attestation = ZapActiveRunnerAttestation.model_validate_json(data)
        except ValidationError:
            self.last_attestation = None
        return self.last_attestation

    def attestation_problem(
        self, attestation: ZapActiveRunnerAttestation | None, job: ZapActiveEngineJob
    ) -> str | None:
        if attestation is None:
            return "RUNNER_UNAVAILABLE_OR_INVALID"
        if not attestation.ready:
            return "RUNNER_NOT_READY"
        manifest = load_manifest()
        engine = attestation.engine
        if not engine.pinned or engine.zap_version != manifest.engine.version:
            return "ENGINE_VERSION_MISMATCH"
        if engine.jar_sha256 != manifest.engine.jar.sha256:
            return "ENGINE_DIGEST_MISMATCH"
        if engine.add_on_inventory_digest != job.add_on_inventory_digest:
            return "ADDON_INVENTORY_MISMATCH"
        expected = {(a.id, a.version, a.sha256) for a in manifest.add_ons}
        attested = {(a.id, a.version, a.sha256) for a in attestation.add_ons}
        if attested != expected or not all(a.pinned for a in attestation.add_ons):
            return "ADDON_INVENTORY_MISMATCH"
        if attestation.unexpected_plugin_files or attestation.forbidden_add_ons_present:
            return "UNEXPECTED_ADDON_FILES"
        if not attestation.addonlist_verified or not attestation.java_verified:
            return "RUNTIME_INVENTORY_NOT_VERIFIED"
        if attestation.manifest_digest != job.manifest_digest:
            return "MANIFEST_DIGEST_MISMATCH"
        if (
            attestation.profile_id != job.profile_id
            or attestation.profile_version != PROFILE_VERSION
        ):
            return "PROFILE_MISMATCH"
        if (
            attestation.parser_version != PARSER_VERSION
            or attestation.projection_version != PROJECTION_VERSION
        ):
            return "PARSER_OR_PROJECTION_VERSION_MISMATCH"
        if tuple(attestation.admitted_rule_ids) != (job.rule_id,):
            return "RULE_MANIFEST_MISMATCH"
        guard = attestation.guard
        if not guard.reachable or guard.guard_version != EXPECTED_GUARD_VERSION:
            return "SCOPE_GUARD_NOT_ATTESTED"
        if set(guard.allowed_origins) != {job.target.origin}:
            return "SCOPE_GUARD_ORIGIN_MISMATCH"
        return None

    async def arm_lease(self, lease_token: str) -> RedactedLeaseRecord | str:
        """Admit the signed lease into the runner's root-owned registry.

        Arming is a distinct, explicit step because signing and arming answer different questions:
        the signature says the controller issued this lease, the armed registry says the runner is
        currently willing to honour exactly one execution of it."""

        data = await self._bounded(
            "POST", "/v1/lease/arm", _json({"lease_token": lease_token})
        )
        if data is None:
            return "LEASE_REGISTRY_UNAVAILABLE"
        try:
            return RedactedLeaseRecord.model_validate_json(data)
        except ValidationError:
            pass
        try:
            problem = json.loads(data)
        except ValueError:
            return "LEASE_INVALID"
        code = problem.get("error_code") if isinstance(problem, dict) else None
        return code if isinstance(code, str) and len(code) <= 40 else "LEASE_INVALID"

    async def revoke_lease(self, lease_id: str, reason: str = "revoked") -> bool:
        """Terminal revoke at the runner. Also disarms the guard, so traffic stops at once."""

        data = await self._bounded(
            "POST", "/v1/lease/revoke", _json({"lease_id": lease_id, "reason": reason})
        )
        if data is None:
            return False
        try:
            RedactedLeaseRecord.model_validate_json(data)
        except ValidationError:
            return False
        return True

    async def lease_status(self) -> ZapActiveLeaseStatusResponse:
        """Redacted runner-side lease status for the Operator Console. Never a token."""

        data = await self._bounded("GET", "/v1/lease/status")
        if data is None:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)
        try:
            return ZapActiveLeaseStatusResponse.model_validate_json(data)
        except ValidationError:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)

    async def emergency_stop(self) -> dict[str, bool]:
        """Trigger the runner's ordered kill switch: revoke, disarm, kill, mark STOPPED."""

        data = await self._bounded("POST", "/v1/emergency-stop", b"{}")
        if data is None:
            return {}
        try:
            decoded = json.loads(data)
        except ValueError:
            return {}
        steps = decoded.get("steps") if isinstance(decoded, dict) else None
        return {k: bool(v) for k, v in steps.items()} if isinstance(steps, dict) else {}

    def build_request(
        self, job: ZapActiveEngineJob, scan_id: str, execution_id: str, lease_token: str
    ) -> ZapActiveRunRequest:
        return ZapActiveRunRequest(
            engine_execution_id=execution_id,
            job_id=job.job_id,
            run_id=job.run_id,
            scan_id=scan_id,
            target_ref=job.target_ref,
            profile_id=job.profile_id,
            capability_id=job.capability_id,
            projection_ref=job.projection_ref,
            projection_digest=job.projection_digest,
            operation_allowlist_digest=job.allowlist_digest,
            query_param=job.query_param,
            budgets=ZapActiveBudgets(
                max_requests=job.max_requests,
                time_budget_ms=job.time_budget_ms,
                max_report_bytes=job.max_report_bytes,
                max_alerts=job.max_alerts,
                delay_ms=job.delay_ms,
            ),
            lease_token=lease_token,
            nonce=secrets.token_hex(16),
            correlation_id=f"corr-{secrets.token_hex(8)}",
        )

    def validate_response(
        self, job: ZapActiveEngineJob, request: ZapActiveRunRequest, response: ZapActiveRunResponse
    ) -> str | None:
        if (
            response.engine_execution_id != request.engine_execution_id
            or response.job_id != job.job_id
            or response.nonce != request.nonce
        ):
            return "CORRELATION_MISMATCH"
        if response.profile_id != job.profile_id or response.profile_version != PROFILE_VERSION:
            return "PROFILE_MISMATCH"
        if response.parse.parser_version != PARSER_VERSION:
            return "PARSER_VERSION_MISMATCH"
        if response.status in {"REJECTED", "STOPPED"}:
            # A stopped run is terminal and carries only bounded evidence; it is never promoted and
            # never re-validated as if it had completed.
            return None
        projection = response.projection
        if projection is None or (
            projection.digest != job.projection_digest
            or projection.allowlist_digest != job.allowlist_digest
        ):
            return "PROJECTION_MISMATCH"
        if response.status != "COMPLETED" and (response.alerts or response.coverage_complete):
            return "RESULTS_ON_FAILED_EXECUTION"
        if len(response.alerts) > job.max_alerts:
            return "ALERT_BUDGET_EXCEEDED"
        traffic = response.traffic
        if traffic is not None and traffic.forwarded > job.max_requests:
            return "REQUEST_BUDGET_EXCEEDED"
        if traffic is not None and any(
            (m, p) != (job.method, job.path) for m, p, _ in traffic.per_path
        ):
            return "UNEXPECTED_ORIGIN_OR_PATH"
        for alert in response.alerts:
            if alert.plugin_id != job.rule_id:
                return "UNADMITTED_RULE"
            if (alert.method, alert.path) != (job.method, job.path):
                return "UNEXPECTED_ORIGIN_OR_PATH"
            if alert.param != job.query_param:
                return "UNEXPECTED_PARAMETER"
        if response.status == "COMPLETED" and not (
            response.coverage_complete
            and traffic is not None
            and traffic.blocked == 0
            and response.stages.active_scan_completed
            and response.stages.plan_succeeded
            and response.parse.status == "PARSED"
        ):
            return "COMPLETED_WITHOUT_COMPLETE_COVERAGE"
        return None

    async def run(
        self,
        job: ZapActiveEngineJob,
        scan_id: str,
        *,
        execution_id: str,
        lease_store: ActiveScanLeaseStore,
        attestation: ZapActiveRunnerAttestation | None = None,
    ) -> ZapActiveAdapterResult:
        """Execute one active job on an attested runner under a consumed lease. Never raises."""

        started = datetime.now(UTC)

        def failed(
            code: EngineErrorCode,
            detail: str,
            lease: ActiveScanLease | None = None,
            **extra: object,
        ) -> ZapActiveAdapterResult:
            execution = EngineExecution(
                execution_id=execution_id,
                job_id=job.job_id,
                engine=self.engine,
                adapter_version=self.adapter_version,
                status=EngineExecutionStatus.FAILED,
                started_at=started,
                completed_at=datetime.now(UTC),
                error=EngineError(
                    engine=self.engine, code=code, detail=detail[:200], job_id=job.job_id
                ),
            )
            return ZapActiveAdapterResult(
                execution=execution,
                attestation=extra.get("attestation"),  # type: ignore[arg-type]
                request=extra.get("request"),  # type: ignore[arg-type]
                response=extra.get("response"),  # type: ignore[arg-type]
                lease=lease,
                validation_code=detail,
                armed=extra.get("armed"),  # type: ignore[arg-type]
                stopped=bool(extra.get("stopped")),
            )

        if not self.enabled:
            return failed(EngineErrorCode.ENGINE_DISABLED, "ADAPTER_DISABLED")
        if attestation is None:
            attestation = await self.attest()
        problem = self.attestation_problem(attestation, job)
        if problem is not None:
            return failed(EngineErrorCode.RUNNER_NOT_ATTESTED, problem, attestation=attestation)

        try:
            lease = lease_store.consume(
                token=lease_store_token(lease_store),
                target_ref=job.target_ref,
                profile_id=job.profile_id,
                capability_id=job.capability_id,
            )
        except LeaseError as exc:
            return failed(
                EngineErrorCode.RUNNER_REJECTED, f"LEASE:{exc.code}", attestation=attestation
            )

        # The activation ceremony (controller) is the ONE place a lease is armed; this method only
        # consumes it. If the lease is somehow not armed, the runner's admission registry refuses
        # the consume below with LEASE_NOT_ARMED — the defense-in-depth is the runner's, not a
        # second arm call here (a second arm would collide with the already-armed registry entry).
        armed: RedactedLeaseRecord | None = None

        request = self.build_request(job, scan_id, execution_id, lease.token)
        data = await self._bounded("POST", "/v1/run", request.model_dump_json().encode())
        if data is None:
            lease_store.revoke(lease.lease_id, "runner_unavailable")
            await self.revoke_lease(lease.lease_id, "runner_unavailable")
            return failed(
                EngineErrorCode.RUNNER_UNAVAILABLE,
                "RUNNER_UNAVAILABLE",
                lease=lease,
                attestation=attestation,
                request=request,
                armed=armed,
            )
        try:
            response = ZapActiveRunResponse.model_validate_json(data)
        except ValidationError:
            lease_store.revoke(lease.lease_id, "response_invalid")
            await self.revoke_lease(lease.lease_id, "response_invalid")
            return failed(
                EngineErrorCode.MALFORMED_ENGINE_OUTPUT,
                "RUNNER_RESPONSE_INVALID",
                lease=lease,
                attestation=attestation,
                request=request,
                armed=armed,
            )
        problem = self.validate_response(job, request, response)
        if problem is not None:
            lease_store.revoke(lease.lease_id, "response_rejected")
            await self.revoke_lease(lease.lease_id, "response_rejected")
            return failed(
                EngineErrorCode.MALFORMED_ENGINE_OUTPUT,
                problem,
                lease=lease,
                attestation=attestation,
                request=request,
                response=response,
                armed=armed,
            )
        if response.status == "STOPPED":
            # The operator stopped this run. STOPPED is terminal: nothing here can turn it into a
            # completion, and the bounded evidence already collected is retained.
            lease_store.revoke(lease.lease_id, "emergency_stop")
            await self.revoke_lease(lease.lease_id, "emergency_stop")
            return failed(
                EngineErrorCode.ENGINE_EXECUTION_INCOMPLETE,
                "EMERGENCY_STOP",
                lease=lease,
                attestation=attestation,
                request=request,
                response=response,
                armed=armed,
                stopped=True,
            )
        if response.status != "COMPLETED" or not response.coverage_complete:
            lease_store.revoke(lease.lease_id, "incomplete")
            return failed(
                EngineErrorCode.ENGINE_EXECUTION_INCOMPLETE,
                str(response.error_code or "COVERAGE_INCOMPLETE"),
                lease=lease,
                attestation=attestation,
                request=request,
                response=response,
                armed=armed,
            )
        lease_store.complete(lease.lease_id)
        # Terminal at the runner too: the armed registry entry is destroyed after exactly one
        # execution, so the same token can never start a second scan.
        await self.revoke_lease(lease.lease_id, "completed")
        execution = EngineExecution(
            execution_id=execution_id,
            job_id=job.job_id,
            engine=self.engine,
            adapter_version=self.adapter_version,
            status=EngineExecutionStatus.COMPLETED,
            started_at=started,
            completed_at=datetime.now(UTC),
        )
        return ZapActiveAdapterResult(
            execution, attestation, request, response, lease, None, armed=armed
        )


def lease_store_token(lease_store: ActiveScanLeaseStore) -> str:
    """Read the live lease token from the store (controller-internal; never sent to the model)."""

    lease = lease_store.current()
    if lease is None:
        raise LeaseError("NO_LIVE_LEASE")
    return lease.token
