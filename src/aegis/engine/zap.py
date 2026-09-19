"""Controller side of the Phase 1.3 ZAP passive OpenAPI integration.

Responsibility split (unchanged kernel invariants, applied to a second external engine):

- the operator or deterministic policy requests an approved CAPABILITY — never a tool, plan, job,
  rule, OpenAPI document or URL, target URL, header, script or option; the AI planner is not
  involved in this path;
- :func:`build_zap_job` deterministically selects the approved profile from the immutable catalog,
  resolves the target REFERENCE through the fixed inventory, builds the projected read-only
  OpenAPI surface from controller-owned inventory, and constructs a typed :class:`ZapEngineJob` —
  or rejects with a structured :class:`EngineError` before any runner call;
- :class:`ZapAdapter` translates the job into the strict runner RPC (ids, target reference,
  profile id, projection reference + digest, allowlist digest, budgets, nonce) and re-validates the
  runner's typed response as UNTRUSTED input;
- ZAP alerts are TOOL_REPORTED only. Promotion belongs to :mod:`aegis.zap_verifier`.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis.engine.adapters import AdapterResult, SecurityEngineAdapter
from aegis.engine.catalog import ADAPTER_VERSIONS, get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineActivity,
    EngineBudget,
    EngineEnvironment,
    EngineError,
    EngineErrorCode,
    EngineExecution,
    EngineExecutionStatus,
    EngineHealth,
    EngineJob,
    SecurityEngine,
    TargetReference,
)
from aegis.engine.policy import EnginePolicyRejection
from aegis.surface import Variant
from aegis_zap.contracts import (
    MAX_RPC_RESPONSE_BYTES,
    ZapBudgets,
    ZapRunnerAttestation,
    ZapRunRequest,
    ZapRunResponse,
)
from aegis_zap.inventory import ZAP_TARGETS, ZapTarget
from aegis_zap.manifest import (
    ZapManifest,
    add_on_inventory_digest,
    load_manifest,
    manifest_digest,
)
from aegis_zap.parser import PARSER_VERSION
from aegis_zap.profile import PROFILE_ID, PROFILE_VERSION
from aegis_zap.projection import (
    PROJECTION_VERSION,
    ProjectionRejected,
    ProjectionResult,
    project,
    projection_ref,
)

ZAP_ADAPTER_VERSION = ADAPTER_VERSIONS[SecurityEngine.ZAP]
ZAP_MAX_ALERTS = 8
ZAP_MAX_REPORT_BYTES = 131_072
EXPECTED_GUARD_VERSION = "zap-scope-guard/1.3.0"
READ_ONLY = frozenset({"GET", "HEAD"})


class ProjectedOperationRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["GET", "HEAD"]
    path: str = Field(pattern=r"^/lab/zap/[A-Za-z0-9/_-]+$")
    operation_id: str = Field(min_length=3, max_length=80)


class ZapEngineJob(BaseModel):
    """The typed ZAP job. Built ONLY by :func:`build_zap_job`.

    Like :class:`aegis.engine.contracts.EngineJob` it has no command, argv, flag, raw URL, header,
    cookie, credential, plan, job, rule setting, script or OpenAPI-content field and forbids extra
    keys. The projected operations are recorded for correlation and provenance; the runner
    re-derives the projection from its own copy of the inventory and must reach the same digests."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    engine: Literal[SecurityEngine.ZAP] = SecurityEngine.ZAP
    profile_id: Literal["ZAP_LAB_PASSIVE_OPENAPI_V1"]
    capability_id: str = Field(min_length=3, max_length=100)
    adapter_version: str = Field(min_length=1, max_length=40)
    run_id: str = Field(pattern=r"^scan-[a-f0-9]{12}$")
    environment: EngineEnvironment
    activity: Literal[EngineActivity.PASSIVE]
    target: TargetReference
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    projection_ref: str = Field(max_length=80)
    projection_version: str = Field(max_length=16)
    projection_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowlist_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    operations: tuple[ProjectedOperationRef, ...] = Field(min_length=1, max_length=8)
    path_count: int = Field(ge=1, le=8)
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"]
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    add_on_inventory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    rule_ids: tuple[int, ...] = Field(min_length=1, max_length=8)
    budget: EngineBudget
    max_alerts: int = Field(ge=1, le=16)
    max_report_bytes: int = Field(ge=4_096, le=262_144)
    created_by: Literal["CONTROLLER"] = "CONTROLLER"

    @property
    def operation_count(self) -> int:
        return len(self.operations)


class ZapProjectionRejection(EnginePolicyRejection):
    """The controller's projection refused the inventory source (zero runner/target traffic)."""

    def __init__(self, error: EngineError, projection_code: str) -> None:
        super().__init__(error)
        self.projection_code = projection_code


def _reject(code: EngineErrorCode, detail: str = "") -> EnginePolicyRejection:
    return EnginePolicyRejection(
        EngineError(engine=SecurityEngine.ZAP, code=code, detail=detail[:200])
    )


def build_zap_job(
    *,
    profile_id: str,
    capability_id: str,
    run_id: str,
    environment: EngineEnvironment,
    target_ref: str,
    remaining_requests: int,
    allowed_origins: Iterable[str],
    adapter_enabled: bool,
    manifest: ZapManifest | None = None,
) -> tuple[ZapEngineJob, ProjectionResult]:
    """Construct a validated job and its projection, or raise before any runner contact."""

    manifest = manifest or load_manifest()
    profile = get_engine_profile(profile_id)
    if profile is None:
        raise _reject(EngineErrorCode.UNKNOWN_PROFILE, profile_id)
    if profile.engine is not SecurityEngine.ZAP:
        raise _reject(EngineErrorCode.UNKNOWN_ENGINE, profile.engine.value)

    capability = get_engine_capability(capability_id)
    if capability is None or capability.engine is not SecurityEngine.ZAP:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    # Safety classification first, so a dangerous capability is refused for the property itself.
    if capability.activity is not EngineActivity.PASSIVE:
        raise _reject(EngineErrorCode.ACTIVE_SCAN_FORBIDDEN, capability_id)
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

    target = ZAP_TARGETS.get(target_ref)
    if target is None:
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, "unknown target reference")
    origins = {o.rstrip("/") for o in allowed_origins}
    if target.origin.rstrip("/") not in origins:
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, target.origin)

    if manifest.profile_id != profile_id:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, "manifest profile")
    rules = manifest.rules_for_capability(capability_id)
    if not rules or any(
        r.verification_policy != capability.verification_policy.value for r in rules
    ):
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, capability_id)

    try:
        projection = project(target)
    except ProjectionRejected as rejected:
        raise ZapProjectionRejection(
            EngineError(
                engine=SecurityEngine.ZAP,
                code=EngineErrorCode.PROJECTION_REJECTED,
                detail=rejected.code.value,
            ),
            rejected.code.value,
        ) from None

    required = projection.operation_count
    if required != target.expected_requests or required > capability.request_budget:
        raise _reject(EngineErrorCode.BUDGET_EXCEEDED, "capability_requests")
    if required > remaining_requests:
        raise _reject(EngineErrorCode.BUDGET_EXCEEDED, "requests")

    anchor = next(
        (op for op in projection.operations if op.operation_id == target.scenario_operation_id),
        projection.operations[0],
    )
    try:
        job = ZapEngineJob(
            job_id=f"job-{uuid4().hex[:12]}",
            profile_id=PROFILE_ID,  # type: ignore[arg-type]
            capability_id=capability_id,
            adapter_version=capability.adapter_version,
            run_id=run_id,
            environment=environment,
            activity=EngineActivity.PASSIVE,
            target=TargetReference(
                engine=SecurityEngine.ZAP,
                environment=environment,
                origin=target.origin,
                operation_id=anchor.operation_id,
                method="GET",
                normalized_path=target.base_path,
            ),
            target_ref=target.target_ref,
            projection_ref=projection_ref(target.target_ref),
            projection_version=projection.projection_version,
            projection_digest=projection.digest,
            allowlist_digest=projection.allowlist_digest,
            source_sha256=projection.source_sha256,
            operations=tuple(
                ProjectedOperationRef(method=op.method, path=op.path, operation_id=op.operation_id)  # type: ignore[arg-type]
                for op in projection.operations
            ),
            path_count=projection.path_count,
            redaction_status=projection.redaction_status,  # type: ignore[arg-type]
            manifest_digest=manifest_digest(),
            add_on_inventory_digest=add_on_inventory_digest(manifest),
            rule_ids=tuple(r.plugin_id for r in rules),
            budget=EngineBudget(
                max_requests=required,
                max_concurrency=capability.concurrency_budget,
                time_budget_ms=capability.time_budget_ms,
            ),
            max_alerts=ZAP_MAX_ALERTS,
            max_report_bytes=ZAP_MAX_REPORT_BYTES,
        )
    except ValidationError as exc:  # pragma: no cover - inputs are already typed
        raise _reject(EngineErrorCode.MALFORMED_ENGINE_OUTPUT, "job_validation") from exc
    return job, projection


def target_for(job: ZapEngineJob) -> ZapTarget:
    return ZAP_TARGETS[job.target_ref]


@dataclass
class ZapAdapterResult:
    """Everything the controller needs from one ZAP execution attempt."""

    execution: EngineExecution
    attestation: ZapRunnerAttestation | None
    request: ZapRunRequest | None
    response: ZapRunResponse | None
    validation_code: str | None


class ZapAdapter(SecurityEngineAdapter):
    """RPC client for the isolated zap-runner. Holds no credential and runs no subprocess."""

    engine = SecurityEngine.ZAP
    adapter_version = ZAP_ADAPTER_VERSION

    def __init__(
        self,
        runner_url: str,
        *,
        enabled: bool,
        timeout_seconds: float = 150.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.runner_url = runner_url.rstrip("/")
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self.last_attestation: ZapRunnerAttestation | None = None
        self.last_checked_at: datetime | None = None
        self.last_reachable: bool | None = None

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
                headers = {"Content-Type": "application/json"} if body is not None else None
                async with client.stream(
                    method, f"{self.runner_url}{path}", content=body, headers=headers
                ) as response:
                    if response.status_code not in {200, 503}:
                        return None
                    data = b""
                    async for chunk in response.aiter_bytes():
                        data += chunk
                        if len(data) > MAX_RPC_RESPONSE_BYTES:
                            return None
                    return data
        except httpx.HTTPError:
            return None

    async def attest(self) -> ZapRunnerAttestation | None:
        """Fetch and strictly validate the runner's attestation. Never raises."""

        self.last_checked_at = datetime.now(UTC)
        if not self.enabled:
            self.last_reachable = None
            return None
        data = await self._bounded("GET", "/v1/attestation")
        if data is None:
            self.last_reachable = False
            self.last_attestation = None
            return None
        self.last_reachable = True
        try:
            self.last_attestation = ZapRunnerAttestation.model_validate_json(data)
        except ValidationError:
            self.last_attestation = None
        return self.last_attestation

    def attestation_problem(
        self, attestation: ZapRunnerAttestation | None, job: ZapEngineJob
    ) -> str | None:
        """Why the attested runner must not execute this job, or None if it may."""

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
        if (
            engine.java_version != manifest.engine.java.version
            or engine.java_runtime_version != manifest.engine.java.runtime_version
        ):
            return "JAVA_RUNTIME_MISMATCH"
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
        if tuple(sorted(attestation.admitted_rule_ids)) != tuple(sorted(job.rule_ids)):
            return "RULE_MANIFEST_MISMATCH"
        guard = attestation.guard
        if not guard.reachable or guard.guard_version != EXPECTED_GUARD_VERSION:
            return "SCOPE_GUARD_NOT_ATTESTED"
        if set(guard.allowed_origins) != {job.target.origin}:
            return "SCOPE_GUARD_ORIGIN_MISMATCH"
        return None

    def build_request(self, job: ZapEngineJob, scan_id: str, execution_id: str) -> ZapRunRequest:
        return ZapRunRequest(
            engine_execution_id=execution_id,
            job_id=job.job_id,
            run_id=job.run_id,
            scan_id=scan_id,
            target_ref=job.target_ref,
            profile_id=job.profile_id,
            projection_ref=job.projection_ref,
            projection_digest=job.projection_digest,
            operation_allowlist_digest=job.allowlist_digest,
            budgets=ZapBudgets(
                max_requests=job.budget.max_requests,
                time_budget_ms=job.budget.time_budget_ms,
                max_report_bytes=job.max_report_bytes,
                max_alerts=job.max_alerts,
            ),
            nonce=secrets.token_hex(16),
            correlation_id=f"corr-{secrets.token_hex(8)}",
        )

    def validate_response(
        self, job: ZapEngineJob, request: ZapRunRequest, response: ZapRunResponse
    ) -> str | None:
        """Cross-check an UNTRUSTED runner response against what the controller authorized."""

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
        if response.status == "REJECTED":
            return None  # a typed runner refusal; nothing ran
        projection = response.projection
        if projection is None or (
            projection.digest != job.projection_digest
            or projection.allowlist_digest != job.allowlist_digest
            or projection.operation_count != job.operation_count
        ):
            return "PROJECTION_MISMATCH"
        if response.status != "COMPLETED" and (response.alerts or response.coverage_complete):
            return "RESULTS_ON_FAILED_EXECUTION"
        if len(response.alerts) > job.max_alerts:
            return "ALERT_BUDGET_EXCEEDED"
        traffic = response.traffic
        if traffic is not None and traffic.forwarded > job.budget.max_requests:
            return "REQUEST_BUDGET_EXCEEDED"
        approved = {(op.method, op.path) for op in job.operations}
        if traffic is not None and any((m, p) not in approved for m, p, _ in traffic.per_path):
            return "UNEXPECTED_ORIGIN_OR_PATH"
        seen: set[tuple[int, str, str, str]] = set()
        for alert in response.alerts:
            if alert.plugin_id not in job.rule_ids:
                return "UNADMITTED_RULE"
            if (alert.method, alert.path) not in approved:
                return "UNEXPECTED_ORIGIN_OR_PATH"
            identity = (alert.plugin_id, alert.method, alert.path, alert.param)
            if identity in seen:
                return "DUPLICATE_ALERT_IDENTITY"
            seen.add(identity)
        if response.status == "COMPLETED" and not (
            response.coverage_complete
            and traffic is not None
            and traffic.forwarded == job.operation_count
            and traffic.blocked == 0
            and response.stages.pscan_drained
            and response.stages.plan_succeeded
            and response.parse.status == "PARSED"
        ):
            return "COMPLETED_WITHOUT_COMPLETE_COVERAGE"
        return None

    async def run(
        self,
        job: ZapEngineJob,
        scan_id: str,
        *,
        execution_id: str,
        attestation: ZapRunnerAttestation | None = None,
    ) -> ZapAdapterResult:
        """Execute one job on an attested runner. Never raises; failures are typed results."""

        started = datetime.now(UTC)

        def failed(code: EngineErrorCode, detail: str, **extra: object) -> ZapAdapterResult:
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
            return ZapAdapterResult(
                execution=execution,
                attestation=extra.get("attestation"),  # type: ignore[arg-type]
                request=extra.get("request"),  # type: ignore[arg-type]
                response=extra.get("response"),  # type: ignore[arg-type]
                validation_code=detail,
            )

        if not self.enabled:
            return failed(EngineErrorCode.ENGINE_DISABLED, "ADAPTER_DISABLED")
        if attestation is None:
            attestation = await self.attest()
        problem = self.attestation_problem(attestation, job)
        if problem is not None:
            return failed(EngineErrorCode.RUNNER_NOT_ATTESTED, problem, attestation=attestation)

        request = self.build_request(job, scan_id, execution_id)
        data = await self._bounded("POST", "/v1/run", request.model_dump_json().encode())
        if data is None:
            return failed(
                EngineErrorCode.RUNNER_UNAVAILABLE,
                "RUNNER_UNAVAILABLE",
                attestation=attestation,
                request=request,
            )
        try:
            response = ZapRunResponse.model_validate_json(data)
        except ValidationError:
            return failed(
                EngineErrorCode.MALFORMED_ENGINE_OUTPUT,
                "RUNNER_RESPONSE_INVALID",
                attestation=attestation,
                request=request,
            )
        problem = self.validate_response(job, request, response)
        if problem is not None:
            return failed(
                EngineErrorCode.MALFORMED_ENGINE_OUTPUT,
                problem,
                attestation=attestation,
                request=request,
                response=response,
            )
        if response.status == "REJECTED":
            return failed(
                EngineErrorCode.RUNNER_REJECTED,
                str(response.error_code or "REJECTED"),
                attestation=attestation,
                request=request,
                response=response,
            )
        if response.status != "COMPLETED" or not response.coverage_complete:
            return failed(
                EngineErrorCode.ENGINE_EXECUTION_INCOMPLETE,
                str(response.error_code or "COVERAGE_INCOMPLETE"),
                attestation=attestation,
                request=request,
                response=response,
            )
        execution = EngineExecution(
            execution_id=execution_id,
            job_id=job.job_id,
            engine=self.engine,
            adapter_version=self.adapter_version,
            status=EngineExecutionStatus.COMPLETED,
            started_at=started,
            completed_at=datetime.now(UTC),
        )
        return ZapAdapterResult(execution, attestation, request, response, None)

    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult:
        """A generic kernel job is never valid for ZAP: it fails closed with zero traffic."""

        now = datetime.now(UTC)
        return AdapterResult(
            execution=EngineExecution(
                execution_id=f"exec-{uuid4().hex[:12]}",
                job_id=job.job_id,
                engine=self.engine,
                adapter_version=self.adapter_version,
                status=EngineExecutionStatus.FAILED,
                started_at=now,
                completed_at=now,
                error=EngineError(
                    engine=self.engine,
                    code=EngineErrorCode.UNSUPPORTED_JOB_TYPE,
                    detail="ZAP executes only controller-built ZapEngineJob records.",
                    job_id=job.job_id,
                ),
            )
        )

    def health(self) -> EngineHealth:
        attestation = self.last_attestation
        authorized = bool(
            self.enabled
            and attestation is not None
            and attestation.ready
            and attestation.engine.pinned
            and attestation.manifest_digest == manifest_digest()
            and attestation.guard.reachable
        )
        if not self.enabled:
            state, detail = "DISABLED", "ZAP adapter is not enabled by the operator."
        elif not self.last_reachable:
            state, detail = "UNREACHABLE", "Isolated zap-runner did not answer attestation."
        elif not authorized:
            state, detail = "NOT_ATTESTED", "Runner is reachable but not attested READY."
        else:
            state, detail = (
                "ENABLED",
                "Isolated runner attested: pinned ZAP, pinned add-ons, attested scope guard.",
            )
        return EngineHealth(
            engine=self.engine,
            adapter_version=self.adapter_version,
            configured=True,
            reachable=self.last_reachable if self.enabled else None,
            enabled=self.enabled,
            authorized=authorized,
            state=state,
            detail=detail,
        )
