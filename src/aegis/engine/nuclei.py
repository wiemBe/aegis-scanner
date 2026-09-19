"""Controller side of the Phase 1.2 Nuclei integration.

Responsibility split (unchanged kernel invariants, applied to an external engine):

- the operator or deterministic policy requests an approved CAPABILITY — never a tool, template,
  flag, URL or header; the AI planner is not involved in this path at all;
- :func:`build_nuclei_job` deterministically selects the approved profile from the immutable
  catalog, resolves the target REFERENCE through the fixed inventory, selects the admitted
  templates for the capability from the checked-in manifest, and constructs a typed
  :class:`NucleiEngineJob` — or rejects with a structured :class:`EngineError` before any runner
  call;
- :class:`NucleiAdapter` translates the job into the strict runner RPC (ids, target reference,
  controller-resolved origin, profile id, template-set id, manifest digest, budgets, nonce) and
  re-validates the runner's typed response as UNTRUSTED input;
- Nuclei results are TOOL_REPORTED only. Promotion belongs to :mod:`aegis.scm_verifier`.
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
from aegis.engine.catalog import (
    ADAPTER_VERSIONS,
    get_engine_capability,
    get_engine_profile,
)
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
from aegis_nuclei.contracts import (
    MAX_RPC_RESPONSE_BYTES,
    NucleiBudgets,
    NucleiRunRequest,
    NucleiRunResponse,
    RunnerAttestation,
)
from aegis_nuclei.manifest import TemplateManifest, load_manifest, manifest_digest
from aegis_nuclei.parser import PARSER_VERSION, expected_request_urls
from aegis_nuclei.profile import PROFILE_ID
from aegis_nuclei.targets import NUCLEI_TARGETS, NucleiTarget

NUCLEI_ADAPTER_VERSION = ADAPTER_VERSIONS[SecurityEngine.NUCLEI]
NUCLEI_MAX_RESULTS = 4
NUCLEI_MAX_OUTPUT_BYTES = 65_536
READ_ONLY = frozenset({"GET", "HEAD"})


class NucleiEngineJob(BaseModel):
    """The typed Nuclei job. Built ONLY by :func:`build_nuclei_job`.

    Like :class:`aegis.engine.contracts.EngineJob` it has no command, argv, flag, raw URL, header,
    cookie, credential or template-path field and forbids extra keys. ``template_ids`` records
    which admitted templates the CONTROLLER selected for the capability (for correlation and
    provenance); it is never sent to the runner, which resolves templates from its own manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    engine: Literal[SecurityEngine.NUCLEI] = SecurityEngine.NUCLEI
    profile_id: Literal["NUCLEI_LAB_SAFE_HTTP_V1"]
    capability_id: str = Field(min_length=3, max_length=100)
    adapter_version: str = Field(min_length=1, max_length=40)
    run_id: str = Field(pattern=r"^scan-[a-f0-9]{12}$")
    environment: EngineEnvironment
    activity: EngineActivity
    target: TargetReference
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    template_set_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    manifest_version: str = Field(max_length=16)
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    template_ids: tuple[str, ...] = Field(min_length=1, max_length=8)
    budget: EngineBudget
    max_results: int = Field(ge=1, le=16)
    max_output_bytes: int = Field(ge=1024, le=262_144)
    created_by: Literal["CONTROLLER"] = "CONTROLLER"


def _reject(code: EngineErrorCode, detail: str = "") -> EnginePolicyRejection:
    return EnginePolicyRejection(
        EngineError(engine=SecurityEngine.NUCLEI, code=code, detail=detail[:200])
    )


def build_nuclei_job(
    *,
    profile_id: str,
    capability_id: str,
    run_id: str,
    environment: EngineEnvironment,
    target_ref: str,
    remaining_requests: int,
    allowed_origins: Iterable[str],
    adapter_enabled: bool,
    manifest: TemplateManifest | None = None,
    digest: str | None = None,
) -> NucleiEngineJob:
    """Construct a validated :class:`NucleiEngineJob`, or raise :class:`EnginePolicyRejection`.

    Every rejection happens before the runner is contacted, so it produces zero target traffic."""

    manifest = manifest or load_manifest()
    digest = digest or manifest_digest()

    profile = get_engine_profile(profile_id)
    if profile is None:
        raise _reject(EngineErrorCode.UNKNOWN_PROFILE, profile_id)
    if profile.engine is not SecurityEngine.NUCLEI:
        raise _reject(EngineErrorCode.UNKNOWN_ENGINE, profile.engine.value)

    capability = get_engine_capability(capability_id)
    if capability is None or capability.engine is not SecurityEngine.NUCLEI:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    # Safety classification is checked before profile membership so a request for a dangerous
    # capability is refused for the dangerous property itself, with a precise code.
    if capability.state_changing_possible or not set(capability.supported_methods) <= READ_ONLY:
        raise _reject(EngineErrorCode.UNAPPROVED_STATE_CHANGE, capability_id)
    if capability.protocol != "http":
        raise _reject(EngineErrorCode.UNSUPPORTED_PROTOCOL, capability.protocol)
    if capability_id not in profile.capability_ids:
        raise _reject(EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)

    if not profile.enabled or not adapter_enabled:
        raise _reject(EngineErrorCode.ENGINE_DISABLED, profile_id)
    if environment not in capability.allowed_environments or profile.environment is not environment:
        raise _reject(EngineErrorCode.DISALLOWED_ENVIRONMENT, environment.value)

    target = NUCLEI_TARGETS.get(target_ref)
    if target is None:
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, "unknown target reference")
    origins = {o.rstrip("/") for o in allowed_origins}
    if target.origin.rstrip("/") not in origins:
        raise _reject(EngineErrorCode.OUT_OF_SCOPE_ORIGIN, target.origin)

    if manifest.profile_id != profile_id:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, "manifest profile")
    templates = manifest.for_capability(capability_id)
    if not templates:
        raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, capability_id)
    for entry in templates:
        if entry.protocol != "http":
            raise _reject(EngineErrorCode.UNSUPPORTED_PROTOCOL, entry.template_id)
        if not set(entry.methods) <= READ_ONLY:
            raise _reject(EngineErrorCode.UNAPPROVED_STATE_CHANGE, entry.template_id)
        if entry.verification_policy != capability.verification_policy.value:
            raise _reject(EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, entry.template_id)

    required = sum(entry.max_requests for entry in templates)
    if required > capability.request_budget:
        raise _reject(EngineErrorCode.BUDGET_EXCEEDED, "capability_requests")
    if required > remaining_requests:
        raise _reject(EngineErrorCode.BUDGET_EXCEEDED, "requests")

    try:
        return NucleiEngineJob(
            job_id=f"job-{uuid4().hex[:12]}",
            profile_id=PROFILE_ID,  # type: ignore[arg-type]
            capability_id=capability_id,
            adapter_version=capability.adapter_version,
            run_id=run_id,
            environment=environment,
            activity=capability.activity,
            target=TargetReference(
                engine=SecurityEngine.NUCLEI,
                environment=environment,
                origin=target.origin,
                operation_id=target.operation_id,
                method="GET",
                normalized_path=target.base_path,
            ),
            target_ref=target.target_ref,
            template_set_id=manifest.template_set_id,
            manifest_version=manifest.manifest_version,
            manifest_digest=digest,
            template_ids=tuple(entry.template_id for entry in templates),
            budget=EngineBudget(
                max_requests=required,
                max_concurrency=capability.concurrency_budget,
                time_budget_ms=capability.time_budget_ms,
            ),
            max_results=NUCLEI_MAX_RESULTS,
            max_output_bytes=NUCLEI_MAX_OUTPUT_BYTES,
        )
    except ValidationError as exc:  # pragma: no cover - inputs are already typed
        raise _reject(EngineErrorCode.MALFORMED_ENGINE_OUTPUT, "job_validation") from exc


@dataclass
class NucleiAdapterResult:
    """Everything the controller needs from one Nuclei execution attempt.

    ``execution`` is the kernel's recordable :class:`EngineExecution`. ``response`` is the
    validated runner response (None when the runner was unreachable or its response was rejected).
    ``validation_code`` names the first cross-check the response failed, if any."""

    execution: EngineExecution
    attestation: RunnerAttestation | None
    request: NucleiRunRequest | None
    response: NucleiRunResponse | None
    validation_code: str | None


def target_for(job: NucleiEngineJob) -> NucleiTarget:
    return NUCLEI_TARGETS[job.target_ref]


class NucleiAdapter(SecurityEngineAdapter):
    """RPC client for the isolated nuclei-runner. Holds no credential and runs no subprocess."""

    engine = SecurityEngine.NUCLEI
    adapter_version = NUCLEI_ADAPTER_VERSION

    def __init__(
        self,
        runner_url: str,
        *,
        enabled: bool,
        timeout_seconds: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.runner_url = runner_url.rstrip("/")
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self._transport = transport
        self.last_attestation: RunnerAttestation | None = None
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

    async def attest(self) -> RunnerAttestation | None:
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
            self.last_attestation = RunnerAttestation.model_validate_json(data)
        except ValidationError:
            self.last_attestation = None
        return self.last_attestation

    def attestation_problem(
        self, attestation: RunnerAttestation | None, job: NucleiEngineJob
    ) -> str | None:
        """Why the attested runner must not execute this job, or None if it may."""

        if attestation is None:
            return "RUNNER_UNAVAILABLE_OR_INVALID"
        if not attestation.ready:
            return "RUNNER_NOT_READY"
        if not attestation.engine.pinned:
            return "ENGINE_NOT_PINNED"
        manifest = load_manifest()
        if attestation.engine.nuclei_version != manifest.engine.version:
            return "ENGINE_VERSION_MISMATCH"
        pinned_digests = {a.binary_sha256 for a in manifest.engine.artifacts.values()}
        if attestation.engine.binary_sha256 not in pinned_digests:
            return "ENGINE_DIGEST_MISMATCH"
        if (
            attestation.manifest_digest != job.manifest_digest
            or attestation.template_set_id != job.template_set_id
        ):
            return "MANIFEST_DIGEST_MISMATCH"
        if attestation.profile_id != job.profile_id:
            return "PROFILE_MISMATCH"
        expected = {(e.template_id, e.sha256) for e in manifest.templates}
        attested = {(t.template_id, t.sha256) for t in attestation.templates}
        if attested != expected:
            return "TEMPLATE_SET_MISMATCH"
        if attestation.signature_probe != "SIGNED_VERIFIED" or any(
            t.signature_status != "SIGNED_VERIFIED" or not t.admitted for t in attestation.templates
        ):
            return "SIGNATURE_NOT_VERIFIED"
        if attestation.unexpected_template_files:
            return "UNEXPECTED_TEMPLATE_FILES"
        return None

    def build_request(
        self, job: NucleiEngineJob, scan_id: str, execution_id: str
    ) -> NucleiRunRequest:
        return NucleiRunRequest(
            engine_execution_id=execution_id,
            job_id=job.job_id,
            run_id=job.run_id,
            scan_id=scan_id,
            target_ref=job.target_ref,
            origin=job.target.origin,
            profile_id=job.profile_id,
            template_set_id=job.template_set_id,
            manifest_digest=job.manifest_digest,
            budgets=NucleiBudgets(
                max_requests=job.budget.max_requests,
                max_results=job.max_results,
                time_budget_ms=job.budget.time_budget_ms,
                max_output_bytes=job.max_output_bytes,
            ),
            nonce=secrets.token_hex(16),
            correlation_id=f"corr-{secrets.token_hex(8)}",
        )

    def validate_response(
        self, job: NucleiEngineJob, request: NucleiRunRequest, response: NucleiRunResponse
    ) -> str | None:
        """Cross-check an UNTRUSTED runner response against what the controller authorized."""

        if (
            response.engine_execution_id != request.engine_execution_id
            or response.job_id != job.job_id
            or response.nonce != request.nonce
        ):
            return "CORRELATION_MISMATCH"
        if response.manifest_digest != job.manifest_digest:
            return "MANIFEST_DIGEST_MISMATCH"
        if response.template_set_id != job.template_set_id or response.profile_id != job.profile_id:
            return "PROFILE_OR_TEMPLATE_SET_MISMATCH"
        if not response.engine.pinned:
            return "ENGINE_NOT_PINNED"
        if response.parse.parser_version != PARSER_VERSION:
            return "PARSER_VERSION_MISMATCH"
        if len(response.results) > job.max_results:
            return "RESULT_BUDGET_EXCEEDED"
        if response.status != "COMPLETED" and response.results:
            return "RESULTS_ON_FAILED_EXECUTION"
        if (
            response.http_connections is not None
            and response.http_connections > job.budget.max_requests
        ):
            return "REQUEST_BUDGET_EXCEEDED"
        target = target_for(job)
        manifest = load_manifest()
        seen: set[tuple[str, str]] = set()
        for record in response.results:
            entry = manifest.by_id(record.template_id)
            if entry is None or record.template_id not in job.template_ids:
                return "UNEXPECTED_TEMPLATE_ID"
            if record.target_ref != job.target_ref:
                return "UNEXPECTED_TARGET"
            allowed_paths = {
                url[len(target.origin) :] for url in expected_request_urls(entry, target)
            } | {target.base_path}
            if record.checked_path not in allowed_paths:
                return "UNEXPECTED_ORIGIN_OR_PATH"
            if record.matcher_status and record.checked_path == target.base_path:
                return "UNEXPECTED_ORIGIN_OR_PATH"
            identity = (record.template_id, record.target_ref)
            if identity in seen:
                return "DUPLICATE_RESULT_IDENTITY"
            seen.add(identity)
        return None

    async def run(
        self,
        job: NucleiEngineJob,
        scan_id: str,
        *,
        execution_id: str,
        attestation: RunnerAttestation | None = None,
    ) -> NucleiAdapterResult:
        """Execute one job on an attested runner. Never raises; failures are typed FAILED results.

        The caller normally attests first (to audit the runner and manifest before execution); the
        attestation is re-checked here regardless, and fetched if it was not supplied."""

        started = datetime.now(UTC)

        def failed(code: EngineErrorCode, detail: str, **extra: object) -> NucleiAdapterResult:
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
            return NucleiAdapterResult(
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
            response = NucleiRunResponse.model_validate_json(data)
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
        return NucleiAdapterResult(execution, attestation, request, response, None)

    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult:
        """A generic kernel job is never valid for Nuclei: it fails closed with zero traffic."""

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
                    detail="Nuclei executes only controller-built NucleiEngineJob records.",
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
            and attestation.signature_probe == "SIGNED_VERIFIED"
            and attestation.manifest_digest == manifest_digest()
        )
        if not self.enabled:
            state, detail = "DISABLED", "Nuclei adapter is not enabled by the operator."
        elif not self.last_reachable:
            state, detail = "UNREACHABLE", "Isolated nuclei-runner did not answer attestation."
        elif not authorized:
            state, detail = "NOT_ATTESTED", "Runner is reachable but not attested READY."
        else:
            state, detail = "ENABLED", "Isolated runner attested: pinned engine, signed templates."
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
