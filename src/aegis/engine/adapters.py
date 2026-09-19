"""Security-engine adapters (Phase 1.1).

An adapter is the ONLY place an engine's execution mechanics live. It receives a typed
:class:`EngineJob` and translates it into engine-specific execution. It must never expand scope,
interpret arbitrary model prose, or reach a target outside the job. Credentials stay inside the
adapter (connector) boundary; no adapter uses a subprocess or shell.

Phase 1.1 ships exactly one enabled adapter — :class:`AegisNativeAdapter`, which wraps the existing
Phase 0.8 executor/safety/verifier path unchanged — plus three fail-closed
:class:`DisabledEngineAdapter` skeletons for Nuclei, ZAP and Burp DAST.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from aegis.engine.catalog import ADAPTER_VERSIONS
from aegis.engine.contracts import (
    EngineError,
    EngineErrorCode,
    EngineExecution,
    EngineExecutionStatus,
    EngineHealth,
    EngineJob,
    EngineObservation,
    EngineReportedFinding,
    SecurityEngine,
)
from aegis.executor import TestExecutor
from aegis.models import PlannedRequest, RequestEvidence
from aegis.safety import SafetyController, SafetyViolation
from aegis.surface import OBJECTS, PROFILE_ACTORS, Variant

PARSER_VERSION = "engine-normalizer/1.1.0"


@dataclass
class AdapterResult:
    """The full result of an adapter execution.

    ``execution`` is the strict, recordable :class:`EngineExecution`. ``evidence`` is the underlying
    :class:`RequestEvidence` list the controller binds exactly as it did before Phase 1.1, so the
    AEGIS_NATIVE behaviour, request sequence and verifier authority are byte-for-byte unchanged."""

    execution: EngineExecution
    evidence: list[RequestEvidence] = field(default_factory=list)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _new_execution_id() -> str:
    return f"exec-{uuid4().hex[:12]}"


class SecurityEngineAdapter(ABC):
    """Common adapter interface. Every engine implements exactly this surface."""

    engine: SecurityEngine
    adapter_version: str
    enabled: bool

    @abstractmethod
    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult:
        """Execute a typed job. Fail closed with zero traffic on any scope/enable error."""

    @abstractmethod
    def health(self) -> EngineHealth:
        """Return honest four-state health. Never reports a disabled adapter as available."""


class AegisNativeAdapter(SecurityEngineAdapter):
    """The enabled native adapter. Wraps the existing executor/safety path with no behaviour change.

    It re-validates every request's scope through the :class:`SafetyController` (defense in depth:
    an adapter can never expand scope even if a mis-compiled job reached it), resolves synthetic
    credentials only inside the executor connector boundary, and reports raw cross-owner 200 signals
    as UNTRUSTED :class:`EngineReportedFinding` observations. It never confirms anything — the
    deterministic verifier remains the sole authority."""

    engine = SecurityEngine.AEGIS_NATIVE
    adapter_version = ADAPTER_VERSIONS[SecurityEngine.AEGIS_NATIVE]
    enabled = True

    def __init__(self, executor: TestExecutor, safety: SafetyController) -> None:
        self._executor = executor
        self._safety = safety

    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult:
        started = datetime.now(UTC)
        execution_id = _new_execution_id()

        # Defense in depth: re-validate the entire job's scope BEFORE any network action. A single
        # out-of-scope request fails the whole job closed with zero traffic.
        for request in job.requests:
            planned = PlannedRequest(
                name=request.name,
                method=request.method,
                path=request.path,
                credential_profile=request.credential_profile,
                purpose="Engine-boundary read-only authorization probe.",
            )
            try:
                self._safety.approve_request(job.target.origin, planned, variant)
            except SafetyViolation:
                return self._failed(
                    job,
                    execution_id,
                    started,
                    EngineErrorCode.SCOPE_EXPANSION_ATTEMPT,
                    request.path,
                )

        if len(job.requests) > job.budget.max_requests:
            return self._failed(
                job, execution_id, started, EngineErrorCode.BUDGET_EXCEEDED, "requests"
            )

        observations: list[EngineObservation] = []
        evidence: list[RequestEvidence] = []
        reported: list[EngineReportedFinding] = []
        for request in job.requests:
            planned = PlannedRequest(
                name=request.name,
                method=request.method,
                path=request.path,
                credential_profile=request.credential_profile,
                purpose="Engine-boundary read-only authorization probe.",
            )
            item = await self._executor.execute_one(job.target.origin, planned, variant)
            evidence.append(item)
            observations.append(
                EngineObservation(
                    request_name=item.name,
                    method=item.method,  # type: ignore[arg-type]
                    path=item.path,
                    credential_profile=item.credential_profile,  # type: ignore[arg-type]
                    status_code=item.status_code,
                    duration_ms=item.duration_ms,
                    content_digest=_digest(item.response_excerpt),
                    has_error=item.error is not None,
                )
            )
            self._maybe_report(job, request, item, reported)

        execution = EngineExecution(
            execution_id=execution_id,
            job_id=job.job_id,
            engine=self.engine,
            adapter_version=self.adapter_version,
            status=EngineExecutionStatus.COMPLETED,
            started_at=started,
            completed_at=datetime.now(UTC),
            observations=observations,
            reported_findings=reported,
        )
        return AdapterResult(execution=execution, evidence=evidence)

    def _maybe_report(
        self,
        job: EngineJob,
        request: object,
        item: RequestEvidence,
        reported: list[EngineReportedFinding],
    ) -> None:
        """Emit a raw, UNTRUSTED cross-owner 200 signal. This is an observation the engine reports,
        not a verdict: the deterministic verifier alone can promote it."""

        obj = item.path.rsplit("/", 1)[-1]
        actor = PROFILE_ACTORS.get(item.credential_profile)
        if (
            item.status_code == 200
            and not item.error
            and obj in OBJECTS
            and actor is not None
            and OBJECTS[obj] != actor
        ):
            reported.append(
                EngineReportedFinding(
                    report_key=f"{job.capability_id}:{item.credential_profile}:{obj}",
                    engine=self.engine,
                    capability_id=job.capability_id,
                    claimed_category="API1:2023 BOLA",
                    target_operation_id=job.target.operation_id,
                    object_ref=obj,
                    principal_profile=item.credential_profile,  # type: ignore[arg-type]
                    observation_names=[item.name],
                    signal="Cross-owner object read returned 200 (unverified raw signal).",
                )
            )

    def _failed(
        self,
        job: EngineJob,
        execution_id: str,
        started: datetime,
        code: EngineErrorCode,
        detail: str,
    ) -> AdapterResult:
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
        return AdapterResult(execution=execution, evidence=[])

    def health(self) -> EngineHealth:
        return EngineHealth(
            engine=self.engine,
            adapter_version=self.adapter_version,
            configured=True,
            reachable=True,
            enabled=True,
            authorized=True,
            state="ENABLED",
            detail="Native in-process adapter over the authorized synthetic lab.",
        )


class DisabledEngineAdapter(SecurityEngineAdapter):
    """A fail-closed skeleton for a planned-but-disconnected engine.

    It installs nothing, opens no network, mounts no credential, invokes no MCP and runs no
    subprocess. Any :meth:`execute` returns a structured ``ENGINE_DISABLED`` result with zero
    traffic. It exists so the console can describe the planned integration honestly and so the
    dispatcher has a uniform, safe target for a job that should never have been built."""

    enabled = False

    def __init__(self, engine: SecurityEngine) -> None:
        self.engine = engine
        self.adapter_version = ADAPTER_VERSIONS[engine]

    async def execute(self, job: EngineJob, variant: Variant) -> AdapterResult:
        started = datetime.now(UTC)
        execution = EngineExecution(
            execution_id=_new_execution_id(),
            job_id=job.job_id,
            engine=self.engine,
            adapter_version=self.adapter_version,
            status=EngineExecutionStatus.FAILED,
            started_at=started,
            completed_at=started,
            error=EngineError(
                engine=self.engine,
                code=EngineErrorCode.ENGINE_DISABLED,
                detail="Adapter is disabled and fails closed (Phase 1.1).",
                job_id=job.job_id,
            ),
        )
        return AdapterResult(execution=execution, evidence=[])

    def health(self) -> EngineHealth:
        return EngineHealth(
            engine=self.engine,
            adapter_version=self.adapter_version,
            configured=True,  # a catalog profile exists
            reachable=None,  # never probed while disabled
            enabled=False,
            authorized=False,
            state="DISABLED",
            detail="Planned integration. Not installed, not connected, fail-closed.",
        )


class EngineDispatcher:
    """Routes a typed job to its adapter. It never builds a job (the policy does) and never widens
    scope. If a job names an engine with no registered adapter, dispatch fails closed."""

    def __init__(self, adapters: dict[SecurityEngine, SecurityEngineAdapter]) -> None:
        self._adapters = adapters

    def adapter_for(self, engine: SecurityEngine) -> SecurityEngineAdapter | None:
        return self._adapters.get(engine)

    def is_enabled(self, engine: SecurityEngine) -> bool:
        adapter = self._adapters.get(engine)
        return bool(adapter and adapter.enabled)

    def adapter_version_for(self, engine: SecurityEngine) -> str:
        adapter = self._adapters.get(engine)
        return adapter.adapter_version if adapter else ADAPTER_VERSIONS.get(engine, "unknown/0.0.0")

    async def dispatch(self, job: EngineJob, variant: Variant) -> AdapterResult:
        adapter = self._adapters.get(job.engine)
        if adapter is None:
            started = datetime.now(UTC)
            execution = EngineExecution(
                execution_id=_new_execution_id(),
                job_id=job.job_id,
                engine=job.engine,
                adapter_version=ADAPTER_VERSIONS.get(job.engine, "unknown/0.0.0"),
                status=EngineExecutionStatus.FAILED,
                started_at=started,
                completed_at=started,
                error=EngineError(
                    engine=job.engine,
                    code=EngineErrorCode.UNKNOWN_ENGINE,
                    detail="No adapter registered for engine.",
                    job_id=job.job_id,
                ),
            )
            return AdapterResult(execution=execution, evidence=[])
        return await adapter.execute(job, variant)

    def health(self) -> list[EngineHealth]:
        return [
            self._adapters[engine].health()
            for engine in SecurityEngine
            if engine in self._adapters
        ]


# A default, static description of the adapter fleet for read-only projections that do not have a
# live dispatcher instance. The live dispatcher is built per-service with a wired executor/safety.
ADAPTERS: dict[SecurityEngine, bool] = {
    SecurityEngine.AEGIS_NATIVE: True,
    SecurityEngine.NUCLEI: False,
    SecurityEngine.ZAP: False,
    SecurityEngine.BURP_DAST: False,
}


def get_adapter(
    engine: SecurityEngine,
    *,
    executor: TestExecutor | None = None,
    safety: SafetyController | None = None,
) -> SecurityEngineAdapter:
    """Build the adapter for an engine. AEGIS_NATIVE requires a wired executor/safety."""

    if engine is SecurityEngine.AEGIS_NATIVE:
        if executor is None or safety is None:
            raise ValueError("AEGIS_NATIVE adapter requires an executor and a safety controller")
        return AegisNativeAdapter(executor, safety)
    return DisabledEngineAdapter(engine)


def build_dispatcher(
    executor: TestExecutor,
    safety: SafetyController,
    *,
    nuclei: SecurityEngineAdapter | None = None,
) -> EngineDispatcher:
    """Wire the adapter fleet: the enabled native adapter, the Phase 1.2 Nuclei adapter when the
    operator enabled it (otherwise its fail-closed skeleton), and the ZAP/Burp skeletons."""

    adapters: dict[SecurityEngine, SecurityEngineAdapter] = {
        SecurityEngine.AEGIS_NATIVE: AegisNativeAdapter(executor, safety),
        SecurityEngine.NUCLEI: nuclei or DisabledEngineAdapter(SecurityEngine.NUCLEI),
        SecurityEngine.ZAP: DisabledEngineAdapter(SecurityEngine.ZAP),
        SecurityEngine.BURP_DAST: DisabledEngineAdapter(SecurityEngine.BURP_DAST),
    }
    return EngineDispatcher(adapters)
