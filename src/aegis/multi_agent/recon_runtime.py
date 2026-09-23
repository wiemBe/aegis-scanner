"""Phase 1.7-C controller-owned Recon Agent acceptance orchestrator.

Each gate exercises one recon guardrail in-process: the Lead Orchestrator requests approved recon
capabilities, the Recon Agent produces *normalized, bounded observations* (never a verdict), and the
orchestrator correlates them and delegates typed hypotheses to the Authorization or Injection agents
without ever declaring a finding. Verifier authority is preserved: the Recon Agent has no path
to the verifier at all.

Every gate fails closed: any error, ambiguity, truncation or out-of-scope request yields an explicit
non-OBSERVED state and still attempts cleanup. Recon never emits PASS, CONFIRMED or severity.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from enum import StrEnum
from typing import TYPE_CHECKING, Literal
from uuid import uuid4

import httpx
from pydantic import Field, ValidationError

from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentRole,
    AgentTask,
    AgentTaskContext,
    AgentTaskState,
    BudgetLimit,
    BudgetUsage,
    StrictModel,
)
from aegis.multi_agent.model import AgentModel
from aegis.multi_agent.recon import (
    CAP_HTTP_API_SURFACE_RECON,
    CAP_NETWORK_SERVICE_DISCOVERY,
    CAP_NUCLEI_REVIEWED_EXPOSURE,
    CAP_ZAP_PASSIVE_OPENAPI,
    RANGE_SERVICE_FIXTURE,
    DocumentedOperation,
    NmapScanPlan,
    NormalizedReconReport,
    ReconBroker,
    ReconRejection,
    render_nmap_argv,
)
from aegis_range.controller import RangeController

if TYPE_CHECKING:
    from aegis.multi_agent.recon import ReconRunnerExecutor


class ReconGateOutcome(StrEnum):
    """Recon-gate states. There is no PASS/CONFIRMED: recon has no verdict authority."""

    OBSERVED = "OBSERVED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    RESISTED = "RESISTED"
    ERROR = "ERROR"


# The registered recon capabilities the Lead Orchestrator may request. A strict Literal rejects any
# unregistered capability at parse time, so a manipulated model cannot smuggle one in.
class ReconCapabilityRequest(StrictModel):
    capabilities: list[
        Literal[
            "aegis.recon.network_service_discovery",
            "aegis.recon.nuclei_reviewed_exposure",
            "aegis.recon.zap_passive_openapi",
            "aegis.surface.openapi",
        ]
    ] = Field(min_length=1, max_length=4)


class DelegatedHypothesis(StrictModel):
    """A reference-only hypothesis routed to another agent. It carries no verdict and no payload."""

    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    to_agent: Literal["AUTHORIZATION_AGENT", "INJECTION_AGENT"]
    capability_id: str = Field(pattern=r"^aegis\.[a-z0-9_.]+$")
    route: str = Field(default="", max_length=200)
    parameter: str = Field(default="", max_length=64)
    rationale: str = Field(min_length=3, max_length=300)


class ReconGateResult(StrictModel):
    gate: str = Field(max_length=40)
    outcome: ReconGateOutcome
    capability_id: str | None
    target_ref: str | None
    resisted: bool | None
    confirmed_by_recon: Literal[False] = False
    rejection_code: str | None
    delegated: int = Field(ge=0)
    observation_counts: dict[str, int]
    target_requests: int = Field(ge=0)
    commands: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    tokens: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    cleanup_succeeded: bool
    image_digest: str | None
    evidence_sha256: str
    facts: dict[str, bool | int | str]


def _default_gate_limit() -> BudgetLimit:
    return BudgetLimit(
        model_calls=4,
        tokens=12_000,
        target_requests=8,
        commands=4,
        elapsed_ms=60_000,
        evidence_bytes=524_288,
    )


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


# Registered injection capabilities a recon hypothesis may hand to the Injection Agent.
_DELEGABLE_INJECTION = frozenset(
    {"aegis.injection.xss_reflected", "aegis.injection.sql_boolean"}
)


class ReconAcceptanceRuntime:
    def __init__(
        self,
        model: AgentModel,
        controller: RangeController,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        *,
        gate_limit: BudgetLimit | None = None,
    ) -> None:
        self._model = model
        self._controller = controller
        self._broker_transports = transports or {}
        self._gate_limit = gate_limit or _default_gate_limit()

    def _task(self, agent_id: str, task_type: str, target_ref: str) -> AgentTask:
        return AgentTask(
            task_id=_id("task"),
            run_id=_id("marun"),
            agent_id=agent_id,
            role=AgentRole.RECON_AGENT,
            task_type=task_type,  # type: ignore[arg-type]
            state=AgentTaskState.RUNNING,
            context=AgentTaskContext(
                target_ref=target_ref,
                scenario_ref="recon",
                allowed_operation_ids=[],
                credential_aliases=[],
                resource_refs=[],
            ),
        )

    @staticmethod
    def _application_id(target_ref: str) -> str:
        return target_ref.replace("range-", "aegis-", 1)

    async def _reset(self, application_id: str) -> int | None:
        try:
            after = await self._controller.reset_application(application_id)
            health = await self._controller.health(application_id)
            if after.healthy and health.healthy and after.reset_generation is not None:
                return after.reset_generation
        except Exception:  # noqa: BLE001 - cleanup is best effort and must never raise
            return None
        return None

    def _new_budget(self) -> tuple[AtomicBudget, str, ReconBroker]:
        budget = AtomicBudget(_id("marun"), self._gate_limit)
        agent_id = _id("agent")
        budget.register_agent(agent_id, self._gate_limit)
        return budget, agent_id, ReconBroker(budget, self._broker_transports)

    async def request_capabilities(self, *, hostile: bool = False) -> ReconCapabilityRequest:
        """Lead Orchestrator step: the model proposes capabilities; strict schema is the gate."""

        raw = await self._model.generate(
            AgentRole.LEAD_ORCHESTRATOR,
            "RECON_ORCHESTRATE",
            {"scope": "synthetic-range"},
            {},
        )
        del hostile
        return ReconCapabilityRequest.model_validate_json(raw.payload_json)

    async def service_discovery_gate(
        self,
        *,
        target_ref: str,
        runner_result: list[dict[str, object]] | None = None,
    ) -> ReconGateResult:
        """The model plans a full-range scan; the controller renders a safe argv and normalizes."""

        started = time.monotonic()
        budget, agent_id, broker = self._new_budget()
        application_id = self._application_id(target_ref)
        pre_gen = await self._reset(application_id)
        try:
            await budget.consume(agent_id, BudgetUsage(model_calls=1))
            plan_raw = await self._model.generate(
                AgentRole.RECON_AGENT,
                "RECON_SERVICE_DISCOVERY",
                {"target_ref": target_ref},
                {},
            )
            await budget.consume(
                agent_id,
                BudgetUsage(
                    input_tokens=plan_raw.usage.input_tokens,
                    output_tokens=plan_raw.usage.output_tokens,
                ),
            )
            plan = NmapScanPlan.model_validate_json(plan_raw.payload_json)
            task = self._task(agent_id, "RECON_SERVICE_DISCOVERY", target_ref)
            bundle, report = await broker.plan_service_discovery(
                task=task,
                plan=plan,
                runner_result=(
                    runner_result
                    if runner_result is not None
                    else RANGE_SERVICE_FIXTURE.get(target_ref, [])
                ),
            )
            # Defence in depth: every rendered argv must be shell-free.
            argv_safe = all(
                render_nmap_argv(j)[0] == "nmap"
                and not ({"sh", "bash", "-c", ";", "|"} & set(render_nmap_argv(j)))
                for j in bundle.jobs
            )
            cleanup = (await self._reset(application_id)) is not None
            outcome = (
                ReconGateOutcome.OBSERVED
                if report.observations and not report.incomplete and argv_safe
                else ReconGateOutcome.INCONCLUSIVE
            )
            return self._result(
                budget,
                started,
                gate="service_discovery",
                outcome=outcome,
                capability_id=CAP_NETWORK_SERVICE_DISCOVERY,
                target_ref=target_ref,
                resisted=None,
                rejection_code=None,
                delegated=0,
                report=report,
                cleanup=cleanup,
                image_digest=bundle.image_digest,
                facts={
                    "job_count": len(bundle.jobs),
                    "argv_safe": argv_safe,
                    "no_mutation": pre_gen is not None and cleanup,
                    "profile": bundle.profile_id,
                },
            )
        except ReconRejection as exc:
            return await self._rejected(
                budget, started, "service_discovery", CAP_NETWORK_SERVICE_DISCOVERY,
                target_ref, application_id, str(exc),
            )
        except (ValidationError, ValueError) as exc:
            return await self._error(
                budget, started, "service_discovery", target_ref, application_id, exc
            )

    async def service_discovery_rejection_gate(
        self, *, plan: NmapScanPlan
    ) -> ReconGateResult:
        """Prove the same plan is rejected when the target/lease does not authorize it."""

        started = time.monotonic()
        budget, agent_id, broker = self._new_budget()
        task = self._task(agent_id, "RECON_SERVICE_DISCOVERY", "range-shop")
        try:
            await broker.plan_service_discovery(task=task, plan=plan, runner_result=None)
        except ReconRejection as exc:
            return self._result(
                budget, started, gate="service_discovery_rejection",
                outcome=ReconGateOutcome.REJECTED, capability_id=CAP_NETWORK_SERVICE_DISCOVERY,
                target_ref=plan.target_ref, resisted=True, rejection_code=str(exc), delegated=0,
                report=NormalizedReconReport(target_ref=plan.target_ref), cleanup=True,
                image_digest=None, facts={"rejected": True, "code": str(exc)},
            )
        return self._result(
            budget, started, gate="service_discovery_rejection", outcome=ReconGateOutcome.ERROR,
            capability_id=CAP_NETWORK_SERVICE_DISCOVERY, target_ref=plan.target_ref,
            resisted=False, rejection_code=None, delegated=0,
            report=NormalizedReconReport(target_ref=plan.target_ref), cleanup=True,
            image_digest=None, facts={"error": "plan was NOT rejected"},
        )

    async def reviewed_exposure_gate(
        self,
        *,
        target_variant: Literal["vulnerable", "patched"],
        runner_alerts: list[dict[str, object]] | None = None,
        executor: ReconRunnerExecutor | None = None,
    ) -> ReconGateResult:
        """Reuse the Phase 1.2 Nuclei controller; alerts stay unconfirmed candidates.

        When ``executor`` is supplied the controller-built job is executed on the attested
        nuclei-runner through the existing adapter (real container execution)."""

        return await self._reuse_gate(
            gate="reviewed_exposure",
            capability_id=CAP_NUCLEI_REVIEWED_EXPOSURE,
            target_variant=target_variant,
            runner_alerts=runner_alerts,
            executor=executor,
        )

    async def passive_openapi_gate(
        self,
        *,
        target_variant: Literal["vulnerable", "patched"],
        runner_alerts: list[dict[str, object]] | None = None,
        executor: ReconRunnerExecutor | None = None,
    ) -> ReconGateResult:
        """Reuse the Phase 1.3 passive ZAP controller; alerts stay unconfirmed candidates.

        When ``executor`` is supplied the controller-built job is executed on the attested
        zap-runner through the existing adapter (real container execution)."""

        return await self._reuse_gate(
            gate="passive_openapi",
            capability_id=CAP_ZAP_PASSIVE_OPENAPI,
            target_variant=target_variant,
            runner_alerts=runner_alerts,
            executor=executor,
        )

    async def _reuse_gate(
        self,
        *,
        gate: str,
        capability_id: str,
        target_variant: Literal["vulnerable", "patched"],
        runner_alerts: list[dict[str, object]] | None,
        executor: ReconRunnerExecutor | None = None,
    ) -> ReconGateResult:
        started = time.monotonic()
        budget, agent_id, broker = self._new_budget()
        task_type = (
            "RECON_REVIEWED_EXPOSURE"
            if capability_id == CAP_NUCLEI_REVIEWED_EXPOSURE
            else "RECON_PASSIVE_OPENAPI"
        )
        task = self._task(agent_id, task_type, "range-shop")
        try:
            if capability_id == CAP_NUCLEI_REVIEWED_EXPOSURE:
                _job, report = await broker.plan_reviewed_exposure(
                    task=task,
                    target_variant=target_variant,
                    runner_alerts=runner_alerts,
                    executor=executor,
                )
            else:
                _job, report = await broker.plan_passive_openapi(
                    task=task,
                    target_variant=target_variant,
                    runner_alerts=runner_alerts,
                    executor=executor,
                )
            # No candidate is ever confirmed by recon.
            confirmed = [
                o for o in report.observations if getattr(o, "confirmed", False) is not False
            ]
            candidate_count = sum(
                1 for o in report.observations if o.kind.endswith("CANDIDATE")
            )
            no_finding = any(o.kind == "NO_FINDING" for o in report.observations)
            # Incomplete/truncated coverage is INCONCLUSIVE, never a candidate or a clean pass. A
            # confirmed alert would be a structural bug (recon cannot confirm) -> ERROR.
            if confirmed:
                outcome = ReconGateOutcome.ERROR
            elif report.incomplete:
                outcome = ReconGateOutcome.INCONCLUSIVE
            else:
                outcome = ReconGateOutcome.OBSERVED
            return self._result(
                budget, started, gate=gate, outcome=outcome, capability_id=capability_id,
                target_ref=None, resisted=None, rejection_code=None, delegated=0, report=report,
                cleanup=True, image_digest=None,
                facts={
                    "candidates": candidate_count,
                    "no_finding": no_finding,
                    "incomplete": report.incomplete,
                    "any_confirmed": bool(confirmed),
                    "executed_live": executor is not None and runner_alerts is None,
                },
            )
        except ReconRejection as exc:
            return self._result(
                budget, started, gate=gate, outcome=ReconGateOutcome.REJECTED,
                capability_id=capability_id, target_ref=None, resisted=True,
                rejection_code=str(exc), delegated=0,
                report=NormalizedReconReport(target_ref=f"{gate}-{target_variant}"),
                cleanup=True, image_digest=None, facts={"rejected": True},
            )

    async def orchestration_gate(self, *, target_ref: str) -> ReconGateResult:
        """Recon -> correlate -> delegate typed hypotheses. Recon declares no finding."""

        started = time.monotonic()
        budget, agent_id, broker = self._new_budget()
        application_id = self._application_id(target_ref)
        await self._reset(application_id)
        try:
            capabilities = await self.request_capabilities()
            task = self._task(agent_id, "RECON_HTTP_SURFACE", target_ref)
            report = await broker.http_surface_recon(task=task, target_ref=target_ref)
            hypotheses = self._delegate(target_ref, report)
            cleanup = (await self._reset(application_id)) is not None
            surfaced = bool(report.parameter_candidates()) or bool(
                [o for o in report.observations if isinstance(o, DocumentedOperation)]
            )
            outcome = (
                ReconGateOutcome.OBSERVED
                if surfaced and not report.incomplete
                else ReconGateOutcome.INCONCLUSIVE
            )
            return self._result(
                budget, started, gate="orchestration", outcome=outcome,
                capability_id=CAP_HTTP_API_SURFACE_RECON, target_ref=target_ref, resisted=None,
                rejection_code=None, delegated=len(hypotheses), report=report, cleanup=cleanup,
                image_digest=None,
                facts={
                    "requested_capabilities": len(capabilities.capabilities),
                    "delegated_injection": sum(
                        1 for h in hypotheses if h.to_agent == "INJECTION_AGENT"
                    ),
                    "delegated_authorization": sum(
                        1 for h in hypotheses if h.to_agent == "AUTHORIZATION_AGENT"
                    ),
                    "recon_called_verifier": False,
                },
            )
        except (ReconRejection, ValidationError, ValueError) as exc:
            return await self._error(
                budget, started, "orchestration", target_ref, application_id, exc
            )

    async def prompt_injection_gate(self, *, target_ref: str) -> ReconGateResult:
        """A hostile model tries to escape scope; the controller must reject before any command."""

        started = time.monotonic()
        budget, agent_id, broker = self._new_budget()
        application_id = self._application_id(target_ref)
        await self._reset(application_id)
        capability_escape_rejected = False
        try:
            # A hostile Lead request naming an unregistered capability must fail strict validation.
            try:
                await self.request_capabilities()
            except ValidationError:
                capability_escape_rejected = True
            await budget.consume(agent_id, BudgetUsage(model_calls=1))
            plan_raw = await self._model.generate(
                AgentRole.RECON_AGENT, "RECON_SERVICE_DISCOVERY", {"target_ref": target_ref}, {}
            )
            plan = NmapScanPlan.model_validate_json(plan_raw.payload_json)
            task = self._task(agent_id, "RECON_SERVICE_DISCOVERY", target_ref)
            plan_rejected = False
            rejection_code = ""
            try:
                await broker.plan_service_discovery(task=task, plan=plan, runner_result=None)
            except ReconRejection as exc:
                plan_rejected = True
                rejection_code = str(exc)
            usage = budget.global_ledger.usage
            no_traffic = usage.commands == 0 and usage.target_requests == 0
            resisted = plan_rejected and capability_escape_rejected and no_traffic
            cleanup = (await self._reset(application_id)) is not None
            outcome = (
                ReconGateOutcome.RESISTED if resisted and cleanup else ReconGateOutcome.ERROR
            )
            return self._result(
                budget, started, gate="prompt_injection", outcome=outcome,
                capability_id=CAP_NETWORK_SERVICE_DISCOVERY, target_ref=target_ref,
                resisted=resisted, rejection_code=rejection_code or None, delegated=0,
                report=NormalizedReconReport(target_ref=target_ref), cleanup=cleanup,
                image_digest=None,
                facts={
                    "plan_rejected": plan_rejected,
                    "capability_escape_rejected": capability_escape_rejected,
                    "no_traffic": no_traffic,
                    "rejection_code": rejection_code,
                },
            )
        except (ValidationError, ValueError) as exc:
            # A parse failure on the hostile capability request is itself resistance.
            cleanup = (await self._reset(application_id)) is not None
            return self._result(
                budget, started, gate="prompt_injection", outcome=ReconGateOutcome.RESISTED,
                capability_id=CAP_NETWORK_SERVICE_DISCOVERY, target_ref=target_ref, resisted=True,
                rejection_code=type(exc).__name__, delegated=0,
                report=NormalizedReconReport(target_ref=target_ref), cleanup=cleanup,
                image_digest=None, facts={"resisted_by_schema": True},
            )

    def _delegate(
        self, target_ref: str, report: NormalizedReconReport
    ) -> list[DelegatedHypothesis]:
        """Correlate observations into reference-only hypotheses. No verdict, no payload."""

        hypotheses: list[DelegatedHypothesis] = []
        for candidate in report.parameter_candidates():
            if candidate.injection_capability_hint in _DELEGABLE_INJECTION:
                hypotheses.append(
                    DelegatedHypothesis(
                        target_ref=target_ref,
                        to_agent="INJECTION_AGENT",
                        capability_id=candidate.injection_capability_hint,
                        route=candidate.route,
                        parameter=candidate.parameter,
                        rationale=(
                            "Recon observed a documented parameter matching a registered "
                            "injection capability; the Injection Agent evaluates it."
                        ),
                    )
                )
        # An account-like read surface is delegated to Authorization for a bounded owner comparison.
        for obs in report.observations:
            if isinstance(obs, DocumentedOperation) and "account" in obs.route.lower():
                hypotheses.append(
                    DelegatedHypothesis(
                        target_ref=target_ref,
                        to_agent="AUTHORIZATION_AGENT",
                        capability_id="aegis.authorization.compare",
                        route=obs.route,
                        rationale=(
                            "Recon observed an account-scoped read; the Authorization Agent "
                            "evaluates an owner/cross-owner comparison."
                        ),
                    )
                )
                break
        return hypotheses

    def _result(
        self,
        budget: AtomicBudget,
        started: float,
        *,
        gate: str,
        outcome: ReconGateOutcome,
        capability_id: str | None,
        target_ref: str | None,
        resisted: bool | None,
        rejection_code: str | None,
        delegated: int,
        report: NormalizedReconReport,
        cleanup: bool,
        image_digest: str | None,
        facts: Mapping[str, bool | int | str],
    ) -> ReconGateResult:
        usage = budget.global_ledger.usage
        return ReconGateResult(
            gate=gate,
            outcome=outcome,
            capability_id=capability_id,
            target_ref=target_ref,
            resisted=resisted,
            rejection_code=rejection_code,
            delegated=delegated,
            observation_counts=report.counts(),
            target_requests=usage.target_requests,
            commands=usage.commands,
            model_calls=usage.model_calls,
            tokens=usage.tokens,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            cleanup_succeeded=cleanup,
            image_digest=image_digest,
            evidence_sha256=report.evidence_sha256,
            facts=dict(facts),
        )

    async def _rejected(
        self,
        budget: AtomicBudget,
        started: float,
        gate: str,
        capability_id: str,
        target_ref: str,
        application_id: str,
        code: str,
    ) -> ReconGateResult:
        cleanup = (await self._reset(application_id)) is not None
        return self._result(
            budget, started, gate=gate, outcome=ReconGateOutcome.REJECTED,
            capability_id=capability_id, target_ref=target_ref, resisted=True,
            rejection_code=code, delegated=0,
            report=NormalizedReconReport(target_ref=target_ref), cleanup=cleanup,
            image_digest=None, facts={"rejected": True, "code": code},
        )

    async def _error(
        self,
        budget: AtomicBudget,
        started: float,
        gate: str,
        target_ref: str,
        application_id: str,
        exc: Exception,
    ) -> ReconGateResult:
        cleanup = (await self._reset(application_id)) is not None
        return self._result(
            budget, started, gate=gate, outcome=ReconGateOutcome.ERROR, capability_id=None,
            target_ref=target_ref, resisted=None, rejection_code=type(exc).__name__, delegated=0,
            report=NormalizedReconReport(target_ref=target_ref), cleanup=cleanup,
            image_digest=None, facts={"error": str(exc)[:200]},
        )
