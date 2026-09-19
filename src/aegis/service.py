import asyncio
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

import httpx

from aegis.budget import BudgetExceeded, ScanBudget
from aegis.candidates import (
    build_context,
    compile_probe,
    compile_retest,
    execution_queue,
    first_valid_blocker,
    ordered_validated,
    preflight,
    validate_blockers,
    validate_candidates,
)
from aegis.engine.adapters import AdapterResult, build_dispatcher
from aegis.engine.contracts import (
    ENGINE_KERNEL_VERSION,
    EngineEnvironment,
    EngineExecutionStatus,
    EngineJob,
    EngineJobRequest,
    FindingLifecycleState,
    SecurityEngine,
    TargetReference,
    VerifierConclusion,
)
from aegis.engine.lifecycle import (
    MalformedEngineOutput,
    correlate_reported_finding,
    dedupe_reported,
    normalize_observation_evidence,
    record_verifier_conclusion,
)
from aegis.engine.policy import EnginePolicyRejection, build_engine_job
from aegis.executor import TestExecutor, redact
from aegis.http import bounded_body
from aegis.models import (
    EXECUTION_POLICY_VERSION,
    BlockerEvaluation,
    BlockingReason,
    CandidateStageRecord,
    ExecuteDecision,
    Hypothesis,
    HypothesisDecision,
    RetestObjective,
    ScanCreate,
    ScanResult,
    ScanStatus,
    ScenarioClass,
)
from aegis.planner import Planner, PlannerFailure
from aegis.safety import SafetyController, SafetyViolation
from aegis.scenarios import ScenarioProjection, authenticated_profiles, project
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis.surface import OBJECTS, account_path
from aegis.verifier import DeterministicVerifier

# The one enabled engine profile in Phase 1.1. The controller selects it deterministically from the
# capability the validated candidate names; the model never chooses an engine or profile.
_AEGIS_NATIVE_PROFILE_ID = "aegis-native-bola-synthetic"


class ScanService:
    def __init__(
        self,
        settings: Settings,
        store: ScanStore,
        planner: Planner,
        safety: SafetyController,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.planner = planner
        self.safety = safety
        self.transport = transport
        self.executor = TestExecutor(settings, safety, transport)
        self.verifier = DeterministicVerifier()
        # The security-tool integration kernel dispatcher: one enabled native adapter (wired to the
        # exact same executor/safety) plus three fail-closed disabled skeletons. The controller
        # constructs every EngineJob; the dispatcher never widens scope.
        self.dispatcher = build_dispatcher(self.executor, self.safety)

    def create(self, request: ScanCreate | None = None) -> ScanResult:
        request = request or ScanCreate()
        scenario = request.scenario
        if request.retest_of or request.variant == "patched":
            scenario = ScenarioClass.PATCHED_NEGATIVE
        variant: Literal["vulnerable", "patched"] = (
            "patched" if scenario is ScenarioClass.PATCHED_NEGATIVE else "vulnerable"
        )
        objectives: list[RetestObjective] = []
        if request.retest_of:
            original = self.store.get(request.retest_of)
            if (
                original is None
                or original.status != ScanStatus.FAIL
                or not original.findings
                or original.variant != "vulnerable"
                or variant != "patched"
            ):
                raise ValueError(
                    "Retest requires a confirmed vulnerable scan and the patched variant"
                )
            verified = self.verifier.verify(
                original.hypotheses, original.evidence, original.variant
            )
            names = {name for finding in verified for name in finding.evidence_names}
            if not names:
                raise ValueError("Parent evidence no longer satisfies deterministic verification")
            objectives = [
                RetestObjective.model_validate(
                    {
                        "credential_profile": e.credential_profile,
                        "account_id": e.path.rsplit("/", 1)[-1],
                    }
                )
                for e in original.evidence
                if e.name in names
            ]
        result = ScanResult(
            id=f"scan-{uuid4().hex[:12]}",
            target_name="Synthetic Bank API",
            target_base_url=self.settings.lab_base_url,
            status=ScanStatus.QUEUED,
            planner=self.planner.name,
            mode=self.planner.name,
            model=self.settings.ai_model if self.planner.name != "DEMO_HEURISTIC" else None,
            variant=variant,
            scenario=scenario,
            retest_of=request.retest_of,
            retest_objectives=objectives,
        )
        self.store.save(result)
        self.store.add_audit(
            result.id,
            "SCAN_CREATED",
            {
                "planner": result.planner,
                "variant": result.variant,
                "scenario": result.scenario,
                "retest_of": result.retest_of,
                "planner_contract_version": result.planner_contract_version,
                "limits": {
                    "requests_including_import": self.settings.max_requests_per_scan,
                    "iterations": self.settings.max_iterations,
                    "model_calls": self.settings.max_model_calls,
                    "token_reservations": self.settings.max_tokens_per_scan,
                    "seconds": self.settings.scan_timeout_seconds,
                },
            },
        )
        return result

    def _audit(self, result: ScanResult, event: str, details: dict[str, Any]) -> None:
        secrets = tuple(self.settings.credentials.values())
        if self.settings.ai_auth_token:
            secrets += (self.settings.ai_auth_token.get_secret_value(),)
        self.store.add_audit(result.id, event, redact(details, secrets))
        self.store.save(result)

    def _verify(self, result: ScanResult) -> None:
        result.findings = self.verifier.verify(
            result.hypotheses, result.evidence, result.variant, scan_id=result.id
        )
        result.verification = self.verifier.evaluate(
            result.hypotheses,
            result.evidence,
            result.variant,
        )
        if result.verification.status == "PASS" and any(
            not any(
                e.credential_profile == objective.credential_profile
                and e.path
                == account_path(result.variant).replace("{account_id}", objective.account_id)
                and e.status_code == 403
                and not e.error
                and e.response_excerpt == {"detail": "Forbidden"}
                for e in result.evidence
            )
            for objective in result.retest_objectives
        ):
            result.verification.status = "INSUFFICIENT"
            result.verification.summary = (
                "Retest must repeat every confirmed parent access direction."
            )
        self._audit(result, "VERIFIER_RESULT", result.verification.model_dump())

    def _context(
        self, result: ScanResult, projection: ScenarioProjection, budget: ScanBudget
    ) -> dict[str, Any]:
        observations = []
        for evidence in result.evidence:
            body = evidence.response_excerpt
            # No raw response text or arbitrary field values are ever sent to the model.
            observations.append(
                {
                    "name": evidence.name,
                    "method": evidence.method,
                    "path": evidence.path,
                    "credential_profile": evidence.credential_profile,
                    "status_code": evidence.status_code,
                    "error": evidence.error,
                    "account_id": evidence.path.rsplit("/", 1)[-1]
                    if evidence.path.rsplit("/", 1)[-1] in OBJECTS
                    else None,
                    "owner_id": body.get("owner_id")
                    if isinstance(body, dict) and body.get("owner_id") in OBJECTS.values()
                    else None,
                }
            )
        return build_context(
            proj=projection,
            stage="retest" if result.retest_of else "discovery",
            observations=observations,
            verification=result.verification.model_dump() if result.verification else {},
            retest=bool(result.retest_of),
            prior_finding="Confirmed cross-owner account read" if result.retest_of else None,
            retest_objectives=[o.model_dump() for o in result.retest_objectives],
            remaining={
                "requests": self.settings.max_requests_per_scan - result.usage.requests,
                "iterations": self.settings.max_iterations - result.usage.iterations,
                "model_calls": self.settings.max_model_calls - result.usage.model_calls,
                "token_reservations": self.settings.max_tokens_per_scan
                - result.usage.reserved_tokens,
                "time_ms": budget.remaining_time_ms(),
            },
            max_candidates=self.settings.max_candidates_per_generation,
        )

    def _terminal(
        self,
        result: ScanResult,
        reason: str,
        status: ScanStatus,
        summary: str,
    ) -> None:
        result.terminal_reason = reason
        result.stop_reason = reason
        result.status = status
        result.summary = summary
        self._audit(
            result,
            "TERMINAL_REASON",
            {"reason": reason, "status": status, "scenario": result.scenario},
        )

    def _record_provider_metadata(self, result: ScanResult, budget: ScanBudget) -> None:
        if budget.provider_metadata is not None:
            result.provider_metadata = budget.provider_metadata

    def _reject_secret_output(self, value: Any) -> None:
        encoded = json.dumps(value, default=str)
        secrets = tuple(self.settings.credentials.values())
        if self.settings.ai_auth_token:
            secrets += (self.settings.ai_auth_token.get_secret_value(),)
        if any(secret and secret in encoded for secret in secrets):
            raise PlannerFailure("SECRET_IN_PLANNER_OUTPUT")

    async def _loop(self, result: ScanResult, budget: ScanBudget) -> None:
        url = self.safety.approve_import()
        budget.request()
        self._audit(result, "TOOL_REQUEST", {"tool": "import_openapi", "path": "/openapi.json"})
        self._audit(result, "SAFETY_APPROVED", {"tool": "import_openapi"})
        async with (
            httpx.AsyncClient(
                timeout=self.settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client,
            client.stream("GET", url) as response,
        ):
            response.raise_for_status()
            spec = json.loads(await bounded_body(response, self.settings.max_response_bytes))
        projection = project(spec, result.scenario)
        if projection.variant != result.variant:
            raise ValueError("Scenario variant does not match the scan variant")
        surface = projection.surface()
        self._audit(
            result,
            "OPENAPI_OBSERVATION",
            {"scenario": result.scenario, "surface": surface},
        )
        self._verify(result)
        while True:
            if result.findings:
                self._terminal(
                    result,
                    "DETERMINISTIC_CONFIRMED",
                    ScanStatus.FAIL,
                    "Deterministic verifier confirmed the bounded synthetic finding.",
                )
                return
            if result.verification and result.verification.status == "PASS":
                self._terminal(
                    result,
                    "COVERAGE_COMPLETE",
                    ScanStatus.PASS,
                    "Deterministic verifier completed conservative scoped coverage.",
                )
                return
            if result.retest_of and result.hypotheses:
                # The linked retest is executed exactly once and never re-run: re-running would
                # violate the fresh-evidence and unique-name invariants. If it neither confirmed nor
                # reached conservative complete coverage, it is inconclusive and fails closed.
                self._terminal(
                    result,
                    "RETEST_COVERAGE_INCOMPLETE",
                    ScanStatus.REVIEW,
                    "Linked retest did not reach conservative complete coverage.",
                )
                return
            budget.iteration()
            context = self._context(result, projection, budget)
            stage: Literal["discovery", "retest"] = "retest" if result.retest_of else "discovery"

            # PART D: deterministic preflight over controller-KNOWN facts, before any model call.
            # A failed preflight issues no target traffic and consumes no model call. The outcome is
            # always persisted (Part J), whether it clears or blocks.
            controller_blocker = preflight(context)
            self._audit(
                result,
                "PREFLIGHT",
                {
                    "stage": stage,
                    "blocker": controller_blocker.value if controller_blocker else None,
                    "constructible": controller_blocker is None,
                    "remaining": context["remaining"],
                },
            )
            if controller_blocker is not None:
                self._preflight_terminal(result, controller_blocker, stage)
                return

            # PART F: the linked patched retest is constructed deterministically from the confirmed
            # finding. The model is never consulted to rediscover or reselect the known direction.
            if result.retest_of:
                await self._run_retest(result, projection, budget, surface)
                continue

            # DISCOVERY: the single model enumeration call (the only model call in the flow).
            self._audit(
                result,
                "CANDIDATE_GENERATION_REQUEST",
                {"planner": result.planner, "context": context},
            )
            generation = await self.planner.enumerate_candidates(
                context,
                budget,
                self.settings.max_candidates_per_generation,
            )
            self._record_provider_metadata(result, budget)
            self._reject_secret_output(generation.model_dump(mode="json"))
            if len(generation.candidates) > self.settings.max_candidates_per_generation:
                raise PlannerFailure("CANDIDATE_LIMIT_EXCEEDED")
            budget.check_time()
            blocker_evaluations = validate_blockers(context, generation.blocking_conditions)
            record = CandidateStageRecord(
                stage=stage,
                generated=len(generation.candidates),
                generated_candidates=generation.candidates,
                blocker_evaluations=blocker_evaluations,
                execution_policy_version=EXECUTION_POLICY_VERSION,
            )
            result.generated_candidates_total += len(generation.candidates)
            self._audit(
                result,
                "CANDIDATE_GENERATED",
                {
                    "candidates": [c.model_dump(mode="json") for c in generation.candidates],
                    "blocking_conditions": [
                        b.model_dump(mode="json") for b in generation.blocking_conditions
                    ],
                },
            )
            self._audit(
                result,
                "BLOCKER_VALIDATION",
                {"evaluations": [e.model_dump(mode="json") for e in blocker_evaluations]},
            )
            if not generation.candidates:
                result.candidate_records.append(record)
                if not generation.blocking_conditions:
                    record.terminal_reason = "GENERATION_INCOMPLETE"
                    self._terminal(
                        result,
                        "GENERATION_INCOMPLETE",
                        ScanStatus.INCOMPLETE,
                        "Candidate enumeration returned neither candidates nor blockers.",
                    )
                    return
                blocker = first_valid_blocker(blocker_evaluations)
                if blocker is None:
                    record.terminal_reason = "BLOCKER_VALIDATION_FAILED"
                    self._terminal(
                        result,
                        "BLOCKER_VALIDATION_FAILED",
                        ScanStatus.INCOMPLETE,
                        "All supplied blocking conditions failed deterministic validation.",
                    )
                    return
                result.validated_blocker = blocker
                reason = f"BLOCKED_{blocker.value}"
                record.terminal_reason = reason
                status = (
                    ScanStatus.REVIEW
                    if blocker.value in {"SCOPE_AMBIGUITY", "SAFETY_CONFLICT"}
                    else ScanStatus.INCOMPLETE
                )
                self._terminal(
                    result,
                    reason,
                    status,
                    "Candidate generation ended on a deterministically validated blocker.",
                )
                return
            # Enumeration consumed a provider call. Re-project remaining budgets before validation
            # and deterministic execution admission.
            context = self._context(result, projection, budget)
            validated, rejections = validate_candidates(context, generation.candidates)
            record.validated_ids = [item.candidate_id for item in validated]
            record.validated_candidates = validated
            record.rejections = rejections
            result.validated_candidates_total += len(validated)
            result.rejected_candidates_total += len(rejections)
            self._audit(
                result,
                "CANDIDATE_VALIDATION",
                {
                    "validated": [v.model_dump(mode="json") for v in validated],
                    "rejections": [r.model_dump(mode="json") for r in rejections],
                },
            )
            if not validated:
                record.terminal_reason = "ALL_CANDIDATES_REJECTED"
                result.candidate_records.append(record)
                self._terminal(
                    result,
                    "ALL_CANDIDATES_REJECTED",
                    ScanStatus.REVIEW,
                    "Every generated candidate failed deterministic validation.",
                )
                return
            # PART A: deterministic execution admission. There is NO model-based selection call.
            result.execution_policy_version = EXECUTION_POLICY_VERSION
            queue = execution_queue(validated, context["remaining"])
            record.queue = queue
            self._audit(
                result,
                "EXECUTION_QUEUE",
                {
                    "execution_policy_version": EXECUTION_POLICY_VERSION,
                    "queue": [q.model_dump() for q in queue],
                },
            )
            admitted = {q.candidate_id for q in queue if q.admitted}
            if not admitted:
                record.terminal_reason = "BLOCKED_BUDGET_UNAVAILABLE"
                result.validated_blocker = BlockingReason.BUDGET_UNAVAILABLE
                result.candidate_records.append(record)
                self._terminal(
                    result,
                    "BLOCKED_BUDGET_UNAVAILABLE",
                    ScanStatus.INCOMPLETE,
                    "No validated candidate fit the remaining request budget.",
                )
                return
            # Execute admitted candidates in deterministic order until a finding is confirmed.
            for item in ordered_validated(validated):
                if item.candidate_id not in admitted:
                    continue
                try:
                    hypothesis = compile_probe(item, projection, len(result.hypotheses) + 1)
                except ValueError:
                    # Compilation failure terminates that candidate fail-closed and issues NO
                    # traffic (Part C). It is a controller integrity error, not a model decision.
                    for entry in record.queue:
                        if entry.candidate_id == item.candidate_id:
                            entry.admitted = False
                            entry.reason = "COMPILATION_FAILED"
                    record.terminal_reason = "REQUEST_COMPILATION_FAILED"
                    result.candidate_records.append(record)
                    raise PlannerFailure("REQUEST_COMPILATION_FAILED") from None
                record.executed_candidate_ids.append(item.candidate_id)
                result.executed_candidate_ids.append(item.candidate_id)
                if result.selected_candidate_id is None:
                    result.selected_candidate_id = item.candidate_id
                decision = HypothesisDecision(
                    summary=f"Execute admitted validated candidate {item.candidate_id}.",
                    hypothesis=hypothesis,
                )
                result.decisions.append(decision)
                result.summary = decision.summary
                await self._execute_hypothesis(
                    result,
                    hypothesis,
                    budget,
                    projection,
                    capability_id=item.candidate.capability,
                    operation_id=item.candidate.operation_id,
                    ai_hypothesis=item.candidate.expected_authorization_invariant,
                )
                # Stop admitting once the deterministic verifier reaches a terminal state (a
                # confirmed finding or conservative scoped PASS): further reads would be wasted.
                if result.findings or (
                    result.verification and result.verification.status == "PASS"
                ):
                    break
            result.candidate_records.append(record)

    def _build_engine_job(
        self,
        result: ScanResult,
        hypothesis: Hypothesis,
        projection: ScenarioProjection,
        *,
        capability_id: str,
        operation_id: str,
    ) -> EngineJob:
        """Deterministically construct the typed EngineJob from controller-owned inputs only.

        The engine and profile are chosen by the controller from the capability the validated
        candidate named; the model never selects an engine, profile, target, credential, command or
        flag. Any policy violation raises EnginePolicyRejection before the adapter is reached."""
        normalized_path = account_path(result.variant)
        credential_refs: list[str] = sorted(
            {str(r.credential_profile) for r in hypothesis.requests}
        )
        target = TargetReference(
            engine=SecurityEngine.AEGIS_NATIVE,
            environment=EngineEnvironment.SYNTHETIC_LAB,
            origin=result.target_base_url,
            operation_id=operation_id,
            method="GET",
            normalized_path=normalized_path,
        )
        requests = [
            EngineJobRequest(
                name=r.name,
                method=r.method,
                path=r.path,
                credential_profile=r.credential_profile,
                object_ref=r.path.rsplit("/", 1)[-1] if r.path.rsplit("/", 1)[-1] in OBJECTS
                else None,
            )
            for r in hypothesis.requests
        ]
        remaining = {"requests": self.settings.max_requests_per_scan - result.usage.requests}
        return build_engine_job(
            engine=SecurityEngine.AEGIS_NATIVE,
            profile_id=_AEGIS_NATIVE_PROFILE_ID,
            capability_id=capability_id,
            run_id=result.id,
            environment=EngineEnvironment.SYNTHETIC_LAB,
            target=target,
            credential_profile_refs=credential_refs,
            requests=requests,
            remaining=remaining,
            allowed_origins=[self.settings.lab_base_url, result.target_base_url],
            authenticated_profiles=authenticated_profiles(list(projection.available_credentials)),
            adapter_enabled=self.dispatcher.is_enabled(SecurityEngine.AEGIS_NATIVE),
        )

    async def _execute_hypothesis(
        self,
        result: ScanResult,
        hypothesis: Hypothesis,
        budget: ScanBudget,
        projection: ScenarioProjection,
        *,
        capability_id: str,
        operation_id: str,
        ai_hypothesis: str,
    ) -> None:
        """Deterministically authorize and execute one compiled read-only hypothesis THROUGH the
        security-tool integration kernel, binding fresh evidence and re-verifying after each read.
        Shared by discovery and the linked retest. AEGIS_NATIVE behaviour is unchanged: the same
        safety controller authorizes, the same executor issues the reads, and the same deterministic
        verifier remains the sole finding authority."""
        surface = projection.surface()
        result.engine = SecurityEngine.AEGIS_NATIVE.value
        result.adapter_version = self.dispatcher.adapter_version_for(SecurityEngine.AEGIS_NATIVE)
        result.engine_kernel_version = ENGINE_KERNEL_VERSION

        # 1) Controller constructs the typed job (or fails closed with zero traffic).
        try:
            job = self._build_engine_job(
                result,
                hypothesis,
                projection,
                capability_id=capability_id,
                operation_id=operation_id,
            )
        except EnginePolicyRejection as rejection:
            self._audit(result, "ENGINE_JOB_REJECTED", rejection.error.model_dump(mode="json"))
            result.engine_job_rejections.append(rejection.error.model_dump(mode="json"))
            raise PlannerFailure(f"ENGINE_JOB_REJECTED_{rejection.error.code.value}") from None
        self._audit(
            result,
            "ENGINE_JOB_CREATED",
            {
                "engine": job.engine.value,
                "profile_id": job.profile_id,
                "capability": job.capability_id,
                "job_id": job.job_id,
                "operation_id": job.target.operation_id,
                "adapter_version": job.adapter_version,
                "request_count": len(job.requests),
            },
        )

        # 2) Existing safety authorization (unchanged path and events).
        self._audit(
            result,
            "TOOL_REQUEST",
            {"tool": "read_only_http", "hypothesis": hypothesis.model_dump()},
        )
        events = self.safety.approve_plan(
            result.target_base_url,
            [hypothesis],
            variant=result.variant,
            used_requests=result.usage.requests,
            used_names=frozenset(e.name for e in result.evidence),
            imported_paths=frozenset(surface["paths"]),
        )
        result.safety_events.extend(events)
        self._audit(result, "SAFETY_APPROVED", {"requests": events})
        result.hypotheses.append(hypothesis)

        # 3) Reserve the request budget up front so budget exhaustion fails closed with zero
        # traffic, then dispatch the whole job to the AEGIS_NATIVE adapter.
        for _ in hypothesis.requests:
            budget.request()
        self._audit(
            result,
            "ENGINE_EXECUTION_STARTED",
            {"engine": job.engine.value, "job_id": job.job_id, "capability": job.capability_id},
        )
        adapter_result = await self.dispatcher.dispatch(job, result.variant)
        if adapter_result.execution.status is EngineExecutionStatus.FAILED:
            error = adapter_result.execution.error
            self._audit(
                result,
                "ENGINE_EXECUTION_FAILED",
                error.model_dump(mode="json") if error else {"job_id": job.job_id},
            )
            result.engine_executions.append(adapter_result.execution.model_dump(mode="json"))
            raise PlannerFailure(
                f"ENGINE_EXECUTION_FAILED_{error.code.value if error else 'UNKNOWN'}"
            )

        # 4) Bind returned evidence exactly as before: REQUEST_STARTED / OBSERVATION / re-verify per
        # read, in order. The final scan evidence and verification are byte-for-byte identical.
        for request, evidence in zip(hypothesis.requests, adapter_result.evidence, strict=True):
            self._audit(result, "REQUEST_STARTED", request.model_dump())
            result.evidence.append(evidence)
            self._audit(result, "OBSERVATION", evidence.model_dump())
            self._verify(result)

        self._audit(
            result,
            "ENGINE_EXECUTION_COMPLETED",
            {
                "engine": job.engine.value,
                "job_id": job.job_id,
                "execution_id": adapter_result.execution.execution_id,
                "observation_count": len(adapter_result.execution.observations),
                "reported_finding_count": len(adapter_result.execution.reported_findings),
            },
        )
        self._record_engine_kernel(result, job, adapter_result, ai_hypothesis)

    def _verifier_conclusion_for(
        self, result: ScanResult, observation_names: set[str]
    ) -> VerifierConclusion:
        """Derive the deterministic verifier's conclusion for one engine-reported signal from the
        authoritative verifier output. The engine's own claim never influences this."""
        for finding in result.findings:
            if observation_names & set(finding.evidence_names):
                return VerifierConclusion(
                    status="CONFIRMED",
                    summary="Deterministic verifier confirmed the cross-owner access direction.",
                    aegis_finding_id=finding.id,
                    evidence_ids=list(finding.evidence_names),
                )
        status = result.verification.status if result.verification else "INSUFFICIENT"
        if status == "PASS":
            return VerifierConclusion(
                status="PASS",
                summary="Owner controls succeeded and the cross-owner read was denied.",
            )
        return VerifierConclusion(
            status="INSUFFICIENT",
            summary="No deterministic confirmation exists for the reported raw signal.",
        )

    def _record_engine_kernel(
        self,
        result: ScanResult,
        job: EngineJob,
        adapter_result: AdapterResult,
        ai_hypothesis: str,
    ) -> None:
        """Record engine execution, provenance-complete evidence, and the normalized finding
        lifecycle. Engine-reported findings are UNTRUSTED: only the deterministic verifier promotes
        one to VERIFIED; anything else is REJECTED or (for a non-deterministic capability) routed to
        HUMAN_REVIEW_REQUIRED."""
        execution = adapter_result.execution
        result.engine_executions.append(execution.model_dump(mode="json"))
        try:
            evidence_items = normalize_observation_evidence(execution, job, result.id)
        except MalformedEngineOutput as exc:
            self._audit(
                result,
                "ENGINE_EXECUTION_FAILED",
                {"job_id": job.job_id, "reason": str(exc)},
            )
            return
        for evidence in evidence_items:
            result.engine_evidence.append(evidence.model_dump(mode="json"))

        reported = dedupe_reported(execution.reported_findings)
        self._audit(
            result,
            "VERIFICATION_STARTED",
            {"job_id": job.job_id, "reported_findings": len(reported)},
        )
        for item in reported:
            self._audit(
                result,
                "ENGINE_FINDING_REPORTED",
                {
                    "engine": item.engine.value,
                    "capability": item.capability_id,
                    "claimed_category": item.claimed_category,
                    "object_ref": item.object_ref,
                    "report_key": item.report_key,
                    "provenance": "TOOL_REPORTED",
                },
            )
            normalized = correlate_reported_finding(
                item, job, ai_hypothesis=ai_hypothesis, in_scope=True
            )
            self._audit(
                result,
                "ENGINE_FINDING_CORRELATED",
                {
                    "normalized_id": normalized.normalized_id,
                    "lifecycle_state": normalized.lifecycle_state.value,
                    "capability": normalized.capability_id,
                },
            )
            conclusion = self._verifier_conclusion_for(result, set(item.observation_names))
            normalized = record_verifier_conclusion(normalized, conclusion)
            if normalized.lifecycle_state is FindingLifecycleState.REJECTED:
                self._audit(
                    result,
                    "ENGINE_FINDING_REJECTED",
                    {
                        "normalized_id": normalized.normalized_id,
                        "verification_status": conclusion.status,
                    },
                )
            elif normalized.lifecycle_state is FindingLifecycleState.REVIEW_REQUIRED:
                self._audit(
                    result,
                    "HUMAN_REVIEW_REQUIRED",
                    {
                        "normalized_id": normalized.normalized_id,
                        "capability": normalized.capability_id,
                    },
                )
            result.normalized_findings.append(normalized.model_dump(mode="json"))
        self._audit(
            result,
            "VERIFICATION_COMPLETED",
            {
                "job_id": job.job_id,
                "verification_status": (
                    result.verification.status if result.verification else None
                ),
                "confirmed_findings": len(result.findings),
            },
        )

    async def _run_retest(
        self,
        result: ScanResult,
        projection: ScenarioProjection,
        budget: ScanBudget,
        surface: dict[str, Any],
    ) -> None:
        """PART F: construct and execute the linked patched retest deterministically from the
        confirmed finding's structured objectives. No model call, no rediscovery."""
        hypothesis = compile_retest(result.retest_objectives, projection)
        decision = ExecuteDecision(
            summary="Execute the deterministic linked patched retest of the confirmed direction.",
            hypothesis=hypothesis,
        )
        result.decisions.append(decision)
        result.summary = decision.summary
        record = CandidateStageRecord(
            stage="retest",
            execution_policy_version=EXECUTION_POLICY_VERSION,
            terminal_reason="RETEST_EXECUTED",
        )
        self._audit(
            result,
            "RETEST_PLAN",
            {
                "hypothesis": hypothesis.model_dump(),
                "objectives": [o.model_dump() for o in result.retest_objectives],
            },
        )
        result.candidate_records.append(record)
        retest_op = next(
            (o for o in projection.operations if o.object_parameter is not None and o.read_only),
            None,
        )
        await self._execute_hypothesis(
            result,
            hypothesis,
            budget,
            projection,
            capability_id="bola_object_read_v1",
            operation_id=retest_op.operation_id if retest_op else "getAccount",
            ai_hypothesis="Linked retest of the confirmed cross-owner access direction.",
        )

    def _preflight_terminal(
        self,
        result: ScanResult,
        blocker: BlockingReason,
        stage: Literal["discovery", "retest"],
    ) -> None:
        """Persist the controller's deterministic preflight decision and fail closed with no model
        call and no target traffic (Part D / Part J)."""
        record = CandidateStageRecord(
            stage=stage,
            execution_policy_version=EXECUTION_POLICY_VERSION,
            blocker_evaluations=[
                BlockerEvaluation(reason=blocker, valid=True, detail="deterministic_preflight")
            ],
            terminal_reason=f"BLOCKED_{blocker.value}",
        )
        result.candidate_records.append(record)
        result.validated_blocker = blocker
        status = (
            ScanStatus.REVIEW
            if blocker.value in {"SCOPE_AMBIGUITY", "SAFETY_CONFLICT"}
            else ScanStatus.INCOMPLETE
        )
        self._terminal(
            result,
            f"BLOCKED_{blocker.value}",
            status,
            "Deterministic preflight blocked the scan before any model or target call.",
        )

    async def run(self, scan_id: str) -> None:
        result = self.store.get(scan_id)
        if result is None or result.status != ScanStatus.QUEUED:
            return
        result.status = ScanStatus.RUNNING
        self._audit(result, "SCAN_STARTED", {})
        budget = ScanBudget(self.settings, result.usage)
        try:
            async with asyncio.timeout(self.settings.scan_timeout_seconds):
                await self._loop(result, budget)
        except SafetyViolation as exc:
            result.status = ScanStatus.REVIEW
            result.stop_reason = "SAFETY_REJECTED"
            result.terminal_reason = "SAFETY_REJECTED"
            result.safety_events.append(str(exc))
            self._audit(result, "SAFETY_REJECTED", {"reason": str(exc)})
        except (BudgetExceeded, TimeoutError) as exc:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = str(exc) if isinstance(exc, BudgetExceeded) else "TIME_BUDGET"
            result.terminal_reason = result.stop_reason
            self._audit(result, "BUDGET_EXHAUSTED", {"reason": result.stop_reason})
        except asyncio.CancelledError:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = "CANCELLED"
            result.terminal_reason = "CANCELLED"
            self._audit(result, "SCAN_CANCELLED", {})
            raise
        except PlannerFailure as exc:
            result.status = ScanStatus.INCOMPLETE
            result.error = str(exc)
            result.stop_reason = "PLANNER_REJECTED"
            result.terminal_reason = f"PLANNER_REJECTED_{exc}"
            self._audit(
                result,
                "PLANNER_REJECTED",
                {
                    "reason": str(exc),
                    "response_sha256": exc.response_digest,
                    "usage": result.usage.model_dump(),
                },
            )
        except Exception as exc:
            result.status = ScanStatus.INCOMPLETE
            result.error = type(exc).__name__
            result.stop_reason = "SCAN_ERROR"
            result.terminal_reason = f"SCAN_ERROR_{type(exc).__name__}"
            self._audit(result, "SCAN_FAILED", {"reason": result.error})
        finally:
            self._verify(result)
            if result.findings:
                result.status = ScanStatus.FAIL
            result.completed_at = datetime.now(UTC)
            self._audit(
                result,
                "SCAN_COMPLETED",
                {
                    "status": result.status,
                    "stop_reason": result.stop_reason,
                    "usage": result.usage.model_dump(),
                },
            )
