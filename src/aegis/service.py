import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

import httpx

from aegis import scm_verifier, zap_verifier
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
from aegis.engine.catalog import get_engine_capability
from aegis.engine.contracts import (
    ENGINE_KERNEL_VERSION,
    EngineEnvironment,
    EngineExecution,
    EngineExecutionStatus,
    EngineJob,
    EngineJobRequest,
    EngineObservation,
    EngineReportedFinding,
    EvidenceSourceClass,
    FindingLifecycleState,
    NormalizedEvidence,
    RetentionClass,
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
from aegis.engine.nuclei import (
    NucleiAdapter,
    NucleiAdapterResult,
    NucleiEngineJob,
    build_nuclei_job,
)
from aegis.engine.policy import EnginePolicyRejection, build_engine_job
from aegis.engine.zap import (
    ZapAdapter,
    ZapAdapterResult,
    ZapEngineJob,
    ZapProjectionRejection,
    build_zap_job,
)
from aegis.executor import TestExecutor, redact
from aegis.http import bounded_body
from aegis.models import (
    EXECUTION_POLICY_VERSION,
    BlockerEvaluation,
    BlockingReason,
    CandidateStageRecord,
    ExecuteDecision,
    Finding,
    Hypothesis,
    HypothesisDecision,
    RetestObjective,
    ScanCreate,
    ScanResult,
    ScanStatus,
    ScenarioClass,
    Verification,
)
from aegis.observability import metrics as obs_metrics
from aegis.planner import Planner, PlannerFailure
from aegis.safety import SafetyController, SafetyViolation
from aegis.scenarios import ScenarioProjection, authenticated_profiles, project
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis.surface import OBJECTS, account_path
from aegis.verifier import DeterministicVerifier
from aegis_nuclei.contracts import NucleiRunResponse
from aegis_nuclei.manifest import load_manifest
from aegis_nuclei.parser import PARSER_VERSION as NUCLEI_PARSER_VERSION
from aegis_nuclei.profile import PROFILE_ID as NUCLEI_PROFILE_ID
from aegis_nuclei.profile import PROFILE_VERSION as NUCLEI_PROFILE_VERSION
from aegis_nuclei.targets import NUCLEI_TARGETS, target_for_variant
from aegis_zap.contracts import ZapRunResponse
from aegis_zap.inventory import ZAP_TARGETS
from aegis_zap.inventory import target_for_variant as zap_target_for_variant
from aegis_zap.manifest import load_manifest as load_zap_manifest
from aegis_zap.parser import PARSER_VERSION as ZAP_PARSER_VERSION
from aegis_zap.profile import PROFILE_ID as ZAP_PROFILE_ID
from aegis_zap.profile import PROFILE_VERSION as ZAP_PROFILE_VERSION
from aegis_zap.projection import ProjectionResult

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
        *,
        nuclei_transport: httpx.AsyncBaseTransport | None = None,
        zap_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.planner = planner
        self.safety = safety
        self.transport = transport
        self.executor = TestExecutor(settings, safety, transport)
        self.verifier = DeterministicVerifier()
        # Phase 1.2: the controller-side RPC client for the isolated nuclei-runner. Disabled unless
        # the operator sets NUCLEI_ENABLED; even then every job requires a READY runner attestation.
        self.nuclei = NucleiAdapter(
            settings.nuclei_runner_url,
            enabled=settings.nuclei_enabled,
            timeout_seconds=settings.nuclei_rpc_timeout_seconds,
            transport=nuclei_transport,
        )
        # Phase 1.3: the controller-side RPC client for the isolated zap-runner. Disabled unless the
        # operator sets ZAP_ENABLED; even then every job requires a READY runner attestation.
        self.zap = ZapAdapter(
            settings.zap_runner_url,
            enabled=settings.zap_enabled,
            timeout_seconds=settings.zap_rpc_timeout_seconds,
            transport=zap_transport,
        )
        # The security-tool integration kernel dispatcher: the enabled native adapter (wired to the
        # exact same executor/safety), the Nuclei and ZAP adapters when enabled (otherwise their
        # fail-closed skeletons), and the Burp skeleton. The controller constructs every job; the
        # dispatcher never widens scope.
        self.dispatcher = build_dispatcher(
            self.executor,
            self.safety,
            nuclei=self.nuclei if settings.nuclei_enabled else None,
            zap=self.zap if settings.zap_enabled else None,
        )

    def create(self, request: ScanCreate | None = None) -> ScanResult:
        request = request or ScanCreate()
        if request.capability is not None:
            # Phase 1.2: an operator-requested engine capability. The native flow is untouched.
            return self._create_capability_scan(request)
        if request.target_ref is not None:
            raise ValueError("A target reference is only valid with an engine capability request")
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
        # Observation only (WP3 / G-OBS-1): bounded, controller-owned terminal-status counter. This
        # reads the verdict the controller already set above; it never changes it.
        obs_metrics.record_scan_completion(str(status.value))

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
        if result.engine == SecurityEngine.NUCLEI.value:
            await self._run_nuclei_scan(result)
            return
        if result.engine == SecurityEngine.ZAP.value:
            await self._run_zap_scan(result)
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

    # --- Phase 1.2: controlled Nuclei integration ----------------------------------------------

    def _create_capability_scan(self, request: ScanCreate) -> ScanResult:
        """Create a scan for an operator-requested engine capability.

        The request names only a catalog capability and (optionally) an inventory target
        reference. It cannot name a tool, template, flag, URL, header or credential — ScanCreate has
        no such field. The AI planner is not involved in this flow."""

        capability = get_engine_capability(request.capability or "")
        if capability is not None and capability.engine is SecurityEngine.ZAP:
            return self._create_zap_scan(request)
        if capability is None or capability.engine is not SecurityEngine.NUCLEI:
            raise ValueError("Unknown or unsupported engine capability")
        target_ref = request.target_ref or target_for_variant(request.variant).target_ref
        known = NUCLEI_TARGETS.get(target_ref)
        variant: Literal["vulnerable", "patched"] = known.variant if known else request.variant
        if request.retest_of:
            original = self.store.get(request.retest_of)
            if (
                original is None
                or original.engine != SecurityEngine.NUCLEI.value
                or original.status != ScanStatus.FAIL
                or not original.findings
                or variant != "patched"
            ):
                raise ValueError("Retest requires a confirmed Nuclei scan and the patched variant")
        result = ScanResult(
            id=f"scan-{uuid4().hex[:12]}",
            target_name="Synthetic Lab — SCM metadata route",
            target_base_url=self.settings.lab_base_url,
            status=ScanStatus.QUEUED,
            planner="NONE",
            mode="OPERATOR_CAPABILITY",
            model=None,
            variant=variant,
            scenario=(
                ScenarioClass.PATCHED_NEGATIVE
                if variant == "patched"
                else ScenarioClass.POSITIVE_VULNERABLE
            ),
            retest_of=request.retest_of,
            engine=SecurityEngine.NUCLEI.value,
            adapter_version=self.nuclei.adapter_version,
            engine_kernel_version=ENGINE_KERNEL_VERSION,
            capability_id=capability.capability_id,
            target_ref=target_ref,
        )
        self.store.save(result)
        self.store.add_audit(
            result.id,
            "SCAN_CREATED",
            {
                "planner": "NONE",
                "variant": result.variant,
                "scenario": result.scenario,
                "retest_of": result.retest_of,
                "engine": SecurityEngine.NUCLEI.value,
                "capability": capability.capability_id,
                "target_ref": target_ref,
                "limits": {
                    "requests_including_import": self.settings.max_requests_per_scan,
                    "seconds": self.settings.scan_timeout_seconds,
                },
            },
        )
        return result

    async def _run_nuclei_scan(self, result: ScanResult) -> None:
        result.status = ScanStatus.RUNNING
        self._audit(result, "SCAN_STARTED", {"engine": SecurityEngine.NUCLEI.value})
        budget = ScanBudget(self.settings, result.usage)
        try:
            async with asyncio.timeout(self.settings.scan_timeout_seconds):
                await self._nuclei_flow(result, budget)
        except SafetyViolation as exc:
            result.status = ScanStatus.REVIEW
            result.stop_reason = result.terminal_reason = "SAFETY_REJECTED"
            result.safety_events.append(str(exc))
            self._audit(result, "SAFETY_REJECTED", {"reason": str(exc)})
        except (BudgetExceeded, TimeoutError) as exc:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = str(exc) if isinstance(exc, BudgetExceeded) else "TIME_BUDGET"
            result.terminal_reason = result.stop_reason
            self._audit(result, "BUDGET_EXHAUSTED", {"reason": result.stop_reason})
        except asyncio.CancelledError:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = result.terminal_reason = "CANCELLED"
            self._audit(result, "SCAN_CANCELLED", {})
            raise
        except Exception as exc:
            result.status = ScanStatus.INCOMPLETE
            result.error = type(exc).__name__
            result.stop_reason = "SCAN_ERROR"
            result.terminal_reason = f"SCAN_ERROR_{type(exc).__name__}"
            self._audit(result, "SCAN_FAILED", {"reason": result.error})
        finally:
            # Nuclei scans never fall through to PASS: an unfinished flow is INCOMPLETE. Findings
            # exist only if the independent verifier promoted them inside the flow.
            if result.status is ScanStatus.RUNNING:
                result.status = ScanStatus.INCOMPLETE
                result.terminal_reason = result.terminal_reason or "NUCLEI_FLOW_INCOMPLETE"
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

    def _nuclei_provenance(
        self,
        job: NucleiEngineJob,
        outcome: NucleiAdapterResult | None,
    ) -> dict[str, Any]:
        manifest = load_manifest()
        response: NucleiRunResponse | None = outcome.response if outcome else None
        attestation = outcome.attestation if outcome else None
        engine = response.engine if response else attestation.engine if attestation else None
        templates = response.templates if response else attestation.templates if attestation else ()
        return {
            "profile_id": job.profile_id,
            "profile_version": NUCLEI_PROFILE_VERSION,
            "adapter_version": job.adapter_version,
            "parser_version": NUCLEI_PARSER_VERSION,
            "runner_version": (
                response.runner_version
                if response
                else attestation.runner_version
                if attestation
                else None
            ),
            "verifier_version": scm_verifier.VERIFIER_VERSION,
            "kernel_version": ENGINE_KERNEL_VERSION,
            "engine": {
                "name": "nuclei",
                "version": engine.nuclei_version if engine else None,
                "binary_sha256": engine.binary_sha256 if engine else None,
                "arch": engine.arch if engine else None,
                "pinned": engine.pinned if engine else False,
            },
            "template_set_id": job.template_set_id,
            "manifest_version": job.manifest_version,
            "manifest_digest": job.manifest_digest,
            "upstream_templates": {
                "release": manifest.upstream_templates.release,
                "commit": manifest.upstream_templates.commit,
            },
            "templates": [
                {
                    "template_id": t.template_id,
                    "sha256": t.sha256,
                    "signature_status": t.signature_status,
                    "admitted": t.admitted,
                }
                for t in templates
            ],
            "job_id": job.job_id,
            "execution_id": outcome.execution.execution_id if outcome else None,
            "target_ref": job.target_ref,
            "operation_id": job.target.operation_id,
            "budgets": {
                "requests": job.budget.max_requests,
                "time_ms": job.budget.time_budget_ms,
                "results": job.max_results,
                "output_bytes": job.max_output_bytes,
            },
            "counts": {
                "http_connections": response.http_connections if response else None,
                "signed_templates_executed": (
                    response.signed_templates_executed if response else None
                ),
                "records": response.parse.records if response else 0,
                "matched": response.parse.matched if response else 0,
                "unmatched": response.parse.unmatched if response else 0,
                "errored": response.parse.errored if response else 0,
                "duplicates_collapsed": response.parse.duplicates_collapsed if response else 0,
            },
            "timing": {
                "started_at": response.started_at.isoformat() if response else None,
                "completed_at": response.completed_at.isoformat() if response else None,
                "duration_ms": response.duration_ms if response else None,
            },
            "exit": {
                "status": response.status if response else "NOT_RUN",
                "exit_class": response.exit_class if response else "NOT_RUN",
                "exit_code": response.exit_code if response else None,
                "error_code": (
                    response.error_code.value if response and response.error_code else None
                ),
                "adapter_error": (
                    outcome.execution.error.code.value
                    if outcome and outcome.execution.error
                    else None
                ),
                "validation_code": outcome.validation_code if outcome else None,
            },
            "output": {
                "bytes": response.output_bytes if response else 0,
                "sha256": response.output_sha256 if response else None,
                "stderr_bytes": response.stderr_bytes if response else 0,
                "stderr_sha256": response.stderr_sha256 if response else None,
                "parse_status": response.parse.status if response else "NOT_PARSED",
                "stripped_fields": list(response.parse.stripped_fields) if response else [],
            },
            "coverage_complete": bool(response and response.coverage_complete),
            "redaction_status": "REDACTED",
        }

    def _nuclei_terminal(self, result: ScanResult, reason: str, status: ScanStatus) -> None:
        summaries = {
            ScanStatus.FAIL: "Independent verifier confirmed the Nuclei-reported condition.",
            ScanStatus.PASS: "Complete coverage; independent verifier confirmed the patched state.",
            ScanStatus.REVIEW: "Nuclei result needs review; nothing was auto-confirmed or passed.",
            ScanStatus.INCOMPLETE: "Nuclei execution or verification incomplete; never a PASS.",
        }
        self._terminal(result, reason, status, summaries.get(status, "Recorded."))

    async def _nuclei_flow(self, result: ScanResult, budget: ScanBudget) -> None:
        # 1) The controller constructs the typed job from controller-owned inputs only.
        try:
            job = build_nuclei_job(
                profile_id=NUCLEI_PROFILE_ID,
                capability_id=result.capability_id or "",
                run_id=result.id,
                environment=EngineEnvironment.SYNTHETIC_LAB,
                target_ref=result.target_ref or "",
                remaining_requests=self.settings.max_requests_per_scan - result.usage.requests,
                allowed_origins=[self.settings.lab_base_url],
                adapter_enabled=self.nuclei.enabled,
            )
        except EnginePolicyRejection as rejection:
            error = rejection.error.model_dump(mode="json")
            result.engine_job_rejections.append(error)
            self._audit(
                result,
                "NUCLEI_JOB_REJECTED",
                {
                    **error,
                    "capability": result.capability_id,
                    "target_ref": result.target_ref,
                    "runner_contacted": False,
                    "target_requests": 0,
                },
            )
            self._nuclei_terminal(
                result, f"NUCLEI_JOB_REJECTED_{rejection.error.code.value}", ScanStatus.REVIEW
            )
            return
        self._audit(
            result,
            "NUCLEI_JOB_ADMITTED",
            {
                "engine": job.engine.value,
                "profile_id": job.profile_id,
                "capability": job.capability_id,
                "job_id": job.job_id,
                "target_ref": job.target_ref,
                "operation_id": job.target.operation_id,
                "template_set_id": job.template_set_id,
                "manifest_version": job.manifest_version,
                "manifest_digest": job.manifest_digest,
                "template_ids": list(job.template_ids),
                "adapter_version": job.adapter_version,
                "budgets": {
                    "requests": job.budget.max_requests,
                    "time_ms": job.budget.time_budget_ms,
                    "results": job.max_results,
                    "output_bytes": job.max_output_bytes,
                },
            },
        )

        # 2) Attest the isolated runner BEFORE any execution: pinned engine, verified manifest.
        attestation = await self.nuclei.attest()
        self._audit(
            result,
            "NUCLEI_RUNNER_STARTED",
            {
                "reachable": attestation is not None,
                "ready": bool(attestation and attestation.ready),
                "runner_version": attestation.runner_version if attestation else None,
                "nuclei_version": attestation.engine.nuclei_version if attestation else None,
                "binary_sha256": attestation.engine.binary_sha256 if attestation else None,
                "arch": attestation.engine.arch if attestation else None,
                "pinned": bool(attestation and attestation.engine.pinned),
                "failure_codes": list(attestation.failure_codes) if attestation else [],
            },
        )
        execution_id = f"exec-{uuid4().hex[:12]}"
        problem = self.nuclei.attestation_problem(attestation, job)
        if problem is not None:
            outcome = await self.nuclei.run(
                job, result.id, execution_id=execution_id, attestation=attestation
            )
            self._record_nuclei_failure(result, job, outcome, "RUNNER_NOT_ATTESTED")
            return
        assert attestation is not None
        self._audit(
            result,
            "NUCLEI_TEMPLATE_MANIFEST_VERIFIED",
            {
                "template_set_id": attestation.template_set_id,
                "manifest_version": attestation.manifest_version,
                "manifest_digest": attestation.manifest_digest,
                "controller_manifest_match": attestation.manifest_digest == job.manifest_digest,
                "signature_probe": attestation.signature_probe,
                "unexpected_template_files": attestation.unexpected_template_files,
                "templates": [
                    {
                        "template_id": t.template_id,
                        "sha256": t.sha256,
                        "signature_status": t.signature_status,
                    }
                    for t in attestation.templates
                ],
            },
        )

        # 3) Execute on the runner. Reserve the target-request budget first (fail closed).
        for _ in range(job.budget.max_requests):
            budget.request()
        self._audit(
            result,
            "NUCLEI_EXECUTION_STARTED",
            {
                "engine": job.engine.value,
                "job_id": job.job_id,
                "execution_id": execution_id,
                "profile_id": job.profile_id,
                "target_ref": job.target_ref,
                "budgets": {
                    "requests": job.budget.max_requests,
                    "time_ms": job.budget.time_budget_ms,
                },
            },
        )
        outcome = await self.nuclei.run(
            job, result.id, execution_id=execution_id, attestation=attestation
        )
        if outcome.execution.status is EngineExecutionStatus.FAILED or outcome.response is None:
            self._record_nuclei_failure(result, job, outcome, "EXECUTION")
            return
        response = outcome.response
        result.nuclei_provenance = self._nuclei_provenance(job, outcome)
        self._audit(
            result,
            "NUCLEI_EXECUTION_COMPLETED",
            {
                "execution_id": execution_id,
                "job_id": job.job_id,
                "exit_class": response.exit_class,
                "exit_code": response.exit_code,
                "duration_ms": response.duration_ms,
                "http_connections": response.http_connections,
                "signed_templates_executed": response.signed_templates_executed,
                "output_bytes": response.output_bytes,
                "output_sha256": response.output_sha256,
                "coverage_complete": response.coverage_complete,
            },
        )
        self._audit(result, "NUCLEI_RESULT_PARSED", self._parse_event(response))

        # 4) Tool results enter as TOOL_REPORTED observations; correlate them deterministically.
        execution, evidence, correlated = self._nuclei_observations(result, job, outcome)
        result.engine_executions.append(execution.model_dump(mode="json"))
        result.engine_evidence.extend(item.model_dump(mode="json") for item in evidence)

        # 5) Independent deterministic verification from fresh, controller-constructed requests.
        target = NUCLEI_TARGETS[job.target_ref]
        plan = scm_verifier.probe_plan(target, result.id)
        self._audit(
            result,
            "NUCLEI_VERIFICATION_STARTED",
            {
                "verifier_version": scm_verifier.VERIFIER_VERSION,
                "requests": [
                    {"name": name, "method": "GET", "path": path} for name, _, path in plan
                ],
                "independent": True,
                "nuclei_inputs_used": [],
            },
        )
        for _ in plan:
            budget.request()
        facts = await scm_verifier.collect(
            target=target,
            scan_id=result.id,
            safety=self.safety,
            transport=self.transport,
            timeout_seconds=self.settings.request_timeout_seconds,
        )
        verdict = scm_verifier.evaluate(facts)
        result.verifier_evidence = [f.model_dump(mode="json") for f in facts]
        result.engine_evidence.extend(
            item.model_dump(mode="json")
            for item in self._verifier_evidence(result, job, execution.execution_id, facts)
        )
        result.verification = Verification(
            status=verdict.status,
            summary=verdict.summary,
            evidence_names=verdict.evidence_names,
        )

        finding: Finding | None = None
        capability = get_engine_capability(job.capability_id)
        for normalized in correlated:
            if normalized.lifecycle_state is not FindingLifecycleState.AEGIS_CORRELATED:
                result.normalized_findings.append(normalized.model_dump(mode="json"))
                continue
            if verdict.status == "CONFIRMED" and finding is None and capability:
                template_id = (normalized.engine_report_key or "::").split(":")[1] or "template"
                finding = Finding(
                    id=f"finding-{result.id}-nuclei-{template_id}",
                    title="Source-control metadata exposed on a synthetic route",
                    severity=capability.verified_severity,
                    category="Security misconfiguration: source-control metadata exposure",
                    confidence="CONFIRMED",
                    description=(
                        "An anonymous read-only GET of the synthetic route returned git "
                        "repository metadata (core config section). Confirmed by the independent "
                        "Aegis verifier from fresh evidence, not by Nuclei."
                    ),
                    remediation="Never serve VCS metadata from the web root; deny /.git/ paths.",
                    evidence_names=list(verdict.evidence_names),
                )
            conclusion = VerifierConclusion(
                status=verdict.status,
                summary=verdict.summary,
                aegis_finding_id=finding.id if finding and verdict.status == "CONFIRMED" else None,
                evidence_ids=[f"{result.id}:{name}" for name in verdict.evidence_names],
            )
            normalized = record_verifier_conclusion(
                normalized,
                conclusion,
                inconclusive_state=FindingLifecycleState.REVIEW_REQUIRED,
            )
            result.normalized_findings.append(normalized.model_dump(mode="json"))
        if finding is not None:
            result.findings = [finding]

        lifecycle = [str(n.get("lifecycle_state")) for n in result.normalized_findings]
        self._audit(
            result,
            "NUCLEI_VERIFICATION_COMPLETED",
            {
                "verifier_version": scm_verifier.VERIFIER_VERSION,
                "status": verdict.status,
                "verification_status": verdict.status,
                "evidence_ids": [f"{result.id}:{name}" for name in verdict.evidence_names],
                "lifecycle_states": lifecycle,
                "finding_id": finding.id if finding else None,
                "tool_reported": len(correlated),
            },
        )

        # 6) Terminal decision. Absence of a Nuclei result is never PASS on its own.
        reported = bool(correlated)
        if reported and finding is not None:
            self._nuclei_terminal(result, "DETERMINISTIC_CONFIRMED", ScanStatus.FAIL)
        elif reported and verdict.status == "PASS":
            self._nuclei_terminal(result, "TOOL_FINDING_REJECTED_BY_VERIFIER", ScanStatus.REVIEW)
        elif reported:
            self._nuclei_terminal(result, "VERIFICATION_INCONCLUSIVE", ScanStatus.REVIEW)
        elif verdict.status == "PASS" and response.coverage_complete:
            self._nuclei_terminal(result, "COVERAGE_COMPLETE", ScanStatus.PASS)
        elif verdict.status == "CONFIRMED":
            self._nuclei_terminal(result, "ENGINE_VERIFIER_DISAGREEMENT", ScanStatus.REVIEW)
        else:
            self._nuclei_terminal(result, "VERIFICATION_INCONCLUSIVE", ScanStatus.INCOMPLETE)

    @staticmethod
    def _parse_event(response: NucleiRunResponse) -> dict[str, Any]:
        parse = response.parse
        return {
            "parser_version": parse.parser_version,
            "parse_status": parse.status,
            "code": parse.failure_code.value if parse.failure_code else None,
            "lines": parse.lines,
            "records": parse.records,
            "matched": parse.matched,
            "unmatched": parse.unmatched,
            "errored": parse.errored,
            "duplicates_collapsed": parse.duplicates_collapsed,
            "stripped_fields": list(parse.stripped_fields),
            "redaction_status": "REDACTED",
        }

    def _record_nuclei_failure(
        self,
        result: ScanResult,
        job: NucleiEngineJob,
        outcome: NucleiAdapterResult,
        stage: str,
    ) -> None:
        """A failed/rejected/incomplete execution is recorded and ends INCOMPLETE — never PASS."""

        result.nuclei_provenance = self._nuclei_provenance(job, outcome)
        result.engine_executions.append(outcome.execution.model_dump(mode="json"))
        error = outcome.execution.error
        response = outcome.response
        self._audit(
            result,
            "NUCLEI_EXECUTION_FAILED",
            {
                "stage": stage,
                "job_id": job.job_id,
                "execution_id": outcome.execution.execution_id,
                "code": error.code.value if error else "UNKNOWN",
                "detail": error.detail if error else "",
                "error_code": (
                    response.error_code.value if response and response.error_code else None
                ),
                "exit_class": response.exit_class if response else "NOT_RUN",
                "exit_code": response.exit_code if response else None,
                "runner_contacted_for_execution": outcome.request is not None,
            },
        )
        if response is not None and response.parse.status != "NOT_PARSED":
            self._audit(result, "NUCLEI_RESULT_PARSED", self._parse_event(response))
        code = (error.detail or error.code.value) if error else "UNKNOWN"
        self._nuclei_terminal(
            result, f"NUCLEI_EXECUTION_INCOMPLETE_{code}"[:120], ScanStatus.INCOMPLETE
        )

    def _nuclei_observations(
        self,
        result: ScanResult,
        job: NucleiEngineJob,
        outcome: NucleiAdapterResult,
    ) -> tuple[EngineExecution, list[NormalizedEvidence], list[Any]]:
        """Turn parsed runner records into kernel observations, provenance-complete evidence and
        correlated normalized findings (TOOL_REPORTED -> AEGIS_CORRELATED or REJECTED)."""

        response = outcome.response
        assert response is not None
        target = NUCLEI_TARGETS[job.target_ref]
        observations: list[EngineObservation] = []
        reported: list[EngineReportedFinding] = []
        evidence: list[NormalizedEvidence] = []
        for record in response.results:
            name = f"nuclei-{record.template_id}-{record.record_digest[:12]}"
            observations.append(
                EngineObservation(
                    request_name=name,
                    method="GET",
                    path=record.checked_path,
                    credential_profile="anonymous",
                    status_code=None,  # Nuclei does not report it under the fixed profile
                    duration_ms=0,
                    content_digest=record.record_digest,
                    has_error=record.error_class != "NONE",
                )
            )
            evidence.append(
                NormalizedEvidence(
                    evidence_id=f"{result.id}:{name}",
                    engine=SecurityEngine.NUCLEI,
                    adapter_version=job.adapter_version,
                    engine_execution_id=outcome.execution.execution_id,
                    run_id=job.run_id,
                    scan_id=result.id,
                    timestamp=record.observed_at,
                    capability_id=job.capability_id,
                    target_ref=job.target_ref,
                    request_refs=[name],
                    artifact_refs=[f"{outcome.execution.execution_id}:{record.template_id}"],
                    redaction_status="REDACTED",
                    content_digest=record.record_digest,
                    parser_version=NUCLEI_PARSER_VERSION,
                    source_class=EvidenceSourceClass.ENGINE_OBSERVATION,
                    retention_class=RetentionClass.STANDARD,
                )
            )
            if record.matcher_status:
                reported.append(
                    EngineReportedFinding(
                        report_key=f"{job.capability_id}:{record.template_id}:{job.target_ref}",
                        engine=SecurityEngine.NUCLEI,
                        capability_id=job.capability_id,
                        claimed_category="SCM metadata exposure (tool claim)",
                        target_operation_id=job.target.operation_id,
                        principal_profile="anonymous",
                        observation_names=[name],
                        signal=(
                            f"Template {record.template_id} matched at {record.checked_path} "
                            "(unverified raw tool signal)."
                        )[:200],
                    )
                )
        execution = outcome.execution.model_copy(
            update={"observations": observations, "reported_findings": reported}
        )
        correlated = []
        for item in dedupe_reported(reported):
            record_ids = {r.template_id for r in response.results if r.matcher_status}
            in_scope = (
                item.capability_id == job.capability_id
                and item.report_key.split(":")[1] in job.template_ids
                and item.report_key.split(":")[1] in record_ids
                and item.report_key.endswith(f":{target.target_ref}")
            )
            self._audit(
                result,
                "NUCLEI_FINDING_REPORTED",
                {
                    "engine": item.engine.value,
                    "capability": item.capability_id,
                    "report_key": item.report_key,
                    "template_id": item.report_key.split(":")[1],
                    "claimed_category": item.claimed_category,
                    "provenance": "TOOL_REPORTED",
                    "lifecycle_state": FindingLifecycleState.TOOL_REPORTED.value,
                },
            )
            normalized = correlate_reported_finding(
                item,
                job,
                ai_hypothesis="None - operator-requested capability; no AI involvement.",
                in_scope=in_scope,
            )
            self._audit(
                result,
                "NUCLEI_FINDING_CORRELATED",
                {
                    "normalized_id": normalized.normalized_id,
                    "lifecycle_state": normalized.lifecycle_state.value,
                    "capability": normalized.capability_id,
                    "target_ref": job.target_ref,
                    "correlation": "IN_SCOPE" if in_scope else "OUT_OF_SCOPE",
                },
            )
            correlated.append(normalized)
        return execution, evidence, correlated

    def _verifier_evidence(
        self,
        result: ScanResult,
        job: NucleiEngineJob,
        execution_id: str,
        facts: list[scm_verifier.ScmProbeFacts],
    ) -> list[NormalizedEvidence]:
        items = []
        for fact in facts:
            digest = fact.body_sha256 or hashlib.sha256(
                json.dumps(fact.model_dump(mode="json"), sort_keys=True).encode()
            ).hexdigest()
            items.append(
                NormalizedEvidence(
                    evidence_id=f"{result.id}:{fact.name}",
                    engine=SecurityEngine.NUCLEI,
                    adapter_version=job.adapter_version,
                    engine_execution_id=execution_id,
                    run_id=job.run_id,
                    scan_id=result.id,
                    timestamp=datetime.now(UTC),
                    capability_id=job.capability_id,
                    target_ref=job.target_ref,
                    request_refs=[fact.name],
                    artifact_refs=[f"{result.id}:{fact.name}"],
                    redaction_status="REDACTED",
                    content_digest=digest,
                    parser_version=scm_verifier.VERIFIER_VERSION,
                    source_class=EvidenceSourceClass.VERIFIER_DERIVED,
                    retention_class=RetentionClass.STANDARD,
                )
            )
        return items

    # --- Phase 1.3: controlled ZAP passive OpenAPI integration ---------------------------------

    def _create_zap_scan(self, request: ScanCreate) -> ScanResult:
        """Create a scan for an operator-requested ZAP capability.

        The request names only a catalog capability and (optionally) an inventory target reference.
        It cannot name a tool, plan, job, rule, OpenAPI document/URL, target URL, header, option or
        credential — ScanCreate has no such field. The AI planner is not involved in this flow."""

        capability = get_engine_capability(request.capability or "")
        profile_capabilities = {"zap_passive_header_openapi_v1"}
        if capability is None or capability.engine is not SecurityEngine.ZAP or not (
            capability.capability_id in profile_capabilities
            or "NEVER_APPROVED" in capability.required_approvals
        ):
            # The retired Phase 1.1 placeholder and unknown ids are refused outright.
            raise ValueError("Unknown or unsupported engine capability")
        target_ref = request.target_ref or zap_target_for_variant(request.variant).target_ref
        known = ZAP_TARGETS.get(target_ref)
        variant: Literal["vulnerable", "patched"] = (
            "patched" if known is not None and known.variant == "patched" else "vulnerable"
        )
        if known is not None and known.purpose == "NEGATIVE_CONTROL":
            scenario = (
                ScenarioClass.STATE_CHANGING_ONLY
                if known.negative_class == "STATE_CHANGING_OPERATION"
                else ScenarioClass.OUT_OF_SCOPE
            )
        else:
            scenario = (
                ScenarioClass.PATCHED_NEGATIVE
                if variant == "patched"
                else ScenarioClass.POSITIVE_VULNERABLE
            )
        if request.retest_of:
            original = self.store.get(request.retest_of)
            if (
                original is None
                or original.engine != SecurityEngine.ZAP.value
                or original.status != ScanStatus.FAIL
                or not original.findings
                or variant != "patched"
            ):
                raise ValueError("Retest requires a confirmed ZAP scan and the patched variant")
        result = ScanResult(
            id=f"scan-{uuid4().hex[:12]}",
            target_name=(
                known.title if known is not None else "Synthetic Lab — ZAP passive surface"
            ),
            target_base_url=self.settings.lab_base_url,
            status=ScanStatus.QUEUED,
            planner="NONE",
            mode="OPERATOR_CAPABILITY",
            model=None,
            variant=variant,
            scenario=scenario,
            retest_of=request.retest_of,
            engine=SecurityEngine.ZAP.value,
            adapter_version=self.zap.adapter_version,
            engine_kernel_version=ENGINE_KERNEL_VERSION,
            capability_id=capability.capability_id,
            target_ref=target_ref,
        )
        self.store.save(result)
        self.store.add_audit(
            result.id,
            "SCAN_CREATED",
            {
                "planner": "NONE",
                "variant": result.variant,
                "scenario": result.scenario,
                "retest_of": result.retest_of,
                "engine": SecurityEngine.ZAP.value,
                "capability": capability.capability_id,
                "target_ref": target_ref,
                "limits": {
                    "requests_including_import": self.settings.max_requests_per_scan,
                    "seconds": self.settings.scan_timeout_seconds,
                },
            },
        )
        return result

    async def _run_zap_scan(self, result: ScanResult) -> None:
        result.status = ScanStatus.RUNNING
        self._audit(result, "SCAN_STARTED", {"engine": SecurityEngine.ZAP.value})
        budget = ScanBudget(self.settings, result.usage)
        try:
            async with asyncio.timeout(
                max(self.settings.scan_timeout_seconds, self.settings.zap_rpc_timeout_seconds + 30)
            ):
                await self._zap_flow(result, budget)
        except SafetyViolation as exc:
            result.status = ScanStatus.REVIEW
            result.stop_reason = result.terminal_reason = "SAFETY_REJECTED"
            result.safety_events.append(str(exc))
            self._audit(result, "SAFETY_REJECTED", {"reason": str(exc)})
        except (BudgetExceeded, TimeoutError) as exc:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = str(exc) if isinstance(exc, BudgetExceeded) else "TIME_BUDGET"
            result.terminal_reason = result.stop_reason
            self._audit(result, "BUDGET_EXHAUSTED", {"reason": result.stop_reason})
        except asyncio.CancelledError:
            result.status = ScanStatus.INCOMPLETE
            result.stop_reason = result.terminal_reason = "CANCELLED"
            self._audit(result, "SCAN_CANCELLED", {})
            raise
        except Exception as exc:
            result.status = ScanStatus.INCOMPLETE
            result.error = type(exc).__name__
            result.stop_reason = "SCAN_ERROR"
            result.terminal_reason = f"SCAN_ERROR_{type(exc).__name__}"
            self._audit(result, "SCAN_FAILED", {"reason": result.error})
        finally:
            # ZAP scans never fall through to PASS: an unfinished flow is INCOMPLETE. Findings
            # exist only if the independent verifier promoted them inside the flow.
            if result.status is ScanStatus.RUNNING:
                result.status = ScanStatus.INCOMPLETE
                result.terminal_reason = result.terminal_reason or "ZAP_FLOW_INCOMPLETE"
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

    def _zap_terminal(self, result: ScanResult, reason: str, status: ScanStatus) -> None:
        summaries = {
            ScanStatus.FAIL: "Independent verifier confirmed the ZAP-reported condition.",
            ScanStatus.PASS: "Complete passive coverage; independent verifier confirmed the patch.",
            ScanStatus.REVIEW: "ZAP result needs review; nothing was auto-confirmed or passed.",
            ScanStatus.INCOMPLETE: "ZAP execution or verification incomplete; never a PASS.",
        }
        self._terminal(result, reason, status, summaries.get(status, "Recorded."))

    def _zap_provenance(
        self,
        job: ZapEngineJob,
        outcome: ZapAdapterResult | None,
    ) -> dict[str, Any]:
        manifest = load_zap_manifest()
        response: ZapRunResponse | None = outcome.response if outcome else None
        attestation = outcome.attestation if outcome else None
        engine = response.engine if response else attestation.engine if attestation else None
        traffic = response.traffic if response else None
        stages = response.stages if response else None
        guard = attestation.guard if attestation else None
        return {
            "profile_id": job.profile_id,
            "profile_version": ZAP_PROFILE_VERSION,
            "adapter_version": job.adapter_version,
            "parser_version": ZAP_PARSER_VERSION,
            "projection_version": job.projection_version,
            "runner_version": (
                response.runner_version
                if response
                else attestation.runner_version
                if attestation
                else None
            ),
            "verifier_version": zap_verifier.VERIFIER_VERSION,
            "kernel_version": ENGINE_KERNEL_VERSION,
            "engine": {
                "name": "zap",
                "version": engine.zap_version if engine else None,
                "pinned_version": manifest.engine.version,
                "image_index_digest": manifest.engine.image.index_digest,
                "image_platform_digests": dict(manifest.engine.image.platforms),
                "jar_sha256": engine.jar_sha256 if engine else None,
                "java_version": engine.java_version if engine else None,
                "java_runtime_version": engine.java_runtime_version if engine else None,
                "arch": engine.arch if engine else None,
                "add_on_inventory_digest": engine.add_on_inventory_digest if engine else None,
                "pinned": engine.pinned if engine else False,
            },
            "add_ons": [
                {"id": a.id, "version": a.version, "status": a.status} for a in manifest.add_ons
            ],
            "rules": [
                {"plugin_id": r.plugin_id, "name": r.name, "threshold": r.threshold}
                for r in manifest.passive_rules
                if r.plugin_id in job.rule_ids
            ],
            "manifest_version": manifest.manifest_version,
            "manifest_digest": job.manifest_digest,
            "projection": {
                "ref": job.projection_ref,
                "digest": job.projection_digest,
                "allowlist_digest": job.allowlist_digest,
                "source_sha256": job.source_sha256,
                "operation_count": job.operation_count,
                "path_count": job.path_count,
                "redaction_status": job.redaction_status,
                "operations": [
                    {"method": op.method, "path": op.path, "operation_id": op.operation_id}
                    for op in job.operations
                ],
            },
            "job_id": job.job_id,
            "execution_id": outcome.execution.execution_id if outcome else None,
            "target_ref": job.target_ref,
            "operation_id": job.target.operation_id,
            "budgets": {
                "requests": job.budget.max_requests,
                "time_ms": job.budget.time_budget_ms,
                "alerts": job.max_alerts,
                "report_bytes": job.max_report_bytes,
            },
            "plan": {
                "digest": response.plan.plan_digest if response else None,
                "validated": bool(response and response.plan.validated),
                "job_types": list(response.plan.job_types) if response else [],
            },
            "stages": stages.model_dump(mode="json") if stages else None,
            "traffic": {
                "expected_requests": job.operation_count,
                "observed_requests": traffic.received if traffic else None,
                "forwarded": traffic.forwarded if traffic else None,
                "blocked": traffic.blocked if traffic else None,
                "blocked_reasons": [list(r) for r in traffic.blocked_reasons] if traffic else [],
                "redirects": traffic.redirects if traffic else None,
                "upstream_failures": traffic.upstream_failures if traffic else None,
                "upstream_timeouts": traffic.upstream_timeouts if traffic else None,
                "budget_exceeded": traffic.budget_exceeded if traffic else None,
                "guard_version": guard.guard_version if guard else None,
            },
            # Bounded, prose-free alert records: ids, manifest rule name, route, UNTRUSTED claims.
            "alerts": [
                {
                    "plugin_id": a.plugin_id,
                    "rule_name": a.rule_name,
                    "method": a.method,
                    "path": a.path,
                    "param": a.param,
                    "claimed_risk": a.claimed_risk,
                    "claimed_confidence": a.claimed_confidence,
                    "record_digest": a.record_digest,
                }
                for a in (response.alerts if response else ())
            ],
            "counts": {
                "alerts": len(response.alerts) if response else 0,
                "records": response.parse.records if response else 0,
                "duplicates_collapsed": response.parse.duplicates_collapsed if response else 0,
                "imported_urls": stages.urls_added if stages else None,
            },
            "timing": {
                "started_at": response.started_at.isoformat() if response else None,
                "completed_at": response.completed_at.isoformat() if response else None,
                "duration_ms": response.duration_ms if response else None,
            },
            "exit": {
                "status": response.status if response else "NOT_RUN",
                "exit_class": response.exit_class if response else "NOT_RUN",
                "exit_code": response.exit_code if response else None,
                "error_code": (
                    response.error_code.value if response and response.error_code else None
                ),
                "adapter_error": (
                    outcome.execution.error.code.value
                    if outcome and outcome.execution.error
                    else None
                ),
                "validation_code": outcome.validation_code if outcome else None,
            },
            "output": {
                "stdout_bytes": response.stdout_bytes if response else 0,
                "stdout_sha256": response.stdout_sha256 if response else None,
                "report_bytes": response.report_bytes if response else 0,
                "report_sha256": response.report_sha256 if response else None,
                "parse_status": response.parse.status if response else "NOT_PARSED",
                "stripped_fields": list(response.parse.stripped_fields) if response else [],
                "session_destroyed": bool(response and response.session_destroyed),
            },
            "coverage_complete": bool(response and response.coverage_complete),
            "redaction_status": "REDACTED",
        }

    async def _zap_flow(self, result: ScanResult, budget: ScanBudget) -> None:
        # 1) The controller projects the inventory and constructs the typed job (no runner yet).
        try:
            job, projection = build_zap_job(
                profile_id=ZAP_PROFILE_ID,
                capability_id=result.capability_id or "",
                run_id=result.id,
                environment=EngineEnvironment.SYNTHETIC_LAB,
                target_ref=result.target_ref or "",
                remaining_requests=self.settings.max_requests_per_scan - result.usage.requests,
                allowed_origins=[self.settings.lab_base_url],
                adapter_enabled=self.zap.enabled,
            )
        except ZapProjectionRejection as rejection:
            error = rejection.error.model_dump(mode="json")
            result.engine_job_rejections.append(error)
            self._audit(
                result,
                "ZAP_PROJECTION_REJECTED",
                {
                    **error,
                    "projection_code": rejection.projection_code,
                    "capability": result.capability_id,
                    "target_ref": result.target_ref,
                    "runner_contacted": False,
                    "target_requests": 0,
                },
            )
            self._zap_terminal(
                result, f"ZAP_PROJECTION_REJECTED_{rejection.projection_code}", ScanStatus.REVIEW
            )
            return
        except EnginePolicyRejection as rejection:
            error = rejection.error.model_dump(mode="json")
            result.engine_job_rejections.append(error)
            self._audit(
                result,
                "ZAP_JOB_REJECTED",
                {
                    **error,
                    "capability": result.capability_id,
                    "target_ref": result.target_ref,
                    "runner_contacted": False,
                    "target_requests": 0,
                },
            )
            self._zap_terminal(
                result, f"ZAP_JOB_REJECTED_{rejection.error.code.value}", ScanStatus.REVIEW
            )
            return
        self._audit(result, "ZAP_PROJECTION_CREATED", self._projection_event(job, projection))
        self._audit(
            result,
            "ZAP_JOB_ADMITTED",
            {
                "engine": job.engine.value,
                "profile_id": job.profile_id,
                "capability": job.capability_id,
                "job_id": job.job_id,
                "target_ref": job.target_ref,
                "operation_id": job.target.operation_id,
                "activity": job.activity.value,
                "projection_digest": job.projection_digest,
                "manifest_digest": job.manifest_digest,
                "add_on_inventory_digest": job.add_on_inventory_digest,
                "rule_ids": list(job.rule_ids),
                "adapter_version": job.adapter_version,
                "budgets": {
                    "requests": job.budget.max_requests,
                    "time_ms": job.budget.time_budget_ms,
                    "alerts": job.max_alerts,
                    "report_bytes": job.max_report_bytes,
                },
            },
        )

        # 2) Attest the isolated runner BEFORE any execution: pinned engine and add-ons, guard.
        attestation = await self.zap.attest()
        self._audit(
            result,
            "ZAP_RUNNER_STARTED",
            {
                "reachable": attestation is not None,
                "ready": bool(attestation and attestation.ready),
                "runner_version": attestation.runner_version if attestation else None,
                "zap_version": attestation.engine.zap_version if attestation else None,
                "jar_sha256": attestation.engine.jar_sha256 if attestation else None,
                "java_version": attestation.engine.java_runtime_version if attestation else None,
                "arch": attestation.engine.arch if attestation else None,
                "pinned": bool(attestation and attestation.engine.pinned),
                "add_on_inventory_digest": (
                    attestation.engine.add_on_inventory_digest if attestation else None
                ),
                "addonlist_verified": bool(attestation and attestation.addonlist_verified),
                "guard_version": attestation.guard.guard_version if attestation else None,
                "guard_reachable": bool(attestation and attestation.guard.reachable),
                "failure_codes": list(attestation.failure_codes) if attestation else [],
            },
        )
        execution_id = f"exec-{uuid4().hex[:12]}"
        if self.zap.attestation_problem(attestation, job) is not None:
            outcome = await self.zap.run(
                job, result.id, execution_id=execution_id, attestation=attestation
            )
            self._record_zap_failure(result, job, outcome, "RUNNER_NOT_ATTESTED")
            return

        # 3) Execute on the runner. Reserve the target-request budget first (fail closed).
        for _ in range(job.budget.max_requests):
            budget.request()
        outcome = await self.zap.run(
            job, result.id, execution_id=execution_id, attestation=attestation
        )
        self._emit_zap_stages(result, job, outcome.response)
        if outcome.execution.status is EngineExecutionStatus.FAILED or outcome.response is None:
            self._record_zap_failure(result, job, outcome, "EXECUTION")
            return
        response = outcome.response
        result.zap_provenance = self._zap_provenance(job, outcome)
        traffic = response.traffic
        self._audit(
            result,
            "ZAP_EXECUTION_COMPLETED",
            {
                "execution_id": execution_id,
                "job_id": job.job_id,
                "exit_class": response.exit_class,
                "exit_code": response.exit_code,
                "duration_ms": response.duration_ms,
                "expected_requests": job.operation_count,
                "observed_requests": traffic.received if traffic else None,
                "forwarded": traffic.forwarded if traffic else None,
                "blocked": traffic.blocked if traffic else None,
                "redirects": traffic.redirects if traffic else None,
                "alerts": len(response.alerts),
                "report_sha256": response.report_sha256,
                "parse_status": response.parse.status,
                "stripped_fields": list(response.parse.stripped_fields),
                "session_destroyed": response.session_destroyed,
                "coverage_complete": response.coverage_complete,
            },
        )

        # 4) Tool alerts enter as TOOL_REPORTED observations; correlate them deterministically.
        execution, evidence, correlated = self._zap_observations(result, job, outcome)
        result.engine_executions.append(execution.model_dump(mode="json"))
        result.engine_evidence.extend(item.model_dump(mode="json") for item in evidence)

        # 5) Independent deterministic verification from fresh, controller-constructed requests.
        target = ZAP_TARGETS[job.target_ref]
        plan = zap_verifier.probe_plan(target, result.id)
        if not plan:
            # Negative-control inventory entries have no verifiable property: never a PASS.
            self._zap_terminal(result, "NEGATIVE_CONTROL_NOT_VERIFIABLE", ScanStatus.INCOMPLETE)
            return
        self._audit(
            result,
            "ZAP_VERIFICATION_STARTED",
            {
                "verifier_version": zap_verifier.VERIFIER_VERSION,
                "requests": [
                    {"name": name, "method": "GET", "path": path} for name, _, path in plan
                ],
                "independent": True,
                "zap_inputs_used": [],
            },
        )
        for _ in plan:
            budget.request()
        facts = await zap_verifier.collect(
            target=target,
            scan_id=result.id,
            safety=self.safety,
            transport=self.transport,
            timeout_seconds=self.settings.request_timeout_seconds,
        )
        verdict = zap_verifier.evaluate(facts)
        result.verifier_evidence = [f.model_dump(mode="json") for f in facts]
        result.engine_evidence.extend(
            item.model_dump(mode="json")
            for item in self._zap_verifier_evidence(result, job, execution.execution_id, facts)
        )
        result.verification = Verification(
            status=verdict.status,
            summary=verdict.summary,
            evidence_names=verdict.evidence_names,
        )

        finding: Finding | None = None
        capability = get_engine_capability(job.capability_id)
        for normalized in correlated:
            if normalized.lifecycle_state is not FindingLifecycleState.AEGIS_CORRELATED:
                result.normalized_findings.append(normalized.model_dump(mode="json"))
                continue
            if verdict.status == "CONFIRMED" and finding is None and capability:
                finding = Finding(
                    id=f"finding-{result.id}-zap-header",
                    title="Anti-MIME-sniffing header missing on a synthetic API route",
                    severity=capability.verified_severity,
                    category="Security misconfiguration: missing X-Content-Type-Options header",
                    confidence="CONFIRMED",
                    description=(
                        "An anonymous read-only GET of the synthetic catalog route returned JSON "
                        "without X-Content-Type-Options: nosniff. Confirmed by the independent "
                        "Aegis verifier from fresh evidence, not by ZAP."
                    ),
                    remediation="Set X-Content-Type-Options: nosniff on every API response.",
                    evidence_names=list(verdict.evidence_names),
                )
            conclusion = VerifierConclusion(
                status=verdict.status,
                summary=verdict.summary,
                aegis_finding_id=finding.id if finding and verdict.status == "CONFIRMED" else None,
                evidence_ids=[f"{result.id}:{name}" for name in verdict.evidence_names],
            )
            normalized = record_verifier_conclusion(
                normalized,
                conclusion,
                inconclusive_state=FindingLifecycleState.REVIEW_REQUIRED,
            )
            result.normalized_findings.append(normalized.model_dump(mode="json"))
        if finding is not None:
            result.findings = [finding]

        lifecycle = [str(n.get("lifecycle_state")) for n in result.normalized_findings]
        self._audit(
            result,
            "ZAP_VERIFICATION_COMPLETED",
            {
                "verifier_version": zap_verifier.VERIFIER_VERSION,
                "status": verdict.status,
                "verification_status": verdict.status,
                "evidence_ids": [f"{result.id}:{name}" for name in verdict.evidence_names],
                "lifecycle_states": lifecycle,
                "finding_id": finding.id if finding else None,
                "tool_reported": len(correlated),
            },
        )

        # 6) Terminal decision. Zero ZAP alerts is never PASS on its own.
        in_scope = [
            n for n in correlated if n.lifecycle_state is FindingLifecycleState.AEGIS_CORRELATED
        ]
        if len(in_scope) != len(correlated):
            self._zap_terminal(result, "UNCORRELATED_TOOL_ALERT", ScanStatus.REVIEW)
        elif in_scope and finding is not None:
            self._zap_terminal(result, "DETERMINISTIC_CONFIRMED", ScanStatus.FAIL)
        elif in_scope and verdict.status == "PASS":
            self._zap_terminal(result, "TOOL_FINDING_REJECTED_BY_VERIFIER", ScanStatus.REVIEW)
        elif in_scope:
            self._zap_terminal(result, "VERIFICATION_INCONCLUSIVE", ScanStatus.REVIEW)
        elif verdict.status == "PASS" and response.coverage_complete and not response.alerts:
            self._zap_terminal(result, "COVERAGE_COMPLETE", ScanStatus.PASS)
        elif verdict.status == "CONFIRMED":
            self._zap_terminal(result, "ENGINE_VERIFIER_DISAGREEMENT", ScanStatus.REVIEW)
        else:
            self._zap_terminal(result, "VERIFICATION_INCONCLUSIVE", ScanStatus.INCOMPLETE)

    @staticmethod
    def _projection_event(job: ZapEngineJob, projection: ProjectionResult) -> dict[str, Any]:
        return {
            "target_ref": job.target_ref,
            "projection_ref": job.projection_ref,
            "projection_version": projection.projection_version,
            "projection_digest": projection.digest,
            "allowlist_digest": projection.allowlist_digest,
            "source_sha256": projection.source_sha256,
            "operation_count": projection.operation_count,
            "path_count": projection.path_count,
            "removed_operations": projection.removed_operations,
            "stripped_fields": list(projection.stripped_categories),
            "redaction_status": projection.redaction_status,
            "methods": sorted({op.method for op in projection.operations}),
            "origin_source": "CONTROLLER_INVENTORY",
        }

    def _emit_zap_stages(
        self, result: ScanResult, job: ZapEngineJob, response: ZapRunResponse | None
    ) -> None:
        """Record the fixed-plan stages ZAP reached, as reported by the runner from ZAP's own
        output. Emitted after the synchronous RPC returns; each event names its source."""

        if response is None or response.status == "REJECTED":
            return
        stages = response.stages
        common = {"job_id": job.job_id, "source": "RUNNER_DERIVED_STAGE_FACT"}
        if response.plan.validated:
            self._audit(
                result,
                "ZAP_PLAN_VALIDATED",
                {
                    **common,
                    "plan_digest": response.plan.plan_digest,
                    "job_types": list(response.plan.job_types),
                    "rule_ids": list(response.plan.admitted_rule_ids),
                    "validated": True,
                },
            )
        if stages.import_started:
            self._audit(
                result,
                "ZAP_OPENAPI_IMPORT_STARTED",
                {**common, "projection_digest": job.projection_digest, "api_source": "LOCAL_FILE"},
            )
        if stages.import_completed:
            self._audit(
                result,
                "ZAP_OPENAPI_IMPORT_COMPLETED",
                {
                    **common,
                    "urls_added": stages.urls_added,
                    "expected_requests": job.operation_count,
                    "import_test_passed": stages.urls_test_passed,
                    "observed_requests": response.traffic.received if response.traffic else None,
                },
            )
        if stages.pscan_wait_started:
            self._audit(
                result,
                "ZAP_PASSIVE_SCAN_WAIT_STARTED",
                {**common, "rules_set": [list(r) for r in stages.rules_set]},
            )
        if stages.pscan_drained:
            self._audit(
                result,
                "ZAP_PASSIVE_SCAN_DRAINED",
                {**common, "drained": True, "max_duration": "UNLIMITED_UNTIL_EMPTY"},
            )

    def _record_zap_failure(
        self,
        result: ScanResult,
        job: ZapEngineJob,
        outcome: ZapAdapterResult,
        stage: str,
    ) -> None:
        """A failed/rejected/incomplete execution is recorded and ends INCOMPLETE — never PASS."""

        result.zap_provenance = self._zap_provenance(job, outcome)
        result.engine_executions.append(outcome.execution.model_dump(mode="json"))
        error = outcome.execution.error
        response = outcome.response
        traffic = response.traffic if response else None
        self._audit(
            result,
            "ZAP_EXECUTION_FAILED",
            {
                "stage": stage,
                "job_id": job.job_id,
                "execution_id": outcome.execution.execution_id,
                "code": error.code.value if error else "UNKNOWN",
                "detail": error.detail if error else "",
                "error_code": (
                    response.error_code.value if response and response.error_code else None
                ),
                "exit_class": response.exit_class if response else "NOT_RUN",
                "exit_code": response.exit_code if response else None,
                "expected_requests": job.operation_count,
                "observed_requests": traffic.received if traffic else None,
                "forwarded": traffic.forwarded if traffic else None,
                "blocked": traffic.blocked if traffic else None,
                "blocked_reasons": [list(r) for r in traffic.blocked_reasons] if traffic else [],
                "redirects": traffic.redirects if traffic else None,
                "session_destroyed": bool(response and response.session_destroyed),
                "runner_contacted_for_execution": outcome.request is not None,
            },
        )
        code = (error.detail or error.code.value) if error else "UNKNOWN"
        self._zap_terminal(
            result, f"ZAP_EXECUTION_INCOMPLETE_{code}"[:120], ScanStatus.INCOMPLETE
        )

    def _zap_observations(
        self,
        result: ScanResult,
        job: ZapEngineJob,
        outcome: ZapAdapterResult,
    ) -> tuple[EngineExecution, list[NormalizedEvidence], list[Any]]:
        """Turn parsed runner alert records into kernel observations, provenance-complete evidence
        and correlated normalized findings (TOOL_REPORTED -> AEGIS_CORRELATED or REJECTED)."""

        response = outcome.response
        assert response is not None
        target = ZAP_TARGETS[job.target_ref]
        by_path = {op.path: op for op in job.operations}
        scenario = next(
            (op for op in job.operations if op.operation_id == target.scenario_operation_id), None
        )
        observations: list[EngineObservation] = []
        reported: list[EngineReportedFinding] = []
        evidence: list[NormalizedEvidence] = []
        rule_names = {r.plugin_id: r.name for r in load_zap_manifest().passive_rules}
        record_by_key: dict[str, Any] = {}
        for record in response.alerts:
            name = f"zap-{record.plugin_id}-{record.record_digest[:12]}"
            observations.append(
                EngineObservation(
                    request_name=name,
                    method=record.method,
                    path=record.path,
                    credential_profile="anonymous",
                    status_code=None,  # the report does not carry it; the guard counted 2xx
                    duration_ms=0,
                    content_digest=record.record_digest,
                    has_error=False,
                )
            )
            evidence.append(
                NormalizedEvidence(
                    evidence_id=f"{result.id}:{name}",
                    engine=SecurityEngine.ZAP,
                    adapter_version=job.adapter_version,
                    engine_execution_id=outcome.execution.execution_id,
                    run_id=job.run_id,
                    scan_id=result.id,
                    timestamp=response.completed_at,
                    capability_id=job.capability_id,
                    target_ref=job.target_ref,
                    request_refs=[name],
                    artifact_refs=[f"{outcome.execution.execution_id}:{record.plugin_id}"],
                    redaction_status="REDACTED",
                    content_digest=record.record_digest,
                    parser_version=ZAP_PARSER_VERSION,
                    source_class=EvidenceSourceClass.ENGINE_OBSERVATION,
                    retention_class=RetentionClass.STANDARD,
                )
            )
            operation = by_path.get(record.path)
            report_key = (
                f"{job.capability_id}:{record.plugin_id}:{job.target_ref}:"
                f"{operation.operation_id if operation else 'unknown'}"
            )
            record_by_key.setdefault(report_key, record)
            reported.append(
                EngineReportedFinding(
                    report_key=report_key,
                    engine=SecurityEngine.ZAP,
                    capability_id=job.capability_id,
                    claimed_category="Missing anti-MIME-sniffing header (tool claim)",
                    target_operation_id=operation.operation_id if operation else "unknown",
                    principal_profile="anonymous",
                    observation_names=[name],
                    signal=(
                        f"Passive rule {record.plugin_id} flagged {record.method} {record.path} "
                        "(unverified raw tool signal)."
                    )[:200],
                )
            )
        execution = outcome.execution.model_copy(
            update={"observations": observations, "reported_findings": reported}
        )
        correlated = []
        for item in dedupe_reported(reported):
            plugin_id = int(item.report_key.split(":")[1])
            record = record_by_key[item.report_key]
            in_scope = (
                item.capability_id == job.capability_id
                and plugin_id in job.rule_ids
                and scenario is not None
                and item.target_operation_id == scenario.operation_id
                and record.path == scenario.path
            )
            self._audit(
                result,
                "ZAP_ALERT_REPORTED",
                {
                    "engine": item.engine.value,
                    "capability": item.capability_id,
                    "report_key": item.report_key,
                    "plugin_id": plugin_id,
                    "rule_name": rule_names.get(plugin_id),
                    "operation_id": item.target_operation_id,
                    "method": record.method,
                    "claimed_risk": record.claimed_risk,
                    "claimed_confidence": record.claimed_confidence,
                    "claim_trust": "UNTRUSTED_TOOL_METADATA",
                    "provenance": "TOOL_REPORTED",
                    "lifecycle_state": FindingLifecycleState.TOOL_REPORTED.value,
                },
            )
            normalized = correlate_reported_finding(
                item,
                job,
                ai_hypothesis="None - operator-requested capability; no AI involvement.",
                in_scope=in_scope,
            )
            self._audit(
                result,
                "ZAP_ALERT_CORRELATED",
                {
                    "normalized_id": normalized.normalized_id,
                    "lifecycle_state": normalized.lifecycle_state.value,
                    "capability": normalized.capability_id,
                    "target_ref": job.target_ref,
                    "operation_id": item.target_operation_id,
                    "correlation": "IN_SCOPE" if in_scope else "OUT_OF_SCOPE",
                },
            )
            correlated.append(normalized)
        return execution, evidence, correlated

    def _zap_verifier_evidence(
        self,
        result: ScanResult,
        job: ZapEngineJob,
        execution_id: str,
        facts: list[zap_verifier.ZapProbeFacts],
    ) -> list[NormalizedEvidence]:
        items = []
        for fact in facts:
            digest = fact.body_sha256 or hashlib.sha256(
                json.dumps(fact.model_dump(mode="json"), sort_keys=True).encode()
            ).hexdigest()
            items.append(
                NormalizedEvidence(
                    evidence_id=f"{result.id}:{fact.name}",
                    engine=SecurityEngine.ZAP,
                    adapter_version=job.adapter_version,
                    engine_execution_id=execution_id,
                    run_id=job.run_id,
                    scan_id=result.id,
                    timestamp=datetime.now(UTC),
                    capability_id=job.capability_id,
                    target_ref=job.target_ref,
                    request_refs=[fact.name],
                    artifact_refs=[f"{result.id}:{fact.name}"],
                    redaction_status="REDACTED",
                    content_digest=digest,
                    parser_version=zap_verifier.VERIFIER_VERSION,
                    source_class=EvidenceSourceClass.VERIFIER_DERIVED,
                    retention_class=RetentionClass.STANDARD,
                )
            )
        return items
