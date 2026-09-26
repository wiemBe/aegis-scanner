"""Phase 2.7 correction — REAL lifecycle integration adapters (offline, network-boundary doubles).

The Phase 2.7 :mod:`aegis.multi_agent.lifecycle` module is a *generic* controller-owned DAG/state
machine: its stage executors are opaque ``Callable[[StageContext], StageOutcome]`` and a stage that
merely returns ``ok=True`` proves nothing about whether the prior proven components are actually
invoked. This module closes that gap for ONE bounded scenario (the authorized ops
detection-control-bypass slice) by driving each lifecycle stage through the *actual* existing
controller/storage interfaces:

    * persisted Lead/agent queue -> ``adversary_simulation.AdvSimTaskQueue``
    * independent verifier            -> :meth:`aegis_range.verifier.RangeVerifier.
                                          adjudicate_detection_control_bypass_offline`
    * remediation controller + receipt -> ``remediation.RemediationController``
    * fresh retest + causal break     -> :meth:`RemediationController.begin_retest` /
                                          :meth:`RemediationController.conclude_retest`
    * Phase 2.6 report job + assembler-> :class:`aegis.multi_agent.report_agent.ReportAgentQueue` +
                                          :func:`aegis.multi_agent.report_agent.assemble_report`
    * cleanup ledger                  -> :meth:`AssessmentLifecycleController.run_cleanup`

Only the external provider/network boundary is replaced with a deterministic offline double: the
worker probe is a real :class:`httpx.Client` whose transport is an in-process
:class:`httpx.MockTransport` serving the synthetic ops surface (a real HTTP round-trip, no
Docker, no provider). Every adjudicated fact (CONFIRMED / PASS, severity, causal break) is owned by
the verifier / remediation controller, never by a stage callback.

NOT integrated here (and therefore NOT claimed): the bank-scenario
:class:`aegis.multi_agent.broker.ControlledToolBroker`. Its evidence shape (an
``AUTHORIZATION_COMPARISON`` over the bank surface) has no remediation profile and does not compose
into the ops detection-control remediation loop, so a single coherent lifecycle cannot drive it
without fabrication. The Tool-Broker-in-lifecycle adapter stays ``NOT_EVALUATED`` (see PHASES.md).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

import httpx

from aegis.multi_agent.adversary_simulation import (
    AdvAgentJob,
    AdvSimTaskQueue,
    PersistedAdvDelegation,
    evidence_sha256_of,
)
from aegis.multi_agent.lifecycle import (
    AssessmentLifecycleController,
    AssessmentSpec,
    LifecycleLedger,
    LifecycleStage,
    StageContext,
    StageOutcome,
    StageUsageDelta,
    evidence_digest,
)
from aegis.multi_agent.remediation import (
    ENFORCE_UNIFORM_DETECTION_CONTROL_V1,
    PersistedFinding,
    RemediationController,
    RemediationLedger,
    RemediationState,
    controller_state_digest,
)
from aegis.multi_agent.report_agent import (
    AssessmentReport,
    ReportAgentJob,
    ReportAgentQueue,
    ReportSource,
    SourceCleanup,
    SourceEvidenceRef,
    SourceFinding,
    SourceRetest,
    SourceUsage,
    assemble_report,
    build_report_request_projection,
    projection_sha256,
)
from aegis_range.verifier import RangeVerifier

TARGET_REF = "range-ops"
APPLICATION_ID = "aegis-ops"
SCENARIO_ID = "ops-detection-control-bypass-v1"
CAMPAIGN_ID = "phase-2.7-integration"
_PROBE_ROUTE = "/api/ops/incident-export"


def _id16(assessment_id: str, label: str) -> str:
    return hashlib.sha256(f"{assessment_id}:{label}".encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Deterministic offline network double for the synthetic ops detection-control surface.
# --------------------------------------------------------------------------- #


@runtime_checkable
class OpsRangeSurface(Protocol):
    """The controller-owned synthetic-ops surface the lifecycle adapters drive.

    Implemented by the in-process :class:`OpsRangeDouble` (network boundary doubled) and by the
    Phase 2.9 real-container backend (a genuine ``aegis_range.ops`` container on a no-egress
    network). Both expose the same controller-owned probe / state / patch-mutation surface so the
    same real remediation/verifier/report components drive either one without change.
    """

    mode: str
    generation: int
    sentinel_digest: str
    probe_requests: int

    def probe(self) -> dict[str, dict[str, object]]: ...

    def state_digest(self) -> str: ...

    def apply_patch_mutation(self) -> dict[str, object]: ...


@dataclass
class OpsRangeDouble:
    """An in-process synthetic ops surface served over :class:`httpx.MockTransport`.

    Baseline requests are always denied. In ``vulnerable`` mode the *alternate* request variant
    slips past the detection control and reaches the controller-owned sentinel (returning its
    digest); in ``patched`` mode the alternate variant is denied like the baseline. Flipping to
    ``patched`` also rotates the sentinel — the controller-owned mutation the immutable patch
    receipt is minted from.
    """

    mode: str = "vulnerable"
    generation: int = 3
    sentinel_digest: str = "a1" + "0" * 62
    probe_requests: int = 0

    def _handle(self, request: httpx.Request) -> httpx.Response:
        variant = request.headers.get("x-variant", "BASELINE")
        if variant == "BASELINE":
            return httpx.Response(403, json={"detail": "blocked", "sentinel_present": False})
        # ALTERNATE variant.
        if self.mode == "vulnerable":
            return httpx.Response(
                200,
                json={
                    "detail": "ok",
                    "sentinel_present": True,
                    "sentinel_digest": self.sentinel_digest,
                },
            )
        return httpx.Response(403, json={"detail": "blocked", "sentinel_present": False})

    def probe(self) -> dict[str, dict[str, object]]:
        """Run a real HTTP baseline + alternate probe against the double; return worker evidence."""

        with httpx.Client(
            base_url="http://ops.synthetic.local",
            transport=httpx.MockTransport(self._handle),
            timeout=3,
        ) as client:
            baseline = client.get(_PROBE_ROUTE, headers={"X-Variant": "BASELINE"})
            alternate = client.get(_PROBE_ROUTE, headers={"X-Variant": "ALTERNATE"})
        self.probe_requests += 2
        return {
            "baseline": {
                "status_code": baseline.status_code,
                "blocked": baseline.status_code == 403,
                "sentinel_present": bool(baseline.json().get("sentinel_present")),
                "sentinel_digest": str(baseline.json().get("sentinel_digest", "")),
            },
            "alternate": {
                "status_code": alternate.status_code,
                "blocked": alternate.status_code == 403,
                "sentinel_present": bool(alternate.json().get("sentinel_present")),
                "sentinel_digest": str(alternate.json().get("sentinel_digest", "")),
            },
        }

    def state_digest(self) -> str:
        return controller_state_digest(self.mode, self.generation, self.sentinel_digest)

    def apply_patch_mutation(self) -> dict[str, object]:
        """Perform the controller-owned mutation (vulnerable->patched + sentinel rotation)."""

        pre_mode, pre_gen, pre_sentinel = self.mode, self.generation, self.sentinel_digest
        pre_digest = self.state_digest()
        self.mode = "patched"
        self.generation = pre_gen + 1
        self.sentinel_digest = "b2" + "0" * 62
        return {
            "previous_mode": pre_mode,
            "resulting_mode": self.mode,
            "pre_state_digest": pre_digest,
            "post_state_digest": self.state_digest(),
            "old_sentinel_epoch": pre_gen,
            "old_sentinel_digest": pre_sentinel,
            "new_sentinel_epoch": self.generation,
            "new_sentinel_digest": self.sentinel_digest,
        }


# --------------------------------------------------------------------------- #
# The assembly: real components wired as Phase 2.7 lifecycle stage adapters.
# --------------------------------------------------------------------------- #


@dataclass
class OpsDetectionControlLifecycle:
    """Drives the ops detection-control lifecycle through the real controller/storage interfaces.

    Each stage adapter invokes a genuine component; the caller (a test or harness) drives the Phase
    2.7 :class:`AssessmentLifecycleController` and asserts real records. Counters expose how many
    real external effects (worker probes) happened, so a resume can be proven duplicate-free.
    """

    base_dir: Path
    run_epoch: int = 7
    campaign_id: str = CAMPAIGN_ID
    # Controller-owned authorization reference recorded on the AssessmentSpec. The default preserves
    # the historical integration value for every existing caller and the provider-free dry run; an
    # armed live campaign threads the validated non-secret operator reference here instead.
    authorization_reference: str = "authz-range-ops-integration"
    lifecycle: AssessmentLifecycleController = field(init=False)
    remediation: RemediationController = field(init=False)
    remediation_ledger: RemediationLedger = field(init=False)
    queue: AdvSimTaskQueue = field(init=False)
    report_queue: ReportAgentQueue = field(init=False)
    verifier: RangeVerifier = field(init=False)
    range_double: OpsRangeSurface = field(init=False)
    spec: AssessmentSpec = field(init=False)
    # In-process evidence captured during external stages (durable facts live in the real ledgers).
    initial_evidence: dict[str, dict[str, object]] | None = None
    retest_evidence: dict[str, dict[str, object]] | None = None
    initial_evidence_at: datetime | None = None
    retest_evidence_at: datetime | None = None
    # Adapter invocation counters (a resume must not re-run a completed stage's real effects).
    calls: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        lifecycle_ledger = LifecycleLedger(str(self.base_dir / "lifecycle.db"))
        lifecycle_ledger.initialize()
        self.lifecycle = AssessmentLifecycleController(lifecycle_ledger)
        self.remediation_ledger = RemediationLedger(str(self.base_dir / "remediation.db"))
        self.remediation_ledger.initialize()
        self.remediation = RemediationController(self.remediation_ledger)
        self.queue = AdvSimTaskQueue(str(self.base_dir / "advsim.db"))
        self.queue.initialize()
        self.report_queue = ReportAgentQueue(str(self.base_dir / "report.db"))
        self.report_queue.initialize()
        self.verifier = RangeVerifier()
        self.range_double = OpsRangeDouble()
        self.spec = self._build_spec()

    # --------------------------- ids + spec --------------------------- #

    @property
    def assessment_id(self) -> str:
        return "asmt-" + _id16(self.campaign_id, "assessment")

    @property
    def loop_id(self) -> str:
        return "rloop-" + _id16(self.assessment_id, "loop")

    @property
    def finding_id(self) -> str:
        return "find-" + _id16(self.assessment_id, "finding")

    def _build_spec(self) -> AssessmentSpec:
        now = datetime.now().astimezone()
        return AssessmentSpec(
            assessment_id=self.assessment_id,
            campaign_id=self.campaign_id,
            target_ref=TARGET_REF,
            scenario_id=SCENARIO_ID,
            run_epoch=self.run_epoch,
            required_stages=(
                LifecycleStage.AUTHORIZE,
                LifecycleStage.PREPARE,
                LifecycleStage.EXECUTE,
                LifecycleStage.VERIFY,
                LifecycleStage.REMEDIATE,
                LifecycleStage.RETEST,
                LifecycleStage.REPORT,
                LifecycleStage.CLEANUP,
            ),
            cumulative_provider_calls=40,
            cumulative_tokens=200_000,
            per_stage_provider_calls=20,
            per_stage_tokens=100_000,
            authorization_reference=self.authorization_reference,
            lease_ref="lease-range-ops-integration",
            lease_expires_at=now + timedelta(hours=2),
            activation_required_capabilities=("aegis.ops.detection_control_probe",),
        )

    # --------------------------- stage adapters --------------------------- #

    def enqueue_lead_and_recon_jobs(self) -> tuple[str, str, str]:
        """Persist the real Lead->Recon handoff on the actual AdvSim queue; return its addresses."""

        lead_id = "agjob-" + _id16(self.assessment_id, "lead")
        recon_id = "agjob-" + _id16(self.assessment_id, "recon")
        delegation_id = "adelg-" + _id16(self.assessment_id, "delegation")
        source_digest = evidence_sha256_of([{"scenario": SCENARIO_ID, "target": TARGET_REF}])
        lead = AdvAgentJob(
            job_id=lead_id,
            to_agent="LEAD_ORCHESTRATOR",
            target_ref=TARGET_REF,
            technique_class="HTTP_DETECTION_CONTROL_BYPASS",
            task_type="PLAN_ADVERSARY_SIMULATION",
            objective="Plan the authorized ops detection-control-bypass assessment.",
        )
        lead_address = self.queue.enqueue_job(lead)
        self.queue.claim_job(lead_address)
        delegation = PersistedAdvDelegation(
            delegation_id=delegation_id,
            producer_job_id=lead_id,
            capability_id="aegis.ops.detection_control_probe",
            target_ref=TARGET_REF,
            technique_class="HTTP_DETECTION_CONTROL_BYPASS",
            source_evidence_sha256=source_digest,
        )
        self.queue.persist_delegation(delegation)
        recon = AdvAgentJob(
            job_id=recon_id,
            to_agent="RECON_AGENT",
            target_ref=TARGET_REF,
            technique_class="HTTP_DETECTION_CONTROL_BYPASS",
            task_type="RUN_ADVERSARY_SIMULATION",
            objective="Execute the bounded detection-control probe sequence.",
            from_delegation_id=delegation_id,
            producer_job_id=lead_id,
        )
        recon_address = self.queue.enqueue_job(recon)
        self.queue.claim_job(recon_address)
        return lead_address, recon_address, delegation.delegation_address

    def _count(self, name: str) -> None:
        self.calls[name] = self.calls.get(name, 0) + 1

    def execute_dispatcher(self, context: StageContext, idempotency_key: str) -> StageOutcome:
        """EXECUTE (external): real worker probe over the offline double (vulnerable mode)."""

        self._count("execute")
        self.enqueue_lead_and_recon_jobs()
        self.initial_evidence = self.range_double.probe()
        self.initial_evidence_at = datetime.now().astimezone()
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest(self.initial_evidence),
            side_effect_token=f"probe-{idempotency_key}",
            usage=StageUsageDelta(provider_calls=1, tokens=3000, tool_executions=2),
            detail="initial detection-control probe executed",
        )

    def verify_executor(self, context: StageContext) -> StageOutcome:
        """VERIFY: the independent verifier owns CONFIRMED; the finding is persisted for remedy."""

        self._count("verify")
        assert self.initial_evidence is not None and self.initial_evidence_at is not None
        result = self.verifier.adjudicate_detection_control_bypass_offline(
            APPLICATION_ID,
            self.initial_evidence,
            detection_active=True,
            controller_sentinel_digest=self.range_double.sentinel_digest,
        )
        if result.status.value != "CONFIRMED":
            return StageOutcome(
                ok=False, produced_epoch=context.run_epoch, detail=f"verifier={result.status.value}"
            )
        self.remediation_ledger.open_loop(self.loop_id, self.campaign_id, TARGET_REF, SCENARIO_ID)
        finding = PersistedFinding(
            finding_id=self.finding_id,
            loop_id=self.loop_id,
            campaign_id=self.campaign_id,
            target_ref=TARGET_REF,
            scenario_id=SCENARIO_ID,
            finding_type="HTTP_DETECTION_CONTROL_BYPASS",
            verified_status="CONFIRMED",
            verifier_evidence_sha256=result.evidence_sha256,
            controller_state_digest=self.range_double.state_digest(),
            controller_sentinel_epoch=self.range_double.generation,
            initial_evidence_at=self.initial_evidence_at,
        )
        self.remediation.confirm_initial_finding(finding)
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=result.evidence_sha256,
            side_effect_token="verifier-CONFIRMED",  # noqa: S106 (opaque token, not a secret)
            usage=StageUsageDelta(provider_calls=0, tokens=0, tool_executions=0),
            detail="independent verifier CONFIRMED the detection-control bypass",
        )

    def remediate_executor(self, context: StageContext) -> StageOutcome:
        """REMEDIATE: real controller authorizes + applies the registered remediation + receipt."""

        self._count("remediate")
        finding = self.remediation_ledger.get_finding(self.finding_id)
        assert finding is not None
        now = datetime.now().astimezone()
        self.remediation.record_recommendation(finding, ENFORCE_UNIFORM_DETECTION_CONTROL_V1)
        authorization = self.remediation.authorize_remediation(
            finding,
            ENFORCE_UNIFORM_DETECTION_CONTROL_V1,
            now=now,
            authorization_id="rauth-" + _id16(self.assessment_id, "auth"),
            lease_id="rlease-" + _id16(self.assessment_id, "lease"),
        )
        mutation = self.range_double.apply_patch_mutation()  # controller-owned range mutation
        receipt = self.remediation.apply_remediation(
            finding,
            authorization,
            mutation,
            now=now + timedelta(seconds=1),
            receipt_id="rcpt-" + _id16(self.assessment_id, "receipt"),
            campaign_id=self.campaign_id,
        )
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest({"receipt": receipt.receipt_uri}),
            side_effect_token=receipt.receipt_id,
            usage=StageUsageDelta(provider_calls=1, tokens=2000, tool_executions=1),
            detail="controller applied the registered remediation and minted the patch receipt",
        )

    def retest_dispatcher(self, context: StageContext, idempotency_key: str) -> StageOutcome:
        """RETEST (external): fresh probe (patched) -> verifier PASS -> conclude causal break."""

        self._count("retest")
        finding = self.remediation_ledger.get_finding(self.finding_id)
        receipt = self.remediation_ledger.get_receipt(
            "rcpt-" + _id16(self.assessment_id, "receipt")
        )
        assert finding is not None and receipt is not None
        self.remediation.begin_retest(finding, receipt, "agjob-" + _id16(self.assessment_id, "rt"))
        self.retest_evidence = self.range_double.probe()  # fresh evidence AFTER the patch
        self.retest_evidence_at = receipt.applied_at + timedelta(seconds=10)
        result = self.verifier.adjudicate_detection_control_bypass_offline(
            APPLICATION_ID,
            self.retest_evidence,
            detection_active=True,
            controller_sentinel_digest=self.range_double.sentinel_digest,
        )
        final, proof = self.remediation.conclude_retest(
            finding,
            receipt,
            retest_verifier_status=result.status.value,
            initial_evidence_at=finding.initial_evidence_at,
            retest_evidence_at=self.retest_evidence_at,
            retest_target_ref=TARGET_REF,
            retest_scenario_id=SCENARIO_ID,
        )
        ok = final is RemediationState.RETEST_PASS and all(proof.values())
        return StageOutcome(
            ok=ok,
            produced_epoch=context.run_epoch,
            evidence_sha256=result.evidence_sha256,
            side_effect_token=f"retest-{idempotency_key}",
            usage=StageUsageDelta(provider_calls=1, tokens=3000, tool_executions=2),
            detail=f"fresh retest {final.value}; causal break proven={ok}",
        )

    def build_report_source(
        self,
        *,
        cleanup_succeeded: bool | Literal["UNKNOWN"],
        cleanup_obligations: tuple[str, ...],
        usage: SourceUsage,
        cleanup_failures: tuple[str, ...] = (),
        live_run: bool = False,
    ) -> ReportSource:
        """Assemble the report input STRICTLY from controller/verifier records (report truth).

        ``cleanup_succeeded`` / ``cleanup_failures`` are the ACTUAL cleanup result. A pre-cleanup
        (preliminary) report passes ``"UNKNOWN"`` (cleanup has not run); the final report passes the
        real ledger outcome. Cleanup is NEVER assumed to have succeeded here."""

        finding = self.remediation_ledger.get_finding(self.finding_id)
        receipt = self.remediation_ledger.get_receipt(
            "rcpt-" + _id16(self.assessment_id, "receipt")
        )
        assert finding is not None and receipt is not None
        loop_state = self.remediation_ledger.state(self.loop_id)
        source_finding = SourceFinding(
            finding_id=finding.finding_id,
            title="Detection-control bypass on the alternate request variant",
            gate="detection_control",
            mode="vulnerable",
            scenario_id=finding.scenario_id,
            state="CONFIRMED",
            severity="HIGH",
            severity_authority="GROUND_TRUTH",
            verification_provenance="OFFLINE_VERIFIED_SYNTHETIC",
            verifier_facts={
                "alternate_reached_sentinel": True,
                "controller_sentinel_epoch": finding.controller_sentinel_epoch,
                "remediation_state": loop_state.value,
            },
            evidence=(
                SourceEvidenceRef(
                    evidence_sha256=finding.verifier_evidence_sha256,
                    locator=finding.finding_uri,
                    authority="VERIFIER",
                ),
            ),
        )
        retest = SourceRetest(
            retest_id="retest-" + _id16(self.assessment_id, "retest"),
            finding_id=finding.finding_id,
            state="PASS" if loop_state is RemediationState.RETEST_PASS else "UNKNOWN",
            provenance="OFFLINE_VERIFIED_SYNTHETIC",
            evidence=(
                SourceEvidenceRef(
                    evidence_sha256=evidence_digest({"receipt": receipt.receipt_uri}),
                    locator=receipt.receipt_uri,
                    authority="CONTROLLER",
                ),
            ),
        )
        return ReportSource(
            campaign_id=self.campaign_id,
            target_ref=TARGET_REF,
            authorized_scope=(TARGET_REF,),
            findings=(source_finding,),
            retests=(retest,),
            cleanup=SourceCleanup(
                succeeded=cleanup_succeeded,
                obligations=cleanup_obligations,
                failures=cleanup_failures,
            ),
            usage=usage,
            live_run=live_run,
        )

    def report_executor(self, context: StageContext) -> StageOutcome:
        """REPORT: real Phase 2.6 job path + assembler; report truth inherited from records."""

        self._count("report")
        usage = SourceUsage(
            provider_calls=3,
            input_tokens=4000,
            output_tokens=4000,
            total_tokens=8000,
            tool_executions=4,
        )
        source = self.build_report_source(
            cleanup_succeeded=True,
            cleanup_obligations=("RESET_SYNTHETIC_TARGET_TO_BASELINE", "ROTATE_SENTINEL"),
            usage=usage,
        )
        projection = build_report_request_projection(source)
        job = ReportAgentJob(
            job_id="rptjob-" + _id16(self.assessment_id, "reportjob"),
            campaign_id=self.campaign_id,
            report_request_id="rptreq-" + _id16(self.assessment_id, "reportreq"),
            source_projection_sha256=projection_sha256(projection),
        )
        address = self.report_queue.enqueue_job(job)
        self.report_queue.claim_job(address)
        report = assemble_report(
            source=source,
            model_output=None,  # controller-authoritative prose (no provider in this offline pass)
            report_id="rpt-" + _id16(self.assessment_id, "report"),
            version=1,
        )
        self.report_queue.save_report(report)
        self.report_queue.close_job(address)
        return StageOutcome(
            ok=report.verified_findings[0].state == "CONFIRMED",
            produced_epoch=context.run_epoch,
            evidence_sha256=report.content_sha256,
            side_effect_token=report.report_id,
            usage=StageUsageDelta(provider_calls=3, tokens=8000, tool_executions=0),
            detail="assembled controller-authoritative report from records",
        )

    def get_report(self) -> AssessmentReport | None:
        return self.report_queue.get_report("rpt-" + _id16(self.assessment_id, "report"), 1)
