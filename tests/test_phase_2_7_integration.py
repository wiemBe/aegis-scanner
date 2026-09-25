"""Phase 2.7 correction — ONE offline lifecycle *integration* test.

Unlike the framework tests (which drive the generic DAG with deterministic stage stubs), this drives
a bounded ops detection-control lifecycle through the ACTUAL existing controller/storage interfaces
via :class:`aegis.multi_agent.lifecycle_adapters.OpsDetectionControlLifecycle`. The only offline
double is the network boundary (an in-process ``httpx.MockTransport`` synthetic ops surface). It
proves the integration that a success-returning stage callback cannot:

    * stable lineage across assessment, jobs, evidence, finding, remediation, retest and report;
    * stage ordering (illegal early stage fails closed);
    * the independent verifier — not a stage callback — owns CONFIRMED / PASS;
    * fresh evidence after remediation (causal-break proof over post-patch evidence);
    * report truth inherited from controller/verifier records (no model prose here);
    * cleanup completion + COMPLETED verdict;
    * resume without duplicate completed-stage execution.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from aegis.multi_agent.lifecycle import (
    AssessmentState,
    LifecycleError,
    LifecycleStage,
    StageStatus,
)
from aegis.multi_agent.lifecycle_adapters import OpsDetectionControlLifecycle, _id16
from aegis.multi_agent.remediation import RemediationState


def test_offline_lifecycle_integration(tmp_path: Path) -> None:
    asm = OpsDetectionControlLifecycle(base_dir=tmp_path / "asm")
    controller, spec = asm.lifecycle, asm.spec
    now = datetime.now().astimezone()

    # --- stage ordering: an early stage before its dependency fails closed --- #
    controller.create_assessment(spec)
    with pytest.raises(LifecycleError, match="STAGE_DEP_NOT_DONE"):
        controller.run_stage(
            spec.assessment_id, LifecycleStage.REPORT, asm.report_executor, now=now
        )

    # Drive the rest of the real lifecycle (create_assessment already done above).
    controller.authorize(
        spec.assessment_id, authorization_reference=spec.authorization_reference, now=now
    )
    controller.mark_ready(
        spec.assessment_id,
        activated_capabilities=("aegis.ops.detection_control_probe",),
        now=now,
    )
    controller.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, asm.execute_dispatcher,
        idempotency_key="ops-execute-1", now=now,
    )
    controller.run_stage(spec.assessment_id, LifecycleStage.VERIFY, asm.verify_executor, now=now)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.REMEDIATE, asm.remediate_executor, now=now
    )
    controller.run_external_stage(
        spec.assessment_id, LifecycleStage.RETEST, asm.retest_dispatcher,
        idempotency_key="ops-retest-1", now=now,
    )
    controller.run_stage(spec.assessment_id, LifecycleStage.REPORT, asm.report_executor, now=now)

    # --- every required work stage reached DONE (ordering respected) --- #
    for stage in (
        LifecycleStage.EXECUTE, LifecycleStage.VERIFY, LifecycleStage.REMEDIATE,
        LifecycleStage.RETEST, LifecycleStage.REPORT,
    ):
        record = controller.ledger.get_stage(spec.assessment_id, stage)
        assert record is not None and record.status is StageStatus.DONE, stage

    # --- persisted Lead/agent queue actually exercised (Lead -> Recon handoff linked) --- #
    assert asm.queue.count_jobs() == 2
    delegation_id = "adelg-" + _id16(asm.assessment_id, "delegation")
    assert asm.queue.handoff_linked(delegation_id) is True

    # --- verifier owns CONFIRMED; finding persisted in the real remediation ledger --- #
    finding = asm.remediation_ledger.get_finding(asm.finding_id)
    assert finding is not None and finding.verified_status == "CONFIRMED"

    # --- fresh evidence after remediation + causal break (retest probed the PATCHED surface) --- #
    assert asm.range_double.mode == "patched"
    assert asm.retest_evidence is not None and asm.retest_evidence["alternate"]["blocked"] is True
    receipt = asm.remediation_ledger.get_receipt(
        "rcpt-" + _id16(asm.assessment_id, "receipt")
    )
    assert receipt is not None
    assert finding.initial_evidence_at < receipt.applied_at  # initial evidence predates patch
    assert asm.retest_evidence_at is not None and asm.retest_evidence_at > receipt.applied_at
    assert asm.remediation_ledger.state(asm.loop_id) is RemediationState.RETEST_PASS
    assert asm.remediation_ledger.receipt_consumed(receipt.receipt_id) is True

    # --- report truth inherited from controller/verifier records (no model prose used) --- #
    report = asm.get_report()
    assert report is not None
    assert report.model_prose_used is False
    vf = report.verified_findings[0]
    # lineage: report finding == verifier/remediation finding
    assert vf.finding_id == asm.finding_id
    assert vf.state == "CONFIRMED"
    assert vf.severity == "HIGH" and vf.severity_authority == "GROUND_TRUTH"
    assert report.retest_results[0].state == "PASS"

    # --- resume without duplicate completed-stage execution --- #
    probes_before = asm.range_double.probe_requests
    calls_before = dict(asm.calls)
    controller.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, asm.execute_dispatcher,
        idempotency_key="ops-execute-1", now=now,
    )
    controller.run_stage(spec.assessment_id, LifecycleStage.VERIFY, asm.verify_executor, now=now)
    controller.run_external_stage(
        spec.assessment_id, LifecycleStage.RETEST, asm.retest_dispatcher,
        idempotency_key="ops-retest-1", now=now,
    )
    controller.run_stage(spec.assessment_id, LifecycleStage.REPORT, asm.report_executor, now=now)
    assert asm.range_double.probe_requests == probes_before  # no re-probe of DONE stages
    assert asm.calls == calls_before  # no adapter re-invocation on a DONE stage

    # --- cleanup completion + COMPLETED verdict --- #
    cleanup_ok = controller.run_cleanup(
        spec.assessment_id,
        ("RESET_SYNTHETIC_TARGET_TO_BASELINE", "ROTATE_SENTINEL", "REVOKE_REFERENCES"),
        lambda _obligation: True,
    )
    assert cleanup_ok is True
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.COMPLETED
    assert verdict.required_stages_complete is True
    assert verdict.cleanup_succeeded is True
    assert verdict.usage_complete is True
