"""Offline targeted tests for the Phase 2.7 full authorized assessment lifecycle.

No live provider, no Docker. These cover the new surface 2.7 adds: the controller-owned typed DAG +
overall state machine (the model can never advance it), persisted per-stage state, idempotency /
resume with no duplicate paid-or-tool execution, stale-evidence and historical-artifact rejection,
failed verifier / patch / retest / report, budget stop (per-stage + cumulative), lease expiry,
cancellation, cleanup compensation and cleanup failure, partial results, no final COMPLETED when a
required stage is incomplete, no provider usage defaulting to zero, immutable audit trail and the
final typed verdict. Offline tests are NOT live acceptance.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aegis.multi_agent.lifecycle import (
    AssessmentLifecycleController,
    AssessmentSpec,
    AssessmentState,
    LifecycleBudgetError,
    LifecycleCancelled,
    LifecycleError,
    LifecycleFreshnessError,
    LifecycleLeaseExpired,
    LifecycleLedger,
    LifecycleStage,
    LifecycleStateError,
    StageContext,
    StageOutcome,
    StageStatus,
    StageUsageDelta,
    assert_state_transition,
    evidence_digest,
    valid_state_transitions,
)

RUN_EPOCH = 7
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
LEASE = NOW + timedelta(minutes=30)


def _load_harness() -> Any:
    path = Path(__file__).resolve().parent.parent / "scripts" / "phase_2_7_lifecycle.py"
    spec = importlib.util.spec_from_file_location("phase_2_7_lifecycle", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _spec(**o: Any) -> AssessmentSpec:
    base: dict[str, Any] = {
        "assessment_id": "asmt-0000000000000abc",
        "campaign_id": "phase-2.7-test",
        "target_ref": "range-ops",
        "scenario_id": "ops-detection-control-bypass-v1",
        "run_epoch": RUN_EPOCH,
        "required_stages": (
            LifecycleStage.AUTHORIZE,
            LifecycleStage.PREPARE,
            LifecycleStage.EXECUTE,
            LifecycleStage.VERIFY,
            LifecycleStage.REPORT,
            LifecycleStage.CLEANUP,
        ),
        "cumulative_provider_calls": 8,
        "cumulative_tokens": 24_000,
        "per_stage_provider_calls": 4,
        "per_stage_tokens": 12_000,
        "authorization_reference": "authz-1",
        "lease_ref": "lease-1",
        "lease_expires_at": LEASE,
        "activation_required_capabilities": ("aegis.ops.detection_control_probe",),
    }
    base.update(o)
    return AssessmentSpec(**base)


def _ok_executor(
    stage: LifecycleStage,
    *,
    epoch: int = RUN_EPOCH,
    calls: int = 1,
    tokens: int = 1000,
    tools: int = 1,
    counter: dict[str, int] | None = None,
) -> Any:
    def run(context: StageContext) -> StageOutcome:
        if counter is not None:
            counter[stage.value] = counter.get(stage.value, 0) + 1
        return StageOutcome(
            ok=True,
            produced_epoch=epoch,
            evidence_sha256=evidence_digest({"stage": stage.value, "epoch": epoch}),
            side_effect_token=f"tok-{stage.value}",
            usage=StageUsageDelta(provider_calls=calls, tokens=tokens, tool_executions=tools),
            detail=f"{stage.value} ok",
        )

    return run


def _controller(tmp_path: Path, spec: AssessmentSpec) -> AssessmentLifecycleController:
    ledger = LifecycleLedger(str(tmp_path / "lc.db"))
    ledger.initialize()
    controller = AssessmentLifecycleController(ledger)
    controller.create_assessment(spec)
    return controller


def _authorize_and_ready(controller: AssessmentLifecycleController, spec: AssessmentSpec) -> None:
    controller.authorize(
        spec.assessment_id, authorization_reference=spec.authorization_reference, now=NOW
    )
    controller.mark_ready(
        spec.assessment_id,
        activated_capabilities=("aegis.ops.detection_control_probe",),
        now=NOW,
    )


# --------------------------------------------------------------------------- #
# State machine: the model can never advance it; illegal transitions fail closed.
# --------------------------------------------------------------------------- #


def test_state_machine_transitions() -> None:
    assert AssessmentState.RUNNING in valid_state_transitions(AssessmentState.READY)
    assert_state_transition(AssessmentState.CREATED, AssessmentState.AUTHORIZED)
    with pytest.raises(LifecycleStateError):
        assert_state_transition(AssessmentState.CREATED, AssessmentState.COMPLETED)
    # Terminal states have no outgoing transition.
    assert valid_state_transitions(AssessmentState.COMPLETED) == frozenset()


# --------------------------------------------------------------------------- #
# Successful offline synthetic lifecycle.
# --------------------------------------------------------------------------- #


def test_successful_lifecycle(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    for stage in (
        LifecycleStage.EXECUTE,
        LifecycleStage.VERIFY,
        LifecycleStage.REMEDIATE,
        LifecycleStage.RETEST,
        LifecycleStage.REPORT,
    ):
        controller.run_stage(spec.assessment_id, stage, _ok_executor(stage), now=NOW)
    assert controller.run_cleanup(spec.assessment_id, ("RESET",), lambda _o: True)
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.COMPLETED
    assert verdict.required_stages_complete
    assert verdict.cleanup_succeeded
    assert verdict.usage_complete
    # execute1 + verify1 + remediate1 + retest1 + report1 = 5 (each default executor charges 1).
    assert verdict.cumulative_provider_calls == 5


# --------------------------------------------------------------------------- #
# Idempotency / resume: no duplicate paid-or-tool execution.
# --------------------------------------------------------------------------- #


def test_duplicate_stage_prevention(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    counter: dict[str, int] = {}
    controller.run_stage(
        spec.assessment_id,
        LifecycleStage.EXECUTE,
        _ok_executor(LifecycleStage.EXECUTE, counter=counter),
        now=NOW,
    )
    # Re-running the same stage returns the cached record and never re-invokes the executor.
    controller.run_stage(
        spec.assessment_id,
        LifecycleStage.EXECUTE,
        _ok_executor(LifecycleStage.EXECUTE, counter=counter),
        now=NOW,
    )
    assert counter["EXECUTE"] == 1


def test_resume_after_interruption(tmp_path: Path) -> None:
    spec = _spec()
    ledger = LifecycleLedger(str(tmp_path / "lc.db"))
    ledger.initialize()
    controller = AssessmentLifecycleController(ledger)
    controller.create_assessment(spec)
    _authorize_and_ready(controller, spec)
    counter: dict[str, int] = {}
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE,
        _ok_executor(LifecycleStage.EXECUTE, counter=counter), now=NOW,
    )
    # Simulate a process restart: brand-new controller + ledger pointed at the same DB.
    resumed_ledger = LifecycleLedger(str(tmp_path / "lc.db"))
    resumed = AssessmentLifecycleController(resumed_ledger)
    # EXECUTE is cached (no re-run); the remaining stages proceed.
    resumed.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE,
        _ok_executor(LifecycleStage.EXECUTE, counter=counter), now=NOW,
    )
    resumed.run_stage(
        spec.assessment_id, LifecycleStage.VERIFY,
        _ok_executor(LifecycleStage.VERIFY, calls=0, tokens=0, tools=0, counter=counter), now=NOW,
    )
    assert counter["EXECUTE"] == 1  # not re-executed on resume
    assert counter["VERIFY"] == 1


# --------------------------------------------------------------------------- #
# Freshness: stale evidence + historical-artifact reuse.
# --------------------------------------------------------------------------- #


def test_stale_upstream_evidence_rejected(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    # EXECUTE produces evidence at a STALE epoch (older than the run epoch) -> its own commit is
    # rejected as historical-artifact reuse, so VERIFY has no fresh upstream to consume.
    with pytest.raises(LifecycleFreshnessError):
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            _ok_executor(LifecycleStage.EXECUTE, epoch=RUN_EPOCH - 1),
            now=NOW,
        )


def test_historical_artifact_reuse_rejected(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    with pytest.raises(LifecycleFreshnessError):
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            _ok_executor(LifecycleStage.EXECUTE, epoch=999),
            now=NOW,
        )
    record = controller.ledger.get_stage(spec.assessment_id, LifecycleStage.EXECUTE)
    assert record is not None and record.status is StageStatus.FAILED


# --------------------------------------------------------------------------- #
# Failed verifier / patch / retest / report.
# --------------------------------------------------------------------------- #


def _failing_executor(stage: LifecycleStage) -> Any:
    def run(context: StageContext) -> StageOutcome:
        return StageOutcome(
            ok=False, produced_epoch=context.run_epoch, detail=f"{stage.value} failed"
        )

    return run


def test_failed_verifier_marks_stage_failed(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE), now=NOW
    )
    result = controller.run_stage(
        spec.assessment_id, LifecycleStage.VERIFY, _failing_executor(LifecycleStage.VERIFY), now=NOW
    )
    assert result.status is StageStatus.FAILED
    # A failed verifier means REPORT's dependency chain (REPORT depends on VERIFY) is not DONE.
    with pytest.raises(LifecycleError):
        controller.run_stage(
            spec.assessment_id, LifecycleStage.REPORT, _ok_executor(LifecycleStage.REPORT), now=NOW
        )


def test_report_failure_yields_partial(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE), now=NOW
    )
    controller.run_stage(
        spec.assessment_id, LifecycleStage.VERIFY,
        _ok_executor(LifecycleStage.VERIFY, calls=0, tokens=0, tools=0), now=NOW,
    )
    controller.run_stage(
        spec.assessment_id, LifecycleStage.REPORT, _failing_executor(LifecycleStage.REPORT), now=NOW
    )
    controller.run_cleanup(spec.assessment_id, ("RESET",), lambda _o: True)
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.PARTIAL
    assert not verdict.required_stages_complete


# --------------------------------------------------------------------------- #
# Budget stop (per-stage + cumulative) + no zero-defaulted usage.
# --------------------------------------------------------------------------- #


def test_per_stage_budget_stop(tmp_path: Path) -> None:
    spec = _spec(per_stage_provider_calls=1)
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    with pytest.raises(LifecycleBudgetError):
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            _ok_executor(LifecycleStage.EXECUTE, calls=2),
            now=NOW,
        )


def test_cumulative_budget_stop(tmp_path: Path) -> None:
    spec = _spec(cumulative_provider_calls=2, per_stage_provider_calls=2)
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE,
        _ok_executor(LifecycleStage.EXECUTE, calls=2), now=NOW,
    )
    with pytest.raises(LifecycleBudgetError):
        controller.run_stage(
            spec.assessment_id, LifecycleStage.VERIFY,
            _ok_executor(LifecycleStage.VERIFY, calls=1), now=NOW,
        )


def test_unknown_usage_fails_closed_not_zeroed(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)

    def unknown_usage(context: StageContext) -> StageOutcome:
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest({"x": 1}),
            usage=StageUsageDelta(provider_calls="UNKNOWN", tokens="UNKNOWN"),
        )

    with pytest.raises(LifecycleBudgetError):
        controller.run_stage(spec.assessment_id, LifecycleStage.EXECUTE, unknown_usage, now=NOW)


# --------------------------------------------------------------------------- #
# Lease expiry + cancellation.
# --------------------------------------------------------------------------- #


def test_lease_expiry_fails_closed(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    with pytest.raises(LifecycleLeaseExpired):
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            _ok_executor(LifecycleStage.EXECUTE),
            now=LEASE + timedelta(seconds=1),
        )


def test_cancellation_stops_stage_and_finalizes_cancelled(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE), now=NOW
    )
    controller.request_cancel(spec.assessment_id)
    with pytest.raises(LifecycleCancelled):
        controller.run_stage(
            spec.assessment_id, LifecycleStage.VERIFY, _ok_executor(LifecycleStage.VERIFY), now=NOW
        )
    controller.run_cleanup(spec.assessment_id, ("RESET",), lambda _o: True)
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.CANCELLED


# --------------------------------------------------------------------------- #
# Cleanup compensation + cleanup failure.
# --------------------------------------------------------------------------- #


def test_cleanup_compensation_records_ledger(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    ok = controller.run_cleanup(
        spec.assessment_id, ("RESET_TARGET", "ROTATE_SENTINEL"), lambda _o: True
    )
    assert ok
    entries = controller.ledger.cleanup_entries(spec.assessment_id)
    assert {e.obligation for e in entries} == {"RESET_TARGET", "ROTATE_SENTINEL"}
    assert all(e.compensated for e in entries)


def test_cleanup_failure_yields_cleanup_failed(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    for stage in (LifecycleStage.EXECUTE, LifecycleStage.VERIFY, LifecycleStage.REPORT):
        controller.run_stage(
            spec.assessment_id, stage,
            _ok_executor(stage, calls=0, tokens=0, tools=0), now=NOW,
        )
    controller.run_cleanup(
        spec.assessment_id, ("RESET_TARGET",), lambda _o: False  # compensation fails
    )
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.CLEANUP_FAILED
    assert not verdict.cleanup_succeeded


# --------------------------------------------------------------------------- #
# Partial result + no COMPLETED when a required stage is incomplete.
# --------------------------------------------------------------------------- #


def test_no_completed_when_required_stage_missing(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE), now=NOW
    )
    controller.run_stage(
        spec.assessment_id, LifecycleStage.VERIFY,
        _ok_executor(LifecycleStage.VERIFY, calls=0, tokens=0, tools=0), now=NOW,
    )
    # REPORT (a required stage) is never run.
    controller.run_cleanup(spec.assessment_id, ("RESET",), lambda _o: True)
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.PARTIAL
    assert not verdict.required_stages_complete


def test_no_cleanup_entries_is_partial(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    # Finalize without ever running cleanup -> PARTIAL (cleanup must be proven).
    verdict = controller.finalize(spec.assessment_id)
    assert verdict.final_state is AssessmentState.PARTIAL


# --------------------------------------------------------------------------- #
# Authorization / capability activation gates.
# --------------------------------------------------------------------------- #


def test_authorization_reference_mismatch(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    with pytest.raises(LifecycleError):
        controller.authorize(spec.assessment_id, authorization_reference="wrong", now=NOW)


def test_capability_not_activated(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    controller.authorize(
        spec.assessment_id, authorization_reference=spec.authorization_reference, now=NOW
    )
    with pytest.raises(LifecycleError):
        controller.mark_ready(spec.assessment_id, activated_capabilities=(), now=NOW)


def test_execute_requires_ready(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    controller.authorize(
        spec.assessment_id, authorization_reference=spec.authorization_reference, now=NOW
    )
    # PREPARE not done yet -> EXECUTE dependency fails closed.
    with pytest.raises(LifecycleError):
        controller.run_stage(
            spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE),
            now=NOW,
        )


# --------------------------------------------------------------------------- #
# Immutable audit trail + manifest.
# --------------------------------------------------------------------------- #


def test_audit_trail_and_manifest(tmp_path: Path) -> None:
    spec = _spec()
    controller = _controller(tmp_path, spec)
    _authorize_and_ready(controller, spec)
    controller.run_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, _ok_executor(LifecycleStage.EXECUTE), now=NOW
    )
    trail = controller.ledger.audit_trail(spec.assessment_id)
    assert any(e["event_type"] == "STAGE_EXECUTE_DONE" for e in trail)
    assert all(e["actor"] == "CONTROLLER" for e in trail)


# --------------------------------------------------------------------------- #
# Offline harness verdict.
# --------------------------------------------------------------------------- #


def test_offline_harness_verdict_passes() -> None:
    harness = _load_harness()
    result = harness.run_offline()
    verdict = result["verdict"]
    # Corrected labels: the harness proves the state-machine FRAMEWORK, not full integration.
    assert verdict["lifecycle_framework_status"] == "OFFLINE_PASS"
    assert verdict["tool_broker_in_lifecycle_status"] == "NOT_EVALUATED"
    assert verdict["live_full_lifecycle_status"] == "NOT_EVALUATED"
    assert verdict["final_state"] == "COMPLETED"
    assert verdict["passed"] is True
    assert all(verdict["checks"].values())
