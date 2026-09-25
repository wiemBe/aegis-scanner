"""Focused Phase 2.7 crash-window / external-effect idempotency tests.

These prove the corrected claim that atomic usage-with-DONE persistence alone does NOT prevent
duplicate *external* execution across a crash. The lifecycle now persists a stable stage-attempt
record + idempotency key BEFORE dispatch and defines resume behaviour at every crash window:

    crash before dispatch (PREPARED)                    -> safe re-attempt, no authorization needed
    crash after dispatch, before response (DISPATCHED)  -> OUTCOME UNKNOWN, never auto-reissued
    crash after response, before stage DONE (COMPLETED) -> replay locally, NO re-dispatch
    resume on a DONE stage / completed key              -> idempotent, no re-exec, no re-charge

They also cover broker reconciliation (dedup where available), the fail-closed requirement that an
UNKNOWN effect stays UNKNOWN where reconciliation is unavailable, and that a new attempt after an
UNKNOWN effect needs an explicit controller decision (+ operator authorization for a paid call).
Fully offline: no provider, no socket, no Docker.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis.multi_agent.lifecycle import (
    UNKNOWN,
    AssessmentLifecycleController,
    AssessmentSpec,
    AttemptStatus,
    ExternalStageAttempt,
    LifecycleBudgetError,
    LifecycleLedger,
    LifecycleReissueNotAuthorized,
    LifecycleStage,
    LifecycleUnreconciledEffect,
    StageContext,
    StageOutcome,
    StageStatus,
    StageUsageDelta,
    evidence_digest,
)

RUN_EPOCH = 5
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
KEY = "exec-idem-key-0001"


class SimulatedCrash(RuntimeError):
    """Stand-in for the process dying inside the external dispatch window."""


def _spec() -> AssessmentSpec:
    return AssessmentSpec(
        assessment_id="asmt-" + "a" * 16,
        campaign_id="phase-2.7-crash",
        target_ref="range-ops",
        scenario_id="ops-detection-control-bypass-v1",
        run_epoch=RUN_EPOCH,
        required_stages=(
            LifecycleStage.AUTHORIZE,
            LifecycleStage.PREPARE,
            LifecycleStage.EXECUTE,
        ),
        cumulative_provider_calls=20,
        cumulative_tokens=100_000,
        per_stage_provider_calls=10,
        per_stage_tokens=50_000,
        authorization_reference="authz-crash-001",
        lease_ref="lease-crash-001",
        lease_expires_at=NOW + timedelta(hours=1),
        activation_required_capabilities=(),
    )


def _ready_controller(tmp_path: Path) -> tuple[AssessmentLifecycleController, AssessmentSpec]:
    ledger = LifecycleLedger(str(tmp_path / "lifecycle.db"))
    ledger.initialize()
    controller = AssessmentLifecycleController(ledger)
    spec = _spec()
    controller.create_assessment(spec)
    controller.authorize(
        spec.assessment_id, authorization_reference=spec.authorization_reference, now=NOW
    )
    controller.mark_ready(spec.assessment_id, activated_capabilities=(), now=NOW)
    return controller, spec


class Dispatcher:
    """A counting external dispatcher that can be told to crash inside the dispatch window."""

    def __init__(self, *, crash: bool = False, usage: StageUsageDelta | None = None) -> None:
        self.calls = 0
        self.keys: list[str] = []
        self.crash = crash
        self.usage = usage or StageUsageDelta(provider_calls=1, tokens=1000, tool_executions=1)

    def __call__(self, context: StageContext, idempotency_key: str) -> StageOutcome:
        self.calls += 1
        self.keys.append(idempotency_key)
        if self.crash:
            raise SimulatedCrash("process died after dispatch, before response persist")
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest({"stage": context.stage.value, "key": idempotency_key}),
            side_effect_token=f"effect-{idempotency_key}",
            usage=self.usage,
            detail="external effect executed",
        )


def _fresh_controller(controller: AssessmentLifecycleController) -> AssessmentLifecycleController:
    """A brand-new controller on the SAME ledger DB — models a process restart / resume."""

    return AssessmentLifecycleController(LifecycleLedger(controller.ledger.database_path))


# --------------------------------------------------------------------------- #
# Happy path + resume on a completed key.
# --------------------------------------------------------------------------- #


def test_external_stage_runs_once_and_is_idempotent_on_resume(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    dispatcher = Dispatcher()
    record = controller.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, dispatcher, idempotency_key=KEY, now=NOW
    )
    assert record.status is StageStatus.DONE
    assert dispatcher.calls == 1

    # Resume with a completed idempotency key: no second execution, no second charge.
    resumed = _fresh_controller(controller)
    again = resumed.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, dispatcher, idempotency_key=KEY, now=NOW
    )
    assert again.status is StageStatus.DONE
    assert dispatcher.calls == 1  # NOT re-dispatched


# --------------------------------------------------------------------------- #
# Crash before dispatch (PREPARED): safe re-attempt.
# --------------------------------------------------------------------------- #


def test_crash_before_dispatch_is_safe_to_reattempt(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    # A crash before dispatch leaves a PREPARED attempt and no external effect.
    controller.ledger.upsert_attempt(
        ExternalStageAttempt(
            assessment_id=spec.assessment_id,
            stage=LifecycleStage.EXECUTE,
            idempotency_key=KEY,
            attempt_no=1,
            status=AttemptStatus.PREPARED,
        )
    )
    resumed = _fresh_controller(controller)
    dispatcher = Dispatcher()
    record = resumed.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, dispatcher, idempotency_key=KEY, now=NOW
    )
    assert record.status is StageStatus.DONE
    assert dispatcher.calls == 1  # ran exactly once (the PREPARED attempt carried no effect)
    attempts = resumed.ledger.attempts_for(spec.assessment_id, LifecycleStage.EXECUTE)
    assert {a.status for a in attempts} == {AttemptStatus.SUPERSEDED, AttemptStatus.COMPLETED}


# --------------------------------------------------------------------------- #
# Crash after dispatch, before response persist (DISPATCHED): OUTCOME UNKNOWN, no auto-reissue.
# --------------------------------------------------------------------------- #


def test_crash_after_dispatch_leaves_unknown_and_is_not_auto_reissued(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    crashing = Dispatcher(crash=True)
    with pytest.raises(SimulatedCrash):
        controller.run_external_stage(
            spec.assessment_id, LifecycleStage.EXECUTE, crashing, idempotency_key=KEY, now=NOW
        )
    # The attempt is DISPATCHED (UNKNOWN); the stage never reached DONE; no usage committed.
    attempts = controller.ledger.attempts_for(spec.assessment_id, LifecycleStage.EXECUTE)
    assert len(attempts) == 1
    assert attempts[0].status is AttemptStatus.DISPATCHED
    assert attempts[0].outcome_unknown() is True
    stage = controller.ledger.get_stage(spec.assessment_id, LifecycleStage.EXECUTE)
    assert stage is not None and stage.status is not StageStatus.DONE

    # Resume must NOT silently replay the external effect.
    resumed = _fresh_controller(controller)
    replay = Dispatcher()
    with pytest.raises(LifecycleUnreconciledEffect):
        resumed.run_external_stage(
            spec.assessment_id, LifecycleStage.EXECUTE, replay, idempotency_key=KEY, now=NOW
        )
    assert replay.calls == 0  # silent provider/tool replay prevented


def test_unknown_effect_new_attempt_requires_explicit_and_operator_authorization(
    tmp_path: Path,
) -> None:
    controller, spec = _ready_controller(tmp_path)
    with pytest.raises(SimulatedCrash):
        controller.run_external_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            Dispatcher(crash=True),
            idempotency_key=KEY,
            now=NOW,
            paid=True,
        )
    resumed = _fresh_controller(controller)
    replay = Dispatcher()

    # Explicit controller decision given, but a PAID call still needs operator authorization.
    with pytest.raises(LifecycleReissueNotAuthorized):
        resumed.run_external_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            replay,
            idempotency_key=KEY,
            now=NOW,
            paid=True,
            new_attempt_authorization="controller-decision-77",
        )
    assert replay.calls == 0

    # With both authorizations, a NEW attempt runs; the UNKNOWN attempt is SUPERSEDED (never
    # recovered), so cumulative usage stays incomplete / UNKNOWN.
    record = resumed.run_external_stage(
        spec.assessment_id,
        LifecycleStage.EXECUTE,
        replay,
        idempotency_key=KEY,
        now=NOW,
        paid=True,
        new_attempt_authorization="controller-decision-77",
        operator_authorization="operator-auth-88",
    )
    assert record.status is StageStatus.DONE
    assert replay.calls == 1
    assert resumed.has_unreconciled_effect(spec.assessment_id) is True
    verdict = resumed.finalize(spec.assessment_id)
    assert verdict.usage_complete is False
    assert verdict.cumulative_provider_calls == UNKNOWN


# --------------------------------------------------------------------------- #
# Crash after response persist, before completion (COMPLETED attempt, no DONE): replay local.
# --------------------------------------------------------------------------- #


def test_crash_after_response_persist_replays_without_redispatch(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    usage = StageUsageDelta(provider_calls=2, tokens=3000, tool_executions=1)
    # A crash after the response was persisted (COMPLETED attempt) but before the DONE stage record.
    controller.ledger.upsert_attempt(
        ExternalStageAttempt(
            assessment_id=spec.assessment_id,
            stage=LifecycleStage.EXECUTE,
            idempotency_key=KEY,
            attempt_no=1,
            status=AttemptStatus.COMPLETED,
            dispatched=True,
            response_persisted=True,
            produced_epoch=RUN_EPOCH,
            evidence_sha256=evidence_digest({"already": "ran"}),
            side_effect_token="effect-once",  # noqa: S106 (opaque token, not a secret)
            usage=usage,
            detail="external effect executed",
        )
    )

    resumed = _fresh_controller(controller)
    must_not_run = Dispatcher()
    record = resumed.run_external_stage(
        spec.assessment_id, LifecycleStage.EXECUTE, must_not_run, idempotency_key=KEY, now=NOW
    )
    assert record.status is StageStatus.DONE
    assert must_not_run.calls == 0  # NO re-dispatch: the response was replayed from the ledger
    assert record.usage.provider_calls == 2
    assert record.side_effect_token == "effect-once"  # noqa: S105 (opaque token)


# --------------------------------------------------------------------------- #
# Broker reconciliation: dedup where available; stays UNKNOWN where it is not.
# --------------------------------------------------------------------------- #


def test_reconcilable_broker_adopts_prior_result_without_redispatch(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    with pytest.raises(SimulatedCrash):
        controller.run_external_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            Dispatcher(crash=True),
            idempotency_key=KEY,
            now=NOW,
            reconcilable=True,
        )
    resumed = _fresh_controller(controller)
    replay = Dispatcher()

    def reconcile(key: str) -> StageOutcome:
        # The broker confirms the idempotency key already completed and returns the real result.
        return StageOutcome(
            ok=True,
            produced_epoch=RUN_EPOCH,
            evidence_sha256=evidence_digest({"reconciled": key}),
            side_effect_token=f"broker-{key}",
            usage=StageUsageDelta(provider_calls=1, tokens=900, tool_executions=1),
            detail="reconciled",
        )

    record = resumed.run_external_stage(
        spec.assessment_id,
        LifecycleStage.EXECUTE,
        replay,
        idempotency_key=KEY,
        now=NOW,
        reconcilable=True,
        reconcile=reconcile,
    )
    assert record.status is StageStatus.DONE
    assert replay.calls == 0  # deduplicated at the broker: no second execution
    assert resumed.has_unreconciled_effect(spec.assessment_id) is False


def test_reconciler_that_cannot_confirm_keeps_effect_unknown(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)
    with pytest.raises(SimulatedCrash):
        controller.run_external_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            Dispatcher(crash=True),
            idempotency_key=KEY,
            now=NOW,
            reconcilable=True,
        )
    resumed = _fresh_controller(controller)
    replay = Dispatcher()
    with pytest.raises(LifecycleUnreconciledEffect):
        resumed.run_external_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            replay,
            idempotency_key=KEY,
            now=NOW,
            reconcilable=True,
            reconcile=lambda _key: None,  # broker cannot tell whether it ran
        )
    assert replay.calls == 0


# --------------------------------------------------------------------------- #
# Usage never zero-defaulted: an UNKNOWN-usage completion fails closed.
# --------------------------------------------------------------------------- #


def test_unknown_usage_completion_fails_closed(tmp_path: Path) -> None:
    controller, spec = _ready_controller(tmp_path)

    def unmeasured(context: StageContext, key: str) -> StageOutcome:
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest({"k": key}),
            usage=StageUsageDelta(provider_calls=UNKNOWN, tokens=UNKNOWN, tool_executions=UNKNOWN),
            detail="usage unmeasured",
        )

    with pytest.raises(LifecycleBudgetError):
        controller.run_external_stage(
            spec.assessment_id, LifecycleStage.EXECUTE, unmeasured, idempotency_key=KEY, now=NOW
        )
