"""Phase 2.7 — OFFLINE bounded, resumable, controller-governed assessment lifecycle (no provider).

Composes the prior proven pieces into ONE deterministic synthetic lifecycle over the authorized
``range-ops`` detection-control scenario and emits the typed verdict:

    create -> authorize -> ready -> EXECUTE -> VERIFY -> REMEDIATE -> RETEST -> REPORT
      -> cleanup compensation -> finalize (COMPLETED)

Every stage is a deterministic executor the controller invokes under lease/budget/freshness/
cancellation guards; the model never advances the workflow state. No provider call, no socket, no
Docker. Allowed offline claim: "OFFLINE PASS for a bounded, resumable and controller-governed
synthetic assessment lifecycle."
"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aegis.multi_agent.lifecycle import (
    AssessmentLifecycleController,
    AssessmentSpec,
    AssessmentState,
    LifecycleLedger,
    LifecycleStage,
    StageContext,
    StageOutcome,
    StageUsageDelta,
    evidence_digest,
)

RUN_EPOCH = 7
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)
LEASE_EXPIRES = NOW + timedelta(minutes=30)


def build_spec() -> AssessmentSpec:
    return AssessmentSpec(
        assessment_id="asmt-000000000000a27a",
        campaign_id="phase-2.7-offline",
        target_ref="range-ops",
        scenario_id="ops-detection-control-bypass-v1",
        run_epoch=RUN_EPOCH,
        required_stages=(
            LifecycleStage.AUTHORIZE,
            LifecycleStage.PREPARE,
            LifecycleStage.EXECUTE,
            LifecycleStage.VERIFY,
            LifecycleStage.REPORT,
            LifecycleStage.CLEANUP,
        ),
        cumulative_provider_calls=8,
        cumulative_tokens=24_000,
        per_stage_provider_calls=4,
        per_stage_tokens=12_000,
        authorization_reference="authz-range-ops-001",
        lease_ref="lease-range-ops-001",
        lease_expires_at=LEASE_EXPIRES,
        activation_required_capabilities=("aegis.ops.detection_control_probe",),
    )


def _executor(stage: LifecycleStage, *, provider_calls: int, tokens: int, tools: int) -> Any:
    def run(context: StageContext) -> StageOutcome:
        return StageOutcome(
            ok=True,
            produced_epoch=context.run_epoch,
            evidence_sha256=evidence_digest({"stage": stage.value, "epoch": context.run_epoch}),
            side_effect_token=f"tok-{stage.value.lower()}",
            usage=StageUsageDelta(
                provider_calls=provider_calls, tokens=tokens, tool_executions=tools
            ),
            detail=f"{stage.value} executed deterministically",
        )

    return run


def run_offline() -> dict[str, Any]:
    spec = build_spec()
    with tempfile.TemporaryDirectory() as scratch:
        ledger = LifecycleLedger(str(Path(scratch) / "lifecycle.db"))
        ledger.initialize()
        controller = AssessmentLifecycleController(ledger)
        controller.create_assessment(spec)
        controller.authorize(
            spec.assessment_id, authorization_reference=spec.authorization_reference, now=NOW
        )
        controller.mark_ready(
            spec.assessment_id,
            activated_capabilities=("aegis.ops.detection_control_probe",),
            now=NOW,
        )
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.EXECUTE,
            _executor(LifecycleStage.EXECUTE, provider_calls=2, tokens=4000, tools=2),
            now=NOW,
        )
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.VERIFY,
            _executor(LifecycleStage.VERIFY, provider_calls=0, tokens=0, tools=0),
            now=NOW,
        )
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.REMEDIATE,
            _executor(LifecycleStage.REMEDIATE, provider_calls=1, tokens=2000, tools=1),
            now=NOW,
        )
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.RETEST,
            _executor(LifecycleStage.RETEST, provider_calls=1, tokens=2000, tools=1),
            now=NOW,
        )
        controller.run_stage(
            spec.assessment_id,
            LifecycleStage.REPORT,
            _executor(LifecycleStage.REPORT, provider_calls=1, tokens=3000, tools=0),
            now=NOW,
        )
        cleanup_ok = controller.run_cleanup(
            spec.assessment_id,
            ("RESET_SYNTHETIC_TARGET_TO_BASELINE", "ROTATE_SENTINEL", "REVOKE_REFERENCES"),
            lambda _obligation: True,
        )
        verdict_obj = controller.finalize(spec.assessment_id)
        audit = ledger.audit_trail(spec.assessment_id)

    checks: dict[str, bool] = {
        "lifecycle_completed": verdict_obj.final_state is AssessmentState.COMPLETED,
        "required_stages_complete": verdict_obj.required_stages_complete,
        "cleanup_succeeded": verdict_obj.cleanup_succeeded and cleanup_ok,
        "usage_complete_no_unknown": verdict_obj.usage_complete,
        "provider_usage_not_zero_defaulted": verdict_obj.cumulative_provider_calls == 5,
        "cumulative_tokens_aggregated": verdict_obj.cumulative_tokens == 11_000,
        "immutable_manifest_digest": bool(verdict_obj.manifest_sha256),
        "immutable_audit_trail": len(audit) >= 6,
    }
    passed = all(checks.values())
    verdict = {
        "phase": "2.7",
        "full_assessment_lifecycle_status": "OFFLINE_PASS" if passed else "OFFLINE_FAIL",
        "live_full_lifecycle_status": "NOT_EVALUATED",
        "evidence_type": "OFFLINE_INTEGRATION",
        "checks": checks,
        "final_state": verdict_obj.final_state.value,
        "assurance_summary": verdict_obj.assurance_summary,
        "passed": passed,
    }
    return {"verdict": verdict, "manifest_sha256": verdict_obj.manifest_sha256}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_offline()
    print(json.dumps(result if args.json else result["verdict"], indent=2, sort_keys=True))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
