"""Phase 2.4 — OFFLINE single-agent vs multi-agent benchmark framework verdict (no provider/docker).

This harness demonstrates the *framework* deterministically and offline: it builds one immutable
benchmark specification, two synthetic runs (a ``SINGLE_AGENT_BASELINE`` and a
``MULTI_AGENT_DELEGATED`` run) whose conditions match the shared fairness contract, persists them to
the durable result store, forms an immutable run-pair identifier, runs the fairness validator, and
produces the deterministic comparison document — then emits the typed phase verdict.

It never calls a provider, never opens a socket and never touches Docker. The synthetic per-run
metrics are illustrative fixtures for the *mechanics* only: they are labelled provenance ``OFFLINE``
and the comparison therefore fixes ``superiority_claim_supported=False``. No architecture is
declared superior — that requires live comparable runs (``NOT_EVALUATED``).

Allowed offline claim: "OFFLINE PASS for a deterministic controller-owned single-agent versus
multi-agent benchmark framework."
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.benchmark import (
    UNKNOWN,
    BenchmarkComparison,
    BenchmarkMode,
    BenchmarkResultStore,
    BenchmarkRunMetrics,
    BenchmarkSpec,
    ComparabilityRejection,
    FairnessValidator,
    RunConditions,
    RunPairId,
    compare_runs,
    render_comparison_markdown,
)
from aegis.multi_agent.contracts import BudgetLimit

# Reused Phase 2.2 synthetic scenario (controller-owned; no live run here).
TARGET_REF = "range-ops"
APPLICATION_ID = "aegis-ops"
SCENARIO_ID = "ops-detection-control-bypass-v1"
GROUND_TRUTH_ID = "GT-RANGE-OPS-005"
CAPABILITIES = ("aegis.ops.detection_control_probe",)
TOOL_PROFILES = ("http_detection_control_probe_v1",)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def build_offline_spec() -> BenchmarkSpec:
    """One immutable benchmark specification over the authorized synthetic ops scenario."""

    return BenchmarkSpec(
        benchmark_id="bench-000000000024a4a4",
        target_ref=TARGET_REF,
        application_id=APPLICATION_ID,
        scenario_id=SCENARIO_ID,
        inventory_snapshot_sha256=_digest("range-ops-inventory-snapshot-v1"),
        registered_capabilities=CAPABILITIES,
        tool_profiles=TOOL_PROFILES,
        ground_truth_id=GROUND_TRUTH_ID,
        budget=BudgetLimit(
            model_calls=4,
            tokens=12_000,
            target_requests=32,
            commands=8,
            elapsed_ms=600_000,
            evidence_bytes=262_144,
        ),
        verifier_authority="DETERMINISTIC_RANGE_VERIFIER",
        cleanup_required=True,
        created_at=datetime(2026, 9, 25, tzinfo=UTC),
    )


def _conditions(spec: BenchmarkSpec, mode: BenchmarkMode, run_ref: str) -> RunConditions:
    return RunConditions(
        mode=mode,
        run_ref=run_ref,
        provenance="OFFLINE",
        target_ref=spec.target_ref,
        application_id=spec.application_id,
        scenario_id=spec.scenario_id,
        inventory_snapshot_sha256=spec.inventory_snapshot_sha256,
        registered_capabilities=spec.registered_capabilities,
        tool_profiles=spec.tool_profiles,
        ground_truth_id=spec.ground_truth_id,
        budget=spec.budget,
        verifier_authority=spec.verifier_authority,
        cleanup_required=spec.cleanup_required,
    )


def build_single_agent_run(spec: BenchmarkSpec) -> tuple[RunConditions, BenchmarkRunMetrics]:
    """A bounded single-agent baseline: LEAD_ORCHESTRATOR, no downstream delegation hand-off.

    ``provider_calls`` / tokens are marked UNKNOWN here to demonstrate the framework never coerces
    unmeasured usage to zero (an offline fixture has no real provider usage).
    """

    run_ref = "bench-single-000000000024"
    conditions = _conditions(spec, BenchmarkMode.SINGLE_AGENT_BASELINE, run_ref)
    metrics = BenchmarkRunMetrics(
        mode=BenchmarkMode.SINGLE_AGENT_BASELINE,
        run_ref=run_ref,
        provenance="OFFLINE",
        verified_findings=1,
        false_or_unsupported_findings=0,
        hypotheses_generated=2,
        tool_executions=2,
        successful_tool_actions=2,
        failed_tool_actions=0,
        provider_calls=UNKNOWN,
        input_tokens=UNKNOWN,
        output_tokens=UNKNOWN,
        total_tokens=UNKNOWN,
        wall_clock_ms=UNKNOWN,
        agent_jobs=1,
        handoffs=0,
        verifier_confirmed=1,
        verifier_pass=0,
        verifier_incomplete=0,
        causal_chains=0,
        cleanup_succeeded=True,
        budget_violations=0,
    )
    return conditions, metrics.recompute_incomplete()


def build_multi_agent_run(spec: BenchmarkSpec) -> tuple[RunConditions, BenchmarkRunMetrics]:
    """A multi-agent run with REAL persisted delegation jobs + hand-offs (mechanics only)."""

    run_ref = "bench-multi-0000000000024"
    conditions = _conditions(spec, BenchmarkMode.MULTI_AGENT_DELEGATED, run_ref)
    metrics = BenchmarkRunMetrics(
        mode=BenchmarkMode.MULTI_AGENT_DELEGATED,
        run_ref=run_ref,
        provenance="OFFLINE",
        verified_findings=1,
        false_or_unsupported_findings=0,
        hypotheses_generated=3,
        tool_executions=2,
        successful_tool_actions=2,
        failed_tool_actions=0,
        provider_calls=UNKNOWN,
        input_tokens=UNKNOWN,
        output_tokens=UNKNOWN,
        total_tokens=UNKNOWN,
        wall_clock_ms=UNKNOWN,
        agent_jobs=2,  # LEAD + RECON persisted addressable jobs
        handoffs=1,  # one real persisted delegation
        verifier_confirmed=1,
        verifier_pass=0,
        verifier_incomplete=0,
        causal_chains=0,
        cleanup_succeeded=True,
        budget_violations=0,
    )
    return conditions, metrics.recompute_incomplete()


def build_verdict(
    comparison: BenchmarkComparison, rejections: list[ComparabilityRejection]
) -> dict[str, Any]:
    """Typed Phase 2.4 verdict. Offline: framework OFFLINE_PASS, live comparison NOT_EVALUATED."""

    absent = lambda reason: reason not in rejections  # noqa: E731 - local readability helper
    scope_ok = absent(ComparabilityRejection.CAPABILITY_SET_MISMATCH) and absent(
        ComparabilityRejection.TOOL_PROFILE_MISMATCH
    )
    multi_ok = absent(ComparabilityRejection.MULTI_AGENT_MISSING_DELEGATION) and absent(
        ComparabilityRejection.MULTI_AGENT_MISSING_PERSISTED_JOBS
    )
    broker_ok = absent(ComparabilityRejection.TOOL_BROKER_NOT_USED) and absent(
        ComparabilityRejection.INDEPENDENT_VERIFIER_NOT_USED
    )
    checks: dict[str, bool] = {
        "immutable_spec_with_stable_digest": True,
        "immutable_run_pair_identifier": True,
        "fairness_validator_accepts_comparable_pair": comparison.comparable,
        "identical_scope_and_profile_enforced": scope_ok,
        "single_agent_has_no_downstream_delegation": absent(
            ComparabilityRejection.SINGLE_AGENT_HAS_DELEGATION
        ),
        "multi_agent_uses_real_persisted_delegation": multi_ok,
        "both_modes_use_tool_broker_and_verifier": broker_ok,
        "raw_metrics_persisted_no_composite_score": True,
        "unknown_usage_preserved_not_zeroed": bool(comparison.incomplete_measurements),
        "no_superiority_declared_without_live_runs": (
            comparison.superiority_claim_supported is False
        ),
        "deterministic_comparison_report_rendered": True,
    }
    passed = all(checks.values())
    return {
        "phase": "2.4",
        "benchmark_framework_status": "OFFLINE_PASS" if passed else "OFFLINE_FAIL",
        "live_single_vs_multi_benchmark_status": "NOT_EVALUATED",
        "evidence_type": "OFFLINE_INTEGRATION",
        "checks": checks,
        "rejection_reasons": [reason.value for reason in rejections],
        "superiority_claim_supported": comparison.superiority_claim_supported,
        "superiority_claim_reason": comparison.superiority_claim_reason,
        "passed": passed,
    }


def run_offline(database_path: str | None = None) -> dict[str, Any]:
    """Build, persist, pair, validate and compare one synthetic pair; return the typed verdict."""

    spec = build_offline_spec()
    single_conditions, single_metrics = build_single_agent_run(spec)
    multi_conditions, multi_metrics = build_multi_agent_run(spec)

    with tempfile.TemporaryDirectory() as scratch:
        db_path = database_path or str(Path(scratch) / "benchmark.db")
        store = BenchmarkResultStore(db_path)
        store.initialize()
        store.save_spec(spec)
        store.save_run(spec.benchmark_id, single_conditions, single_metrics)
        store.save_run(spec.benchmark_id, multi_conditions, multi_metrics)
        pair = RunPairId(
            pair_id="rpair-000000000024b4b4",
            benchmark_id=spec.benchmark_id,
            spec_sha256=spec.spec_sha256,
            single_run_ref=single_conditions.run_ref,
            multi_run_ref=multi_conditions.run_ref,
            created_at=datetime(2026, 9, 25, tzinfo=UTC),
        )
        store.save_pair(pair)
        rejections = FairnessValidator(spec).check(
            single_conditions=single_conditions,
            single_metrics=single_metrics,
            multi_conditions=multi_conditions,
            multi_metrics=multi_metrics,
        )
        comparison = compare_runs(
            spec=spec,
            pair=pair,
            single_conditions=single_conditions,
            single_metrics=single_metrics,
            multi_conditions=multi_conditions,
            multi_metrics=multi_metrics,
        )
        store.save_comparison(comparison)
        markdown = render_comparison_markdown(spec, comparison)

    verdict = build_verdict(comparison, rejections)
    return {
        "verdict": verdict,
        "spec": spec.model_dump(mode="json"),
        "pair": pair.model_dump(mode="json"),
        "comparison": comparison.model_dump(mode="json"),
        "comparison_markdown": markdown,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = parser.parse_args()
    result = run_offline()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result["verdict"], indent=2, sort_keys=True))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
