"""Offline targeted tests for the Phase 2.4 single-agent vs multi-agent benchmark framework.

No live provider and no Docker. These cover the *new* surface 2.4 adds: the immutable benchmark
spec + stable digest, the immutable run-pair identifier, the fairness validator and every typed
comparability rejection reason (identical scope/profile enforcement, unequal-budget rejection,
different inventory/ground-truth rejection, single-vs-multi mode integrity — a role label is not
execution), UNKNOWN usage never coerced to zero, partial runs, verifier-disagreement rejection,
cleanup-requirement mismatch, the deterministic comparison (no composite winner; no superiority
without live comparable runs), the durable result store, and the offline harness verdict. Offline
tests are NOT live acceptance.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.multi_agent.benchmark import (
    UNKNOWN,
    BenchmarkError,
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


def _load_harness() -> Any:
    path = Path(__file__).resolve().parent.parent / "scripts" / "phase_2_4_benchmark.py"
    spec = importlib.util.spec_from_file_location("phase_2_4_benchmark", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Fixtures.
# --------------------------------------------------------------------------- #

_INV = "a" * 64


def _budget(model_calls: int = 4, tokens: int = 12_000) -> BudgetLimit:
    return BudgetLimit(
        model_calls=model_calls,
        tokens=tokens,
        target_requests=32,
        commands=8,
        elapsed_ms=600_000,
        evidence_bytes=262_144,
    )


def _spec(**overrides: Any) -> BenchmarkSpec:
    base: dict[str, Any] = {
        "benchmark_id": "bench-00000000000000aa",
        "target_ref": "range-ops",
        "application_id": "aegis-ops",
        "scenario_id": "ops-detection-control-bypass-v1",
        "inventory_snapshot_sha256": _INV,
        "registered_capabilities": ("aegis.ops.detection_control_probe",),
        "tool_profiles": ("http_detection_control_probe_v1",),
        "ground_truth_id": "GT-RANGE-OPS-005",
        "budget": _budget(),
        "created_at": datetime(2026, 9, 25, tzinfo=UTC),
    }
    base.update(overrides)
    return BenchmarkSpec(**base)


def _conditions(spec: BenchmarkSpec, mode: BenchmarkMode, run_ref: str, **o: Any) -> RunConditions:
    base: dict[str, Any] = {
        "mode": mode,
        "run_ref": run_ref,
        "provenance": "OFFLINE",
        "target_ref": spec.target_ref,
        "application_id": spec.application_id,
        "scenario_id": spec.scenario_id,
        "inventory_snapshot_sha256": spec.inventory_snapshot_sha256,
        "registered_capabilities": spec.registered_capabilities,
        "tool_profiles": spec.tool_profiles,
        "ground_truth_id": spec.ground_truth_id,
        "budget": spec.budget,
        "cleanup_required": spec.cleanup_required,
    }
    base.update(o)
    return RunConditions(**base)


def _metrics(mode: BenchmarkMode, run_ref: str, **o: Any) -> BenchmarkRunMetrics:
    is_multi = mode is BenchmarkMode.MULTI_AGENT_DELEGATED
    base: dict[str, Any] = {
        "mode": mode,
        "run_ref": run_ref,
        "provenance": "OFFLINE",
        "verified_findings": 1,
        "false_or_unsupported_findings": 0,
        "hypotheses_generated": 2,
        "tool_executions": 2,
        "successful_tool_actions": 2,
        "failed_tool_actions": 0,
        "provider_calls": UNKNOWN,
        "input_tokens": UNKNOWN,
        "output_tokens": UNKNOWN,
        "total_tokens": UNKNOWN,
        "wall_clock_ms": UNKNOWN,
        "agent_jobs": 2 if is_multi else 1,
        "handoffs": 1 if is_multi else 0,
        "verifier_confirmed": 1,
        "verifier_pass": 0,
        "verifier_incomplete": 0,
        "causal_chains": 0,
        "cleanup_succeeded": True,
        "budget_violations": 0,
    }
    base.update(o)
    return BenchmarkRunMetrics(**base).recompute_incomplete()


def _pair(spec: BenchmarkSpec, single_ref: str, multi_ref: str) -> RunPairId:
    return RunPairId(
        pair_id="rpair-00000000000000bb",
        benchmark_id=spec.benchmark_id,
        spec_sha256=spec.spec_sha256,
        single_run_ref=single_ref,
        multi_run_ref=multi_ref,
        created_at=datetime(2026, 9, 25, tzinfo=UTC),
    )


def _comparable_pair() -> tuple[
    BenchmarkSpec, RunConditions, BenchmarkRunMetrics, RunConditions, BenchmarkRunMetrics
]:
    spec = _spec()
    sc = _conditions(spec, BenchmarkMode.SINGLE_AGENT_BASELINE, "run-single")
    sm = _metrics(BenchmarkMode.SINGLE_AGENT_BASELINE, "run-single")
    mc = _conditions(spec, BenchmarkMode.MULTI_AGENT_DELEGATED, "run-multi")
    mm = _metrics(BenchmarkMode.MULTI_AGENT_DELEGATED, "run-multi")
    return spec, sc, sm, mc, mm


# --------------------------------------------------------------------------- #
# Spec + digest + pair immutability.
# --------------------------------------------------------------------------- #


def test_spec_digest_is_stable_and_order_independent() -> None:
    a = _spec(registered_capabilities=("cap.b", "cap.a"))
    b = _spec(registered_capabilities=("cap.a", "cap.b"))
    assert a.registered_capabilities == ("cap.a", "cap.b")  # sorted canonical
    assert a.spec_sha256 == b.spec_sha256


def test_spec_rejects_duplicate_capability() -> None:
    with pytest.raises(ValidationError):
        _spec(registered_capabilities=("cap.a", "cap.a"))


def test_spec_and_pair_are_frozen() -> None:
    spec = _spec()
    with pytest.raises(ValidationError):
        spec.scenario_id = "other"  # type: ignore[misc]
    pair = _pair(spec, "run-single", "run-multi")
    with pytest.raises(ValidationError):
        pair.single_run_ref = "x"  # type: ignore[misc]
    assert pair.pair_address == f"benchmarkpair://{spec.benchmark_id}/{pair.pair_id}"


# --------------------------------------------------------------------------- #
# Fairness: the happy path is comparable.
# --------------------------------------------------------------------------- #


def test_comparable_pair_has_no_rejections() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert rejections == []


# --------------------------------------------------------------------------- #
# Fairness: identical scope / profile enforcement.
# --------------------------------------------------------------------------- #


def test_capability_set_mismatch_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mc = mc.model_copy(update={"registered_capabilities": ("aegis.ops.other_probe",)})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.CAPABILITY_SET_MISMATCH in rejections
    assert ComparabilityRejection.SPEC_MISMATCH in rejections


def test_tool_profile_mismatch_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    sc = sc.model_copy(update={"tool_profiles": ("other_profile_v1",)})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.TOOL_PROFILE_MISMATCH in rejections


# --------------------------------------------------------------------------- #
# Fairness: unequal-budget rejection.
# --------------------------------------------------------------------------- #


def test_unequal_budget_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mc = mc.model_copy(update={"budget": _budget(model_calls=8)})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.BUDGET_NOT_EQUIVALENT in rejections


# --------------------------------------------------------------------------- #
# Fairness: different inventory / ground-truth rejection.
# --------------------------------------------------------------------------- #


def test_different_inventory_snapshot_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mc = mc.model_copy(update={"inventory_snapshot_sha256": "b" * 64})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.INVENTORY_SNAPSHOT_MISMATCH in rejections


def test_different_ground_truth_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    sc = sc.model_copy(update={"ground_truth_id": "GT-RANGE-OPS-999"})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.GROUND_TRUTH_MISMATCH in rejections


# --------------------------------------------------------------------------- #
# Fairness: cleanup-requirement mismatch.
# --------------------------------------------------------------------------- #


def test_cleanup_requirement_mismatch_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mc = mc.model_copy(update={"cleanup_required": False})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.CLEANUP_REQUIREMENT_MISMATCH in rejections


# --------------------------------------------------------------------------- #
# Mode integrity: a role label is not agent execution.
# --------------------------------------------------------------------------- #


def test_single_agent_with_delegation_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    sm = sm.model_copy(update={"handoffs": 1})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.SINGLE_AGENT_HAS_DELEGATION in rejections


def test_multi_agent_without_persisted_jobs_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mm = mm.model_copy(update={"agent_jobs": 1, "handoffs": 0})
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.MULTI_AGENT_MISSING_DELEGATION in rejections
    assert ComparabilityRejection.MULTI_AGENT_MISSING_PERSISTED_JOBS in rejections


def test_wrong_mode_in_slot_rejected() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    # Put a multi-agent run in the single slot.
    sc2 = _conditions(spec, BenchmarkMode.MULTI_AGENT_DELEGATED, "run-single")
    sm2 = _metrics(BenchmarkMode.MULTI_AGENT_DELEGATED, "run-single")
    rejections = FairnessValidator(spec).check(
        single_conditions=sc2, single_metrics=sm2, multi_conditions=mc, multi_metrics=mm
    )
    assert ComparabilityRejection.WRONG_MODE_FOR_SLOT in rejections
    assert ComparabilityRejection.MODE_COLLISION in rejections


# --------------------------------------------------------------------------- #
# Partial runs (missing usage / missing run).
# --------------------------------------------------------------------------- #


def test_missing_run_rejected() -> None:
    spec, sc, sm, _mc, _mm = _comparable_pair()
    rejections = FairnessValidator(spec).check(
        single_conditions=sc, single_metrics=sm, multi_conditions=None, multi_metrics=None
    )
    assert rejections == [ComparabilityRejection.MISSING_RUN]


def test_unknown_usage_not_zeroed() -> None:
    metrics = _metrics(BenchmarkMode.SINGLE_AGENT_BASELINE, "run-single")
    assert metrics.provider_calls == UNKNOWN
    assert "provider_calls" in metrics.incomplete_measurements
    assert "total_tokens" in metrics.incomplete_measurements
    # A measured value is NOT reported as incomplete.
    assert "verified_findings" not in metrics.incomplete_measurements


# --------------------------------------------------------------------------- #
# Verifier disagreement (single confirms, multi incomplete) — still comparable, direction shown.
# --------------------------------------------------------------------------- #


def test_verifier_disagreement_is_comparable_and_shows_direction() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    # Multi run's verifier returned INCOMPLETE (no confirmation) and found nothing verified.
    mm = mm.model_copy(
        update={"verified_findings": 0, "verifier_confirmed": 0, "verifier_incomplete": 1}
    )
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm,
        multi_conditions=mc,
        multi_metrics=mm,
    )
    assert comparison.comparable is True
    verified = next(row for row in comparison.metrics if row.metric == "verified_findings")
    assert verified.single_value == 1
    assert verified.multi_value == 0
    # Fewer verified findings on the multi side: "multi is lower" — but no winner is declared.
    assert verified.direction == "MULTI_LOWER"


# --------------------------------------------------------------------------- #
# Cleanup failure surfaced as a raw metric (not hidden).
# --------------------------------------------------------------------------- #


def test_cleanup_failure_surfaced_in_metrics() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mm = mm.model_copy(update={"cleanup_succeeded": False})
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm,
        multi_conditions=mc,
        multi_metrics=mm,
    )
    assert comparison.comparable is True
    stored = mm.model_dump()
    assert stored["cleanup_succeeded"] is False


# --------------------------------------------------------------------------- #
# No superiority without live comparable evidence.
# --------------------------------------------------------------------------- #


def test_no_superiority_offline() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm,
        multi_conditions=mc,
        multi_metrics=mm,
    )
    assert comparison.superiority_claim_supported is False
    assert "live" in comparison.superiority_claim_reason.lower()


def test_no_superiority_even_for_live_pair_in_this_framework() -> None:
    # Even a live comparable pair does not auto-crown a winner here; the framework never sets True.
    spec, sc, sm, mc, mm = _comparable_pair()
    sc = sc.model_copy(update={"provenance": "LIVE_PROVIDER"})
    mc = mc.model_copy(update={"provenance": "LIVE_PROVIDER"})
    sm = sm.model_copy(
        update={"provider_calls": 2, "input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                "wall_clock_ms": 100}
    )
    mm = mm.model_copy(
        update={"provider_calls": 4, "input_tokens": 2, "output_tokens": 2, "total_tokens": 4,
                "wall_clock_ms": 200}
    )
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm.recompute_incomplete(),
        multi_conditions=mc,
        multi_metrics=mm.recompute_incomplete(),
    )
    assert comparison.comparable is True
    assert comparison.superiority_claim_supported is False


def test_non_comparable_produces_no_metric_rows() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    mc = mc.model_copy(update={"budget": _budget(tokens=99)})
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm,
        multi_conditions=mc,
        multi_metrics=mm,
    )
    assert comparison.comparable is False
    assert comparison.metrics == ()
    assert ComparabilityRejection.BUDGET_NOT_EQUIVALENT in comparison.rejection_reasons


# --------------------------------------------------------------------------- #
# UNKNOWN direction in the comparison.
# --------------------------------------------------------------------------- #


def test_unknown_measurement_direction_is_unknown() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec,
        pair=pair,
        single_conditions=sc,
        single_metrics=sm,
        multi_conditions=mc,
        multi_metrics=mm,
    )
    provider = next(row for row in comparison.metrics if row.metric == "provider_calls")
    assert provider.direction == "UNKNOWN"
    assert "provider_calls" in comparison.incomplete_measurements


# --------------------------------------------------------------------------- #
# Durable result store.
# --------------------------------------------------------------------------- #


def test_store_roundtrip_and_immutability(tmp_path: Path) -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    store = BenchmarkResultStore(str(tmp_path / "b.db"))
    store.initialize()
    store.save_spec(spec)
    store.save_run(spec.benchmark_id, sc, sm)
    store.save_run(spec.benchmark_id, mc, mm)
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    address = store.save_pair(pair)
    assert address == pair.pair_address

    got_spec = store.get_spec(spec.benchmark_id)
    assert got_spec is not None and got_spec.spec_sha256 == spec.spec_sha256
    got_run = store.get_run(sc.run_ref)
    assert got_run is not None and got_run[0].mode is BenchmarkMode.SINGLE_AGENT_BASELINE

    # A spec with the same id but a different digest is rejected (immutable).
    drifted = _spec(scenario_id="different-scenario-v2")
    drifted = drifted.model_copy(update={"benchmark_id": spec.benchmark_id})
    with pytest.raises(BenchmarkError):
        store.save_spec(drifted)

    # A duplicate run_ref is rejected.
    with pytest.raises(BenchmarkError):
        store.save_run(spec.benchmark_id, sc, sm)


def test_store_run_ref_and_mode_consistency(tmp_path: Path) -> None:
    spec, sc, sm, _mc, _mm = _comparable_pair()
    store = BenchmarkResultStore(str(tmp_path / "b.db"))
    store.initialize()
    mismatched = sm.model_copy(update={"run_ref": "other-ref"})
    with pytest.raises(BenchmarkError):
        store.save_run(spec.benchmark_id, sc, mismatched)


# --------------------------------------------------------------------------- #
# Deterministic report render.
# --------------------------------------------------------------------------- #


def test_render_markdown_comparable_and_non_comparable() -> None:
    spec, sc, sm, mc, mm = _comparable_pair()
    pair = _pair(spec, sc.run_ref, mc.run_ref)
    comparison = compare_runs(
        spec=spec, pair=pair, single_conditions=sc, single_metrics=sm,
        multi_conditions=mc, multi_metrics=mm,
    )
    text = render_comparison_markdown(spec, comparison)
    assert "Raw metric comparison" in text
    assert "no superiority is declared without live comparable runs" in text.lower()

    bad_mc = mc.model_copy(update={"budget": _budget(tokens=5)})
    bad = compare_runs(
        spec=spec, pair=pair, single_conditions=sc, single_metrics=sm,
        multi_conditions=bad_mc, multi_metrics=mm,
    )
    bad_text = render_comparison_markdown(spec, bad)
    assert "Not comparable" in bad_text
    assert "BUDGET_NOT_EQUIVALENT" in bad_text


# --------------------------------------------------------------------------- #
# Offline harness verdict.
# --------------------------------------------------------------------------- #


def test_offline_harness_verdict_passes() -> None:
    harness = _load_harness()
    result = harness.run_offline()
    verdict = result["verdict"]
    assert verdict["benchmark_framework_status"] == "OFFLINE_PASS"
    assert verdict["live_single_vs_multi_benchmark_status"] == "NOT_EVALUATED"
    assert verdict["evidence_type"] == "OFFLINE_INTEGRATION"
    assert verdict["passed"] is True
    assert verdict["superiority_claim_supported"] is False
    assert all(verdict["checks"].values())


def test_offline_harness_is_deterministic() -> None:
    harness = _load_harness()
    a = harness.run_offline()
    b = harness.run_offline()
    assert a["spec"]["benchmark_id"] == b["spec"]["benchmark_id"]
    assert a["comparison"] == b["comparison"]
