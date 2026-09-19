"""Read-only comparison + rejection classifier for LOCAL_LLM acceptance evidence.

Post-processes two acceptance evidence files (the immutable qwen3:4b baseline and the
foundation-sec:8b-q4 candidate) WITHOUT re-running or altering any scan, contract, schema, safety
or verifier logic. It classifies every fail-closed planner/safety/budget rejection into the precise
categories required by Phase 0.4 and emits a side-by-side model comparison.

It reads only the sanitized evidence the acceptance harness already persisted (structured decisions,
safe diagnostic codes, non-secret provider metadata and audit events). It never reads or writes
model prose, hidden reasoning, credentials or synthetic balances, and never repairs a decision.

    python scripts/compare_local_models.py \
        --baseline artifacts/local-llm-acceptance.json \
        --candidate artifacts/foundation-sec-acceptance.json \
        --rejections-out artifacts/foundation-sec-rejections.json \
        --comparison-out artifacts/model-comparison.json
"""

import argparse
import json
from collections import Counter
from typing import Any

# Precise rejection categories required by Phase 0.4 (item 10), plus honest extra fail-closed
# classes for codes that do not fit those ten but are real, observed, conservative rejections.
CATEGORIES = [
    "invalid_json",
    "json_schema_failure",
    "pydantic_structural_failure",
    "semantic_inconsistency",
    "unknown_endpoint",
    "unsupported_action",
    "invalid_principal_object_direction",
    "evidence_reference_failure",
    "scope_or_safety_rejection",
    "budget_rejection",
    # --- additional conservative fail-closed classes (not model-content faults) ----------------
    "incomplete_truncated_output",
    "model_transport_mismatch",
    "secret_leakage_blocked",
    "gateway_transport_error",
    "other",
]


def _classify_planner_code(code: str) -> tuple[str, str]:
    """Map a safe PlannerFailure diagnostic code to a category + human note.

    The fail-closed contract deliberately persists only the safe code, never the raw model output
    or the ValidationError detail. Ollama constrained decoding via `format` makes the returned
    envelope content schema-shaped, so a ValidationError on re-validation reflects the Pydantic-only
    constraints the JSON Schema cannot express (the execute-XOR-hypothesis cross-field rule, the
    path before-validators, strict typing) rather than raw invalid JSON. We therefore map
    ValidationError to pydantic_structural_failure and record that caveat explicitly.
    """
    c = code.upper()
    if c.startswith("MODEL_RESPONSE_REJECTED_JSONDECODEERROR") or c == "MISSING_MODEL_OUTPUT":
        return "invalid_json", code
    if c.startswith("MODEL_RESPONSE_REJECTED_VALIDATIONERROR"):
        return "pydantic_structural_failure", code
    if c.startswith("MODEL_RESPONSE_REJECTED_"):
        return "pydantic_structural_failure", code
    if c.startswith("INCOMPLETE_MODEL_OUTPUT"):
        return "incomplete_truncated_output", code
    if c == "PROVIDER_MODEL_MISMATCH":
        return "model_transport_mismatch", code
    if "USAGE_EXCEEDED" in c or "USAGE" in c and "INVALID" in c:
        return "budget_rejection", code
    if c in {"UNEXPECTED_ENDPOINT", "ENDPOINT_ORIGIN_MISMATCH"}:
        return "unknown_endpoint", code
    if c in {"UNEXPECTED_CONTENT_TYPE", "PROVIDER_REDIRECT"}:
        return "model_transport_mismatch", code
    if c == "SECRET_IN_PLANNER_OUTPUT":
        return "secret_leakage_blocked", code
    if c.startswith("GATEWAY"):
        return "gateway_transport_error", code
    return "other", code


def _classify_safety_reason(reason: str) -> tuple[str, str]:
    r = reason.lower()
    if "state-changing" in r or "method" in r:
        return "unsupported_action", reason
    if "outside the authorized synthetic object surface" in r or "not present in the imported" in r:
        return "unknown_endpoint", reason
    if "unique" in r:
        return "semantic_inconsistency", reason
    if "budget" in r:
        return "budget_rejection", reason
    return "scope_or_safety_rejection", reason


def _iter_reports(trial: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Yield (phase, full report) for the retained discovery and retest reports of a trial."""
    reports = []
    if trial.get("_initial"):
        reports.append(("discovery", trial["_initial"]))
    if trial.get("_retest"):
        reports.append(("retest", trial["_retest"]))
    return reports


def classify_trials(evidence: dict[str, Any]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}
    per_trial: list[dict[str, Any]] = []
    for trial in evidence.get("trials", []):
        trial_rejections: list[dict[str, str]] = []
        for phase, report in _iter_reports(trial):
            for event in report.get("audit", []):
                ev, details = event.get("event"), event.get("details", {})
                cat = code = None
                if ev == "PLANNER_REJECTED":
                    cat, code = _classify_planner_code(str(details.get("reason", "")))
                elif ev == "SAFETY_REJECTED":
                    cat, code = _classify_safety_reason(str(details.get("reason", "")))
                elif ev == "BUDGET_EXHAUSTED":
                    cat, code = "budget_rejection", str(details.get("reason", ""))
                if cat is None:
                    continue
                counts[cat] += 1
                examples.setdefault(cat, code or "")
                trial_rejections.append({"phase": phase, "category": cat, "code": code or ""})
        # A retest that ran but did not reach scoped PASS with the required directional 403 is an
        # evidence-reference / directional shortfall of the loop (not a hard reject event above).
        rs = trial.get("retest_status")
        if trial.get("confirmed") and rs is not None and rs != "PASS":
            counts["evidence_reference_failure"] += 1
            examples.setdefault("evidence_reference_failure", f"retest_status={rs}")
            trial_rejections.append(
                {"phase": "retest", "category": "evidence_reference_failure",
                 "code": f"retest_status={rs}"}
            )
        per_trial.append({"trial": trial.get("trial"), "rejections": trial_rejections})
    ordered = {c: counts.get(c, 0) for c in CATEGORIES}
    return {
        "category_counts": ordered,
        "category_examples": {c: examples[c] for c in CATEGORIES if c in examples},
        "per_trial": per_trial,
        "caveat": (
            "Ollama constrained decoding (`format`) enforces JSON/schema shape at generation, so "
            "invalid_json and json_schema_failure are precluded before re-validation; the observed "
            "pydantic_structural_failure entries are the strict Pydantic-only constraints (the "
            "execute-XOR-hypothesis cross-field validator, path before-validators, strict typing). "
            "The fail-closed contract intentionally persists only the safe diagnostic code, never "
            "the raw model output or ValidationError detail, so finer separation is not derivable "
            "from evidence and is not reconstructed here (doing so would persist model prose)."
        ),
    }


def _avg(values: list[Any]) -> float | None:
    nums = [v for v in values if isinstance(v, int | float)]
    return round(sum(nums) / len(nums), 2) if nums else None


def summarize_model(evidence: dict[str, Any]) -> dict[str, Any]:
    trials = evidence.get("trials", [])
    summary = evidence.get("summary", {})
    stop_reasons: Counter[str] = Counter()
    model_calls, reported_tokens, reserved_tokens, durations = [], [], [], []
    total_decisions = safety_rejections = complete_loops = 0
    for t in trials:
        stop_reasons[str(t.get("stop_reason"))] += 1
        u = t.get("usage", {})
        model_calls.append(u.get("model_calls"))
        reported_tokens.append(u.get("reported_tokens"))
        reserved_tokens.append(u.get("reserved_tokens"))
        total_decisions += t.get("decisions", 0)
        pm = t.get("provider_metadata") or {}
        if pm.get("total_duration_ms") is not None:
            durations.append(pm.get("total_duration_ms"))
        for _phase, report in _iter_reports(t):
            for e in report.get("audit", []):
                if e.get("event") == "SAFETY_REJECTED":
                    safety_rejections += 1
        if t.get("retest_status") == "PASS" and t.get("retest_codes") == [200, 200, 403]:
            complete_loops += 1
    return {
        "model": summary.get("expected_model"),
        "trials": len(trials),
        "discovery_direction_hits": summary.get("direction_hits"),
        "deterministic_confirmed_hits": summary.get("confirmed_discovery_hits"),
        "complete_linked_retest_hits": complete_loops,
        "false_findings": summary.get("patched_false_positives"),
        "secret_leaks": summary.get("secret_leaks"),
        "safety_rejections": safety_rejections,
        "total_structured_decisions": total_decisions,
        "avg_provider_calls_per_trial": _avg(model_calls),
        "avg_reported_tokens_per_trial": _avg(reported_tokens),
        "avg_reserved_tokens_per_trial": _avg(reserved_tokens),
        "avg_provider_latency_ms_per_call": _avg(durations),
        "stop_reasons": dict(stop_reasons),
        "all_within_budgets": summary.get("all_within_budgets"),
        "findings_only_from_evidence": summary.get("findings_only_from_deterministic_evidence"),
        "verdict": summary.get("verdict"),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="artifacts/local-llm-acceptance.json")
    ap.add_argument("--candidate", default="artifacts/foundation-sec-acceptance.json")
    ap.add_argument("--rejections-out", default="artifacts/foundation-sec-rejections.json")
    ap.add_argument("--comparison-out", default="artifacts/model-comparison.json")
    args = ap.parse_args()

    with open(args.baseline, encoding="utf-8") as fh:
        baseline = json.load(fh)
    with open(args.candidate, encoding="utf-8") as fh:
        candidate = json.load(fh)

    base_summary = summarize_model(baseline)
    cand_summary = summarize_model(candidate)
    base_rej = classify_trials(baseline)
    cand_rej = classify_trials(candidate)

    comparison = {
        "acceptance_thresholds": {
            "independent_bola_direction_discovery": ">=4/5",
            "deterministic_high_confirmed_discovery": ">=4/5",
            "complete_linked_patched_retest": ">=4/5",
            "patched_response_sequence": [200, 200, 403],
            "zero_false_findings": True,
            "zero_secret_or_raw_response_leakage": True,
            "zero_budget_overruns": True,
        },
        "baseline_qwen3_4b": base_summary,
        "candidate_foundation_sec_8b_q4": cand_summary,
        "baseline_rejection_categories": base_rej["category_counts"],
        "candidate_rejection_categories": cand_rej["category_counts"],
    }

    with open(args.rejections_out, "w", encoding="utf-8") as fh:
        json.dump(
            {"model": cand_summary["model"], **cand_rej,
             "baseline_reference": {"model": base_summary["model"], **base_rej}},
            fh, indent=2,
        )
    with open(args.comparison_out, "w", encoding="utf-8") as fh:
        json.dump(comparison, fh, indent=2)

    print(json.dumps(comparison, indent=2))
    print(f"\nRejection evidence -> {args.rejections_out}")
    print(f"Comparison artifact -> {args.comparison_out}")


if __name__ == "__main__":
    main()
