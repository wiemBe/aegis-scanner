"""Part A: machine-readable Contract V1 validation-failure matrix.

Read-only post-processing of the immutable Phase 0.3/0.4 acceptance evidence (qwen3:4b baseline and
foundation-sec:8b-q4 candidate). It reconstructs, per (trial, phase), the orchestrator state, the
decision types that WOULD have been legal in Contract V2 for that state, the fail-closed rejection
class, and whether the rejected decision would have been safe had it been structurally valid.

Honesty constraints (Part A item 3): this script reads and emits only structured, non-sensitive
fields already persisted by the fail-closed harness (event names, verifier statuses, retest status
codes, safe diagnostic codes). It never reads or writes model prose, hidden reasoning, credentials,
headers, cookies, raw target responses or secret values. The Contract V1 harness deliberately
persisted ONLY the safe diagnostic code for a rejected planner decision — never the raw model
output or the Pydantic ValidationError detail — so the exact returned decision type, the populated
mutually-exclusive fields, the missing required fields and the Pydantic error locations are NOT
derivable from evidence. Those cells are reported as `not_persisted_by_failclosed_contract` with an
analytic attribution to the known Contract V1 constraint classes, rather than reconstructed (which
would require persisting model prose).

    python scripts/build_failure_matrix.py \
        --inputs artifacts/local-llm-acceptance.json artifacts/foundation-sec-acceptance.json \
        --out artifacts/contract-v1-failure-matrix.json
"""

import argparse
import json
from typing import Any

# Reuse the exact rejection classifier used by the Phase 0.4 comparison so categories are identical.
from compare_local_models import _classify_planner_code, _classify_safety_reason

from aegis.contract import permitted_decision_types

# Analytic attribution for the classes the fail-closed contract does not persist in detail. These
# are the Contract V1 constraints the JSON Schema could NOT express, so constrained decoding
# produced schema-shaped but Pydantic-invalid decisions (see the Phase 0.4 rejection caveat).
_V1_STRUCTURAL_CONSTRAINTS = [
    "execute-XOR-hypothesis cross-field model_validator (AgentDecision.validate_action)",
    "PlannedRequest.path before-validator (authority/query/fragment/traversal rejection)",
    "strict typing / extra=forbid on the monolithic AgentDecision and nested models",
]
_NOT_PERSISTED = "not_persisted_by_failclosed_contract"


def _state_label(retest: bool, verification_status: str | None) -> str:
    if verification_status in {"CONFIRMED", "PASS"}:
        return "post_verification"
    return "retest_confirmatory" if retest else "discovery_generative"


def _rows_for_report(
    model: str, trial: int, phase: str, report: dict[str, Any]
) -> list[dict[str, Any]]:
    """One row per fail-closed rejection recorded in a discovery or retest report."""
    rows: list[dict[str, Any]] = []
    verification_status: str | None = None
    retest = phase == "retest"
    for event in report.get("audit", []):
        name, details = event.get("event"), event.get("details", {})
        # Track the deterministic verifier status the orchestrator held at each planner turn.
        if name == "VERIFIER_RESULT":
            verification_status = details.get("status")
        elif name == "PLANNER_REQUEST":
            verification_status = (details.get("context", {}).get("verification") or {}).get(
                "status", verification_status
            )
        elif name in {"PLANNER_REJECTED", "SAFETY_REJECTED", "BUDGET_EXHAUSTED"}:
            if name == "PLANNER_REJECTED":
                category, code = _classify_planner_code(str(details.get("reason", "")))
            elif name == "SAFETY_REJECTED":
                category, code = _classify_safety_reason(str(details.get("reason", "")))
            else:
                category, code = "budget_rejection", str(details.get("reason", ""))
            state = _state_label(retest, verification_status)
            structural = category == "pydantic_structural_failure"
            # A structural or evidence-reference rejection never reached the executor: no scope,
            # safety, budget or leakage rejection co-occurred in any observed trial, and only the
            # deterministic verifier can create a finding. So a structurally VALID decision at this
            # turn would have been re-checked by the same safety/scope/budget chain before any
            # request, i.e. it was safe to reject and would have been safe had it been valid.
            safe_if_valid = category not in {
                "scope_or_safety_rejection",
                "unsupported_action",
                "unknown_endpoint",
                "secret_leakage_blocked",
            }
            rows.append(
                {
                    "model": model,
                    "trial": trial,
                    "phase": phase,
                    "orchestrator_state": state,
                    "contract_v2_permitted_decision_types": list(
                        permitted_decision_types(
                            retest=retest, verification_status=verification_status
                        )
                    ),
                    "returned_decision_type": _NOT_PERSISTED,
                    "populated_mutually_exclusive_fields": _NOT_PERSISTED,
                    "missing_required_fields": _NOT_PERSISTED,
                    "pydantic_error_locations": _NOT_PERSISTED,
                    "analytic_attribution": (
                        _V1_STRUCTURAL_CONSTRAINTS if structural else []
                    ),
                    "rejection_event": name,
                    "rejection_category": category,
                    "rejection_code": code,
                    "invalid_evidence_reference": (
                        category == "evidence_reference_failure"
                    ),
                    "would_have_been_safe_if_structurally_valid": safe_if_valid,
                }
            )
    # A retest that ran but never reached scoped PASS with the required 200/200/403 direction is an
    # evidence-reference / directional shortfall of the loop, not a discrete reject event above.
    return rows


def build_matrix(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    model = evidence.get("summary", {}).get("expected_model")
    rows: list[dict[str, Any]] = []
    for trial in evidence.get("trials", []):
        idx = trial.get("trial")
        if trial.get("_initial"):
            rows.extend(_rows_for_report(model, idx, "discovery", trial["_initial"]))
        if trial.get("_retest"):
            rows.extend(_rows_for_report(model, idx, "retest", trial["_retest"]))
        # Directional coverage shortfall (retest ran, confirmed, but did not reach PASS).
        rs = trial.get("retest_status")
        if trial.get("confirmed") and rs is not None and rs != "PASS":
            rows.append(
                {
                    "model": model,
                    "trial": idx,
                    "phase": "retest",
                    "orchestrator_state": "retest_confirmatory",
                    "contract_v2_permitted_decision_types": list(
                        permitted_decision_types(retest=True, verification_status=None)
                    ),
                    "returned_decision_type": _NOT_PERSISTED,
                    "populated_mutually_exclusive_fields": _NOT_PERSISTED,
                    "missing_required_fields": _NOT_PERSISTED,
                    "pydantic_error_locations": _NOT_PERSISTED,
                    "analytic_attribution": [
                        "linked retest did not repeat the confirmed cross-owner access direction "
                        "with fresh 200/200/403 evidence (deterministic coverage shortfall)"
                    ],
                    "rejection_event": "RETEST_COVERAGE_SHORTFALL",
                    "rejection_category": "evidence_reference_failure",
                    "rejection_code": f"retest_status={rs}",
                    "invalid_evidence_reference": True,
                    "would_have_been_safe_if_structurally_valid": True,
                }
            )
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--inputs",
        nargs="+",
        default=[
            "artifacts/local-llm-acceptance.json",
            "artifacts/foundation-sec-acceptance.json",
        ],
    )
    ap.add_argument("--out", default="artifacts/contract-v1-failure-matrix.json")
    args = ap.parse_args()

    matrix: list[dict[str, Any]] = []
    per_model: dict[str, Any] = {}
    for path in args.inputs:
        with open(path, encoding="utf-8") as handle:
            evidence = json.load(handle)
        rows = build_matrix(evidence)
        matrix.extend(rows)
        model = evidence.get("summary", {}).get("expected_model")
        categories: dict[str, int] = {}
        for row in rows:
            categories[row["rejection_category"]] = categories.get(row["rejection_category"], 0) + 1
        per_model[str(model)] = {"rows": len(rows), "category_counts": categories}

    document = {
        "contract_version_analyzed": 1,
        "description": (
            "Contract V1 validation-failure matrix. Reconstructed read-only from immutable Phase "
            "0.3/0.4 acceptance evidence. Cells marked 'not_persisted_by_failclosed_contract' were "
            "never persisted by the fail-closed contract (only the safe diagnostic code was kept, "
            "never raw model output or ValidationError detail); reconstructing them would require "
            "persisting model prose and is therefore not done."
        ),
        "honesty": {
            "no_model_prose": True,
            "no_hidden_reasoning": True,
            "no_secrets_or_raw_responses": True,
            "source": "structured audit events, verifier statuses, safe diagnostic codes only",
        },
        "per_model": per_model,
        "rows": matrix,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    print(json.dumps({"out": args.out, "rows": len(matrix), "per_model": per_model}, indent=2))


if __name__ == "__main__":
    main()
