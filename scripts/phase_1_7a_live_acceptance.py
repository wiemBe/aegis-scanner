"""Live DeepSeek Phase 1.7-A smoke: exactly four sequential Bank BOLA cases."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.contracts import AgentRunState, BudgetLimit
from aegis.multi_agent.model import GatewayAgentModel
from aegis.multi_agent.provider_binding import (
    PHASE_1_7A_CANONICAL_MODEL,
    ProviderBindingFailure,
    provider_binding_preflight,
)
from aegis.multi_agent.runtime import MultiAgentRuntime, console_projection
from aegis.multi_agent.store import MultiAgentStore
from aegis.settings import Settings
from aegis_range.controller import RangeController
from aegis_range.runtime import Mode

MATRIX = (
    ("single-agent-vulnerable", "single_agent", Mode.VULNERABLE, "CONFIRMED"),
    ("single-agent-patched", "single_agent", Mode.PATCHED, "PASS"),
    ("multi-agent-vulnerable", "multi_agent", Mode.VULNERABLE, "CONFIRMED"),
    ("multi-agent-patched", "multi_agent", Mode.PATCHED, "PASS"),
)
EXPECTED_CALLS = {"single_agent": 1, "multi_agent": 4}
TERMINAL_TASK_STATES = {"COMPLETED", "FAILED", "CANCELLED"}
# A leaked HTTP Authorization header would appear as a STRING value ('authorization": "<value>').
# The bounded contracts also define a legitimate structured field named `authorization`
# (SingleAgentOutput/AuthorizationAgentOutput), but it is always an OBJECT ('authorization": {),
# so the string-value form discriminates a real credential leak from the contract's own field
# without weakening detection: bearer credentials remain covered by the "bearer " marker below.
SECRET_MARKERS = (
    "range-user-alex",
    "range-user-blair",
    'authorization": "',
    "bearer ",
    "ai_auth_token",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rate(value: int, denominator: int, *, scale: int = 1) -> float | None:
    return round(value * scale / denominator, 8) if denominator else None


def _comparison(cases: list[dict[str, Any]]) -> dict[str, object]:
    rows: dict[str, object] = {}
    for architecture in ("single_agent", "multi_agent"):
        selected = [item for item in cases if item["execution_mode"] == architecture]
        calls = sum(int(item["model_usage"]["calls"]) for item in selected)
        tokens = sum(int(item["model_usage"]["total_tokens"]) for item in selected)
        requests = sum(int(item["target_requests"]) for item in selected)
        confirmed = sum(int(item["metrics"]["verifier_confirmed_findings"]) for item in selected)
        hypotheses = sum(int(item["hypotheses_produced"]) for item in selected)
        false_positives = sum(int(item["metrics"]["false_positives"]) for item in selected)
        rows[architecture] = {
            "architecture_native": {
                "cases": len(selected),
                "model_calls": calls,
                "tokens": tokens,
                "target_requests": requests,
                "confirmed_findings": confirmed,
                "valid_hypotheses": hypotheses,
                "false_positives": false_positives,
            },
            "cost_normalized": {
                "confirmed_findings_per_model_call": _rate(confirmed, calls),
                "valid_hypotheses_per_model_call": _rate(hypotheses, calls),
                "false_positives_per_model_call": _rate(false_positives, calls),
                "confirmed_findings_per_1000_tokens": _rate(confirmed, tokens, scale=1000),
                "valid_hypotheses_per_1000_tokens": _rate(hypotheses, tokens, scale=1000),
                "false_positives_per_1000_tokens": _rate(false_positives, tokens, scale=1000),
                "confirmed_findings_per_target_request": _rate(confirmed, requests),
                "valid_hypotheses_per_target_request": _rate(hypotheses, requests),
                "false_positives_per_target_request": _rate(false_positives, requests),
            },
        }
    return rows


async def main() -> int:
    started = time.monotonic()
    settings = Settings()
    if settings.ai_provider != "internal_openai_compatible":
        raise SystemExit("LIVE_PROVIDER_NOT_INTERNAL_OPENAI_COMPATIBLE")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence_dir = Path("artifacts") / f"phase-1.7a-live-{timestamp}"
    evidence_dir.mkdir(parents=True, exist_ok=False)
    try:
        binding = await provider_binding_preflight(settings, PHASE_1_7A_CANONICAL_MODEL)
    except ProviderBindingFailure as exc:
        failure = {
            "phase": "1.7-A",
            "scope": "live DeepSeek smoke for the initial aegis-bank BOLA slice only",
            "provider_binding_preflight": {
                **exc.projection,
                "status": "FAILED_CLOSED",
                "classification": exc.code,
            },
            "matrix_order": [item[0] for item in MATRIX],
            "cases": [],
            "global_usage": {
                "provider_call_attempts": 0,
                "provider_tokens": 0,
                "target_requests": 0,
                "agent_commands": 0,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            },
            "range_state": "NOT_TOUCHED_PREFLIGHT_FAILED",
            "failed_classification": exc.code,
            "preliminary_verdict": "NO-GO",
            "final_verdict": "PENDING_EXTERNAL_GATES",
            "claim_limit": "No Phase 1.7 completion or multi-agent superiority claim.",
        }
        _write(evidence_dir / "acceptance.json", failure)
        _write(evidence_dir / "gateway-request-projections.json", [])
        _write(evidence_dir / "console-projections.json", [])
        print(
            json.dumps(
                {
                    "artifact_dir": str(evidence_dir),
                    "preliminary_verdict": "NO-GO",
                    "failed_classification": exc.code,
                    "provider_call_attempts": 0,
                    "target_requests": 0,
                },
                sort_keys=True,
            )
        )
        print(f"ARTIFACT_DIR={evidence_dir}")
        return 1
    store = MultiAgentStore(str(evidence_dir / "agent-runs.db"))
    store.initialize()
    controller = RangeController()
    cases: list[dict[str, Any]] = []
    request_projections: list[dict[str, Any]] = []
    console_projections: list[dict[str, Any]] = []
    total_attempts = 0
    failed_classification: str | None = None
    limit = BudgetLimit(
        model_calls=6,
        tokens=60_000,
        target_requests=8,
        commands=0,
        elapsed_ms=600_000,
        evidence_bytes=524_288,
    )

    for case_name, execution_mode, mode, expected in MATRIX:
        if time.monotonic() - started >= 600:
            failed_classification = "GLOBAL_ELAPSED_TIME_BUDGET"
            break
        model = GatewayAgentModel(settings)
        runtime = MultiAgentRuntime(
            model,
            controller,
            store=store,
            global_limit=limit,
            per_agent_limit=limit,
        )
        case_started = time.monotonic()
        try:
            evaluation = await runtime.execute(mode=mode, execution_mode=execution_mode)
        except Exception as exc:
            total_attempts += model.call_attempts
            cleanup = await controller.reset_application("aegis-bank")
            health = await controller.health("aegis-bank")
            failed_classification = (
                model.failure_codes[-1] if model.failure_codes else type(exc).__name__
            )
            cases.append(
                {
                    "case": case_name,
                    "execution_mode": execution_mode,
                    "status": "FAILED_CLOSED",
                    "classification": failed_classification,
                    "model_call_attempts": model.call_attempts,
                    "provider_token_usage": "UNAVAILABLE_AFTER_GATEWAY_REJECTION"
                    if model.call_attempts
                    else "NO_PROVIDER_CALL",
                    "target_requests_before_failure": (
                        1 if execution_mode == "single_agent" and model.call_attempts else 0
                    ),
                    "retry_count": 0,
                    "provider_reported_models": model.provider_reported_models,
                    "gateway_request_proof": {
                        "captured_count": len(model.failed_request_projections),
                        "requests": [
                            item.model_dump(mode="json")
                            for item in model.failed_request_projections
                        ],
                    },
                    "cleanup": cleanup.model_dump(mode="json"),
                    "health": health.model_dump(mode="json"),
                }
            )
            request_projections.append(
                {
                    "case": case_name,
                    "requests": [
                        item.model_dump(mode="json") for item in model.failed_request_projections
                    ],
                    "status": "FAILED_CLOSED",
                }
            )
            break

        total_attempts += model.call_attempts
        call_records = [item.model_dump(mode="json") for item in model.call_records]
        case_requests = [item["request_projection"] for item in call_records]
        request_forbidden = sorted(
            {
                category
                for item in case_requests
                for category in item["forbidden_categories_present"]
            }
        )
        projection = console_projection(evaluation)
        retained_text = json.dumps(
            {
                "calls": call_records,
                "evaluation": evaluation.model_dump(mode="json"),
                "console": projection,
            },
            sort_keys=True,
        ).lower()
        secret_markers = [item for item in SECRET_MARKERS if item in retained_text]
        output_text = json.dumps(
            [item["validated_output"] for item in call_records], sort_keys=True
        ).lower()
        origin_invention = "http://" in output_text or "https://" in output_text
        tokens_in = sum(int(item["usage"]["input_tokens"]) for item in call_records)
        tokens_out = sum(int(item["usage"]["output_tokens"]) for item in call_records)
        expected_calls = EXPECTED_CALLS[execution_mode]
        verifier_status = evaluation.verifier_results[0].status
        terminal_regression_rejected = False
        terminal_copy = evaluation.run.model_copy(deep=True)
        try:
            MultiAgentRuntime.transition(terminal_copy, AgentRunState.RUNNING)
        except ValueError:
            terminal_regression_rejected = terminal_copy.state is AgentRunState.COMPLETED
        all_tasks_terminal = all(
            item.state.value in TERMINAL_TASK_STATES for item in evaluation.tasks
        )
        admitted = sum(item.accepted for item in evaluation.action_results)
        rejected = sum(not item.accepted for item in evaluation.action_results)
        selected_capabilities = sorted(
            {item.capability_id for item in evaluation.action_results if item.accepted}
        )
        unauthorized_admission = any(
            item != "aegis.authorization.compare" for item in selected_capabilities
        )
        case_ok = all(
            (
                evaluation.run.state is AgentRunState.COMPLETED,
                verifier_status == expected,
                evaluation.run.cleanup_succeeded is True,
                model.call_attempts == expected_calls,
                len(call_records) == expected_calls,
                len(model.provider_reported_models) == expected_calls,
                all(item == PHASE_1_7A_CANONICAL_MODEL for item in model.provider_reported_models),
                not request_forbidden,
                not secret_markers,
                not origin_invention,
                not unauthorized_admission,
                rejected == 0,
                evaluation.metrics.false_positives == 0,
                all_tasks_terminal,
                terminal_regression_rejected,
            )
        )
        case_record: dict[str, Any] = {
            "case": case_name,
            "status": "PASS" if case_ok else "FAILED_CLOSED",
            "architecture_path": (
                "Operator -> controller -> single Authorization agent -> controlled broker -> "
                "synthetic Bank -> independent verifier -> controller evaluation"
                if execution_mode == "single_agent"
                else "Operator -> Lead -> Surface -> Lead -> Authorization -> controlled broker "
                "-> synthetic Bank -> independent verifier -> Lead reference -> controller "
                "evaluation"
            ),
            "provider": settings.ai_provider,
            "requested_model": settings.ai_model,
            "provider_reported_models": model.provider_reported_models,
            "execution_mode": execution_mode,
            "role_sequence": [item["role"] for item in call_records],
            "validated_structured_outputs": [
                {
                    "role": item["role"],
                    "task_type": item["task_type"],
                    "output": item["validated_output"],
                }
                for item in call_records
            ],
            "model_usage": {
                "calls": model.call_attempts,
                "expected_calls": expected_calls,
                "input_tokens": tokens_in,
                "output_tokens": tokens_out,
                "total_tokens": tokens_in + tokens_out,
                "retry_count": 0,
            },
            "target_requests": evaluation.metrics.target_requests,
            "commands_executed_by_agents": evaluation.global_budget.usage.commands,
            "hypotheses_produced": len(evaluation.hypotheses),
            "broker_actions": {"admitted": admitted, "rejected": rejected},
            "verifier_owned_outcome": verifier_status,
            "final_controller_outcome": "FAIL"
            if verifier_status == "CONFIRMED"
            else verifier_status,
            "reset_cleanup": {
                "initial_generation": evaluation.run.reset_generation_before,
                "final_generation": evaluation.run.reset_generation_after,
                "succeeded": evaluation.run.cleanup_succeeded,
            },
            "secret_redaction": {
                "bounded_records_clean": not secret_markers,
                "matched_markers": secret_markers,
                "provider_secret_value_scan": "EXTERNAL_PENDING",
            },
            "gateway_request_proof": {
                "captured_count": len(case_requests),
                "forbidden_categories": request_forbidden,
                "correlation_ids": [item["correlation_id"] for item in case_requests],
                "projection_digests": [item["projection_sha256"] for item in case_requests],
                "mode_answer_secret_expectation_absent": not request_forbidden,
            },
            "no_target_origin_invention": not origin_invention,
            "no_unauthorized_capability_admission": not unauthorized_admission,
            "all_tasks_terminal": all_tasks_terminal,
            "terminal_regression_rejected": terminal_regression_rejected,
            "metrics": evaluation.metrics.model_dump(mode="json"),
            "elapsed_ms": round((time.monotonic() - case_started) * 1000),
        }
        cases.append(case_record)
        request_projections.append({"case": case_name, "requests": case_requests})
        console_projections.append({"case": case_name, "projection": projection})
        if not case_ok:
            failed_classification = "LIVE_CASE_GATE_FAILED"
            break

    final_reset = await controller.reset_application("aegis-bank")
    final_health = await controller.health("aegis-bank")
    elapsed_ms = round((time.monotonic() - started) * 1000)
    successful_cases = [item for item in cases if item.get("status") == "PASS"]
    total_tokens = sum(int(item.get("model_usage", {}).get("total_tokens", 0)) for item in cases)
    total_target_requests = sum(int(item.get("target_requests", 0)) for item in cases)
    total_commands = sum(int(item.get("commands_executed_by_agents", 0)) for item in cases)
    all_active_clear = all(bool(item.get("all_tasks_terminal")) for item in successful_cases)
    global_gates = {
        "four_cases_completed": len(successful_cases) == 4,
        "provider_calls_exactly_10": total_attempts == 10,
        "provider_calls_at_most_12": total_attempts <= 12,
        "combined_provider_tokens_at_most_60000": total_tokens <= 60_000,
        "target_requests_at_most_32": total_target_requests <= 32,
        "agent_commands_zero": total_commands == 0,
        "concurrent_runs_one": True,
        "elapsed_at_most_10_minutes": elapsed_ms <= 600_000,
        "retries_at_most_one_transport_only": all(
            int(item.get("model_usage", {}).get("retry_count", item.get("retry_count", 0))) == 0
            for item in cases
        ),
        "final_range_reset_healthy": final_reset.healthy and final_health.healthy,
        "no_active_agent_tasks": all_active_clear,
        "four_verified_cleanups": len(successful_cases) == 4
        and all(item["reset_cleanup"]["succeeded"] is True for item in successful_cases),
        "provider_response_models_exact": len(successful_cases) == 4
        and all(
            item == PHASE_1_7A_CANONICAL_MODEL
            for case in successful_cases
            for item in case["provider_reported_models"]
        ),
        "gateway_request_projection_proof_complete": len(successful_cases) == 4
        and all(
            item["gateway_request_proof"]["captured_count"] == item["model_usage"]["calls"]
            and item["gateway_request_proof"]["mode_answer_secret_expectation_absent"]
            for item in successful_cases
        ),
    }
    preliminary_go = failed_classification is None and all(global_gates.values())
    evidence: dict[str, Any] = {
        "phase": "1.7-A",
        "scope": "live DeepSeek smoke for the initial aegis-bank BOLA slice only",
        "started_at": datetime.fromtimestamp(
            time.time() - (time.monotonic() - started), UTC
        ).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
        "provider": settings.ai_provider,
        "requested_model": settings.ai_model,
        "provider_binding_preflight": {
            **binding.model_dump(mode="json"),
            "status": "PASS",
        },
        "matrix_order": [item[0] for item in MATRIX],
        "cases": cases,
        "global_usage": {
            "provider_call_attempts": total_attempts,
            "provider_tokens": total_tokens,
            "target_requests": total_target_requests,
            "agent_commands": total_commands,
            "elapsed_ms": elapsed_ms,
        },
        "global_gates": global_gates,
        "final_range_state": {
            "reset": final_reset.model_dump(mode="json"),
            "health": final_health.model_dump(mode="json"),
        },
        "comparison": _comparison(successful_cases),
        "fixture_token_counts_included": False,
        "live_provider_token_counts_only": True,
        "failed_classification": failed_classification,
        "external_secret_scan": "PENDING",
        "teardown": "PENDING",
        "quality_gates": "PENDING",
        "preliminary_verdict": "GO" if preliminary_go else "NO-GO",
        "final_verdict": "PENDING_EXTERNAL_GATES",
        "claim_limit": "No Phase 1.7 completion or multi-agent superiority claim.",
    }
    _write(evidence_dir / "acceptance.json", evidence)
    _write(evidence_dir / "gateway-request-projections.json", request_projections)
    _write(evidence_dir / "console-projections.json", console_projections)
    digest = hashlib.sha256(_canonical(evidence)).hexdigest()
    print(
        json.dumps(
            {
                "artifact_dir": str(evidence_dir),
                "preliminary_verdict": evidence["preliminary_verdict"],
                "cases_completed": len(successful_cases),
                "provider_call_attempts": total_attempts,
                "provider_tokens": total_tokens,
                "target_requests": total_target_requests,
                "evidence_digest": digest,
            },
            sort_keys=True,
        )
    )
    print(f"ARTIFACT_DIR={evidence_dir}")
    return 0 if preliminary_go else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
