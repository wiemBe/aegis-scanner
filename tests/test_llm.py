"""Control-plane GatewayPlanner tests.

The GatewayPlanner is the control-plane RPC client. It never holds a provider credential and never
reaches the provider; it only talks to the llm-gateway over the internal planner-rpc network and
re-enforces admission budgets, usage reconciliation, model-allowlist and output-schema validation.
It is provider-agnostic: it knows only the mode label and the RPC contract.
"""

import json
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from aegis.budget import BudgetExceeded, ScanBudget
from aegis.models import BudgetUsage, ExecuteDecision, PlannedRequest
from aegis.planner import GatewayPlanner, PlannerFailure
from aegis.settings import Settings


def settings(**kwargs: Any) -> Settings:
    # The control plane holds no provider credential; the default local model is qwen3:4b.
    return Settings(ai_provider="ollama", ai_base_url="http://ollama.test:11434", **kwargs)


def gateway_reply(
    action: str = "stop",
    model: str = "qwen3:4b",
    input_tokens: int = 100,
    output_tokens: int = 20,
    total_tokens: int | None = None,
) -> dict[str, Any]:
    return {
        "model": model,
        "decision": {"decision_type": action, "summary": "Need more evidence"},
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens if total_tokens is None else total_tokens,
        },
        "metadata": {
            "provider_type": "ollama",
            "runtime": "ollama",
            "runtime_version": "0.34.2",
            "model": model,
            "model_digest": "sha256:abc",
            "context_length": 8192,
            "temperature": 0.0,
            "seed": 42,
            "prompt_eval_count": input_tokens,
            "eval_count": output_tokens,
            "total_duration_ms": 11000,
            "load_duration_ms": 2000,
            "stop_reason": "stop",
        },
    }


def planner_with(handler: Any, **kwargs: Any) -> tuple[GatewayPlanner, Settings, ScanBudget]:
    config = settings(**kwargs)
    planner = GatewayPlanner(config, "LOCAL_LLM", httpx.MockTransport(handler))
    return planner, config, ScanBudget(config, BudgetUsage())


async def test_gateway_planner_forwards_context_and_records_metadata() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        assert payload["max_output_tokens"] == 2048
        assert "context" in payload
        assert "authorization" not in request.headers  # control plane never sends credentials
        assert str(request.url).endswith("/v1/plan")
        return httpx.Response(200, json=gateway_reply())

    planner, _, budget = planner_with(handler)
    assert planner.name == "LOCAL_LLM"
    decision = await planner.decide({"surface": {"paths": {}}}, budget)
    assert decision.decision_type == "stop" and len(seen) == 1
    assert budget.usage.model_calls == 1 and budget.usage.reported_tokens == 120
    assert budget.usage.reserved_tokens > 2048
    # The gateway planner records only non-secret provider run facts, local to this scan's budget.
    assert budget.provider_metadata is not None
    assert budget.provider_metadata.runtime_version == "0.34.2"
    assert budget.provider_metadata.model_digest == "sha256:abc"
    assert not hasattr(planner, "api_key") and not hasattr(planner, "_token")


async def test_gateway_planner_rejects_over_reservation() -> None:
    planner, _, budget = planner_with(
        lambda r: httpx.Response(
            200, json=gateway_reply(input_tokens=1, output_tokens=1, total_tokens=500000)
        )
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_USAGE_EXCEEDED_RESERVATION"):
        await planner.decide({}, budget)
    assert budget.usage.reported_tokens == 500000


async def test_gateway_planner_rejects_inconsistent_usage() -> None:
    planner, _, budget = planner_with(
        lambda r: httpx.Response(200, json=gateway_reply(total_tokens=999))
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_USAGE_EXCEEDED_RESERVATION"):
        await planner.decide({}, budget)


async def test_gateway_planner_rejects_model_mismatch() -> None:
    planner, _, budget = planner_with(
        lambda r: httpx.Response(200, json=gateway_reply(model="qwen3:0.5b"))
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH"):
        await planner.decide({}, budget)


async def test_gateway_planner_rejects_model_outside_allowlist() -> None:
    # A model the gateway echoes that is not in the exact allowlist is refused (defence in depth).
    planner, _, budget = planner_with(
        lambda r: httpx.Response(200, json=gateway_reply(model="qwen3:70b"))
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH"):
        await planner.decide({}, budget)


@pytest.mark.parametrize("status", [400, 422, 500, 502])
async def test_gateway_planner_propagates_safe_error_code(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json={
                "detail": {
                    "code": "INCOMPLETE_MODEL_OUTPUT_LENGTH",
                    "response_sha256": "a" * 64,
                }
            },
        )

    planner, _, budget = planner_with(handler)
    with pytest.raises(PlannerFailure) as exc:
        await planner.decide({}, budget)
    assert str(exc.value) == "INCOMPLETE_MODEL_OUTPUT_LENGTH"
    assert exc.value.response_digest == "a" * 64
    assert budget.usage.model_calls == 1


async def test_gateway_planner_unreachable_is_failure_not_crash() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("provider gateway secret detail", request=request)

    planner, _, budget = planner_with(handler)
    with pytest.raises(PlannerFailure, match="GATEWAY_RESPONSE_REJECTED_ConnectError") as exc:
        await planner.decide({}, budget)
    assert "secret detail" not in str(exc.value)
    assert budget.usage.model_calls == 1


async def test_gateway_planner_oversized_response_rejected() -> None:
    planner, _, budget = planner_with(
        lambda r: httpx.Response(200, text="x" * 2000), max_response_bytes=1024
    )
    with pytest.raises(PlannerFailure):
        await planner.decide({}, budget)


@pytest.mark.parametrize("limit", ["tokens", "calls"])
async def test_gateway_planner_admission_budgets_prevent_call(limit: str) -> None:
    config = settings(max_tokens_per_scan=1) if limit == "tokens" else settings(max_model_calls=1)
    usage = BudgetUsage(model_calls=1) if limit == "calls" else BudgetUsage()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=gateway_reply())

    planner = GatewayPlanner(config, "LOCAL_LLM", httpx.MockTransport(handler))
    with pytest.raises(BudgetExceeded):
        await planner.decide({}, ScanBudget(config, usage))
    assert not calls


@pytest.mark.parametrize(
    "path",
    ["//evil.invalid/x", "/%2f%2fevil", "/a/../b", "/a?x=1", "/a#b", "/a\\b", "/a\n", "/a;%20"],
)
def test_malicious_paths_rejected(path: str) -> None:
    with pytest.raises(ValidationError):
        PlannedRequest(
            name="attack",
            method="GET",
            path=path,
            credential_profile="user_a",
            purpose="Escape scope",
        )


def test_extra_fields_and_mutation_rejected() -> None:
    valid = {
        "name": "test",
        "method": "GET",
        "path": "/api/v1/accounts/A-100",
        "credential_profile": "user_a",
        "purpose": "Test policy",
    }
    for key, value in [
        ("method", "POST"),
        ("headers", {}),
        ("body", "payload"),
        ("credential_profile", "admin"),
    ]:
        with pytest.raises(ValidationError):
            PlannedRequest.model_validate({**valid, key: value})
    with pytest.raises(ValidationError):
        ExecuteDecision(summary="No plan")  # execute must carry a hypothesis
