"""OpenRouter/Qwen provider contract. Every HTTP exchange is local and mocked."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis.beast.contracts import BeastDecisionRequest
from aegis.planner import PlannerFailure
from aegis.providers import OPENROUTER_QWEN_MODEL, OpenRouterProvider, build_provider
from aegis.settings import (
    OPENROUTER_APPROVED_MODELS,
    OPENROUTER_DEEPSEEK_FLASH_MODEL,
    Settings,
)


def reply(
    content: str = '{"decision_type":"stop","summary":"done"}',
    *,
    model: str = OPENROUTER_QWEN_MODEL,
    finish_reason: str = "stop",
    completion_tokens: int = 12,
) -> dict[str, Any]:
    return {
        "id": "gen-test",
        "model": model,
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {
            "prompt_tokens": 20,
            "completion_tokens": completion_tokens,
            "total_tokens": 20 + completion_tokens,
        },
    }


def settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "ai_provider": "openrouter",
        "ai_base_url": "https://openrouter.test",
        "ai_model": OPENROUTER_QWEN_MODEL,
        "ai_allowed_models": ",".join(sorted(OPENROUTER_APPROVED_MODELS)),
        "openrouter_api_key": "sk-or-test-placeholder",
        "ai_use_egress_proxy": True,
    }
    values.update(overrides)
    return Settings(**values)


async def test_request_is_exactly_pinned_private_and_schema_validated() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.method == "POST"
        assert str(request.url) == "https://openrouter.test/api/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer sk-or-test-placeholder"
        payload = json.loads(request.content)
        assert payload["model"] == OPENROUTER_QWEN_MODEL
        assert payload["stream"] is False
        assert payload["response_format"]["type"] == "json_schema"
        assert payload["response_format"]["json_schema"]["strict"] is True
        assert payload["provider"] == {
            "require_parameters": True,
            "data_collection": "deny",
            "zdr": True,
        }
        assert "seed" not in payload
        assert "plugins" not in payload and "tools" not in payload
        return httpx.Response(200, json=reply())

    provider = OpenRouterProvider(settings(), httpx.MockTransport(handler))
    result = await provider.decide({"surface": {}}, 512)

    assert len(seen) == 1
    assert result.decision.decision_type == "stop"
    assert result.metadata.provider_type == "openrouter"
    assert result.metadata.runtime == "openrouter"
    assert result.metadata.model == OPENROUTER_QWEN_MODEL
    assert result.metadata.seed is None
    assert result.usage.total_tokens == 32
    assert "sk-or-test-placeholder" not in result.metadata.model_dump_json()


def test_build_provider_selects_openrouter() -> None:
    built = build_provider(settings(), httpx.MockTransport(lambda _: httpx.Response(200, json={})))
    assert isinstance(built, OpenRouterProvider)


@pytest.mark.parametrize("model", ["qwen/qwen3-27b", "qwen/qwen3.8-27b:free", "openrouter/auto"])
def test_model_alias_or_substitution_is_rejected(model: str) -> None:
    with pytest.raises(ValueError, match="reviewed model catalog"):
        OpenRouterProvider(
            settings(ai_model=model, ai_allowed_models=model),
            httpx.MockTransport(lambda _: httpx.Response(200)),
        )


def test_allowlist_must_exactly_match_reviewed_catalog() -> None:
    with pytest.raises(ValueError, match="allowlist"):
        OpenRouterProvider(
            settings(ai_allowed_models=f"{OPENROUTER_QWEN_MODEL},openrouter/auto"),
            httpx.MockTransport(lambda _: httpx.Response(200)),
        )


def test_reviewed_alternate_model_is_accepted() -> None:
    provider = OpenRouterProvider(
        settings(ai_model=OPENROUTER_DEEPSEEK_FLASH_MODEL),
        httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    assert provider.model == OPENROUTER_DEEPSEEK_FLASH_MODEL


def test_missing_or_ambiguous_key_fails_closed(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200))
    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        OpenRouterProvider(settings(openrouter_api_key=None), transport)

    key_file = tmp_path / "key"
    key_file.write_text("file-key", encoding="utf-8")
    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        OpenRouterProvider(
            settings(openrouter_api_key_file=str(key_file)),
            transport,
        )


def test_absolute_key_file_is_supported(tmp_path: Path) -> None:
    key_file = tmp_path / "key"
    key_file.write_text("file-key-placeholder\n", encoding="utf-8")
    provider = OpenRouterProvider(
        settings(openrouter_api_key=None, openrouter_api_key_file=str(key_file)),
        httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    assert provider._headers()["Authorization"] == "Bearer file-key-placeholder"


def test_non_https_and_non_openrouter_origin_are_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        OpenRouterProvider(
            settings(ai_base_url="http://openrouter.test"),
            httpx.MockTransport(lambda _: httpx.Response(200)),
        )
    with pytest.raises(ValueError, match="openrouter.ai"):
        OpenRouterProvider(settings(ai_base_url="https://example.invalid"))


@pytest.mark.parametrize(
    ("response", "failure"),
    [
        (reply(model="qwen/qwen3.8-27b:free"), "PROVIDER_MODEL_MISMATCH"),
        (reply(finish_reason="length"), "INCOMPLETE_MODEL_OUTPUT_LENGTH"),
        (reply(completion_tokens=3000), "PROVIDER_USAGE_EXCEEDED_CEILING"),
    ],
)
async def test_response_failures_are_closed(response: dict[str, Any], failure: str) -> None:
    provider = OpenRouterProvider(
        settings(max_completion_tokens=2048),
        httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )
    with pytest.raises(PlannerFailure, match=failure):
        await provider.decide({"surface": {}}, 512)


async def test_http_rejection_reports_only_bounded_status_code() -> None:
    provider = OpenRouterProvider(
        settings(),
        httpx.MockTransport(lambda _: httpx.Response(404, json={"sensitive": "not surfaced"})),
    )
    with pytest.raises(PlannerFailure, match="MODEL_RESPONSE_REJECTED_HTTP_404") as failure:
        await provider.decide({"surface": {}}, 512)
    assert "sensitive" not in str(failure.value)


# --- BEAST adversary route (mirrors the DeepSeek adversary contract) ------------------------------


def beast_reply(content: str) -> dict[str, Any]:
    return reply(
        content=content,
        model=OPENROUTER_QWEN_MODEL,
        completion_tokens=48,
    )


def beast_request() -> BeastDecisionRequest:
    return BeastDecisionRequest(
        run_id="run-001",
        scenario_id="endpoint_discovery",
        objective="Enumerate the reachable endpoint surface of the synthetic target.",
        target_origin="http://beast-target:8080",
        target_base_path="/lab/beast/vulnerable",
        synthetic_public_accounts=[{"username": "user-a", "token": "lab-token-user-a"}],
        sequence=1,
        remaining_commands=8,
        remaining_time_seconds=120,
        objective_evidence_sufficient=False,
        decision_requirements=["Expose actual response-body bytes from an observed URL."],
        observations=[],
    )


BEAST_COMMAND = json.dumps(
    {
        "decision_type": "command",
        "hypothesis": "probe the documented root endpoint to enumerate the surface",
        "expected_intent": "retrieve the base response body",
        "command_text": "curl http://beast-target:8080/lab/beast/vulnerable",
    }
)


async def test_adversary_decision_sends_raw_brief_with_hosted_provenance() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        # The reviewed OpenRouter request contract stays intact on the adversary route: pinned
        # model, json_schema mode, ZDR/data-collection denial, no seed and no tools/plugins.
        assert payload["model"] == OPENROUTER_QWEN_MODEL
        assert payload["stream"] is False
        assert payload["response_format"]["type"] == "json_schema"
        assert payload["provider"] == {
            "require_parameters": True,
            "data_collection": "deny",
            "zdr": True,
        }
        assert "seed" not in payload
        # The decision brief is the raw user message, not a JSON-encoded wrapper object.
        assert payload["messages"][0]["role"] == "system"
        assert isinstance(payload["messages"][1]["content"], str)
        assert "Enumerate the reachable endpoint surface" in payload["messages"][1]["content"]
        return httpx.Response(200, json=beast_reply(BEAST_COMMAND))

    provider = OpenRouterProvider(settings(), httpx.MockTransport(handler))
    result = await provider.adversary_decide(beast_request())

    assert len(seen) == 1
    assert result.model == OPENROUTER_QWEN_MODEL
    assert result.decision.decision_type == "command"
    # Hosted provenance: model identity, request parameters, token counts and timings — no digest
    # and no reproducible seed are claimed for routed upstreams.
    assert result.metadata.provider_type == "openrouter"
    assert result.metadata.model == OPENROUTER_QWEN_MODEL
    assert result.metadata.seed is None
    assert result.metadata.prompt_eval_count == 20
    assert result.metadata.eval_count == 48
    assert "sk-or-test-placeholder" not in result.metadata.model_dump_json()


async def test_adversary_decision_fails_closed_on_model_identity_mismatch() -> None:
    provider = OpenRouterProvider(
        settings(),
        httpx.MockTransport(
            lambda _: httpx.Response(
                200, json=beast_reply(BEAST_COMMAND) | {"model": "other/unreviewed-model"}
            )
        ),
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH"):
        await provider.adversary_decide(beast_request())


async def test_adversary_decision_rejects_malformed_decisions() -> None:
    provider = OpenRouterProvider(
        settings(),
        httpx.MockTransport(lambda _: httpx.Response(200, json=beast_reply("not json at all"))),
    )
    with pytest.raises(PlannerFailure, match="BEAST_MODEL_RESPONSE_REJECTED_"):
        await provider.adversary_decide(beast_request())
