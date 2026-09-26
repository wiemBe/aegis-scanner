"""OpenRouter/Qwen provider contract. Every HTTP exchange is local and mocked."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis.planner import PlannerFailure
from aegis.providers import OPENROUTER_QWEN_MODEL, OpenRouterProvider, build_provider
from aegis.settings import Settings


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
        "ai_allowed_models": OPENROUTER_QWEN_MODEL,
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
    with pytest.raises(ValueError, match="exact model"):
        OpenRouterProvider(
            settings(ai_model=model, ai_allowed_models=model),
            httpx.MockTransport(lambda _: httpx.Response(200)),
        )


def test_allowlist_must_contain_only_pinned_model() -> None:
    with pytest.raises(ValueError, match="allowlist"):
        OpenRouterProvider(
            settings(ai_allowed_models=f"{OPENROUTER_QWEN_MODEL},openrouter/auto"),
            httpx.MockTransport(lambda _: httpx.Response(200)),
        )


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
