"""DeepSeekProvider tests. All DeepSeek traffic is mocked (httpx.MockTransport); no network is used.

Covers the OpenAI-compatible /chat/completions contract for the beast adversary route: deepseek-chat
(JSON-object mode + temperature) and deepseek-reasoner (no response_format/temperature/seed, hidden
reasoning_content dropped), honest cloud provenance (no digest, no reproducible seed, response id
recorded), the relaxed reasoner token accounting, and the fail-closed paths (model mismatch,
truncated/length output, missing content, malformed JSON). Configuration guards live in
test_providers_config.py-style checks at the bottom.
"""

import json
from typing import Any

import httpx
import pytest

from aegis.beast.contracts import BeastDecisionRequest
from aegis.planner import PlannerFailure
from aegis.providers import DeepSeekProvider, build_provider
from aegis.settings import Settings

COMMAND = json.dumps(
    {
        "decision_type": "command",
        "hypothesis": "probe the documented root endpoint to enumerate the surface",
        "expected_intent": "retrieve the base response body",
        "command_text": "curl http://beast-target:8080/lab/beast/vulnerable",
    }
)
STOP = json.dumps(
    {
        "decision_type": "stop",
        "hypothesis": "the endpoint surface is fully enumerated",
        "summary": "accounts and search endpoints were observed in the openapi body",
        "evidence_observation_ids": ["obs-run-001"],
    }
)


def request_fixture() -> BeastDecisionRequest:
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


def deepseek_reply(
    content: str = STOP,
    model: str = "deepseek-chat",
    finish_reason: str = "stop",
    prompt_tokens: int = 420,
    completion_tokens: int = 60,
    response_id: str = "chatcmpl-abc123",
    reasoning_content: str | None = None,
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if reasoning_content is not None:
        message["reasoning_content"] = reasoning_content
    return {
        "id": response_id,
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def provider(chat_handler: Any, model: str = "deepseek-chat", **kwargs: Any) -> DeepSeekProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        return chat_handler(request)

    settings = Settings(
        ai_provider="deepseek",
        ai_base_url="https://api.deepseek.test",
        ai_model=model,
        ai_allowed_models="deepseek-chat,deepseek-reasoner",
        deepseek_api_key="sk-test-secret",
        **kwargs,
    )
    return DeepSeekProvider(settings, httpx.MockTransport(handler))


async def test_chat_command_decision_payload_and_metadata() -> None:
    seen: list[httpx.Request] = []

    def chat(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.method == "POST"
        assert str(request.url) == "https://api.deepseek.test/chat/completions"
        assert request.headers["Authorization"] == "Bearer sk-test-secret"
        payload = json.loads(request.content)
        assert payload["model"] == "deepseek-chat"
        assert payload["stream"] is False
        # deepseek-chat: JSON mode + temperature are sent.
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["temperature"] == 0.0
        # The system prompt + user brief are present; the brief is passed as a raw string.
        assert payload["messages"][0]["role"] == "system"
        assert isinstance(payload["messages"][1]["content"], str)
        return httpx.Response(200, json=deepseek_reply(content=COMMAND))

    result = await provider(chat).adversary_decide(request_fixture())
    assert len(seen) == 1
    assert result.decision.decision_type == "command"
    assert result.decision.command_text == "curl http://beast-target:8080/lab/beast/vulnerable"
    md = result.metadata
    assert md.provider_type == "deepseek" and md.runtime == "deepseek"
    assert md.model == "deepseek-chat"
    assert md.model_digest is None  # cloud: no content digest
    assert md.seed is None  # DeepSeek does not honour seed
    assert md.temperature == 0.0
    assert md.response_id == "chatcmpl-abc123"
    assert md.total_duration_ms is not None and md.total_duration_ms >= 0
    assert result.usage.total_tokens == result.usage.input_tokens + result.usage.output_tokens


async def test_reasoner_omits_unsupported_params_and_drops_reasoning() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["model"] == "deepseek-reasoner"
        # deepseek-reasoner: response_format/temperature must NOT be sent.
        assert "response_format" not in payload
        assert "temperature" not in payload
        # Hidden chain-of-thought is returned but must be ignored; only content is read.
        return httpx.Response(
            200,
            json=deepseek_reply(
                content=STOP,
                model="deepseek-reasoner",
                reasoning_content="secret hidden chain of thought that must never be stored",
            ),
        )

    result = await provider(chat, model="deepseek-reasoner").adversary_decide(request_fixture())
    assert result.decision.decision_type == "stop"
    assert result.metadata.temperature is None  # honestly recorded: reasoner ignores it
    assert result.metadata.model == "deepseek-reasoner"


async def test_reasoner_large_completion_within_call_ceiling_is_allowed() -> None:
    # reasoner spends many tokens on hidden reasoning (counted in completion_tokens). That must be
    # bounded only by the per-call ceiling, not by the concise-output cap.
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=deepseek_reply(
                content=STOP, model="deepseek-reasoner", completion_tokens=6000
            ),
        )

    result = await provider(
        chat, model="deepseek-reasoner", max_completion_tokens=2048
    ).adversary_decide(request_fixture())
    assert result.usage.output_tokens == 6000


async def test_chat_completion_over_output_cap_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=deepseek_reply(content=COMMAND, completion_tokens=6000))

    with pytest.raises(PlannerFailure, match="PROVIDER_USAGE_EXCEEDED_CEILING"):
        await provider(chat, max_completion_tokens=2048).adversary_decide(request_fixture())


async def test_model_mismatch_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=deepseek_reply(content=STOP, model="deepseek-chat-cheap"))

    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH"):
        await provider(chat).adversary_decide(request_fixture())


async def test_truncated_length_output_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=deepseek_reply(content=COMMAND, finish_reason="length"))

    with pytest.raises(PlannerFailure, match="INCOMPLETE_MODEL_OUTPUT_LENGTH"):
        await provider(chat).adversary_decide(request_fixture())


async def test_non_schema_json_rejected_not_coerced() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        # Valid JSON, but not a valid beast decision (unknown decision_type): reject, never coerce.
        return httpx.Response(200, json=deepseek_reply(content='{"decision_type":"noop"}'))

    with pytest.raises(PlannerFailure, match="BEAST_MODEL_RESPONSE_REJECTED_"):
        await provider(chat).adversary_decide(request_fixture())


async def test_missing_content_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        body = deepseek_reply(content=COMMAND)
        body["choices"][0]["message"]["content"] = None
        return httpx.Response(200, json=body)

    with pytest.raises(PlannerFailure, match="MISSING_MODEL_OUTPUT"):
        await provider(chat).adversary_decide(request_fixture())


def test_build_provider_selects_deepseek() -> None:
    settings = Settings(
        ai_provider="deepseek",
        ai_base_url="https://api.deepseek.test",
        ai_model="deepseek-reasoner",
        ai_allowed_models="deepseek-chat,deepseek-reasoner",
        deepseek_api_key="sk-test-secret",
    )
    built = build_provider(settings, httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    assert isinstance(built, DeepSeekProvider)
    assert built.provider_type == "deepseek"


def test_missing_api_key_fails_closed() -> None:
    # Settings construct fine (the key is optional at the settings layer); the provider is what
    # refuses to start without a key, so no keyless DeepSeek gateway can ever run.
    settings = Settings(
        ai_provider="deepseek",
        ai_base_url="https://api.deepseek.test",
        ai_model="deepseek-chat",
        ai_allowed_models="deepseek-chat,deepseek-reasoner",
    )
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        DeepSeekProvider(settings, httpx.MockTransport(lambda r: httpx.Response(200, json={})))


def test_non_https_base_url_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        DeepSeekProvider(
            Settings(
                ai_provider="deepseek",
                ai_base_url="http://api.deepseek.test",
                ai_model="deepseek-chat",
                ai_allowed_models="deepseek-chat,deepseek-reasoner",
                deepseek_api_key="sk-test-secret",
            ),
            httpx.MockTransport(lambda r: httpx.Response(200, json={})),
        )


def test_unsupported_model_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported DeepSeek model"):
        DeepSeekProvider(
            Settings(
                ai_provider="deepseek",
                ai_base_url="https://api.deepseek.test",
                ai_model="deepseek-frontier",
                ai_allowed_models="deepseek-chat,deepseek-reasoner,deepseek-frontier",
                deepseek_api_key="sk-test-secret",
            ),
            httpx.MockTransport(lambda r: httpx.Response(200, json={})),
        )
