"""LLM gateway tests: the schema-validated /v1/plan RPC boundary and the deprecated OpenAI
Responses compatibility provider's fail-closed parsing. All provider traffic is mocked.
"""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

import aegis.gateway as gateway
from aegis.planner import PlannerFailure
from aegis.providers import OllamaProvider, OpenAIResponsesProvider
from aegis.settings import Settings

STOP = '{"decision_type":"stop","summary":"Need more evidence"}'


def ollama_provider(chat_handler: Any) -> OllamaProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.34.2"})
        if request.method == "GET" and request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"model": "qwen3:4b", "digest": "d"}]})
        return chat_handler(request)

    return OllamaProvider(
        Settings(ai_provider="ollama", ai_base_url="http://ollama.test:11434"),
        httpx.MockTransport(handler),
    )


def ollama_reply(content: str = STOP, done_reason: str = "stop") -> dict[str, Any]:
    return {
        "model": "qwen3:4b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": done_reason,
        "prompt_eval_count": 100,
        "eval_count": 20,
        "total_duration": 5_000_000_000,
    }


async def _plan(provider: Any, body: dict[str, Any]) -> httpx.Response:
    gateway._provider = provider
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        return await http.post("/v1/plan", json=body)


async def test_health_reports_provider_and_model() -> None:
    gateway._provider = ollama_provider(lambda r: httpx.Response(200, json=ollama_reply()))
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        body = (await http.get("/health")).json()
    assert body["provider"] == "ollama" and body["model"] == "qwen3:4b"


async def test_plan_endpoint_happy_path_via_ollama() -> None:
    provider = ollama_provider(lambda r: httpx.Response(200, json=ollama_reply()))
    response = await _plan(
        provider,
        {"context": {"surface": {"paths": {}}, "observations": []}, "max_output_tokens": 2048},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["model"] == "qwen3:4b" and body["decision"]["decision_type"] == "stop"
    assert body["usage"]["total_tokens"] == 120
    assert body["metadata"]["provider_type"] == "ollama"
    assert body["metadata"]["runtime_version"] == "0.34.2"


async def test_plan_endpoint_rejects_unsanitized_context() -> None:
    provider = ollama_provider(lambda r: httpx.Response(200, json=ollama_reply()))
    response = await _plan(
        provider,
        {"context": {"surface": {}, "injected_tool": "shell"}, "max_output_tokens": 2048},
    )
    assert response.status_code == 422


async def test_plan_endpoint_maps_failure_to_safe_code() -> None:
    bad = ollama_reply(content="lab-token-user-a not json")
    provider = ollama_provider(lambda r: httpx.Response(200, json=bad))
    response = await _plan(provider, {"context": {"surface": {}}, "max_output_tokens": 2048})
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["code"].startswith("MODEL_RESPONSE_REJECTED")
    assert "lab-token" not in json.dumps(response.json())


# --- Deprecated public OpenAI Responses compatibility provider (disabled by default) ------------


def responses_reply(
    content: str = STOP,
    status: str = "completed",
    input_tokens: int = 100,
    output_tokens: int = 20,
    total_tokens: int | None = None,
    extra_output: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    output: list[dict[str, Any]] = [
        {
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": content}],
        }
    ]
    if extra_output:
        output = extra_output + output
    return {
        "status": status,
        "output": output,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens if total_tokens is None else total_tokens,
        },
    }


def responses_provider(handler: Any, **kwargs: Any) -> OpenAIResponsesProvider:
    base: dict[str, Any] = {
        "ai_provider": "openai_responses",
        "ai_base_url": "https://api.openai.com",
        "ai_model": "gpt-5-mini",
        "ai_allowed_models": "gpt-5-mini",
        "ai_auth_token": SecretStr("sk-fake-key"),
    }
    base.update(kwargs)
    return OpenAIResponsesProvider(Settings(**base), httpx.MockTransport(handler))


async def test_responses_contract_and_bearer() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["text"]["format"]["strict"] is True
        assert payload["store"] is False
        assert request.headers["authorization"] == "Bearer sk-fake-key"
        assert str(request.url).endswith("/v1/responses")
        return httpx.Response(200, json=responses_reply())

    result = await responses_provider(handler).decide({"surface": {}}, 2048)
    assert result.model == "gpt-5-mini" and result.decision.decision_type == "stop"
    assert result.usage.total_tokens == 120


@pytest.mark.parametrize(
    "kind",
    [
        "refusal",
        "incomplete",
        "bad_usage",
        "inconsistent_usage",
        "over_usage",
        "bad_json",
        "tool_call",
    ],
)
async def test_responses_fail_closed(kind: str) -> None:
    payload = responses_reply()
    if kind == "refusal":
        payload["output"][0]["content"] = [{"type": "refusal", "refusal": "No"}]
    elif kind == "incomplete":
        payload["status"] = "incomplete"
        payload["incomplete_details"] = {"reason": "max_output_tokens"}
    elif kind == "bad_usage":
        payload["usage"]["total_tokens"] = -1
    elif kind == "inconsistent_usage":
        payload["usage"]["total_tokens"] = 999
    elif kind == "over_usage":
        payload["usage"] = {"input_tokens": 100, "output_tokens": 3000, "total_tokens": 3100}
    elif kind == "bad_json":
        payload["output"][0]["content"][0]["text"] = "lab-token-user-a not json"
    else:  # tool_call
        payload["output"].insert(0, {"type": "function_call", "name": "shell", "arguments": "{}"})
    with pytest.raises(PlannerFailure) as exc:
        await responses_provider(lambda r: httpx.Response(200, json=payload)).decide({}, 2048)
    assert "lab-token" not in str(exc.value) and "sk-fake-key" not in str(exc.value)


@pytest.mark.parametrize("status", [302, 401, 429, 500])
async def test_responses_no_redirects_or_retries(status: int) -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            status, headers={"location": "https://evil.invalid/"}, text="sk-fake-key"
        )

    with pytest.raises(PlannerFailure) as exc:
        await responses_provider(handler).decide({}, 2048)
    assert len(calls) == 1 and "sk-fake-key" not in str(exc.value)


def test_responses_insecure_base_url_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        responses_provider(lambda r: httpx.Response(200), ai_base_url="http://provider.invalid")


def test_responses_real_path_disables_env_proxy() -> None:
    provider = OpenAIResponsesProvider(
        Settings(
            ai_provider="openai_responses",
            ai_base_url="https://api.openai.com",
            ai_model="gpt-5-mini",
            ai_allowed_models="gpt-5-mini",
            ai_auth_token=SecretStr("sk-fake-key"),
            provider_proxy_url="http://egress-proxy:3128",
        )
    )
    built = provider._client()
    assert built.trust_env is False
