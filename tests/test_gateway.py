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
from aegis.providers import (
    OPENROUTER_APPROVED_MODELS,
    OPENROUTER_QWEN_MODEL,
    InternalOpenAICompatibleProvider,
    OllamaProvider,
    OpenAIResponsesProvider,
    OpenRouterProvider,
)
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


def ollama_reply(
    content: str = STOP, done_reason: str = "stop", model: str = "qwen3:4b"
) -> dict[str, Any]:
    return {
        "model": model,
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


async def test_runtime_model_dropdown_is_allowlisted_and_synthetic_test_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        ai_provider="ollama",
        ai_model="qwen3:4b",
        ai_allowed_models="qwen3:4b,qwen3:8b",
        ai_base_url="http://ollama.test:11434",
    )

    def provider_for(selected: Settings) -> OllamaProvider:
        return OllamaProvider(
            selected,
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    json=ollama_reply(model=selected.ai_model),
                    headers={"content-type": "application/json"},
                )
            ),
        )

    monkeypatch.setattr(gateway, "get_settings", lambda: settings)
    monkeypatch.setattr(gateway, "build_provider", provider_for)
    gateway._provider = provider_for(settings)  # noqa: SLF001 - gateway singleton under test
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        catalog = (await http.get("/v1/models")).json()
        assert catalog["current_model"] == "qwen3:4b"
        assert catalog["models"] == ["qwen3:4b", "qwen3:8b"]

        refused = await http.post("/v1/models/select", json={"model": "unapproved:70b"})
        assert refused.status_code == 409

        selected = await http.post("/v1/models/select", json={"model": "qwen3:8b"})
        assert selected.status_code == 200
        assert selected.json()["current_model"] == "qwen3:8b"

        tested = await http.post("/v1/synthetic-test", json={})
        assert tested.status_code == 200
        result = tested.json()
        assert result["status"] == "PASS"
        assert result["model"] == "qwen3:8b"
        assert result["fixture_state"] == "DESTROYED"
        assert result["cleanup_verified"] is True
        assert result["docker_resources_created"] == 0

        failing_settings = settings.model_copy(update={"ai_model": "qwen3:8b"})
        gateway._provider = OllamaProvider(  # noqa: SLF001 - failure cleanup path under test
            failing_settings,
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    json=ollama_reply(content="not-json", model="qwen3:8b"),
                    headers={"content-type": "application/json"},
                )
            ),
        )
        failed = (await http.post("/v1/synthetic-test", json={})).json()
        assert failed["status"] == "FAIL"
        assert failed["fixture_state"] == "DESTROYED"
        assert failed["cleanup_verified"] is True
        assert failed["docker_resources_created"] == 0


@pytest.mark.parametrize("provider_name", ["openrouter", "deepseek"])
async def test_balance_endpoint_returns_only_normalized_money_fields(provider_name: str) -> None:
    secret = "provider-secret-never-returned"  # noqa: S105 - inert test credential

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {secret}"
        if provider_name == "openrouter":
            assert request.url.path == "/api/v1/key"
            payload = {
                "data": {
                    "limit": 20.5,
                    "limit_remaining": 16.25,
                    "limit_reset": "monthly",
                    "usage": 4.25,
                }
            }
        else:
            assert request.url.path == "/user/balance"
            payload = {
                "is_available": True,
                "balance_infos": [
                    {
                        "currency": "USD",
                        "total_balance": "16.25",
                        "granted_balance": "1.25",
                        "topped_up_balance": "15.00",
                    }
                ],
            }
        return httpx.Response(200, json=payload, headers={"content-type": "application/json"})

    if provider_name == "openrouter":
        provider = OpenRouterProvider(
            Settings(
                ai_provider="openrouter",
                ai_base_url="https://openrouter.ai",
                ai_model="qwen/qwen3.8-27b",
                ai_allowed_models=",".join(sorted(OPENROUTER_APPROVED_MODELS)),
                openrouter_api_key=SecretStr(secret),
            ),
            httpx.MockTransport(handler),
        )
    else:
        provider = InternalOpenAICompatibleProvider(
            Settings(
                ai_provider="internal_openai_compatible",
                ai_base_url="https://api.deepseek.com",
                ai_model="deepseek-chat",
                ai_allowed_models="deepseek-chat",
                ai_auth_mode="bearer",
                ai_auth_token=SecretStr(secret),
            ),
            httpx.MockTransport(handler),
        )
    gateway._provider = provider
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        response = await http.get("/v1/billing/balance")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "AVAILABLE"
    assert body["balances"][0]["remaining"] == "16.25"
    assert secret not in response.text


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


# --- BEAST adversary route admission --------------------------------------------------------------


def _beast_decide_body() -> dict[str, Any]:
    return {
        "run_id": "run-001",
        "scenario_id": "endpoint_discovery",
        "objective": "Enumerate the reachable endpoint surface of the synthetic target.",
        "target_origin": "http://beast-target:8080",
        "target_base_path": "/lab/beast/vulnerable",
        "synthetic_public_accounts": [{"username": "user-a", "token": "lab-token-user-a"}],
        "sequence": 1,
        "remaining_commands": 8,
        "remaining_time_seconds": 120,
        "objective_evidence_sufficient": False,
        "decision_requirements": ["Expose actual response-body bytes from an observed URL."],
        "observations": [],
    }


_BEAST_COMMAND_DECISION = json.dumps(
    {
        "decision_type": "command",
        "hypothesis": "probe the documented root endpoint",
        "expected_intent": "retrieve the base response body",
        "command_text": "curl http://beast-target:8080/lab/beast/vulnerable",
    }
)


async def test_beast_decide_admits_the_selected_hosted_model() -> None:
    """BEAST follows the operator's selected gateway model: the routed OpenRouter model serves the
    adversary decision with its hosted provenance shape, exactly like the Ollama path."""

    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "gen-test",
                "model": OPENROUTER_QWEN_MODEL,
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": _BEAST_COMMAND_DECISION},
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 48, "total_tokens": 68},
            },
        )

    gateway._provider = OpenRouterProvider(  # noqa: SLF001 - gateway singleton under test
        Settings(
            ai_provider="openrouter",
            ai_base_url="https://openrouter.test",
            ai_model=OPENROUTER_QWEN_MODEL,
            ai_allowed_models=",".join(sorted(OPENROUTER_APPROVED_MODELS)),
            openrouter_api_key="sk-or-test-placeholder",
        ),
        httpx.MockTransport(chat),
    )
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        response = await http.post("/v1/beast/decide", json=_beast_decide_body())
    assert response.status_code == 200
    body = response.json()
    assert body["model"] == OPENROUTER_QWEN_MODEL
    assert body["decision"]["decision_type"] == "command"
    # The hosted provenance envelope is passed through for the controller's per-family check.
    assert body["metadata"]["provider_type"] == "openrouter"
    assert body["metadata"]["model"] == OPENROUTER_QWEN_MODEL


async def test_beast_decide_refuses_providers_without_an_adversary_route() -> None:
    gateway._provider = responses_provider(lambda r: httpx.Response(200))  # noqa: SLF001
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as http:
        response = await http.post("/v1/beast/decide", json=_beast_decide_body())
    assert response.status_code == 409
    assert response.json()["detail"] == "BEAST_REQUIRES_SUPPORTED_PROVIDER"
