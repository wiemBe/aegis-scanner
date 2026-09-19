"""OllamaProvider tests. All Ollama traffic is mocked (httpx.MockTransport); no network is used.

Covers the native /api/chat contract and the fail-closed paths required for a local/private model:
malformed JSON, schema violations, model mismatch, redirects, timeouts, oversized bodies, non-JSON
content types, Ollama unavailable, model-not-installed, truncated (length) output, hidden-reasoning
suppression, and configuration-only model interchange (qwen3:4b <-> qwen3:8b).
"""

import json
from typing import Any

import httpx
import pytest

from aegis.planner import PlannerFailure
from aegis.providers import OllamaProvider
from aegis.settings import Settings

VALID_EXECUTE = json.dumps(
    {
        "decision_type": "execute",
        "summary": "Read user_b's object with user_a's credentials",
        "hypothesis": {
            "id": "bola-cross-owner",
            "title": "Cross-owner account read",
            "category": "BOLA",
            "rationale": "Caller-selected object IDs require ownership checks.",
            "confidence": 0.8,
            "requests": [
                {
                    "name": "cross-owner-probe",
                    "method": "GET",
                    "path": "/api/v1/accounts/B-200",
                    "credential_profile": "user_a",
                    "purpose": "Read another owner's synthetic object.",
                }
            ],
        },
    }
)
STOP = '{"decision_type":"stop","summary":"Need more evidence"}'


def ollama_reply(
    content: str = STOP,
    model: str = "qwen3:4b",
    done: bool = True,
    done_reason: str = "stop",
    prompt_eval_count: int = 416,
    eval_count: int = 239,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "created_at": "2026-01-01T00:00:00Z",
        "message": {"role": "assistant", "content": content},
        "done": done,
        "done_reason": done_reason,
        "total_duration": 11_000_000_000,
        "load_duration": 2_000_000_000,
        "prompt_eval_count": prompt_eval_count,
        "eval_count": eval_count,
    }
    if extra:
        body.update(extra)
    return body


def provider(chat_handler: Any, **kwargs: Any) -> OllamaProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.34.2"})
        if request.method == "GET" and request.url.path == "/api/tags":
            return httpx.Response(
                200,
                json={"models": [{"model": "qwen3:4b", "digest": "sha256:abc"}]},
            )
        return chat_handler(request)

    settings = Settings(ai_provider="ollama", ai_base_url="http://ollama.test:11434", **kwargs)
    return OllamaProvider(settings, httpx.MockTransport(handler))


async def test_successful_schema_response_and_metadata() -> None:
    seen: list[httpx.Request] = []

    def chat(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = json.loads(request.content)
        assert str(request.url).endswith("/api/chat")
        assert payload["stream"] is False and payload["think"] is False
        assert payload["model"] == "qwen3:4b"
        assert payload["options"] == {
            "temperature": 0.0,
            "seed": 42,
            "num_ctx": 8192,
            "num_predict": 2048,
        }
        # Contract V2: the per-state discriminated-union schema is passed through Ollama's
        # format field (no permitted set declared here -> full vocabulary).
        fmt = payload["format"]
        assert "oneOf" in fmt and set(fmt["discriminator"]["mapping"]) == {
            "hypothesis", "execute", "continue", "stop", "review"
        }
        return httpx.Response(200, json=ollama_reply(content=VALID_EXECUTE))

    result = await provider(chat).decide({"surface": {"paths": {}}}, 2048)
    assert result.decision.decision_type == "execute"
    assert result.decision.hypothesis is not None
    assert result.decision.hypothesis.category == "BOLA"
    assert result.model == "qwen3:4b"
    assert result.usage.input_tokens == 416 and result.usage.output_tokens == 239
    assert result.usage.total_tokens == 655
    meta = result.metadata
    assert meta.provider_type == "ollama" and meta.runtime_version == "0.34.2"
    assert meta.model_digest == "sha256:abc" and meta.context_length == 8192
    assert meta.temperature == 0.0 and meta.seed == 42 and meta.stop_reason == "stop"
    assert meta.total_duration_ms == 11000 and meta.load_duration_ms == 2000
    assert len(seen) == 1


async def test_malformed_json_fails_closed() -> None:
    p = provider(lambda r: httpx.Response(200, json=ollama_reply(content="not json at all")))
    with pytest.raises(PlannerFailure) as exc:
        await p.decide({}, 2048)
    assert str(exc.value).startswith("MODEL_RESPONSE_REJECTED")


async def test_schema_violation_fails_closed() -> None:
    # Valid JSON, wrong shape (missing required fields / bad action).
    bad = json.dumps({"decision_type": "delete-everything", "summary": "xyz"})
    p = provider(lambda r: httpx.Response(200, json=ollama_reply(content=bad)))
    with pytest.raises(PlannerFailure):
        await p.decide({}, 2048)


async def test_state_changing_method_in_plan_fails_closed() -> None:
    plan = json.loads(VALID_EXECUTE)
    plan["hypothesis"]["requests"][0]["method"] = "POST"
    p = provider(lambda r: httpx.Response(200, json=ollama_reply(content=json.dumps(plan))))
    with pytest.raises(PlannerFailure):
        await p.decide({}, 2048)


async def test_origin_escape_path_in_plan_fails_closed() -> None:
    plan = json.loads(VALID_EXECUTE)
    plan["hypothesis"]["requests"][0]["path"] = "//evil.invalid/api/v1/accounts/B-200"
    p = provider(lambda r: httpx.Response(200, json=ollama_reply(content=json.dumps(plan))))
    with pytest.raises(PlannerFailure):
        await p.decide({}, 2048)


async def test_model_mismatch_fails_closed() -> None:
    p = provider(lambda r: httpx.Response(200, json=ollama_reply(model="qwen3:0.5b")))
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH"):
        await p.decide({}, 2048)


async def test_redirect_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.invalid/api/chat"})

    with pytest.raises(PlannerFailure, match="PROVIDER_REDIRECT"):
        await provider(chat).decide({}, 2048)


async def test_timeout_fails_closed_without_leak() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("ollama internal secret detail", request=request)

    with pytest.raises(PlannerFailure, match="ReadTimeout") as exc:
        await provider(chat).decide({}, 2048)
    assert "secret detail" not in str(exc.value)


async def test_oversized_body_fails_closed() -> None:
    p = provider(lambda r: httpx.Response(200, text="x" * 5000), max_response_bytes=1024)
    with pytest.raises(PlannerFailure):
        await p.decide({}, 2048)


async def test_non_json_content_type_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{}", headers={"content-type": "text/html"})

    with pytest.raises(PlannerFailure, match="UNEXPECTED_CONTENT_TYPE"):
        await provider(chat).decide({}, 2048)


async def test_ollama_unavailable_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(PlannerFailure, match="MODEL_RESPONSE_REJECTED_ConnectError"):
        await provider(chat).decide({}, 2048)


async def test_model_not_installed_fails_closed() -> None:
    def chat(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": 'model "qwen3:4b" not found'})

    with pytest.raises(PlannerFailure):
        await provider(chat).decide({}, 2048)


async def test_truncated_length_output_fails_closed() -> None:
    # qwen3 over-generates free-text fields and hits num_predict -> truncated (invalid) JSON.
    truncated = '{"decision_type":"stop","summary":"the model rambled on and on and'
    p = provider(
        lambda r: httpx.Response(
            200, json=ollama_reply(content=truncated, done_reason="length")
        )
    )
    with pytest.raises(PlannerFailure, match="INCOMPLETE_MODEL_OUTPUT_LENGTH"):
        await p.decide({}, 2048)


async def test_hidden_reasoning_is_dropped() -> None:
    # Even if a future model leaks a 'thinking' field, it is never read, stored or returned.
    reply = ollama_reply(content=STOP)
    reply["message"]["thinking"] = "secret chain of thought that must never be stored"
    result = await provider(lambda r: httpx.Response(200, json=reply)).decide({}, 2048)
    serialized = json.dumps(result.metadata.model_dump()) + result.decision.model_dump_json()
    assert "secret chain of thought" not in serialized


async def test_credential_exfiltration_in_output_is_not_repaired() -> None:
    # A decision echoing a credential is still schema-valid here; the provider returns it verbatim
    # and the control-plane SECRET_IN_PLANNER_OUTPUT guard (tested in the loop) fails the scan.
    leak = json.dumps(
        {"decision_type": "stop", "summary": "token is lab-token-user-a"}
    )
    result = await provider(lambda r: httpx.Response(200, json=ollama_reply(content=leak))).decide(
        {}, 2048
    )
    assert result.decision.decision_type == "stop"  # not repaired; caught downstream


def test_model_interchange_is_configuration_only() -> None:
    # Switching qwen3:4b -> qwen3:8b requires configuration only; both are in the allowlist.
    small = provider(lambda r: httpx.Response(200, json=ollama_reply()))
    assert small.model == "qwen3:4b"
    big = provider(
        lambda r: httpx.Response(200, json=ollama_reply(model="qwen3:8b")), ai_model="qwen3:8b"
    )
    assert big.model == "qwen3:8b"


def test_model_outside_allowlist_rejected() -> None:
    with pytest.raises(ValueError, match="allowlist"):
        provider(lambda r: httpx.Response(200), ai_model="llama3:70b")


def test_base_url_with_path_rejected() -> None:
    with pytest.raises(ValueError, match="bare origin"):
        OllamaProvider(Settings(ai_provider="ollama", ai_base_url="http://ollama.test:11434/api"))


async def test_qwen3_8b_switch_sends_new_model() -> None:
    seen: list[str] = []

    def chat(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content)["model"])
        return httpx.Response(200, json=ollama_reply(model="qwen3:8b"))

    await provider(chat, ai_model="qwen3:8b").decide({}, 2048)
    assert seen == ["qwen3:8b"]
