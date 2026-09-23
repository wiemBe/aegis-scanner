"""Regression tests for the exact Phase 1.7-A provider binding and safe rejection audit."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from aegis.multi_agent.contracts import AgentRole
from aegis.multi_agent.model import GatewayAgentModel
from aegis.multi_agent.provider_binding import (
    PHASE_1_7A_CANONICAL_MODEL,
    ProviderBindingFailure,
    provider_binding_preflight,
)
from aegis.planner import PlannerFailure
from aegis.providers import InternalOpenAICompatibleProvider
from aegis.settings import Settings


def settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "ai_provider": "internal_openai_compatible",
        "ai_base_url": "https://api.deepseek.com",
        "ai_model": PHASE_1_7A_CANONICAL_MODEL,
        "ai_allowed_models": PHASE_1_7A_CANONICAL_MODEL,
        "ai_auth_mode": "none",
        "ai_response_format": "json_object",
        "ai_supports_seed": False,
        "ai_use_egress_proxy": False,
        "llm_gateway_url": "http://gateway",
    }
    values.update(overrides)
    return Settings(**values)


def health_transport(*, model: str | None = PHASE_1_7A_CANONICAL_MODEL) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET" and request.url.path == "/health"
        body = {"status": "ok", "provider": "internal_openai_compatible"}
        if model is not None:
            body["model"] = model
        return httpx.Response(200, json=body)

    return httpx.MockTransport(handler)


async def test_canonical_model_binding_match() -> None:
    result = await provider_binding_preflight(
        settings(), PHASE_1_7A_CANONICAL_MODEL, health_transport()
    )
    assert result.exact_match is True
    assert result.acceptance_requested_model == PHASE_1_7A_CANONICAL_MODEL
    assert result.gateway_configured_model == PHASE_1_7A_CANONICAL_MODEL
    assert result.gateway_health_model == PHASE_1_7A_CANONICAL_MODEL
    assert result.allowlisted_models == [PHASE_1_7A_CANONICAL_MODEL]


async def test_gateway_requested_model_mismatch_fails_before_health() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    with pytest.raises(ProviderBindingFailure, match="GATEWAY_REQUESTED_MODEL_MISMATCH"):
        await provider_binding_preflight(
            settings(ai_model="deepseek-chat"),
            PHASE_1_7A_CANONICAL_MODEL,
            httpx.MockTransport(handler),
        )
    assert calls == 0


async def test_gateway_health_requested_model_mismatch() -> None:
    with pytest.raises(ProviderBindingFailure, match="GATEWAY_HEALTH_REQUESTED_MODEL_MISMATCH"):
        await provider_binding_preflight(
            settings(), PHASE_1_7A_CANONICAL_MODEL, health_transport(model="deepseek-chat")
        )


async def test_allowlist_mismatch_fails_before_health() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    with pytest.raises(ProviderBindingFailure, match="MODEL_ALLOWLIST_MISMATCH"):
        await provider_binding_preflight(
            settings(ai_allowed_models="deepseek-v4-pro,deepseek-chat"),
            PHASE_1_7A_CANONICAL_MODEL,
            httpx.MockTransport(handler),
        )
    assert calls == 0


async def test_stale_environment_default_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_MODEL", "deepseek-chat")
    stale = Settings(
        ai_provider="internal_openai_compatible",
        ai_allowed_models=PHASE_1_7A_CANONICAL_MODEL,
        llm_gateway_url="http://gateway",
    )
    with pytest.raises(ProviderBindingFailure, match="GATEWAY_REQUESTED_MODEL_MISMATCH"):
        await provider_binding_preflight(stale, PHASE_1_7A_CANONICAL_MODEL, health_transport())


async def test_missing_gateway_health_model_identity_fails_closed() -> None:
    with pytest.raises(ProviderBindingFailure, match="GATEWAY_HEALTH_MODEL_MISSING"):
        await provider_binding_preflight(
            settings(), PHASE_1_7A_CANONICAL_MODEL, health_transport(model=None)
        )


async def test_provider_response_mismatch_retains_exact_reported_identity() -> None:
    response = {
        "model": "deepseek-chat",
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    provider = InternalOpenAICompatibleProvider(
        settings(), httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_MISMATCH") as caught:
        await provider.generate_agent(
            AgentRole.SURFACE_AGENT,
            "OBSERVE_SURFACE",
            {"target_ref": "range-bank"},
            {"type": "object"},
            128,
        )
    assert caught.value.provider_reported_model == "deepseek-chat"


async def test_missing_provider_response_model_identity_fails_closed() -> None:
    response = {
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    provider = InternalOpenAICompatibleProvider(
        settings(), httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    )
    with pytest.raises(PlannerFailure, match="PROVIDER_MODEL_IDENTITY_MISSING"):
        await provider.generate_agent(
            AgentRole.SURFACE_AGENT,
            "OBSERVE_SURFACE",
            {"target_ref": "range-bank"},
            {"type": "object"},
            128,
        )


async def test_rejected_provider_response_returns_auditable_sanitized_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis import gateway

    response = {
        "model": "deepseek-chat",
        "choices": [{"finish_reason": "stop", "message": {"content": "{}"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    provider = InternalOpenAICompatibleProvider(
        settings(), httpx.MockTransport(lambda _: httpx.Response(200, json=response))
    )
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(settings(), httpx.ASGITransport(app=gateway.app))

    with pytest.raises(ValueError, match="PROVIDER_MODEL_MISMATCH"):
        await model.generate(
            AgentRole.SURFACE_AGENT,
            "OBSERVE_SURFACE",
            {"target_ref": "range-bank", "operation_ids": ["getAccount"]},
            {},
        )

    assert model.provider_reported_models == ["deepseek-chat"]
    assert len(model.failed_request_projections) == 1
    projection = model.failed_request_projections[0]
    serialized = projection.model_dump_json()
    assert projection.requested_model == PHASE_1_7A_CANONICAL_MODEL
    assert projection.redaction_status == "CLEAN"
    assert projection.forbidden_categories_present == []
    assert projection.correlation_id in gateway._agent_request_projections
    assert "context" not in json.loads(serialized)
    assert "range-user-" not in serialized and "http://" not in serialized


def test_secret_markers_ignore_authorization_field_but_catch_header_leak() -> None:
    """The secret-redaction markers must catch a real Authorization header value without matching
    the contract's own legitimate `authorization` object field (regression for the single-agent
    LIVE_CASE_GATE_FAILED false positive)."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "phase_1_7a_live_acceptance", root / "scripts" / "phase_1_7a_live_acceptance.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    markers = module.SECRET_MARKERS

    legitimate = json.dumps(
        {
            "authorization": {
                "capability_id": "aegis.authorization.compare",
                "owner_credential_alias": "cred-bank-alex",
                "rationale": "Compare authorization for getAccount across owners.",
            }
        },
        sort_keys=True,
    ).lower()
    assert [m for m in markers if m in legitimate] == []

    leaked_header = json.dumps(
        {"authorization": "Bearer sk-live-provider-credential-value"}, sort_keys=True
    ).lower()
    assert [m for m in markers if m in leaked_header]
