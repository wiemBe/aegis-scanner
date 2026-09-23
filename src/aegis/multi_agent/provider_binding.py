"""Exact Phase 1.7-A provider-model binding preflight.

This check runs before the synthetic range is reset, health-checked, or contacted. It compares
only non-secret model identity/configuration fields and never accesses the provider credential.
"""

from __future__ import annotations

import json

import httpx
from pydantic import Field

from aegis.http import bounded_body
from aegis.multi_agent.contracts import StrictModel
from aegis.settings import Settings

PHASE_1_7A_CANONICAL_MODEL = "deepseek-v4-pro"


class ProviderBindingProjection(StrictModel):
    acceptance_requested_model: str = Field(min_length=1, max_length=200)
    gateway_configured_model: str = Field(min_length=1, max_length=200)
    gateway_health_model: str = Field(min_length=1, max_length=200)
    allowlisted_models: list[str] = Field(min_length=1, max_length=8)
    gateway_provider: str = Field(min_length=1, max_length=100)
    exact_match: bool


class ProviderBindingFailure(ValueError):
    def __init__(self, code: str, projection: dict[str, object]) -> None:
        super().__init__(code)
        self.code = code
        self.projection = projection


async def provider_binding_preflight(
    settings: Settings,
    requested_model: str,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ProviderBindingProjection:
    """Require one exact model string across acceptance, gateway config, health and allowlist."""
    partial: dict[str, object] = {
        "acceptance_requested_model": requested_model,
        "gateway_configured_model": settings.ai_model,
        "gateway_health_model": "MISSING",
        "allowlisted_models": sorted(settings.allowed_model_set),
        "gateway_provider": "MISSING",
        "exact_match": False,
    }
    if requested_model != PHASE_1_7A_CANONICAL_MODEL:
        raise ProviderBindingFailure("ACCEPTANCE_REQUESTED_MODEL_MISMATCH", partial)
    if settings.ai_model != requested_model:
        raise ProviderBindingFailure("GATEWAY_REQUESTED_MODEL_MISMATCH", partial)
    if settings.allowed_model_set != frozenset({requested_model}):
        raise ProviderBindingFailure("MODEL_ALLOWLIST_MISMATCH", partial)
    if settings.ai_provider != "internal_openai_compatible":
        raise ProviderBindingFailure("GATEWAY_PROVIDER_MISMATCH", partial)

    health_url = settings.llm_gateway_url.rstrip("/") + "/health"
    try:
        async with (
            httpx.AsyncClient(
                timeout=settings.model_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            ) as client,
            client.stream("GET", health_url) as response,
        ):
            raw = await bounded_body(response, settings.max_response_bytes)
            if response.status_code != 200:
                raise ProviderBindingFailure("GATEWAY_HEALTH_REJECTED", partial)
    except ProviderBindingFailure:
        raise
    except (httpx.HTTPError, ValueError):
        raise ProviderBindingFailure("GATEWAY_HEALTH_TRANSPORT_FAILURE", partial) from None

    try:
        body = json.loads(raw)
    except (TypeError, ValueError):
        raise ProviderBindingFailure("GATEWAY_HEALTH_MALFORMED", partial) from None
    health_model = body.get("model") if isinstance(body, dict) else None
    health_provider = body.get("provider") if isinstance(body, dict) else None
    if isinstance(health_provider, str) and health_provider:
        partial["gateway_provider"] = health_provider
    if not isinstance(health_model, str) or not health_model:
        raise ProviderBindingFailure("GATEWAY_HEALTH_MODEL_MISSING", partial)
    partial["gateway_health_model"] = health_model
    if health_model != requested_model:
        raise ProviderBindingFailure("GATEWAY_HEALTH_REQUESTED_MODEL_MISMATCH", partial)
    if health_provider != settings.ai_provider:
        raise ProviderBindingFailure("GATEWAY_HEALTH_PROVIDER_MISMATCH", partial)
    partial["exact_match"] = True
    return ProviderBindingProjection.model_validate(partial)
