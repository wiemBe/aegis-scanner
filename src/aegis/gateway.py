"""LLM gateway service.

This process is the *only* component that talks to a model endpoint and the only holder of any
provider credential. It sits on the internal planner-rpc network (reachable by the control plane)
and, for the local Ollama route, on a dedicated model-egress network reaching the configured
endpoint only. It is never attached to the lab/target network.

It accepts schema-validated, sanitized planner context from the control plane, delegates to a
typed PlannerProvider selected by AI_PROVIDER (the control plane holds no provider-specific request
logic), and returns only a validated AgentDecision, provider-reported token usage and non-secret
run metadata. Provider response bodies, headers, hidden chain-of-thought and any credential never
appear in its responses or logs.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from aegis.models import (
    GatewayCandidateRequest,
    GatewayCandidateResponse,
    GatewayPlanRequest,
    GatewayPlanResponse,
    GatewaySelectRequest,
    GatewaySelectResponse,
)
from aegis.planner import PlannerFailure
from aegis.providers import PlannerProvider, build_provider
from aegis.settings import get_settings

_provider: PlannerProvider | None = None


def get_provider() -> PlannerProvider:
    """Lazily build the single configured provider. Construction validates the endpoint, model
    allowlist and any credential, so the gateway fails closed at startup (via lifespan) on any
    invalid provider configuration."""
    global _provider
    if _provider is None:
        _provider = build_provider(get_settings())
    return _provider


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    get_provider()  # Fail closed on startup if provider configuration is invalid.
    yield


app = FastAPI(title="Aegis LLM Gateway", version="0.3.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    provider = get_provider()
    return {"status": "ok", "provider": provider.provider_type, "model": provider.model}


@app.post("/v1/plan", response_model=GatewayPlanResponse)
async def plan(request: GatewayPlanRequest) -> GatewayPlanResponse:
    try:
        result = await get_provider().decide(
            request.context.model_dump(mode="json"), request.max_output_tokens
        )
    except PlannerFailure as exc:
        # Only a safe diagnostic code and an optional response digest leave the gateway. No
        # provider body, no headers, no credential, no raw model text.
        raise HTTPException(
            status_code=502,
            detail={"code": str(exc), "response_sha256": exc.response_digest},
        ) from None
    return GatewayPlanResponse(
        model=result.model,
        decision=result.decision,
        usage=result.usage,
        metadata=result.metadata,
        planner_contract_version=result.planner_contract_version,
    )


@app.post("/v1/candidates", response_model=GatewayCandidateResponse)
async def candidates(request: GatewayCandidateRequest) -> GatewayCandidateResponse:
    try:
        result = await get_provider().enumerate_candidates(
            request.context.model_dump(mode="json"),
            request.max_output_tokens,
            request.max_candidates,
        )
    except PlannerFailure as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": str(exc), "response_sha256": exc.response_digest},
        ) from None
    return GatewayCandidateResponse(
        model=result.model,
        result=result.result,
        usage=result.usage,
        metadata=result.metadata,
        planner_contract_version=result.planner_contract_version,
    )


@app.post("/v1/select", response_model=GatewaySelectResponse)
async def select(request: GatewaySelectRequest) -> GatewaySelectResponse:
    try:
        result = await get_provider().select_candidate(
            request.context.model_dump(mode="json"),
            request.max_output_tokens,
            request.validated_candidates,
        )
    except PlannerFailure as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": str(exc), "response_sha256": exc.response_digest},
        ) from None
    return GatewaySelectResponse(
        model=result.model,
        selection=result.selection,
        usage=result.usage,
        metadata=result.metadata,
        planner_contract_version=result.planner_contract_version,
    )
