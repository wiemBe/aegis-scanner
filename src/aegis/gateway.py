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

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from aegis.beast.contracts import BeastDecisionRequest, BeastDecisionResponse
from aegis.models import (
    GatewayCandidateRequest,
    GatewayCandidateResponse,
    GatewayPlanRequest,
    GatewayPlanResponse,
    GatewaySelectRequest,
    GatewaySelectResponse,
)
from aegis.multi_agent.contracts import (
    AgentGatewayRequest,
    AgentGatewayRequestProjection,
    AgentGatewayResponse,
    AgentRole,
    AuthorizationAgentOutput,
    LeadTaskOutput,
    ModelUsage,
    SingleAgentOutput,
    SurfaceAgentOutput,
)
from aegis.planner import PlannerFailure
from aegis.providers import OllamaProvider, PlannerProvider, agent_system_prompt, build_provider
from aegis.settings import get_settings

_provider: PlannerProvider | None = None
_AGENT_PROJECTION_LIMIT = 256
_agent_request_projections: dict[str, AgentGatewayRequestProjection] = {}


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

_AGENT_OUTPUTS: dict[str, type[BaseModel]] = {
    "PLAN_SURFACE": LeadTaskOutput,
    "OBSERVE_SURFACE": SurfaceAgentOutput,
    "PLAN_AUTHORIZATION": LeadTaskOutput,
    "TEST_AUTHORIZATION": AuthorizationAgentOutput,
    "SINGLE_AGENT_BOLA": SingleAgentOutput,
}
_AGENT_TASK_ROLES = {
    "PLAN_SURFACE": AgentRole.LEAD_ORCHESTRATOR,
    "OBSERVE_SURFACE": AgentRole.SURFACE_AGENT,
    "PLAN_AUTHORIZATION": AgentRole.LEAD_ORCHESTRATOR,
    "TEST_AUTHORIZATION": AgentRole.AUTHORIZATION_AGENT,
    "SINGLE_AGENT_BOLA": AgentRole.AUTHORIZATION_AGENT,
}


@app.get("/health")
async def health() -> dict[str, str]:
    provider = get_provider()
    return {"status": "ok", "provider": provider.provider_type, "model": provider.model}


def _agent_projection(
    request: AgentGatewayRequest,
    role: AgentRole,
    output_type: type[BaseModel],
    schema: dict[str, object],
    system_contract: str,
) -> AgentGatewayRequestProjection:
    """Create the bounded audit projection before provider dispatch.

    The digest binds the safe metadata to the exact outbound message material while the projection
    itself contains no prompt bodies, credential values, scenario mode, answer key or reasoning.
    """
    provider = get_provider()
    context_json = json.dumps(request.context, sort_keys=True, separators=(",", ":"))
    schema_json = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    outbound = {
        "model": provider.model,
        "system": system_contract,
        "context": request.context,
        "schema": schema,
    }
    outbound_text = json.dumps(outbound, sort_keys=True, separators=(",", ":")).lower()
    forbidden_checks = {
        "SCENARIO_MODE": ("vulnerable", "patched"),
        "ANSWER_KEY": ("answer_key", "ground_truth"),
        "EXPECTED_VERDICT": ("expected_verdict", '"confirmed"', '"pass"'),
        "CREDENTIAL_VALUE": ("range-user-", "bearer ", "lab-token-"),
        "TARGET_ORIGIN": ("http://", "https://"),
    }
    present = [
        category
        for category, markers in forbidden_checks.items()
        if any(marker in outbound_text for marker in markers)
    ]
    if present:
        raise HTTPException(status_code=422, detail={"code": "AGENT_REQUEST_NOT_SANITIZED"})
    digest_material = json.dumps(outbound, sort_keys=True, separators=(",", ":")).encode()
    base = {
        "correlation_id": f"agreq-{uuid4().hex[:24]}",
        "role": role,
        "task_type": request.task_type,
        "requested_model": provider.model,
        "schema_identifier": output_type.__name__,
        "message_field_classifications": {
            "system": "BOUNDED_SYSTEM_CONTRACT",
            "user": "BOUNDED_REFERENCE_CONTEXT",
            "response_format": "STRICT_OUTPUT_SCHEMA",
        },
        "context_field_names": sorted(request.context),
        "context_sha256": hashlib.sha256(context_json.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(schema_json.encode()).hexdigest(),
        "system_contract_sha256": hashlib.sha256(system_contract.encode()).hexdigest(),
        "redaction_status": "CLEAN",
        "forbidden_categories_present": present,
    }
    projection_digest = hashlib.sha256(
        json.dumps(base, sort_keys=True, separators=(",", ":"), default=str).encode()
        + digest_material
    ).hexdigest()
    projection = AgentGatewayRequestProjection.model_validate(
        {**base, "projection_sha256": projection_digest}
    )
    if len(_agent_request_projections) >= _AGENT_PROJECTION_LIMIT:
        _agent_request_projections.pop(next(iter(_agent_request_projections)))
    _agent_request_projections[projection.correlation_id] = projection
    return projection


@app.get("/v1/agents/projections/{correlation_id}", response_model=AgentGatewayRequestProjection)
async def agent_projection(correlation_id: str) -> AgentGatewayRequestProjection:
    projection = _agent_request_projections.get(correlation_id)
    if projection is None:
        raise HTTPException(status_code=404, detail={"code": "PROJECTION_NOT_FOUND"})
    return projection


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


@app.post("/v1/agents/generate", response_model=AgentGatewayResponse)
async def generate_agent(request: AgentGatewayRequest) -> AgentGatewayResponse:
    output_type = _AGENT_OUTPUTS[request.task_type]
    role = AgentRole(request.role)
    if role is not _AGENT_TASK_ROLES[request.task_type]:
        raise HTTPException(status_code=422, detail={"code": "AGENT_TASK_ROLE_MISMATCH"})
    schema = output_type.model_json_schema()
    system_contract = agent_system_prompt(role, request.task_type)
    projection = _agent_projection(request, role, output_type, schema, system_contract)
    try:
        result = await get_provider().generate_agent(
            role,
            request.task_type,
            request.context,
            schema,
            request.max_output_tokens,
        )
        validated = output_type.model_validate_json(result.payload_json)
    except PlannerFailure as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "code": str(exc),
                "response_sha256": exc.response_digest,
                "provider_reported_model": exc.provider_reported_model,
                "request_projection": projection.model_dump(mode="json"),
            },
        ) from None
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "AGENT_OUTPUT_REJECTED",
                "request_projection": projection.model_dump(mode="json"),
            },
        ) from exc
    return AgentGatewayResponse(
        model=result.model,
        payload_json=validated.model_dump_json(),
        usage=ModelUsage(
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
        ),
        request_projection=projection,
    )


@app.post("/v1/beast/decide", response_model=BeastDecisionResponse)
async def beast_decide(request: BeastDecisionRequest) -> BeastDecisionResponse:
    """Phase 1.4 deliberately has no demo/mock/heuristic provider or command fallback."""

    provider = get_provider()
    if not isinstance(provider, OllamaProvider) or provider.provider_type != "ollama":
        raise HTTPException(status_code=409, detail="BEAST_REQUIRES_LOCAL_OLLAMA_MODEL")
    try:
        result = await provider.adversary_decide(request)
    except PlannerFailure as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": str(exc), "response_sha256": exc.response_digest},
        ) from None
    return BeastDecisionResponse(
        model=result.model,
        decision=result.decision,
        usage=result.usage.model_dump(mode="json"),
        metadata=result.metadata.model_dump(mode="json"),
    )
