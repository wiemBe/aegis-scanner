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
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

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
    AttackChainPlanOutput,
    AuthorizationAgentOutput,
    ChainExplanationOutput,
    ChainNextStepOutput,
    ChainStageInterpretationOutput,
    CloudBoundaryInterpretationOutput,
    CloudBoundaryPlanOutput,
    CloudBoundarySubmissionOutput,
    LeadTaskOutput,
    ModelUsage,
    ReconDelegationOutput,
    ReconInterpretationOutput,
    ReconPlanOutput,
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
    # Phase 1.7-C controlled Recon Agent task types. The schema is server-selected per task; the
    # caller never supplies or weakens it. Each shape is reference-only: no raw flag, origin,
    # template, policy, payload, credential or verdict is representable.
    "PLAN_RECON": ReconPlanOutput,
    "INTERPRET_RECON_OBSERVATIONS": ReconInterpretationOutput,
    "DELEGATE_RECON_HYPOTHESIS": ReconDelegationOutput,
    # Phase 1.9 controlled Cloud Boundary Agent task types. Same reference-only guarantee: no raw
    # URL, credential, header, request body or verdict is representable in any of these shapes.
    "PLAN_CLOUD_BOUNDARY": CloudBoundaryPlanOutput,
    "INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS": CloudBoundaryInterpretationOutput,
    "SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION": CloudBoundarySubmissionOutput,
    # Phase 2.0 verified multi-primitive attack-chain task types. Same reference-only guarantee: no
    # raw URL, credential value, request body, verdict, severity or final impact is representable.
    "PLAN_ATTACK_CHAIN": AttackChainPlanOutput,
    "INTERPRET_CHAIN_STAGE": ChainStageInterpretationOutput,
    "SELECT_NEXT_CHAIN_STEP": ChainNextStepOutput,
    "EXPLAIN_VERIFIED_CHAIN": ChainExplanationOutput,
}
_AGENT_TASK_ROLES = {
    "PLAN_SURFACE": AgentRole.LEAD_ORCHESTRATOR,
    "OBSERVE_SURFACE": AgentRole.SURFACE_AGENT,
    "PLAN_AUTHORIZATION": AgentRole.LEAD_ORCHESTRATOR,
    "TEST_AUTHORIZATION": AgentRole.AUTHORIZATION_AGENT,
    "SINGLE_AGENT_BOLA": AgentRole.AUTHORIZATION_AGENT,
    "PLAN_RECON": AgentRole.RECON_AGENT,
    "INTERPRET_RECON_OBSERVATIONS": AgentRole.RECON_AGENT,
    "DELEGATE_RECON_HYPOTHESIS": AgentRole.RECON_AGENT,
    "PLAN_CLOUD_BOUNDARY": AgentRole.CLOUD_BOUNDARY_AGENT,
    "INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS": AgentRole.CLOUD_BOUNDARY_AGENT,
    "SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION": AgentRole.CLOUD_BOUNDARY_AGENT,
    # Phase 2.0: the Chain Agent plans/interprets/explains the chain; the Stage-B (Authorization)
    # agent selects the next credential-backed step it will execute.
    "PLAN_ATTACK_CHAIN": AgentRole.CHAIN_AGENT,
    "INTERPRET_CHAIN_STAGE": AgentRole.CHAIN_AGENT,
    "SELECT_NEXT_CHAIN_STEP": AgentRole.AUTHORIZATION_AGENT,
    "EXPLAIN_VERIFIED_CHAIN": AgentRole.CHAIN_AGENT,
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


# Bound on the number of validation-error locations surfaced on an AGENT_OUTPUT_REJECTED response.
_MAX_VALIDATION_ERRORS = 20
# A contract validator code is a SCREAMING_SNAKE_CASE constant raised by our own model validators
# (e.g. PLAN_RECON_NMAP_REQUIRES_TYPED_PLAN). Only a message matching this exact shape may be
# surfaced, so a value_error whose message would echo model input (lowercase JSON, free text,
# punctuation) never matches and never leaks.
_CONTRACT_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,80}$")


def _validation_error_summary(exc: Exception) -> list[dict[str, str]] | None:
    """Bounded, value-free summary of a structured-output validation failure.

    Only the schema-side location path and the pydantic error *type* are copied — never the
    offending value, the raw input or any error context — so no fragment of raw model output leaves
    the gateway. For a model-level ``value_error`` (a cross-field ``@model_validator`` on our own
    contract) the validator's constant code is added too, but only when the message is a bare
    SCREAMING_SNAKE_CASE token; a message that would carry model-supplied text never matches. Each
    location is truncated and the list is capped. This lets an operator see *which* contract
    constraint the completed output violated without exposing what the model actually produced.
    """
    if not isinstance(exc, ValidationError):
        return None
    summary: list[dict[str, str]] = []
    for err in exc.errors(include_url=False):
        loc = ".".join(str(part) for part in err.get("loc", ()))[:200]
        item = {"loc": loc, "type": str(err.get("type", "unknown"))[:100]}
        code = _contract_code(err)
        if code is not None:
            item["code"] = code
        summary.append(item)
        if len(summary) >= _MAX_VALIDATION_ERRORS:
            break
    return summary


def _contract_code(err: Mapping[str, object]) -> str | None:
    """Return our own validator's constant code for a value_error, or None. Never returns input."""
    if err.get("type") != "value_error":
        return None
    msg = str(err.get("msg", ""))
    # Pydantic renders a raised ValueError as "Value error, <message>"; recover the raw message.
    token = msg.removeprefix("Value error, ").strip()
    return token if _CONTRACT_CODE_RE.match(token) else None


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
        # The sanitized pre-dispatch projection is always returned, including on a
        # finish_reason=length truncation, so every rejection path stays auditable. Only non-secret
        # scalars leave here: code, digest, model identity, finish reason and bounded token/length
        # counts. No provider body, raw content or reasoning_content text is ever included.
        raise HTTPException(
            status_code=502,
            detail={
                "code": str(exc),
                "response_sha256": exc.response_digest,
                "provider_reported_model": exc.provider_reported_model,
                "finish_reason": exc.finish_reason,
                "provider_usage": exc.provider_usage,
                "content_length": exc.content_length,
                "reasoning_present": exc.reasoning_present,
                "reasoning_length": exc.reasoning_length,
                "request_projection": projection.model_dump(mode="json"),
            },
        ) from None
    except (ValueError, KeyError, TypeError) as exc:
        # A complete response whose JSON fails the strict server-selected contract fails closed. A
        # bounded, value-free summary (schema location + error type only) is attached so the reason
        # is auditable; no raw payload, content or reasoning text is ever included.
        raise HTTPException(
            status_code=502,
            detail={
                "code": "AGENT_OUTPUT_REJECTED",
                "validation_errors": _validation_error_summary(exc),
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
