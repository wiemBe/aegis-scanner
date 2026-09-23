"""Model adapter contract for role-scoped structured generation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Protocol

import httpx

from aegis.http import bounded_body
from aegis.multi_agent.contracts import (
    AgentGatewayRequestProjection,
    AgentGatewayResponse,
    AgentRole,
    GatewayCallRecord,
    ModelResult,
    ModelUsage,
)
from aegis.settings import Settings


class AgentModel(Protocol):
    name: str

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult: ...


class GatewayAgentModel:
    """Provider-independent control-plane adapter to the existing isolated model gateway."""

    name = "MODEL_GATEWAY"

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = settings.llm_gateway_url.rstrip("/") + "/v1/agents/generate"
        self._model = settings.ai_model
        self._allowed_models = settings.allowed_model_set
        self._max_output_tokens = settings.max_completion_tokens
        self._body_limit = settings.max_response_bytes
        self._timeout = settings.model_timeout_seconds + 10
        self._transport = transport
        self.call_attempts = 0
        self.call_records: list[GatewayCallRecord] = []
        self.failure_codes: list[str] = []
        self.failed_request_projections: list[AgentGatewayRequestProjection] = []
        self.provider_reported_models: list[str] = []

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        # The gateway derives the schema from role/task; it never trusts a caller-supplied schema.
        del output_schema
        request = {
            "role": role.value,
            "task_type": task_type,
            "context": dict(context),
            "max_output_tokens": self._max_output_tokens,
        }
        self.call_attempts += 1
        async with (
            httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client,
            client.stream("POST", self._url, json=request) as response,
        ):
            raw = await bounded_body(response, self._body_limit)
            if response.status_code != 200:
                code = "AGENT_GATEWAY_REJECTED"
                try:
                    detail = json.loads(raw).get("detail")
                    if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                        code = detail["code"][:100]
                        reported_model = detail.get("provider_reported_model")
                        if isinstance(reported_model, str) and reported_model:
                            self.provider_reported_models.append(reported_model[:200])
                        safe_projection = detail.get("request_projection")
                        if isinstance(safe_projection, dict):
                            self.failed_request_projections.append(
                                AgentGatewayRequestProjection.model_validate_json(
                                    json.dumps(safe_projection)
                                )
                            )
                except (ValueError, AttributeError):
                    pass
                self.failure_codes.append(code)
                raise ValueError(f"AGENT_GATEWAY_REJECTED:{code}")
        body = AgentGatewayResponse.model_validate_json(raw)
        if body.model != self._model or body.model not in self._allowed_models:
            raise ValueError("PROVIDER_MODEL_MISMATCH")
        self.provider_reported_models.append(body.model)
        if body.usage.input_tokens + body.usage.output_tokens > self._max_output_tokens * 8:
            raise ValueError("PROVIDER_USAGE_EXCEEDED_CEILING")
        validated_output: object = json.loads(body.payload_json)
        if not isinstance(validated_output, dict):
            raise ValueError("AGENT_GATEWAY_OUTPUT_NOT_OBJECT")
        self.call_records.append(
            GatewayCallRecord(
                role=role,
                task_type=task_type,
                request_projection=body.request_projection,
                validated_output=validated_output,
                usage=body.usage,
            )
        )
        return ModelResult(payload_json=body.payload_json, usage=body.usage)


class OfflineBankModel:
    """Bounded offline acceptance model.

    It receives the same mode-blind envelope as a real provider adapter and emits only strict
    structured output. It is an acceptance fixture, not evidence of live-model performance.
    """

    name = "OFFLINE_STRUCTURED_FIXTURE"

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        del output_schema
        if task_type == "PLAN_SURFACE":
            payload: dict[str, object] = {
                "task_type": "OBSERVE_SURFACE",
                "objective": (
                    "Identify documented account read operations and resource identifiers."
                ),
            }
        elif task_type == "OBSERVE_SURFACE":
            payload = {
                "summary": (
                    "Documented account detail and transaction reads accept account identifiers."
                ),
                "operation_ids": ["getAccount", "listAccountTransactions"],
                "resource_refs": ["resource-account-owner", "resource-account-alternate"],
            }
        elif task_type == "PLAN_AUTHORIZATION":
            payload = {
                "task_type": "TEST_AUTHORIZATION",
                "objective": (
                    "Compare owner and cross-owner access using controller credential aliases."
                ),
            }
        elif task_type == "TEST_AUTHORIZATION":
            payload = self._authorization()
        elif task_type == "SINGLE_AGENT_BOLA":
            payload = {
                "summary": "The documented account surface supports a bounded owner comparison.",
                "operation_ids": ["getAccount", "listAccountTransactions"],
                "resource_refs": ["resource-account-owner", "resource-account-alternate"],
                "authorization": self._authorization(),
            }
        else:
            raise ValueError("OFFLINE_MODEL_TASK_UNSUPPORTED")
        # Stable approximate usage is sufficient for offline accounting tests; real adapters use
        # provider-reported usage.
        input_tokens = max(1, len(json.dumps(dict(context), sort_keys=True)) // 4)
        output = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return ModelResult(
            payload_json=output,
            usage=ModelUsage(input_tokens=input_tokens, output_tokens=max(1, len(output) // 4)),
        )

    @staticmethod
    def _authorization() -> dict[str, object]:
        return {
            "category": "BOLA",
            "operation_id": "getAccount",
            "owner_credential_alias": "cred-bank-alex",
            "alternate_credential_alias": "cred-bank-blair",
            "owner_resource_ref": "resource-account-owner",
            "alternate_resource_ref": "resource-account-alternate",
            "rationale": (
                "Compare an owner's account with another owner's account under the same principal."
            ),
            "capability_id": "aegis.authorization.compare",
        }
