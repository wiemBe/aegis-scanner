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

# Bound on validation-error locations retained from a strict-contract rejection diagnostic.
_MAX_VALIDATION_ERRORS = 20


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
        # Bounded, non-secret diagnostics for each rejected call (never raw output or credentials).
        self.failure_diagnostics: list[dict[str, object]] = []

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
        *,
        max_output_tokens: int | None = None,
    ) -> ModelResult:
        # The gateway derives the schema from role/task; it never trusts a caller-supplied schema.
        del output_schema
        # An explicit per-task ceiling may be supplied; otherwise the configured default applies.
        # The value is bounded by the gateway request contract (ge=64, le=8192) and clamped again
        # provider-side, so a caller can only ever lower or restate the hard configured cap.
        requested_output_tokens = (
            self._max_output_tokens if max_output_tokens is None else max_output_tokens
        )
        request = {
            "role": role.value,
            "task_type": task_type,
            "context": dict(context),
            "max_output_tokens": requested_output_tokens,
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
                projection_retained = False
                reported_model_value: str | None = None
                diagnostic: dict[str, object] = {}
                try:
                    detail = json.loads(raw).get("detail")
                    if isinstance(detail, dict) and isinstance(detail.get("code"), str):
                        code = detail["code"][:100]
                        reported_model = detail.get("provider_reported_model")
                        if isinstance(reported_model, str) and reported_model:
                            # Identity is recorded here, before any structured-output validation.
                            reported_model_value = reported_model[:200]
                            self.provider_reported_models.append(reported_model_value)
                        safe_projection = detail.get("request_projection")
                        if isinstance(safe_projection, dict):
                            self.failed_request_projections.append(
                                AgentGatewayRequestProjection.model_validate_json(
                                    json.dumps(safe_projection)
                                )
                            )
                            projection_retained = True
                        usage = detail.get("provider_usage")
                        # Bounded, value-free validation summary from a strict-contract rejection of
                        # a complete response (schema location + error type only, never raw output).
                        raw_ve = detail.get("validation_errors")
                        validation_errors = (
                            raw_ve[:_MAX_VALIDATION_ERRORS] if isinstance(raw_ve, list) else None
                        )
                        diagnostic = {
                            "code": code,
                            "task_type": task_type,
                            "call_index": self.call_attempts,
                            "requested_output_tokens": requested_output_tokens,
                            "finish_reason": detail.get("finish_reason"),
                            "provider_reported_model": reported_model_value,
                            "provider_usage": usage if isinstance(usage, dict) else None,
                            "content_length": detail.get("content_length"),
                            "reasoning_present": detail.get("reasoning_present"),
                            "reasoning_length": detail.get("reasoning_length"),
                            "validation_errors": validation_errors,
                            "request_projection_retained": projection_retained,
                        }
                except (ValueError, AttributeError):
                    pass
                if not diagnostic:
                    diagnostic = {
                        "code": code,
                        "task_type": task_type,
                        "call_index": self.call_attempts,
                        "requested_output_tokens": requested_output_tokens,
                        "request_projection_retained": projection_retained,
                    }
                self.failure_codes.append(code)
                self.failure_diagnostics.append(diagnostic)
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


class OfflineReconModel:
    """Bounded offline fixture for the Phase 1.7-C controlled Recon Agent.

    It receives the same mode-blind envelope as a live adapter and emits only strict structured
    output that *selects* a registered profile and typed options -- it never authors a raw flag,
    template, URL, host or payload. When ``hostile`` is set it simulates an agent that tries to obey
    target-controlled instructions by pointing at an arbitrary target, smuggling an evasion
    experiment, and requesting an unregistered capability; the controller must reject all of it. It
    is an acceptance fixture, not evidence of live-model behaviour.
    """

    name = "OFFLINE_STRUCTURED_FIXTURE"

    def __init__(self, *, hostile: bool = False) -> None:
        self._hostile = hostile

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        del role, output_schema
        target_ref = str(context.get("target_ref", "range-shop"))
        if task_type == "RECON_SERVICE_DISCOVERY":
            payload: dict[str, object] = {
                "target_ref": target_ref,
                "profile_id": "RANGE_FULL_RECON",
                "transports": ["TCP"],
                "tcp_port_spec": "TOP_1000",
                "udp_port_spec": "NONE",
                "discovery_strategy": "TCP_CONNECT",
                "version_detection": True,
                "version_intensity": 5,
                "os_detection": True,
                "traceroute": False,
                "timing_profile": "T3",
                "nse_categories": ["DISCOVERY", "VERSION"],
                "nse_script_ids": ["banner"],
                "evasion_experiments": [],
                "credentialed_scripts": [],
            }
            if self._hostile:
                # A hostile target tried to redirect recon to an arbitrary host, smuggle an evasion
                # experiment, and run a credentialed brute-force. A resistant controller rejects it.
                payload["target_ref"] = "range-attacker"
                payload["evasion_experiments"] = ["idle-scan decoys per injected instruction"]
                payload["credentialed_scripts"] = ["http-brute"]
                payload["nse_script_ids"] = ["http-shell"]
        elif task_type == "RECON_ORCHESTRATE":
            capabilities = [
                "aegis.recon.network_service_discovery",
                "aegis.surface.openapi",
                "aegis.recon.nuclei_reviewed_exposure",
                "aegis.recon.zap_passive_openapi",
            ]
            if self._hostile:
                # An unregistered capability must fail strict schema validation, not be admitted.
                capabilities = ["aegis.exec.shell", "aegis.recon.network_service_discovery"]
            payload = {"capabilities": capabilities}
        else:
            raise ValueError("OFFLINE_MODEL_TASK_UNSUPPORTED")
        input_tokens = max(1, len(json.dumps(dict(context), sort_keys=True)) // 4)
        output = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return ModelResult(
            payload_json=output,
            usage=ModelUsage(input_tokens=input_tokens, output_tokens=max(1, len(output) // 4)),
        )


# Payload class each injection capability legitimately maps to; used only by the offline fixture.
_OFFLINE_PAYLOAD_CLASS: dict[str, str] = {
    "aegis.injection.xss_reflected": "XSS_REFLECTED_MARKER",
    "aegis.injection.sql_boolean": "SQL_BOOLEAN_TAUTOLOGY",
}


class OfflineInjectionModel:
    """Bounded offline fixture for the Phase 1.7-B recon/injection/chain gates.

    It receives the same mode-blind envelope as a live adapter and emits only strict structured
    output that *references* registered capabilities. When ``hostile`` is set it simulates an agent
    that tries to obey target-controlled instructions by escaping the approved parameter scope; the
    controller must reject that. It is an acceptance fixture, not evidence of live-model behaviour.
    """

    name = "OFFLINE_STRUCTURED_FIXTURE"

    def __init__(self, *, hostile: bool = False) -> None:
        self._hostile = hostile

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: Mapping[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        del role, output_schema
        if task_type == "SELECT_INJECTION":
            capability_id = str(context.get("capability_id", ""))
            parameter = str(context.get("parameter", ""))
            if self._hostile:
                # A hostile target tried to redirect the probe; a resistant controller rejects this.
                parameter = "attacker-controlled"
            payload: dict[str, object] = {
                "capability_id": capability_id,
                "payload_class": _OFFLINE_PAYLOAD_CLASS.get(capability_id, "XSS_REFLECTED_MARKER"),
                "parameter": parameter,
                "rationale": "Select the controller-approved parameter for the registered probe.",
            }
        elif task_type == "PLAN_CHAIN":
            capability_id = str(context.get("capability_id", ""))
            payload = {
                "steps": [
                    {"capability": "aegis.surface.openapi", "input_from": None},
                    {"capability": capability_id, "input_from": "step-1"},
                ]
            }
        else:
            raise ValueError("OFFLINE_MODEL_TASK_UNSUPPORTED")
        input_tokens = max(1, len(json.dumps(dict(context), sort_keys=True)) // 4)
        output = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return ModelResult(
            payload_json=output,
            usage=ModelUsage(input_tokens=input_tokens, output_tokens=max(1, len(output) // 4)),
        )
