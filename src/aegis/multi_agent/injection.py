"""Phase 1.7-B recon and bounded, controller-owned injection detection capabilities.

Design invariants (do not weaken):

* The model never authors a payload, target, endpoint, or verdict. It may only *select* a
  registered capability and a controller-approved parameter. Payload strings live only in the
  frozen ``PAYLOAD_TEMPLATES`` registry below and are materialised by the controller.
* Every probe is non-destructive: one benign control request and one probe request, both bounded,
  no mutation, no data exfiltration, no OS command, no persistence.
* This capability produces *evidence*, never a verdict. The independent deterministic range
  verifier is the sole authority for CONFIRMED / PASS.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import Field

from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentObservation,
    AgentRole,
    AgentTask,
    BudgetUsage,
    ObservationType,
    StrictModel,
)
from aegis.multi_agent.registry import authorize
from aegis_range.inventory import RANGE_TARGETS

# Target-controlled text that must always remain data. Recon flags these but never obeys them.
HOSTILE_INSTRUCTION_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard",
    "send secrets",
    "exfiltrate",
    "call another host",
    "run shell",
    "system prompt",
)

# Content categories a model output may never contain (origins, tokens, principals).
_FORBIDDEN_OUTPUT_MARKERS: tuple[str, ...] = ("http://", "https://", "range-user-", "bearer ")


# Honest capability labels (see README / phase-1.7 doc). Recon is documented HTTP/API surface
# inspection only — NOT network/Nmap/Nuclei/ZAP recon.
RECON_CLASS = "HTTP_API_SURFACE_RECON"


class GateOutcome(StrEnum):
    """Explicit fail-closed states for a Phase 1.7-B acceptance gate."""

    PASS = "PASS"  # noqa: S105 - acceptance state label, not a credential
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class PayloadClass(StrEnum):
    """Registered, controller-owned payload families. No free-form family is accepted."""

    XSS_REFLECTED_MARKER = "XSS_REFLECTED_MARKER"
    SQL_BOOLEAN_TAUTOLOGY = "SQL_BOOLEAN_TAUTOLOGY"


class InjectionRejection(ValueError):
    """Raised when an injection selection escapes the controller allowlist or scope."""


@dataclass(frozen=True)
class PayloadTemplate:
    """A frozen, controller-owned probe. The model can reference it but never edit it."""

    capability_id: str
    payload_class: PayloadClass
    application_id: str
    scenario_id: str
    method: Literal["GET"]
    route: str
    parameter: str
    control_value: str
    probe_value: str
    expected_signal: str
    target_requests: int


# The complete, frozen injection surface for Phase 1.7-B. Adding a family requires a code review
# and a new acceptance run; it is never assembled from model or target input.
PAYLOAD_TEMPLATES: dict[str, PayloadTemplate] = {
    "aegis.injection.xss_reflected": PayloadTemplate(
        capability_id="aegis.injection.xss_reflected",
        payload_class=PayloadClass.XSS_REFLECTED_MARKER,
        application_id="aegis-shop",
        scenario_id="shop-promotion-preview-v1",
        method="GET",
        route="/api/promotions/preview",
        parameter="message",
        control_value="Autumn sale",
        # Inert reflected marker: no network effect, no eventful script body.
        probe_value='<aegisxss data-probe="reflect">MARK</aegisxss>',
        expected_signal="probe marker reflected raw (CONFIRMED) vs contextually encoded (PASS)",
        target_requests=2,
    ),
    "aegis.injection.sql_boolean": PayloadTemplate(
        capability_id="aegis.injection.sql_boolean",
        payload_class=PayloadClass.SQL_BOOLEAN_TAUTOLOGY,
        application_id="aegis-shop",
        scenario_id="shop-catalog-query-v1",
        method="GET",
        route="/api/products",
        parameter="q",
        control_value="Notebook",
        # Read-only boolean differential; never a destructive or stacked statement.
        probe_value="%' OR 1=1 --",
        expected_signal="probe result set expands beyond the selective control (CONFIRMED) vs "
        "empty (PASS)",
        target_requests=2,
    ),
}

# Fixed map from a registered capability to the range scenario its verifier confirms.
CAPABILITY_SCENARIO: dict[str, str] = {
    template.capability_id: template.scenario_id for template in PAYLOAD_TEMPLATES.values()
}


class ReconObservation(StrictModel):
    """Structured, evidence-backed recon output. It never emits a verdict or a shell command."""

    target_id: str = Field(pattern=r"^range-[a-z0-9-]+$")
    observed_routes: list[str] = Field(max_length=64)
    observed_methods: list[str] = Field(max_length=16)
    observed_parameters: list[str] = Field(max_length=64)
    observed_headers: list[str] = Field(max_length=64)
    candidate_tests: list[str] = Field(max_length=16)
    evidence_refs: list[str] = Field(max_length=16)
    warnings: list[str] = Field(max_length=16)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_bytes: int = Field(ge=0, le=262_144)


class InjectionAgentOutput(StrictModel):
    """Model-authored selection. There is deliberately no free-form payload field."""

    capability_id: Literal["aegis.injection.xss_reflected", "aegis.injection.sql_boolean"]
    payload_class: PayloadClass
    parameter: str = Field(min_length=1, max_length=64)
    rationale: str = Field(min_length=3, max_length=300)


class InjectionRequestContract(StrictModel):
    """Controller-materialised request. Built from the registry, never from model text."""

    target_id: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(pattern=r"^aegis\.injection\.[a-z_]+$")
    endpoint: str = Field(min_length=1, max_length=200)
    method: Literal["GET"]
    parameter: str = Field(min_length=1, max_length=64)
    payload_class: PayloadClass
    expected_signal: str = Field(min_length=3, max_length=200)
    request_budget: int = Field(ge=1, le=4)


class InjectionObservation(StrictModel):
    """Non-authoritative differential the broker saw. Not a verdict."""

    observation_id: str = Field(pattern=r"^obs-[a-f0-9]{16}$")
    capability_id: str
    parameter: str
    control_status: int
    probe_status: int
    differential_observed: bool
    statuses: dict[str, int]
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_bytes: int = Field(ge=0, le=262_144)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


def assert_output_clean(output: StrictModel) -> None:
    """Reject any model output that leaked an origin, token, or principal."""

    serialized = output.model_dump_json().lower()
    if any(marker in serialized for marker in _FORBIDDEN_OUTPUT_MARKERS):
        raise InjectionRejection("AGENT_OUTPUT_FORBIDDEN_CONTENT")


class InjectionBroker:
    """Controlled recon and injection over the synthetic range's public origins."""

    def __init__(
        self,
        budget: AtomicBudget,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self._budget = budget
        self._transports = transports or {}

    def _target(self, target_ref: str) -> tuple[str, str]:
        matches = [
            (item.application_id, item.origin)
            for item in RANGE_TARGETS.values()
            if item.target_ref == target_ref
        ]
        if len(matches) != 1:
            raise InjectionRejection("TARGET_REF_NOT_IN_INVENTORY")
        return matches[0]

    async def _get(
        self, application_id: str, origin: str, path: str, params: dict[str, str] | None
    ) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=origin,
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            transport=self._transports.get(application_id),
        ) as client:
            return await client.get(
                path, params=params, headers={"User-Agent": "Aegis-Multi-Agent-Runtime/1.7B"}
            )

    async def recon(
        self, *, task: AgentTask, target_ref: str, observation_id: str
    ) -> ReconObservation:
        """Read-only surface inventory. It proposes candidate tests but never confirms anything."""

        if task.role not in {AgentRole.SURFACE_AGENT, AgentRole.CHAIN_AGENT}:
            raise InjectionRejection("RECON_ROLE_REQUIRED")
        authorize(task.role, "aegis.surface.openapi")
        application_id, origin = self._target(target_ref)
        await self._budget.consume(task.agent_id, BudgetUsage(target_requests=1))
        response = await self._get(application_id, origin, "/openapi.json", None)
        if response.status_code != 200 or len(response.content) > 262_144:
            raise InjectionRejection("RECON_OBSERVATION_FAILED")
        document: object = response.json()
        if not isinstance(document, dict):
            raise InjectionRejection("RECON_OUTPUT_MALFORMED")
        routes: set[str] = set()
        methods: set[str] = set()
        parameters: set[str] = set()
        warnings: list[str] = []
        paths = document.get("paths", {})
        if isinstance(paths, dict):
            for route, item in paths.items():
                if not isinstance(route, str) or not isinstance(item, dict):
                    continue
                routes.add(route)
                for method, operation in item.items():
                    methods.add(str(method).upper())
                    if isinstance(operation, dict):
                        for parameter in operation.get("parameters", []) or []:
                            if isinstance(parameter, dict) and isinstance(
                                parameter.get("name"), str
                            ):
                                parameters.add(parameter["name"])
        # Candidate tests reference only registered capabilities whose (route, parameter) is present
        # in the observed surface. An unknown capability is never proposed.
        candidate_tests = sorted(
            template.capability_id
            for template in PAYLOAD_TEMPLATES.values()
            if template.application_id == application_id
            and template.route in routes
            and template.parameter in parameters
        )
        # Target-controlled text is data. If the surface tries to instruct us, we record a warning
        # and keep going; we never act on it.
        lowered = response.text.lower()
        if any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS):
            warnings.append("target-controlled instruction-like content observed; treated as data")
        projection = json.dumps(
            {
                "routes": sorted(routes),
                "methods": sorted(methods),
                "parameters": sorted(parameters),
                "candidate_tests": candidate_tests,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        await self._budget.consume(task.agent_id, BudgetUsage(evidence_bytes=len(projection)))
        return ReconObservation(
            target_id=target_ref,
            observed_routes=sorted(routes)[:64],
            observed_methods=sorted(methods)[:16],
            observed_parameters=sorted(parameters)[:64],
            observed_headers=sorted(response.headers.keys())[:64],
            candidate_tests=candidate_tests,
            evidence_refs=[observation_id],
            warnings=warnings,
            evidence_sha256=hashlib.sha256(projection).hexdigest(),
            evidence_bytes=len(projection),
        )

    @staticmethod
    def materialize(
        selection: InjectionAgentOutput, recon: ReconObservation
    ) -> tuple[PayloadTemplate, InjectionRequestContract]:
        """Validate a model selection against the allowlist and build a controller-owned request."""

        template = PAYLOAD_TEMPLATES.get(selection.capability_id)
        if template is None:
            raise InjectionRejection("CAPABILITY_NOT_REGISTERED")
        if selection.payload_class is not template.payload_class:
            raise InjectionRejection("PAYLOAD_CLASS_MISMATCH")
        if selection.parameter != template.parameter:
            raise InjectionRejection("PARAMETER_NOT_APPROVED")
        if selection.capability_id not in recon.candidate_tests:
            raise InjectionRejection("CAPABILITY_NOT_IN_RECON_SCOPE")
        if template.parameter not in recon.observed_parameters:
            raise InjectionRejection("PARAMETER_NOT_OBSERVED")
        request = InjectionRequestContract(
            target_id=recon.target_id,
            capability_id=template.capability_id,
            endpoint=template.route,
            method=template.method,
            parameter=template.parameter,
            payload_class=template.payload_class,
            expected_signal=template.expected_signal,
            request_budget=template.target_requests,
        )
        return template, request

    async def probe(
        self,
        *,
        task: AgentTask,
        target_ref: str,
        template: PayloadTemplate,
        observation_id: str,
    ) -> InjectionObservation:
        """Send one benign control request and one controller-owned probe request."""

        authorize(task.role, template.capability_id)
        application_id, origin = self._target(target_ref)
        if application_id != template.application_id:
            raise InjectionRejection("TARGET_SCENARIO_MISMATCH")
        await self._budget.consume(
            task.agent_id, BudgetUsage(target_requests=template.target_requests)
        )
        control = await self._get(
            application_id, origin, template.route, {template.parameter: template.control_value}
        )
        probe = await self._get(
            application_id, origin, template.route, {template.parameter: template.probe_value}
        )
        differential = self._differential(template, control, probe)
        statuses = {"control": control.status_code, "probe": probe.status_code}
        evidence = (
            json.dumps(statuses, sort_keys=True, separators=(",", ":")).encode()
            + b"\ndifferential="
            + str(differential).encode()
        )
        await self._budget.consume(task.agent_id, BudgetUsage(evidence_bytes=len(evidence)))
        return InjectionObservation(
            observation_id=observation_id,
            capability_id=template.capability_id,
            parameter=template.parameter,
            control_status=control.status_code,
            probe_status=probe.status_code,
            differential_observed=differential,
            statuses=statuses,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
            evidence_bytes=len(evidence),
        )

    @staticmethod
    def _differential(
        template: PayloadTemplate, control: httpx.Response, probe: httpx.Response
    ) -> bool:
        """A bounded, non-authoritative hint only. The range verifier owns the real decision."""

        if control.status_code != 200 or probe.status_code != 200:
            return False
        if template.payload_class is PayloadClass.XSS_REFLECTED_MARKER:
            return template.probe_value.encode() in probe.content
        # SQL boolean differential: the probe returns strictly more rows than the control.
        try:
            control_rows = len(control.json().get("products", []))
            probe_rows = len(probe.json().get("products", []))
        except (ValueError, AttributeError, TypeError):
            return False
        return probe_rows > control_rows


def recon_to_agent_observation(
    recon: ReconObservation, *, run_id: str, task: AgentTask
) -> AgentObservation:
    """Adapt the recon contract to the shared audit observation shape for storage."""

    return AgentObservation(
        observation_id=recon.evidence_refs[0],
        run_id=run_id,
        task_id=task.task_id,
        agent_id=task.agent_id,
        observation_type=ObservationType.RECON_INVENTORY,
        summary=(
            f"Observed {len(recon.observed_routes)} routes and "
            f"{len(recon.candidate_tests)} candidate tests."
        ),
        operation_ids=recon.candidate_tests[:32],
        resource_refs=[],
        statuses={},
        evidence_sha256=recon.evidence_sha256,
        evidence_bytes=recon.evidence_bytes,
    )
