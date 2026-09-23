"""Phase 1.7-C gateway recon task types and reused-adapter execution mappers.

No live provider and no Docker are used. These tests prove that the gateway derives strict,
server-selected schemas for the three RECON_AGENT task types (PLAN_RECON,
INTERPRET_RECON_OBSERVATIONS, DELEGATE_RECON_HYPOTHESIS); that a caller cannot supply or weaken the
schema; that the schemas are reference-only (no raw shell, flag, origin, template, policy, payload,
credential, verdict/PASS/CONFIRMED/severity is representable); that the sanitized pre-dispatch
projection stays CLEAN and never carries scenario mode or an answer key; and that the reused
Nuclei/ZAP execution mappers turn an UNTRUSTED runner response into unconfirmed candidates,
NO_FINDING, or INCOMPLETE_TOOL_ERROR without ever confirming.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, ValidationError

from aegis import gateway
from aegis.models import ProviderRunMetadata, ProviderUsage
from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentRole,
    AgentTask,
    AgentTaskContext,
    AgentTaskState,
    BudgetLimit,
    GatewayNmapPlanSelection,
    ReconDelegationOutput,
    ReconInterpretationOutput,
    ReconPlanOutput,
)
from aegis.multi_agent.model import GatewayAgentModel
from aegis.multi_agent.recon import (
    ADMITTED_NSE_SCRIPT_IDS,
    CAP_NUCLEI_REVIEWED_EXPOSURE,
    NMAP_PROFILES,
    NUCLEI_PROFILE_ID,
    ZAP_PROFILE_ID,
    NmapProfileId,
    ReconBroker,
    ReconExecutionOutcome,
    nuclei_execution_outcome,
    zap_execution_outcome,
)
from aegis.providers import AgentProviderResult
from aegis.settings import Settings

CANONICAL_MODEL = "deepseek-v4-pro"

# Markers the gateway's sanitized-projection check forbids in the outbound message material (system
# contract + context + derived schema). The recon schemas must trip none of them.
_FORBIDDEN_MARKERS = (
    "vulnerable",
    "patched",
    "answer_key",
    "ground_truth",
    "expected_verdict",
    '"confirmed"',
    '"pass"',
    "range-user-",
    "bearer ",
    "lab-token-",
    "http://",
    "https://",
)


# --------------------------------------------------------------------------- #
# Contract-level: the three server-selected recon schemas.
# --------------------------------------------------------------------------- #


def test_plan_recon_accepts_typed_nmap_selection() -> None:
    plan = ReconPlanOutput(
        capability_id="aegis.recon.network_service_discovery",
        target_ref="range-bank",
        profile_id="RANGE_FULL_RECON",
        nmap_plan=GatewayNmapPlanSelection(
            transports=["TCP"], nse_script_ids=["banner", "http-title"]
        ),
        rationale="Discover the documented HTTP service surface.",
    )
    assert plan.nmap_plan is not None
    assert plan.scanner_profile_id is None


def test_plan_recon_accepts_scanner_profile_selection() -> None:
    plan = ReconPlanOutput(
        capability_id="aegis.recon.nuclei_reviewed_exposure",
        target_ref="range-shop",
        scanner_profile_id="NUCLEI_LAB_SAFE_HTTP_V1",
        rationale="Reuse the reviewed exposure profile.",
    )
    assert plan.scanner_profile_id == "NUCLEI_LAB_SAFE_HTTP_V1"
    assert plan.nmap_plan is None and plan.profile_id is None


def test_plan_recon_surface_needs_no_plan_fields() -> None:
    plan = ReconPlanOutput(
        capability_id="aegis.surface.openapi",
        target_ref="range-bank",
        rationale="Inspect the documented API surface only.",
    )
    assert plan.nmap_plan is None and plan.scanner_profile_id is None


def test_plan_recon_nmap_capability_requires_typed_plan() -> None:
    with pytest.raises(ValidationError, match="PLAN_RECON_NMAP_REQUIRES_TYPED_PLAN"):
        ReconPlanOutput(
            capability_id="aegis.recon.network_service_discovery",
            target_ref="range-bank",
            rationale="Missing the typed plan and profile.",
        )


def test_plan_recon_scanner_capability_requires_profile() -> None:
    with pytest.raises(ValidationError, match="PLAN_RECON_SCANNER_REQUIRES_PROFILE"):
        ReconPlanOutput(
            capability_id="aegis.recon.zap_passive_openapi",
            target_ref="range-shop",
            rationale="Missing the approved scanner profile.",
        )


def test_plan_recon_rejects_nmap_fields_on_non_nmap_capability() -> None:
    with pytest.raises(ValidationError, match="PLAN_RECON_NMAP_FIELDS_NOT_ALLOWED"):
        ReconPlanOutput(
            capability_id="aegis.surface.openapi",
            target_ref="range-bank",
            profile_id="RANGE_FULL_RECON",
            rationale="Surface must not carry nmap fields.",
        )


def test_plan_recon_rejects_unregistered_capability() -> None:
    with pytest.raises(ValidationError):
        ReconPlanOutput.model_validate(
            {
                "capability_id": "aegis.exec.shell",
                "target_ref": "range-bank",
                "rationale": "smuggle a shell capability",
            }
        )


def test_plan_recon_rejects_extra_fields_and_raw_flags() -> None:
    # extra="forbid": a model cannot smuggle a raw argv/host/origin field past the schema.
    with pytest.raises(ValidationError):
        ReconPlanOutput.model_validate(
            {
                "capability_id": "aegis.surface.openapi",
                "target_ref": "range-bank",
                "rationale": "attempt raw flags",
                "argv": ["nmap", "-sS", "-D", "10.0.0.9"],
            }
        )


def test_nmap_plan_selection_rejects_unadmitted_nse_script() -> None:
    with pytest.raises(ValidationError):
        GatewayNmapPlanSelection.model_validate(
            {"transports": ["TCP"], "nse_script_ids": ["http-shell"]}
        )


def test_nmap_plan_selection_has_no_evasion_or_credentialed_fields() -> None:
    fields = set(GatewayNmapPlanSelection.model_fields)
    assert "evasion_experiments" not in fields
    assert "credentialed_scripts" not in fields


def test_interpretation_output_has_no_verdict_and_is_unconfirmed() -> None:
    out = ReconInterpretationOutput(
        summary="Discovered one HTTP service and documented account reads.",
        salient_observation_kinds=["DISCOVERED_SERVICE", "DOCUMENTED_OPERATION"],
        recommended_followups=["aegis.surface.openapi"],
    )
    assert out.unconfirmed is True
    fields = set(ReconInterpretationOutput.model_fields)
    assert not (
        {"verdict", "severity", "confirmed", "pass_", "status"} & fields
    ), "interpretation must expose no verdict/severity/confirmed field"


def test_interpretation_output_cannot_set_unconfirmed_false() -> None:
    with pytest.raises(ValidationError):
        ReconInterpretationOutput.model_validate(
            {"summary": "attempt to confirm", "unconfirmed": False}
        )


def test_delegation_output_is_reference_only() -> None:
    out = ReconDelegationOutput(
        to_agent="INJECTION_AGENT",
        capability_id="aegis.injection.xss_reflected",
        target_ref="range-shop",
        route="/search",
        parameter="q",
        rationale="A documented parameter matches a registered injection capability.",
    )
    assert out.route == "/search"
    fields = set(ReconDelegationOutput.model_fields)
    assert not ({"payload", "verdict", "severity", "origin", "url"} & fields)


def test_delegation_output_rejects_origin_in_route() -> None:
    with pytest.raises(ValidationError):
        ReconDelegationOutput.model_validate(
            {
                "to_agent": "INJECTION_AGENT",
                "capability_id": "aegis.injection.xss_reflected",
                "target_ref": "range-shop",
                "route": "http://evil.example/x",
                "rationale": "smuggle an origin",
            }
        )


def test_delegation_output_rejects_shell_capability_id() -> None:
    with pytest.raises(ValidationError):
        ReconDelegationOutput.model_validate(
            {
                "to_agent": "AUTHORIZATION_AGENT",
                "capability_id": "sh -c id",
                "target_ref": "range-bank",
                "rationale": "smuggle a shell",
            }
        )


@pytest.mark.parametrize(
    "model_cls",
    [ReconPlanOutput, ReconInterpretationOutput, ReconDelegationOutput],
)
def test_recon_schemas_carry_no_forbidden_markers(model_cls: type[BaseModel]) -> None:
    """The derived JSON schema must trip none of the gateway's sanitized-projection markers.

    In particular no "vulnerable"/"patched" scenario token and no "confirmed"/"pass" verdict token
    may appear, or the gateway would refuse the request as unsanitized (or leak scenario mode).
    """
    schema_text = json.dumps(model_cls.model_json_schema(), sort_keys=True).lower()
    present = [m for m in _FORBIDDEN_MARKERS if m in schema_text]
    assert present == [], f"{model_cls.__name__} schema contains forbidden markers: {present}"


def test_gateway_literals_match_recon_source_of_truth() -> None:
    """Drift guard: the gateway's duplicated literal aliases match aegis.multi_agent.recon."""
    from typing import get_args

    assert set(get_args(NmapProfileId)) == set(NMAP_PROFILES)
    # nse_script_ids is list[Literal[...]]: unwrap the list, then the Literal members.
    nse_annotation = GatewayNmapPlanSelection.model_fields["nse_script_ids"].annotation
    nse_literal = get_args(nse_annotation)[0]
    assert set(get_args(nse_literal)) == set(ADMITTED_NSE_SCRIPT_IDS)
    # scanner_profile_id is Literal[...] | None: the first arg is the Literal.
    scanner_annotation = ReconPlanOutput.model_fields["scanner_profile_id"].annotation
    scanner_literal = get_args(scanner_annotation)[0]
    assert set(get_args(scanner_literal)) == {NUCLEI_PROFILE_ID, ZAP_PROFILE_ID}


# --------------------------------------------------------------------------- #
# Gateway wiring: task-type -> role/schema, and end-to-end through a fake provider.
# --------------------------------------------------------------------------- #


def _settings() -> Settings:
    return Settings(
        ai_provider="internal_openai_compatible",
        ai_base_url="https://api.deepseek.com",
        ai_model=CANONICAL_MODEL,
        ai_allowed_models=CANONICAL_MODEL,
        ai_auth_mode="none",
        ai_response_format="json_object",
        ai_supports_seed=False,
        ai_use_egress_proxy=False,
        llm_gateway_url="http://gateway",
    )


class _FakeReconProvider:
    """A minimal provider that returns a fixed structured payload for a recon task type."""

    provider_type = "internal_openai_compatible"
    model = CANONICAL_MODEL

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    async def generate_agent(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        schema: dict[str, Any],
        max_output_tokens: int,
    ) -> AgentProviderResult:
        del role, task_type, context, schema, max_output_tokens
        return AgentProviderResult(
            self.model,
            json.dumps(self._payload),
            ProviderUsage(input_tokens=11, output_tokens=13, total_tokens=24),
            ProviderRunMetadata(
                provider_type=self.provider_type, runtime=self.provider_type, model=self.model
            ),
        )


def test_gateway_maps_recon_task_types_to_recon_role() -> None:
    for task_type in ("PLAN_RECON", "INTERPRET_RECON_OBSERVATIONS", "DELEGATE_RECON_HYPOTHESIS"):
        assert gateway._AGENT_TASK_ROLES[task_type] is AgentRole.RECON_AGENT
        assert task_type in gateway._AGENT_OUTPUTS
    assert gateway._AGENT_OUTPUTS["PLAN_RECON"] is ReconPlanOutput
    assert gateway._AGENT_OUTPUTS["INTERPRET_RECON_OBSERVATIONS"] is ReconInterpretationOutput
    assert gateway._AGENT_OUTPUTS["DELEGATE_RECON_HYPOTHESIS"] is ReconDelegationOutput


async def test_gateway_generate_plan_recon_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "capability_id": "aegis.recon.network_service_discovery",
        "target_ref": "range-bank",
        "profile_id": "RANGE_FULL_RECON",
        "nmap_plan": {"transports": ["TCP"], "nse_script_ids": ["banner"]},
        "rationale": "Discover the documented HTTP service surface on the range target.",
    }
    monkeypatch.setattr(gateway, "_provider", _FakeReconProvider(payload))
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    result = await model.generate(
        AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
    )
    validated = ReconPlanOutput.model_validate_json(result.payload_json)
    assert validated.capability_id == "aegis.recon.network_service_discovery"
    # The pre-dispatch projection is recorded, CLEAN, and carries no forbidden category.
    assert len(gateway._agent_request_projections) == 1
    projection = next(iter(gateway._agent_request_projections.values()))
    assert projection.role is AgentRole.RECON_AGENT
    assert projection.task_type == "PLAN_RECON"
    assert projection.schema_identifier == "ReconPlanOutput"
    assert projection.redaction_status == "CLEAN"
    assert projection.forbidden_categories_present == []


async def test_gateway_rejects_role_task_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gateway, "_provider", _FakeReconProvider({}))
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    # A caller that names the wrong role for a recon task must be rejected server-side.
    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED"):
        await model.generate(
            AgentRole.SURFACE_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )


async def test_gateway_rejects_schema_violating_recon_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # capability/plan incoherence must be caught by the server-selected schema, not the caller.
    bad = {
        "capability_id": "aegis.recon.network_service_discovery",
        "target_ref": "range-bank",
        "rationale": "no typed plan supplied",
    }
    monkeypatch.setattr(gateway, "_provider", _FakeReconProvider(bad))
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED"):
        await model.generate(
            AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )
    # Even on rejection the caller receives an auditable, sanitized projection.
    assert len(model.failed_request_projections) == 1
    assert model.failed_request_projections[0].schema_identifier == "ReconPlanOutput"


def test_validation_error_summary_is_bounded_and_value_free() -> None:
    # A non-ValidationError yields no summary (only strict-contract failures produce one).
    assert gateway._validation_error_summary(ValueError("boom")) is None
    # A real ValidationError yields only schema location + error type, never the offending value.
    try:
        ReconPlanOutput.model_validate(
            {
                "capability_id": "aegis.exec.SENTINEL_LEAK_VALUE",
                "target_ref": "range-bank",
                "rationale": "unregistered capability",
            }
        )
    except ValidationError as exc:
        summary = gateway._validation_error_summary(exc)
    assert summary is not None and summary != []
    assert len(summary) <= gateway._MAX_VALIDATION_ERRORS
    for item in summary:
        assert {"loc", "type"} <= set(item) <= {"loc", "type", "code"}
    # The offending model-supplied value must never appear in the value-free summary.
    assert "SENTINEL_LEAK_VALUE" not in json.dumps(summary)


def test_validation_error_summary_surfaces_model_validator_code() -> None:
    # A cross-field @model_validator failure (root loc) surfaces its own constant code, not input.
    try:
        ReconPlanOutput.model_validate(
            {
                "capability_id": "aegis.recon.network_service_discovery",
                "target_ref": "range-bank",
                "rationale": "nmap capability without the required typed plan",
            }
        )
    except ValidationError as exc:
        summary = gateway._validation_error_summary(exc)
    assert summary is not None
    root = [e for e in summary if e["loc"] == ""]
    assert root and root[0]["type"] == "value_error"
    assert root[0]["code"] == "PLAN_RECON_NMAP_REQUIRES_TYPED_PLAN"


def test_contract_code_never_surfaces_model_input() -> None:
    # A value_error whose message would echo model text (lowercase/free text) yields no code.
    leaky = {"type": "value_error", "msg": "Value error, bad q=payload"}
    assert gateway._contract_code(leaky) is None
    assert gateway._contract_code({"type": "literal_error", "msg": "Value error, X"}) is None
    assert (
        gateway._contract_code(
            {"type": "value_error", "msg": "Value error, PLAN_RECON_SCANNER_REQUIRES_PROFILE"}
        )
        == "PLAN_RECON_SCANNER_REQUIRES_PROFILE"
    )


async def test_gateway_output_rejected_surfaces_value_free_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A *complete* response (finish_reason=stop) whose JSON violates the strict contract by naming
    # an unregistered capability. The offending value is a sentinel that must not leak anywhere.
    bad = {
        "capability_id": "aegis.exec.SENTINEL_LEAK_VALUE",
        "target_ref": "range-bank",
        "rationale": "smuggle an unregistered capability id",
    }
    monkeypatch.setattr(gateway, "_provider", _FakeReconProvider(bad))
    gateway._agent_request_projections.clear()
    transport = httpx.ASGITransport(app=gateway.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gateway") as client:
        response = await client.post(
            "/v1/agents/generate",
            json={
                "role": "RECON_AGENT",
                "task_type": "PLAN_RECON",
                "context": {"target_ref": "range-bank"},
                "max_output_tokens": 512,
            },
        )
    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["code"] == "AGENT_OUTPUT_REJECTED"
    errors = detail["validation_errors"]
    assert isinstance(errors, list) and errors
    assert len(errors) <= gateway._MAX_VALIDATION_ERRORS
    assert any(e["loc"] == "capability_id" for e in errors)
    for item in errors:
        assert {"loc", "type"} <= set(item) <= {"loc", "type", "code"}
    # No fragment of raw model output (the offending value) is present anywhere in the 502 body.
    assert "SENTINEL_LEAK_VALUE" not in json.dumps(detail)


async def test_model_records_validation_errors_in_failure_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad = {
        "capability_id": "aegis.exec.SENTINEL_LEAK_VALUE",
        "target_ref": "range-bank",
        "rationale": "smuggle an unregistered capability id",
    }
    monkeypatch.setattr(gateway, "_provider", _FakeReconProvider(bad))
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED:AGENT_OUTPUT_REJECTED"):
        await model.generate(
            AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )
    diag = model.failure_diagnostics[-1]
    assert diag["code"] == "AGENT_OUTPUT_REJECTED"
    ve = diag["validation_errors"]
    assert isinstance(ve, list) and ve
    assert any(e["loc"] == "capability_id" for e in ve)
    assert "SENTINEL_LEAK_VALUE" not in json.dumps(diag)


def test_gateway_agent_request_admits_recon_role_and_task_types() -> None:
    from aegis.multi_agent.contracts import AgentGatewayRequest

    request = AgentGatewayRequest.model_validate(
        {
            "role": "RECON_AGENT",
            "task_type": "DELEGATE_RECON_HYPOTHESIS",
            "context": {"target_ref": "range-bank"},
            "max_output_tokens": 512,
        }
    )
    assert request.role == "RECON_AGENT"


# --------------------------------------------------------------------------- #
# Gate 1 reused-adapter execution mappers and broker execution path.
# --------------------------------------------------------------------------- #


def _nuclei_result(status: str, records: list[dict[str, Any]], *, response: bool = True) -> Any:
    resp = SimpleNamespace(results=[SimpleNamespace(**r) for r in records]) if response else None
    return SimpleNamespace(
        execution=SimpleNamespace(status=status, error=None),
        response=resp,
        validation_code=None,
    )


def _zap_result(status: str, alerts: list[dict[str, Any]], *, coverage: bool = True) -> Any:
    resp = (
        SimpleNamespace(alerts=[SimpleNamespace(**a) for a in alerts], coverage_complete=coverage)
        if status == "COMPLETED"
        else None
    )
    return SimpleNamespace(
        execution=SimpleNamespace(status=status, error=None),
        response=resp,
        validation_code=None,
    )


def test_nuclei_mapper_matched_template_becomes_candidate() -> None:
    outcome = nuclei_execution_outcome(
        _nuclei_result(
            "COMPLETED",
            [
                {"template_id": "git-config", "claimed_severity": "medium", "matcher_status": True},
                {"template_id": "noise", "claimed_severity": "info", "matcher_status": False},
            ],
        )
    )
    assert outcome.completed is True
    assert outcome.alerts == [{"template_id": "git-config", "severity": "medium"}]


def test_nuclei_mapper_clean_completed_has_empty_alerts() -> None:
    outcome = nuclei_execution_outcome(_nuclei_result("COMPLETED", []))
    assert outcome.completed is True and outcome.alerts == []


def test_nuclei_mapper_failed_is_incomplete() -> None:
    outcome = nuclei_execution_outcome(_nuclei_result("FAILED", [], response=False))
    assert outcome.completed is False and outcome.alerts is None


def test_zap_mapper_alert_becomes_candidate() -> None:
    outcome = zap_execution_outcome(
        _zap_result("COMPLETED", [{"plugin_id": 10096, "claimed_risk": "medium"}])
    )
    assert outcome.completed is True
    assert outcome.alerts == [{"rule_id": 10096, "severity": "medium"}]


def test_zap_mapper_incomplete_coverage_is_incomplete() -> None:
    outcome = zap_execution_outcome(_zap_result("COMPLETED", [], coverage=False))
    assert outcome.completed is False and outcome.alerts is None


def _recon_task() -> AgentTask:
    return AgentTask(
        task_id="task-" + "a" * 16,
        run_id="marun-" + "b" * 16,
        agent_id="agent-" + "c" * 16,
        role=AgentRole.RECON_AGENT,
        task_type="RECON_REVIEWED_EXPOSURE",
        state=AgentTaskState.RUNNING,
        context=AgentTaskContext(
            target_ref="range-shop",
            scenario_ref="recon",
            allowed_operation_ids=[],
            credential_aliases=[],
            resource_refs=[],
        ),
    )


def _broker() -> tuple[ReconBroker, AtomicBudget, AgentTask]:
    limit = BudgetLimit(
        model_calls=4,
        tokens=12_000,
        target_requests=8,
        commands=4,
        elapsed_ms=60_000,
        evidence_bytes=524_288,
    )
    budget = AtomicBudget("marun-" + "b" * 16, limit)
    task = _recon_task()
    budget.register_agent(task.agent_id, limit)
    return ReconBroker(budget), budget, task


async def test_broker_execution_candidate_from_matched_alert() -> None:
    broker, _budget, task = _broker()

    async def executor(_job: object) -> ReconExecutionOutcome:
        return ReconExecutionOutcome(
            True, "COMPLETED", "ok", [{"template_id": "git-config", "severity": "medium"}]
        )

    _job, report = await broker.plan_reviewed_exposure(
        task=task, target_variant="vulnerable", executor=executor
    )
    kinds = {o.kind for o in report.observations}
    assert "NUCLEI_CANDIDATE" in kinds
    assert all(getattr(o, "confirmed", False) is False for o in report.observations)


async def test_broker_execution_clean_is_no_finding() -> None:
    broker, _budget, task = _broker()

    async def executor(_job: object) -> ReconExecutionOutcome:
        return ReconExecutionOutcome(True, "COMPLETED", "ok", [])

    _job, report = await broker.plan_reviewed_exposure(
        task=task, target_variant="patched", executor=executor
    )
    assert [o.kind for o in report.observations] == ["NO_FINDING"]
    assert report.incomplete is False


async def test_broker_execution_incomplete_never_clean_or_candidate() -> None:
    broker, _budget, task = _broker()

    async def executor(_job: object) -> ReconExecutionOutcome:
        return ReconExecutionOutcome(False, "INCOMPLETE", "runner unreachable", None)

    _job, report = await broker.plan_reviewed_exposure(
        task=task, target_variant="vulnerable", executor=executor
    )
    assert report.incomplete is True
    kinds = {o.kind for o in report.observations}
    assert "NUCLEI_CANDIDATE" not in kinds and "NO_FINDING" not in kinds
    assert CAP_NUCLEI_REVIEWED_EXPOSURE  # capability constant is importable
