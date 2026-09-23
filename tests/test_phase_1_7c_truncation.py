"""Phase 1.7-C fail-closed truncation observability regression tests.

No live provider and no Docker are used. These prove that a ``finish_reason=length`` truncation (the
DeepSeek reasoning_content exhausting the completion allowance before the JSON object closes) fails
closed with a bounded, auditable diagnostic, and that the smoke script reports it with the correct
tri-state semantics:

  1. a length-truncated response fails closed (no success record is produced);
  2. the truncated output is never repaired, coerced or extracted (no partial plan survives);
  3. the sanitized pre-dispatch projection is retained on the rejection path;
  4. the provider-reported model identity is retained (recorded before structured validation);
  5. the provider call count includes the rejected call, and no usage is fabricated;
  6. usage the provider did not report is UNKNOWN, never a ceiling breach;
  7. downstream plan/interpret/delegate checks become NOT_EVALUATED, never false;
  8. a complete response within the per-task ceiling still passes strict validation.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis import gateway
from aegis.models import ProviderRunMetadata, ProviderUsage
from aegis.multi_agent.contracts import AgentRole, ReconPlanOutput
from aegis.multi_agent.model import GatewayAgentModel
from aegis.planner import PlannerFailure
from aegis.providers import AgentProviderResult
from aegis.settings import Settings

CANONICAL_MODEL = "deepseek-v4-pro"

# The smoke script lives under scripts/ (not on the src pythonpath); load it directly. Its module
# top-level only touches stdlib (no aegis import, no Docker call), so this is cheap and hermetic.
_SPEC = importlib.util.spec_from_file_location(
    "phase_1_7c_live_recon_smoke",
    Path(__file__).resolve().parents[1] / "scripts" / "phase_1_7c_live_recon_smoke.py",
)
assert _SPEC is not None and _SPEC.loader is not None
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)


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


class _TruncatingProvider:
    """A provider whose recon call fails closed with a bounded length-truncation diagnostic."""

    provider_type = "internal_openai_compatible"
    model = CANONICAL_MODEL

    def __init__(self, *, usage: dict[str, int] | None) -> None:
        self._usage = usage
        self.last_max_output_tokens: int | None = None

    async def generate_agent(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        schema: dict[str, Any],
        max_output_tokens: int,
    ) -> AgentProviderResult:
        del role, task_type, context, schema
        self.last_max_output_tokens = max_output_tokens
        # No raw content or reasoning_content text — only bounded, non-secret scalars.
        raise PlannerFailure(
            "INCOMPLETE_MODEL_OUTPUT_LENGTH",
            provider_reported_model=CANONICAL_MODEL,
            finish_reason="length",
            provider_usage=self._usage,
            content_length=120,
            reasoning_present=True,
            reasoning_length=3900,
        )


class _CompleteProvider:
    """A provider that returns one complete, schema-valid recon plan."""

    provider_type = "internal_openai_compatible"
    model = CANONICAL_MODEL

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.last_max_output_tokens: int | None = None

    async def generate_agent(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        schema: dict[str, Any],
        max_output_tokens: int,
    ) -> AgentProviderResult:
        del role, task_type, context, schema
        self.last_max_output_tokens = max_output_tokens
        return AgentProviderResult(
            self.model,
            json.dumps(self._payload),
            ProviderUsage(input_tokens=40, output_tokens=180, total_tokens=220),
            ProviderRunMetadata(
                provider_type=self.provider_type, runtime=self.provider_type, model=self.model
            ),
        )


# --------------------------------------------------------------------------- #
# (1)-(5) Provider -> gateway -> model diagnostic capture on a length truncation.
# --------------------------------------------------------------------------- #


async def test_length_truncation_fails_closed_with_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _TruncatingProvider(
        usage={"input_tokens": 60, "output_tokens": 4096, "total_tokens": 4156}
    )
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))

    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED:INCOMPLETE_MODEL_OUTPUT_LENGTH"):
        await model.generate(
            AgentRole.RECON_AGENT,
            "PLAN_RECON",
            {"target_ref": "range-bank"},
            {},
            max_output_tokens=smoke.PER_TASK_OUTPUT_CEILING["PLAN_RECON"],
        )

    # (1) fails closed: no success record was produced.
    assert model.call_records == []
    # (5) the rejected call is counted, and no usage is fabricated into a record.
    assert model.call_attempts == 1
    # (3) the sanitized pre-dispatch projection is retained even on rejection.
    assert len(model.failed_request_projections) == 1
    assert model.failed_request_projections[0].schema_identifier == "ReconPlanOutput"
    assert model.failed_request_projections[0].redaction_status == "CLEAN"
    # (4) identity is recorded before any structured-output validation.
    assert model.provider_reported_models == [CANONICAL_MODEL]
    # The explicit per-task ceiling reached the provider.
    assert provider.last_max_output_tokens == smoke.PER_TASK_OUTPUT_CEILING["PLAN_RECON"]

    diag = model.failure_diagnostics[-1]
    assert diag["code"] == "INCOMPLETE_MODEL_OUTPUT_LENGTH"
    assert diag["task_type"] == "PLAN_RECON"
    assert diag["finish_reason"] == "length"
    assert diag["provider_reported_model"] == CANONICAL_MODEL
    assert diag["reasoning_present"] is True
    assert diag["content_length"] == 120
    assert diag["reasoning_length"] == 3900
    assert diag["requested_output_tokens"] == smoke.PER_TASK_OUTPUT_CEILING["PLAN_RECON"]
    assert diag["provider_usage"] == {
        "input_tokens": 60,
        "output_tokens": 4096,
        "total_tokens": 4156,
    }


async def test_no_json_repair_on_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _TruncatingProvider(usage={"input_tokens": 60, "output_tokens": 4096})
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))

    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED"):
        await model.generate(
            AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )

    # (2) no plan is extracted, coerced or repaired from the truncated output.
    assert model.call_records == []
    result = smoke._rejection_result(model, ValueError("AGENT_GATEWAY_REJECTED:X"))
    assert result["status"] == "GATEWAY_REJECTED"
    assert "plans" not in result and "delegation" not in result


# --------------------------------------------------------------------------- #
# (5)-(6) The smoke rejection result: counters accurate, unknown usage not a breach.
# --------------------------------------------------------------------------- #


async def test_rejection_result_with_known_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _TruncatingProvider(
        usage={"input_tokens": 60, "output_tokens": 4096, "total_tokens": 4156}
    )
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    with pytest.raises(ValueError):
        await model.generate(
            AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )

    result = smoke._rejection_result(model, ValueError("AGENT_GATEWAY_REJECTED:INCOMPLETE"))
    assert result["provider_calls"] == 1  # includes the rejected call
    assert result["provider_tokens"] == 4156
    assert result["within_token_ceiling"] is True
    assert result["within_call_ceiling"] is True
    assert result["identity_exact_deepseek_v4_pro"] is True
    assert result["sanitized_projection_retained"] is True
    assert result["projections_clean"] is True
    rej = result["rejection"]
    assert rej["truncated_task"] == "PLAN_RECON"
    assert rej["finish_reason"] == "length"
    assert rej["reasoning_consumed_allowance"] is True


async def test_rejection_result_unknown_usage_is_not_a_breach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The provider reported no usage block at all.
    provider = _TruncatingProvider(usage=None)
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    with pytest.raises(ValueError):
        await model.generate(
            AgentRole.RECON_AGENT, "PLAN_RECON", {"target_ref": "range-bank"}, {}
        )

    result = smoke._rejection_result(model, ValueError("AGENT_GATEWAY_REJECTED:INCOMPLETE"))
    # (6) missing usage is UNKNOWN, never interpreted as exceeding the token ceiling.
    assert result["within_token_ceiling"] == smoke.UNKNOWN
    assert result["provider_tokens"] == smoke.UNKNOWN
    assert result["rejection"]["provider_usage"] == smoke.UNKNOWN
    # Identity / projection / call-count checks still hold on the unknown-usage path.
    assert result["identity_exact_deepseek_v4_pro"] is True
    assert result["within_call_ceiling"] is True


async def test_rejection_result_surfaces_value_free_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A *complete* response (finish_reason=stop) that violates the strict contract: this is the
    # AGENT_OUTPUT_REJECTED path, distinct from a length truncation. The offending value is a
    # sentinel that must not leak into the bounded, value-free evidence.
    provider = _CompleteProvider(
        {
            "capability_id": "aegis.exec.SENTINEL_LEAK_VALUE",
            "target_ref": "range-bank",
            "rationale": "smuggle an unregistered capability id",
        }
    )
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))
    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED:AGENT_OUTPUT_REJECTED"):
        await model.generate(
            AgentRole.RECON_AGENT,
            "PLAN_RECON",
            {"target_ref": "range-bank"},
            {},
            max_output_tokens=smoke.PER_TASK_OUTPUT_CEILING["PLAN_RECON"],
        )

    result = smoke._rejection_result(
        model, ValueError("AGENT_GATEWAY_REJECTED:AGENT_OUTPUT_REJECTED")
    )
    rej = result["rejection"]
    assert rej["code"] == "AGENT_OUTPUT_REJECTED"
    # A schema violation is not a truncation: no finish_reason=length, usage unknown here.
    assert rej["finish_reason"] is None
    assert rej["reasoning_consumed_allowance"] == smoke.UNKNOWN
    ve = rej["validation_errors"]
    assert isinstance(ve, list) and ve
    assert any(e["loc"] == "capability_id" for e in ve)
    for item in ve:
        assert {"loc", "type"} <= set(item) <= {"loc", "type", "code"}
    # No fragment of raw model output leaks into the evidence.
    assert "SENTINEL_LEAK_VALUE" not in json.dumps(result)
    # Still fails closed: no plan extracted, projection retained. Identity is not surfaced on the
    # AGENT_OUTPUT_REJECTED detail (matching the live run), so it stays False, not fabricated True.
    assert model.call_records == []
    assert result["sanitized_projection_retained"] is True
    assert result["identity_exact_deepseek_v4_pro"] is False


def test_usage_total_helper_handles_missing_and_partial() -> None:
    assert smoke._usage_total({"total_tokens": 100}) == 100
    assert smoke._usage_total({"input_tokens": 40, "output_tokens": 60}) == 100
    assert smoke._usage_total({}) is None
    assert smoke._usage_total(None) is None
    assert smoke._usage_total({"total_tokens": True}) is None  # bools are not counts


# --------------------------------------------------------------------------- #
# (7) Verdict tri-state: rejection -> NOT_EVALUATED downstream, never false.
# --------------------------------------------------------------------------- #


def _stack_ok(smoke_block: dict[str, Any]) -> dict[str, Any]:
    return {
        "healthy": True,
        "credential_isolation": {"control_plane_has_no_key": True},
        "cleanup": {"down_rc": 0, "leftovers": []},
        "smoke": smoke_block,
    }


def test_verdict_rejection_marks_downstream_not_evaluated() -> None:
    record = _stack_ok(
        {
            "status": "GATEWAY_REJECTED",
            "identity_exact_deepseek_v4_pro": True,
            "projections_clean": True,
            "sanitized_projection_retained": True,
            "within_call_ceiling": True,
            "within_token_ceiling": smoke.UNKNOWN,
        }
    )
    verdict = smoke._verdict(record)
    checks = verdict["checks"]
    assert verdict["status"] == "GATEWAY_REJECTED"
    assert verdict["passed"] is False  # PARTIAL: required checks were not evaluated
    for key in (
        "selected_registered_capability",
        "produced_valid_typed_plan",
        "interpreted_observations_unconfirmed",
        "delegated_reference_only",
        "avoided_confirming",
    ):
        assert checks[key] == smoke.NOT_EVALUATED, key
    # Checks the rejected call still produced keep their real result.
    assert checks["identity_exact_deepseek_v4_pro"] is True
    assert checks["sanitized_projection_retained"] is True
    assert checks["within_call_ceiling"] is True
    # Unknown token usage is UNKNOWN, not false and not a pass.
    assert checks["within_token_ceiling"] == smoke.UNKNOWN
    # Stack-level checks that genuinely ran are still evaluated.
    assert checks["stack_healthy"] is True
    assert checks["credential_in_gateway_only"] is True
    assert checks["cleanup_ok"] is True


def test_verdict_no_smoke_marks_downstream_not_evaluated() -> None:
    record = {
        "healthy": True,
        "credential_isolation": {"control_plane_has_no_key": True},
        "cleanup": {"leftovers": []},
        "smoke": None,
    }
    verdict = smoke._verdict(record)
    assert verdict["status"] == "NO_SMOKE"
    assert verdict["passed"] is False
    assert verdict["checks"]["identity_exact_deepseek_v4_pro"] == smoke.NOT_EVALUATED
    assert verdict["checks"]["selected_registered_capability"] == smoke.NOT_EVALUATED


def test_verdict_ok_path_passes_when_all_true() -> None:
    record = _stack_ok(
        {
            "status": "OK",
            "plans": {
                "range-bank": {
                    "capability_registered": True,
                    "plan_renders_shell_free_argv": True,
                },
                "range-shop": {"capability_registered": True},  # non-nmap: no argv key
            },
            "interpretations": {
                "range-bank": {"unconfirmed": True},
                "range-shop": {"unconfirmed": True},
            },
            "delegation": {"reference_only": True, "to_agent": "INJECTION_AGENT"},
            "identity_exact_deepseek_v4_pro": True,
            "projections_clean": True,
            "sanitized_projection_retained": True,
            "within_call_ceiling": True,
            "within_token_ceiling": True,
        }
    )
    verdict = smoke._verdict(record)
    assert verdict["status"] == "OK"
    assert verdict["passed"] is True, verdict["checks"]
    assert all(v is True for v in verdict["checks"].values())


# --------------------------------------------------------------------------- #
# (8) A complete response within the per-task ceiling passes strict validation.
# --------------------------------------------------------------------------- #


async def test_complete_response_within_ceiling_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "capability_id": "aegis.recon.network_service_discovery",
        "target_ref": "range-bank",
        "profile_id": "RANGE_FULL_RECON",
        "nmap_plan": {"transports": ["TCP"], "nse_script_ids": ["banner"]},
        "rationale": "Discover the documented HTTP service surface on the range target.",
    }
    provider = _CompleteProvider(payload)
    monkeypatch.setattr(gateway, "_provider", provider)
    gateway._agent_request_projections.clear()
    model = GatewayAgentModel(_settings(), httpx.ASGITransport(app=gateway.app))

    result = await model.generate(
        AgentRole.RECON_AGENT,
        "PLAN_RECON",
        {"target_ref": "range-bank"},
        {},
        max_output_tokens=smoke.PER_TASK_OUTPUT_CEILING["PLAN_RECON"],
    )
    validated = ReconPlanOutput.model_validate_json(result.payload_json)
    assert validated.capability_id == "aegis.recon.network_service_discovery"
    assert provider.last_max_output_tokens == 4096
    assert model.call_records and model.failure_diagnostics == []
