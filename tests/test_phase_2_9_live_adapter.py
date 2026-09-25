"""Focused tests for the Phase 2.9 isolated LIVE model-gateway adapter and orchestrator.

Every test mocks the docker-compose / gateway boundary through an injected runner; NO real docker
daemon, gateway or provider is ever touched. The tests prove the selection, transport, validation,
identity, budget, cleanup and secret-isolation behaviour of the live path while the deterministic
dry-run path stays exactly as before.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aegis.multi_agent.consolidated_campaign import (
    CANONICAL_MODEL,
    ConsolidatedOpsCampaign,
    Phase29ModelDouble,
)
from aegis.multi_agent.contracts import AgentRole
from aegis.multi_agent.live_safety import LiveExecutionRequest
from aegis.multi_agent.phase_2_9_live_gateway import (
    _HEALTH_PY,
    _KEY_PROBE_PY,
    _STEP_PY,
    ComposeResult,
    Phase29GatewayStack,
    Phase29LiveGatewayModel,
    Phase29LiveModelError,
    Phase29ProjectionError,
    assert_phase29_projection_clean,
    guard_is_armed_for_live,
    run_live_campaign,
    scan_projection_categories,
)

NOT_EVALUATED = "NOT_EVALUATED"

# The exact five (role, task) calls the campaign must make, in order.
EXPECTED_CALLS = [
    ("LEAD_ORCHESTRATOR", "DELEGATE_ADVERSARY_SIMULATION"),
    ("RECON_AGENT", "PLAN_ADVERSARY_SIMULATION"),
    ("RECON_AGENT", "RECOMMEND_ADVERSARY_REMEDIATION"),
    ("RECON_AGENT", "PLAN_ADVERSARY_SIMULATION"),
    ("REPORT_AGENT", "GENERATE_ASSESSMENT_REPORT"),
]

_GW_HEALTH_SNIPPET = "urllib.request.urlopen('http://127.0.0.1:8080/health')"
_CP_HEALTH_SNIPPET = "urllib.request.urlopen('http://127.0.0.1:8000/health')"


class FakeCompose:
    """A deterministic docker-compose runner double.

    It records every argv (and step stdin), answers build/up/health/identity/exec/teardown with
    canned results, and can be told to reject a call, report a wrong model, emit UNKNOWN usage or
    return an over-budget usage — all without any real docker or provider.
    """

    def __init__(
        self,
        *,
        health_model: str = CANONICAL_MODEL,
        control_plane_has_key: bool = False,
        fail_up: bool = False,
        unhealthy: bool = False,
        reject_at: int | None = None,
        reject_usage: dict[str, int] | None = None,
        mismatch_at: int | None = None,
        invalid_payload_at: int | None = None,
        output_tokens_at: dict[int, int] | None = None,
        leftovers: bool = False,
    ) -> None:
        self.health_model = health_model
        self.control_plane_has_key = control_plane_has_key
        self.fail_up = fail_up
        self.unhealthy = unhealthy
        self.reject_at = reject_at
        self.reject_usage = reject_usage
        self.mismatch_at = mismatch_at
        self.invalid_payload_at = invalid_payload_at
        self.output_tokens_at = output_tokens_at or {}
        self.leftovers = leftovers
        self.argv_log: list[list[str]] = []
        self.step_stdins: list[str] = []
        self.step_calls: list[tuple[str, str]] = []
        self.step_index = 0
        self.down_calls = 0

    def __call__(self, argv: list[str], stdin: str | None, timeout: int) -> ComposeResult:
        self.argv_log.append(argv)
        last = argv[-1]
        if "build" in argv:
            return ComposeResult(0)
        if "up" in argv:
            return ComposeResult(1 if self.fail_up else 0)
        if "down" in argv:
            self.down_calls += 1
            return ComposeResult(0)
        if argv[:2] == ["/usr/local/bin/docker", "ps"] or (len(argv) > 1 and argv[1] == "ps"):
            return ComposeResult(0, stdout="leftover-container\n" if self.leftovers else "")
        if len(argv) > 1 and argv[1] in ("network", "volume"):
            return ComposeResult(0, stdout="")
        # exec-based commands: dispatch on the executed code string.
        if last == _STEP_PY:
            return self._step(stdin)
        if last == _KEY_PROBE_PY:
            return ComposeResult(0, stdout="True" if self.control_plane_has_key else "False")
        if last == _HEALTH_PY:
            return ComposeResult(0, stdout=json.dumps({"model": self.health_model}))
        if _GW_HEALTH_SNIPPET in last or _CP_HEALTH_SNIPPET in last:
            return ComposeResult(1 if self.unhealthy else 0)
        return ComposeResult(0, stdout="")

    def argv_log_steps(self) -> list[list[str]]:
        return [a for a in self.argv_log if a and a[-1] == _STEP_PY]

    def _step(self, stdin: str | None) -> ComposeResult:
        assert stdin is not None, "step must receive bounded stdin JSON, never argv/env"
        self.step_stdins.append(stdin)
        req = json.loads(stdin)
        role, task, ctx = req["role"], req["task_type"], req["context"]
        self.step_calls.append((role, task))
        idx = self.step_index = self.step_index + 1

        reported = CANONICAL_MODEL
        if self.mismatch_at == idx:
            reported = "some-other-model:latest"

        if self.reject_at == idx:
            body: dict[str, Any] = {
                "status": "REJECTED",
                "code": "AGENT_GATEWAY_REJECTED",
                "error": "ValueError:AGENT_GATEWAY_REJECTED",
                "provider_reported_models": [reported],
                "provider_usage": self.reject_usage,  # None => UNKNOWN
                "diagnostic": {"task_type": task, "call_index": idx, "code": "SCHEMA_REJECTED"},
            }
            return ComposeResult(0, stdout=json.dumps(body))

        if self.invalid_payload_at == idx:
            payload_json = json.dumps({"not": "a valid contract"})
        else:
            payload = Phase29ModelDouble._payload(AgentRole(role), task, ctx)
            payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)

        out_tokens = self.output_tokens_at.get(idx, 60)
        body = {
            "status": "OK",
            "payload_json": payload_json,
            "usage": {"input_tokens": 40, "output_tokens": out_tokens},
            "provider_reported_models": [reported],
            "request_projection": {"redaction_status": "CLEAN", "forbidden_categories_present": []},
        }
        return ComposeResult(0, stdout=json.dumps(body))


def _run(tmp_path: Path, fake: FakeCompose, **kwargs: Any) -> dict[str, Any]:
    def stack_factory(campaign_id: str) -> Phase29GatewayStack:
        return Phase29GatewayStack(campaign_id=campaign_id, runner=fake)

    def campaign_factory(base_dir: Path, live_model: Any) -> ConsolidatedOpsCampaign:
        return ConsolidatedOpsCampaign(base_dir=base_dir, containerized=False, model=live_model)

    return run_live_campaign(
        authorization_ref="ops-2-9-approval-001",
        out_root=tmp_path / "out",
        stack_factory=stack_factory,
        campaign_factory=campaign_factory,
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Selection + guard.
# --------------------------------------------------------------------------- #


def test_dry_run_still_uses_deterministic_double(tmp_path: Path) -> None:
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "dry")
    assert isinstance(campaign.model, Phase29ModelDouble)
    assert campaign.model.name == "DETERMINISTIC_GATEWAY_DOUBLE"


def test_guard_probe_matches_exact_flags() -> None:
    assert not guard_is_armed_for_live(LiveExecutionRequest())
    assert not guard_is_armed_for_live(LiveExecutionRequest(execute_live=True))
    assert not guard_is_armed_for_live(
        LiveExecutionRequest(
            execute_live=True, authorization_ref="ops", max_provider_calls=4, max_total_tokens=15000
        )
    )
    assert guard_is_armed_for_live(
        LiveExecutionRequest(
            execute_live=True,
            authorization_ref="ops-2-9",
            max_provider_calls=5,
            max_total_tokens=15000,
        )
    )


def test_live_adapter_bound_to_stack_and_selected(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake, build=True)
    assert acceptance["status"] == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
    # The live adapter — not the double — served the campaign.
    assert acceptance["evidence_accounting"]["model_boundary"] == "ISOLATED_LIVE_GATEWAY"


# --------------------------------------------------------------------------- #
# Five task calls + role/task mapping + sanitized stdin transport.
# --------------------------------------------------------------------------- #


def test_exactly_five_calls_with_role_task_mapping(tmp_path: Path) -> None:
    fake = FakeCompose()
    _run(tmp_path, fake)
    assert fake.step_calls == EXPECTED_CALLS
    assert len(fake.step_stdins) == 5


def test_task_context_crosses_only_via_bounded_stdin_json(tmp_path: Path) -> None:
    fake = FakeCompose()
    _run(tmp_path, fake)
    for argv, stdin in zip(fake.argv_log_steps(), fake.step_stdins, strict=True):
        # Context is in stdin, never in argv (no task data on the command line).
        assert stdin is not None
        parsed = json.loads(stdin)
        assert set(parsed) == {"role", "task_type", "context", "max_output_tokens"}
        assert "-e" not in argv  # no env-var injection of task data


# --------------------------------------------------------------------------- #
# Projection safety.
# --------------------------------------------------------------------------- #


def test_projection_sanitizer_flags_forbidden_categories() -> None:
    assert scan_projection_categories({"target_ref": "range-ops"}) == []
    # A benign descriptive label containing the word "sentinel" is NOT a leak.
    assert scan_projection_categories({"salient": "alternate_reached_sentinel"}) == []
    assert "FORBIDDEN_KEY:auth_token" in scan_projection_categories({"auth_token": "x"})
    assert "FORBIDDEN_KEY:ground_truth" in scan_projection_categories({"ground_truth": "PASS"})
    assert "SECRET_OR_DIGEST_VALUE" in scan_projection_categories({"x": "a" * 64})
    assert "SECRET_OR_DIGEST_VALUE" in scan_projection_categories({"x": "sk-abcdefgh1234"})
    with pytest.raises(Phase29ProjectionError):
        assert_phase29_projection_clean({"sentinel_digest": "deadbeef"})


def test_adapter_refuses_forbidden_projection_before_dispatch() -> None:
    fake = FakeCompose()
    stack = Phase29GatewayStack(campaign_id="c1", runner=fake)
    model = Phase29LiveGatewayModel(stack)
    with pytest.raises(Phase29ProjectionError):
        model.generate(AgentRole.RECON_AGENT, "PLAN_ADVERSARY_SIMULATION", {"api_key": "secret"})
    # Nothing was dispatched to the gateway.
    assert fake.step_index == 0


def test_no_secret_value_in_projections_or_artifacts(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    blob = json.dumps(acceptance)
    for stdin in fake.step_stdins:
        blob += stdin
    # No bearer/sk- token or 64-hex digest anywhere in the transported/recorded evidence.
    import re

    assert not re.search(r"sk-[a-z0-9]{8,}", blob)
    assert not re.search(r"\b[0-9a-f]{64}\b", blob)
    # Sanitized projections are recorded and clean.
    for entry in acceptance["sanitized_projections"]:
        assert scan_projection_categories(entry["projection"]) == []


# --------------------------------------------------------------------------- #
# Identity + strict validation + fail-closed behaviour.
# --------------------------------------------------------------------------- #


def test_model_identity_preflight_mismatch_aborts_before_calls(tmp_path: Path) -> None:
    fake = FakeCompose(health_model="wrong-model")
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "MODEL_IDENTITY_PREFLIGHT_MISMATCH"
    assert fake.step_index == 0  # no provider call attempted
    assert fake.down_calls == 1  # stack still torn down


def test_per_call_model_mismatch_is_hard_failure(tmp_path: Path) -> None:
    fake = FakeCompose(mismatch_at=2)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "PROVIDER_MODEL_MISMATCH"
    # No retry: exactly the mismatching call was attempted, none after it.
    assert fake.step_index == 2
    assert fake.down_calls == 1


def test_invalid_output_stops_without_repair_or_retry(tmp_path: Path) -> None:
    fake = FakeCompose(invalid_payload_at=1)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    # The strict host-side contract validation rejected the payload; no second attempt of that call.
    assert fake.step_index == 1
    assert fake.down_calls == 1


def test_failed_call_unknown_usage_stops_subsequent_calls(tmp_path: Path) -> None:
    fake = FakeCompose(reject_at=3, reject_usage=None)  # UNKNOWN usage on the 3rd call
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    # Stopped at the failing call; calls 4 and 5 never happened.
    assert fake.step_index == 3
    assert fake.down_calls == 1
    diags = acceptance["failure_diagnostics"]
    assert any(d.get("code") in ("AGENT_GATEWAY_REJECTED", "SCHEMA_REJECTED") for d in diags)


def test_rejected_call_preserves_provider_usage_when_known(tmp_path: Path) -> None:
    fake = FakeCompose(reject_at=1, reject_usage={"input_tokens": 30, "output_tokens": 20})
    # Drive one adapter call directly to assert usage propagation onto the typed error.
    stack = Phase29GatewayStack(campaign_id="c1", runner=fake)
    model = Phase29LiveGatewayModel(stack)
    with pytest.raises(Phase29LiveModelError) as ei:
        model.generate(AgentRole.LEAD_ORCHESTRATOR, "DELEGATE_ADVERSARY_SIMULATION", {"a": "b"})
    assert ei.value.provider_input == 30
    assert ei.value.provider_output == 20
    assert ei.value.usage_known is True


# --------------------------------------------------------------------------- #
# Budget stops (call + token ceilings) via the single campaign authority.
# --------------------------------------------------------------------------- #


def test_token_ceiling_stops_the_campaign(tmp_path: Path) -> None:
    # Call 1 reports a huge output so the worst-case reservation for call 2 breaches 15,000 tokens.
    fake = FakeCompose(output_tokens_at={1: 14_000})
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    # The budget refused call 2 before dispatch: only one provider call ran.
    assert fake.step_index == 1
    assert fake.down_calls == 1


def test_full_success_records_five_calls_within_ceilings(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    acc = acceptance["evidence_accounting"]
    assert acc["provider_calls"] == 5
    assert acc["provider_usage_tokens"] <= 15_000
    assert acc["live_provider_budget_enforced"] is True


# --------------------------------------------------------------------------- #
# Identity + report-agent lifecycle + NOT_EVALUATED live status.
# --------------------------------------------------------------------------- #


def test_exact_identity_and_report_agent_job_lifecycle(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["provider_reported_models"] == [CANONICAL_MODEL]
    assert acceptance["evidence_accounting"]["exact_model_identity"] is True
    addr = acceptance["canonical_job_addresses"]["report"]
    assert str(addr).startswith("agentjob://REPORT_AGENT/")
    assert acceptance["checks"]["real_report_agent_job_persisted"] is True


def test_live_provider_status_stays_not_evaluated_in_mock(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["phase_2_9_live_provider_status"] == NOT_EVALUATED
    verdicts = acceptance["typed_verdicts"]
    for phase in ("phase_2_3", "phase_2_6", "phase_2_7", "phase_2_9"):
        assert verdicts[phase]["live_status"] == NOT_EVALUATED


def test_dry_run_accounting_keeps_live_fields_not_evaluated(tmp_path: Path) -> None:
    from aegis.multi_agent.consolidated_campaign import build_evidence_accounting

    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "dry")
    record = campaign.run()
    acc = build_evidence_accounting(record)  # default live=False
    assert acc["gateway_mode"] == "DETERMINISTIC_DOUBLE"
    assert acc["provider_calls"] == 0
    assert acc["exact_model_identity"] == NOT_EVALUATED
    assert acc["live_provider_budget_enforced"] == NOT_EVALUATED


# --------------------------------------------------------------------------- #
# Secret isolation + unconditional cleanup of both stacks.
# --------------------------------------------------------------------------- #


def test_secret_isolation_requires_key_free_control_plane(tmp_path: Path) -> None:
    fake = FakeCompose(control_plane_has_key=True)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "CONTROL_PLANE_HOLDS_CREDENTIAL"
    assert fake.step_index == 0
    assert fake.down_calls == 1


def test_secret_isolation_reported_on_success(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    iso = acceptance["secret_isolation"]
    assert iso["provider_key_only_in_gateway"] is True
    assert iso["control_plane_key_free"] is True
    assert iso["host_output_key_free"] is True


def test_cleanup_runs_on_gateway_up_failure(tmp_path: Path) -> None:
    fake = FakeCompose(fail_up=True)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "GATEWAY_STACK_UP_FAILED"
    assert fake.step_index == 0
    assert fake.down_calls == 1  # teardown still ran


def test_cleanup_proves_no_leftovers_on_success(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["cleanup"]["no_leftovers"] is True
    assert acceptance["cleanup"]["down_rc"] == 0


def test_cleanup_detects_leftovers(tmp_path: Path) -> None:
    fake = FakeCompose(leftovers=True)
    acceptance = _run(tmp_path, fake)
    assert acceptance["cleanup"]["no_leftovers"] is False
    assert acceptance["cleanup"]["container_leftovers"] == ["leftover-container"]


# --------------------------------------------------------------------------- #
# Stack argv discipline: shell-free, unique project, stdin transport.
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Script entry point: guard gates every side effect (no .env.gateway load, no live import).
# --------------------------------------------------------------------------- #


def _load_script() -> Any:
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "phase_2_9_consolidated_acceptance.py"
    spec = importlib.util.spec_from_file_location("phase_2_9_runner_under_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_default_is_inert() -> None:
    module = _load_script()
    assert module.main([]) == 0  # proposed-only, no side effect


def test_script_malformed_live_rejected_before_any_side_effect(monkeypatch: Any) -> None:
    module = _load_script()

    # Tripwire: any Path(...) use (e.g. the .env.gateway existence check) on a rejected invocation
    # would mean a side effect was reached before the guard rejected — the test fails loudly then.
    monkeypatch.setattr(module, "Path", _TripwirePath)
    # Missing --authorization-ref: rejected with rc 2, before .env.gateway existence is checked.
    rc = module.main(["--execute-live", "--max-provider-calls", "5", "--max-total-tokens", "15000"])
    assert rc == 2
    # Wrong caps: also rejected before any gateway/docker access.
    rc = module.main(
        ["--execute-live", "--authorization-ref", "ops-2-9", "--max-provider-calls", "4",
         "--max-total-tokens", "15000"]
    )
    assert rc == 2


class _TripwirePath:
    """Any use of Path(...) on the rejection path is a bug (the guard must reject first)."""

    def __init__(self, *_a: Any, **_k: Any) -> None:
        raise AssertionError(".env.gateway existence checked before authorization")


def test_stack_uses_unique_project_name_and_compose_files() -> None:
    fake = FakeCompose()
    stack = Phase29GatewayStack(campaign_id="phase-2.9-consolidated-abc123", runner=fake)
    assert stack.project == "aegis-p29-live-ds-phase-2.9-consolidated-abc123"
    stack.up()
    argv = fake.argv_log[-1]
    assert "-p" in argv and stack.project in argv
    assert "docker-compose.yml" in argv and "docker-compose.deepseek.yml" in argv
