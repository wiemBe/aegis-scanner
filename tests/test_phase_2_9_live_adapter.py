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

import aegis.multi_agent.phase_2_9_live_gateway as live_gateway
from aegis.container_acceptance.contracts import CleanupProof
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
    Phase29ProjectionShapeError,
    assert_phase29_projection_clean,
    assert_phase29_projection_shape,
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
        fail_build: bool = False,
        probe_fail: str | None = None,
        bad_usage_at: dict[int, Any] | None = None,
        projection_mismatch_at: int | None = None,
        projection_missing_at: int | None = None,
        projection_missing_malformed: bool = False,
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
        self.fail_build = fail_build
        # Which teardown listing probe reports rc!=0: "ps" | "network" | "volume".
        self.probe_fail = probe_fail
        # Per-call replacement usage dict (or None) for a success response (missing/negative/etc.).
        self.bad_usage_at = bad_usage_at or {}
        # Emit a non-corresponding gateway request projection on this call index.
        self.projection_mismatch_at = projection_mismatch_at
        # Omit (or malform) the retained request projection on this call index.
        self.projection_missing_at = projection_missing_at
        self.projection_missing_malformed = projection_missing_malformed
        self.build_calls = 0
        self.argv_log: list[list[str]] = []
        self.step_stdins: list[str] = []
        self.step_calls: list[tuple[str, str]] = []
        self.step_index = 0
        self.down_calls = 0

    def __call__(self, argv: list[str], stdin: str | None, timeout: int) -> ComposeResult:
        self.argv_log.append(argv)
        last = argv[-1]
        if "build" in argv:
            self.build_calls += 1
            return ComposeResult(1 if self.fail_build else 0)
        if "up" in argv:
            return ComposeResult(1 if self.fail_up else 0)
        if "down" in argv:
            self.down_calls += 1
            return ComposeResult(0)
        if len(argv) > 1 and argv[1] == "ps":
            rc = 1 if self.probe_fail == "ps" else 0
            return ComposeResult(rc, stdout="leftover-container\n" if self.leftovers else "")
        if len(argv) > 1 and argv[1] == "network":
            return ComposeResult(1 if self.probe_fail == "network" else 0, stdout="")
        if len(argv) > 1 and argv[1] == "volume":
            return ComposeResult(1 if self.probe_fail == "volume" else 0, stdout="")
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
        usage: Any = {"input_tokens": 40, "output_tokens": out_tokens}
        if idx in self.bad_usage_at:
            usage = self.bad_usage_at[idx]  # missing/partial/negative/boolean/non-int
        projection: dict[str, Any] = {
            "redaction_status": "CLEAN",
            "forbidden_categories_present": [],
            "context_field_names": sorted(ctx.keys()),
        }
        if self.projection_mismatch_at == idx:
            # A retained projection whose recorded context fields do NOT match what was dispatched.
            projection["context_field_names"] = ["unexpected_leaked_field"]
        body = {
            "status": "OK",
            "payload_json": payload_json,
            "usage": usage,
            "provider_reported_models": [reported],
            "request_projection": projection,
        }
        if self.projection_missing_at == idx:
            # A successful response with NO retained request projection at all.
            if self.projection_missing_malformed:
                body["request_projection"] = "not-an-object"
            else:
                body.pop("request_projection")
        return ComposeResult(0, stdout=json.dumps(body))


ARMED_AUTHORIZATION_REF = "ops-2-9-approval-001"

# An explicit SUCCESSFUL range-cleanup boundary result the mock happy path injects. Observed success
# must be earned through a genuine PASS snapshot — never merely because the in-process campaign
# returns no_leftovers=None.
SUCCESSFUL_RANGE_CLEANUP: dict[str, Any] = {
    "status": "PASS",
    "backend": "CONTAINERIZED_SYNTHETIC",
    "teardown_ran": True,
    "teardown_error": None,
    "leftover_query_ok": True,
    "no_leftovers": True,
    "leftover_proof": {
        "stack_containers_remaining": 0,
        "volumes_remaining": 0,
        "networks_remaining": 0,
        "network_was_internal": True,
        "egress_blocked_proof": "EGRESS_BLOCKED:TimeoutError",
    },
    "network_was_internal": True,
    "egress_blocked_proof": "EGRESS_BLOCKED:TimeoutError",
}


def _run(
    tmp_path: Path,
    fake: FakeCompose,
    *,
    authorization_ref: str = ARMED_AUTHORIZATION_REF,
    range_cleanup_override: dict[str, Any] | None = SUCCESSFUL_RANGE_CLEANUP,
    **kwargs: Any,
) -> dict[str, Any]:
    def stack_factory(campaign_id: str) -> Phase29GatewayStack:
        return Phase29GatewayStack(campaign_id=campaign_id, runner=fake)

    def campaign_factory(
        base_dir: Path, live_model: Any, authorization_reference: str
    ) -> ConsolidatedOpsCampaign:
        return ConsolidatedOpsCampaign(
            base_dir=base_dir,
            containerized=False,
            model=live_model,
            authorization_reference=authorization_reference,
            range_cleanup_override=range_cleanup_override,
        )

    return run_live_campaign(
        authorization_ref=authorization_ref,
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
        model.generate(
            AgentRole.LEAD_ORCHESTRATOR,
            "DELEGATE_ADVERSARY_SIMULATION",
            {"target_ref": "range-ops", "capability_catalog": ["x"]},
        )
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


def test_secret_isolation_is_evidence_derived_or_not_evaluated(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    iso = acceptance["secret_isolation"]
    # control-plane probe genuinely ran and proved the process env is key-free.
    assert iso["control_plane_key_free"] is True
    # "only in gateway" cannot be established from the single control-plane probe -> NOT_EVALUATED.
    assert iso["provider_key_only_in_gateway"] == NOT_EVALUATED
    # There is NO hard-coded host_output_key_free=True claim anymore.
    assert "host_output_key_free" not in iso
    # The credential-free claim is evidence-derived from a scan of the transported evidence.
    assert iso["recorded_evidence_credential_free"] is True


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
    # A gateway leftover controls the verdict: it can no longer be observed-success.
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["live_acceptance_gates"]["gateway_cleanup_no_leftovers"] is False


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


# --------------------------------------------------------------------------- #
# CORRECTION: authorization binding threaded into the controller-owned spec.
# --------------------------------------------------------------------------- #


def test_armed_authorization_ref_equals_controller_recorded_ref(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["armed_authorization_reference"] == ARMED_AUTHORIZATION_REF
    assert acceptance["controller_authorization_reference"] == ARMED_AUTHORIZATION_REF
    assert acceptance["preflight"]["authorization_binding_ok"] is True


def test_authorization_binding_mismatch_aborts_before_dispatch(tmp_path: Path) -> None:
    fake = FakeCompose()

    def stack_factory(campaign_id: str) -> Phase29GatewayStack:
        return Phase29GatewayStack(campaign_id=campaign_id, runner=fake)

    def bad_factory(
        base_dir: Path, model: Any, authorization_reference: str
    ) -> ConsolidatedOpsCampaign:
        # The controller records a DIFFERENT reference than the armed operator reference.
        return ConsolidatedOpsCampaign(
            base_dir=base_dir,
            containerized=False,
            model=model,
            authorization_reference="authz-range-ops-integration",
        )

    acceptance = run_live_campaign(
        authorization_ref="ops-2-9-approval-001",
        out_root=tmp_path / "out",
        stack_factory=stack_factory,
        campaign_factory=bad_factory,
    )
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "AUTHORIZATION_BINDING_MISMATCH"
    assert fake.build_calls == 0  # aborted before build/up/dispatch
    assert fake.step_index == 0
    assert fake.down_calls == 1
    assert acceptance["integrity_manifest_verified"] is True


# --------------------------------------------------------------------------- #
# CORRECTION: cleanup controls the verdict (build / probe rc / leftovers).
# --------------------------------------------------------------------------- #


def test_build_failure_stops_before_up(tmp_path: Path) -> None:
    fake = FakeCompose(fail_build=True)
    acceptance = _run(tmp_path, fake, build=True)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "GATEWAY_BUILD_FAILED"
    assert fake.build_calls == 1
    assert not any("up" in a for a in fake.argv_log)  # never reached `up`
    assert fake.step_index == 0
    assert fake.down_calls == 1


@pytest.mark.parametrize(
    ("probe", "rc_key"),
    [
        ("ps", "container_probe_rc"),
        ("network", "network_probe_rc"),
        ("volume", "volume_probe_rc"),
    ],
)
def test_failed_cleanup_probe_cannot_prove_cleanup(
    tmp_path: Path, probe: str, rc_key: str
) -> None:
    fake = FakeCompose(probe_fail=probe)
    acceptance = _run(tmp_path, fake)
    assert acceptance["cleanup"][rc_key] == 1
    assert acceptance["cleanup"]["no_leftovers"] is False
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["live_acceptance_gates"]["gateway_cleanup_no_leftovers"] is False


# --------------------------------------------------------------------------- #
# CORRECTION: usage never defaults to zero.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_usage",
    [
        {"input_tokens": 40},  # missing output
        {"output_tokens": 60},  # missing input
        {"input_tokens": 40, "output_tokens": -5},  # negative
        {"input_tokens": True, "output_tokens": 60},  # boolean
        {"input_tokens": "40", "output_tokens": 60},  # non-integer
        "not-a-dict",  # malformed
        {},  # absent
    ],
)
def test_success_bad_usage_becomes_unknown_and_stops(tmp_path: Path, bad_usage: Any) -> None:
    fake = FakeCompose(bad_usage_at={2: bad_usage})
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "PROVIDER_USAGE_UNKNOWN"
    # Stopped at call 2; calls 3+ were never dispatched (no zero substituted, no next call).
    assert fake.step_index == 2
    assert fake.down_calls == 1
    last = acceptance["dispatched_attempts"][-1]
    assert last["status"] == "USAGE_UNKNOWN"
    assert last["input_tokens"] == "UNKNOWN"
    assert last["output_tokens"] == "UNKNOWN"
    assert last["usage_known"] is False


def test_model_mismatch_preserves_known_usage(tmp_path: Path) -> None:
    fake = FakeCompose(mismatch_at=1)
    stack = Phase29GatewayStack(campaign_id="c1", runner=fake)
    model = Phase29LiveGatewayModel(stack)
    with pytest.raises(Phase29LiveModelError) as ei:
        model.generate(
            AgentRole.LEAD_ORCHESTRATOR,
            "DELEGATE_ADVERSARY_SIMULATION",
            {"target_ref": "range-ops", "capability_catalog": ["x"]},
        )
    assert ei.value.code == "PROVIDER_MODEL_MISMATCH"
    # The usage the OK response supplied is parsed and preserved on the identity-mismatch error.
    assert ei.value.provider_input == 40
    assert ei.value.provider_output == 60
    assert ei.value.usage_known is True
    assert model.dispatched_attempts[-1]["status"] == "MODEL_MISMATCH"
    assert model.dispatched_attempts[-1]["input_tokens"] == 40


# --------------------------------------------------------------------------- #
# CORRECTION: projection shape allowlist + gateway-projection correspondence.
# --------------------------------------------------------------------------- #


def test_projection_shape_allowlist_rejects_unexpected_keys() -> None:
    # A benign-looking but unexpected extra key for the task fails the shape allowlist.
    with pytest.raises(Phase29ProjectionShapeError):
        assert_phase29_projection_shape(
            "DELEGATE_ADVERSARY_SIMULATION",
            {"target_ref": "range-ops", "capability_catalog": ["x"], "extra": "nope"},
        )
    # An unknown task type has no allowlisted shape.
    with pytest.raises(Phase29ProjectionShapeError):
        assert_phase29_projection_shape("UNKNOWN_TASK", {"a": "b"})
    # Each of the two PLAN shapes is accepted.
    assert_phase29_projection_shape(
        "PLAN_ADVERSARY_SIMULATION", {"target_ref": "range-ops", "capability_id": "c"}
    )
    assert_phase29_projection_shape(
        "PLAN_ADVERSARY_SIMULATION", {"target_ref": "range-ops", "finding_ref": "f"}
    )


def test_adapter_rejects_unexpected_projection_shape_before_dispatch() -> None:
    fake = FakeCompose()
    stack = Phase29GatewayStack(campaign_id="c1", runner=fake)
    model = Phase29LiveGatewayModel(stack)
    with pytest.raises(Phase29ProjectionShapeError):
        model.generate(
            AgentRole.RECON_AGENT,
            "PLAN_ADVERSARY_SIMULATION",
            {"target_ref": "range-ops", "unexpected_key": "x"},
        )
    assert fake.step_index == 0  # nothing dispatched


def test_gateway_projection_mismatch_is_hard_failure(tmp_path: Path) -> None:
    fake = FakeCompose(projection_mismatch_at=1)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "GATEWAY_PROJECTION_MISMATCH"
    assert fake.step_index == 1
    assert fake.down_calls == 1


# --------------------------------------------------------------------------- #
# CORRECTION: abort + success artifacts are persisted, manifested, non-overwriting.
# --------------------------------------------------------------------------- #


def test_abort_produces_manifested_artifact(tmp_path: Path) -> None:
    fake = FakeCompose(mismatch_at=2)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    ev = Path(acceptance["evidence_dir"])
    assert (ev / "live_acceptance.json").exists()
    assert (ev / "LIVE_SHA256SUMS").exists()
    assert (ev / "gateway_cleanup.json").exists()
    assert (ev / "dispatched_attempts.json").exists()
    assert acceptance["integrity_manifest_verified"] is True
    sums = (ev / "LIVE_SHA256SUMS").read_text()
    # The decisive live acceptance verdict is INSIDE the integrity manifest.
    assert "live_acceptance.json" in sums
    persisted = json.loads((ev / "live_acceptance.json").read_text())
    assert persisted["abort_code"] == "PROVIDER_MODEL_MISMATCH"
    assert persisted["controller_authorization_reference"] == ARMED_AUTHORIZATION_REF


def test_success_artifact_contains_verdict_and_cleanups(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
    ev = Path(acceptance["evidence_dir"])
    la = json.loads((ev / "live_acceptance.json").read_text())
    assert la["status"] == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
    assert la["cleanup"]["no_leftovers"] is True  # gateway cleanup evidence inside the verdict
    names = {p.name for p in ev.iterdir()}
    assert "gateway_cleanup.json" in names
    assert "cleanup_ledger.json" in names  # range cleanup bundle
    sums = (ev / "LIVE_SHA256SUMS").read_text()
    assert "live_acceptance.json" in sums and "gateway_cleanup.json" in sums
    assert acceptance["integrity_manifest_verified"] is True


def test_artifact_collision_is_refused_without_overwriting(tmp_path: Path) -> None:
    out_root = tmp_path / "out"

    def stack_factory(campaign_id: str) -> Phase29GatewayStack:
        return Phase29GatewayStack(campaign_id=campaign_id, runner=FakeCompose())

    def fixed_factory(
        base_dir: Path, model: Any, authorization_reference: str
    ) -> ConsolidatedOpsCampaign:
        return ConsolidatedOpsCampaign(
            base_dir=base_dir,
            containerized=False,
            model=model,
            authorization_reference=authorization_reference,
            campaign_id="phase-2.9-consolidated-fixedid01",
        )

    first = run_live_campaign(
        authorization_ref="ops-2-9-approval-001",
        out_root=out_root,
        stack_factory=stack_factory,
        campaign_factory=fixed_factory,
    )
    ev = Path(first["evidence_dir"])
    assert ev.exists()
    sentinel = (ev / "live_acceptance.json").read_bytes()
    # A second run into the SAME collision-resistant path is refused (never overwritten).
    with pytest.raises(FileExistsError):
        run_live_campaign(
            authorization_ref="ops-2-9-approval-001",
            out_root=out_root,
            stack_factory=stack_factory,
            campaign_factory=fixed_factory,
        )
    assert (ev / "live_acceptance.json").read_bytes() == sentinel  # unchanged


# --------------------------------------------------------------------------- #
# CORRECTION: false checks / evidence semantics gate the observed-success status.
# --------------------------------------------------------------------------- #


def test_false_required_check_prevents_observed_success(
    tmp_path: Path, monkeypatch: Any
) -> None:
    real = getattr(live_gateway, "build_phase_2_9_checks")  # noqa: B009 - patched attr, avoid re-export typing

    def patched(record: dict[str, Any], **kw: Any) -> dict[str, Any]:
        checks: dict[str, Any] = real(record, **kw)
        checks["retest_verifier_passed"] = False  # force a required check False
        return checks

    monkeypatch.setattr(live_gateway, "build_phase_2_9_checks", patched)
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["live_acceptance_gates"]["no_false_checks"] is False
    assert "retest_verifier_passed" in acceptance["false_checks"]


def test_live_checks_have_no_affirmative_simulated_semantics(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    checks = acceptance["checks"]
    for key, value in checks.items():
        if key.startswith("simulated_"):
            assert value == NOT_EVALUATED, (key, value)
    # The live-provider identity/budget checks carry the observed facts instead.
    assert checks["exact_model_identity"] is True
    assert checks["live_provider_budget_enforced"] is True
    acct = acceptance["evidence_accounting"]
    assert acct["gateway_mode"] == "ISOLATED_LIVE_GATEWAY"
    assert acct["simulated_model_identity_reported"] == NOT_EVALUATED


# --------------------------------------------------------------------------- #
# CORRECTION 2: range cleanup proof is MANDATORY for a live campaign.
# --------------------------------------------------------------------------- #


class _FakeRange:
    """A minimal range double: enough to create + tear down before an early abort."""

    def __init__(self, *, clean: bool = True) -> None:
        self._clean = clean
        self.mode = "vulnerable"
        self.generation = 0
        self.sentinel_digest = ""
        self.probe_requests = 0
        self.created = False
        self.torn_down = False

    def create(self) -> None:
        self.created = True

    def network_is_internal(self) -> bool:
        return True

    def egress_blocked_proof(self) -> str:
        return "EGRESS_BLOCKED:TimeoutError"

    def teardown(self) -> None:
        self.torn_down = True

    def leftover_proof(self, *, was_internal: bool, egress_proof: str) -> CleanupProof:
        remaining = 0 if self._clean else 1
        return CleanupProof(
            stack_containers_remaining=remaining,
            volumes_remaining=0,
            networks_remaining=0,
            network_was_internal=was_internal,
            egress_blocked_proof=egress_proof,
        )


def test_range_cleanup_none_prevents_observed_success(tmp_path: Path) -> None:
    none_snapshot = dict(SUCCESSFUL_RANGE_CLEANUP)
    none_snapshot["no_leftovers"] = None
    none_snapshot["status"] = "NOT_STARTED"
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake, range_cleanup_override=none_snapshot)
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["live_acceptance_gates"]["range_cleanup_complete"] is False


def test_range_leftover_query_failure_prevents_observed_success(tmp_path: Path) -> None:
    bad = dict(SUCCESSFUL_RANGE_CLEANUP)
    bad["leftover_query_ok"] = False
    bad["status"] = "COLLECT_FAILED"
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake, range_cleanup_override=bad)
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["live_acceptance_gates"]["range_cleanup_complete"] is False


def test_range_cleanup_failure_visible_even_when_gateway_clean(tmp_path: Path) -> None:
    failed = dict(SUCCESSFUL_RANGE_CLEANUP)
    failed["status"] = "CLEANUP_FAILED"
    failed["no_leftovers"] = False
    fake = FakeCompose()  # gateway teardown is clean (no leftovers)
    acceptance = _run(tmp_path, fake, range_cleanup_override=failed)
    assert acceptance["cleanup"]["no_leftovers"] is True  # gateway cleanup succeeded
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"  # range failure still fails closed
    assert acceptance["live_acceptance_gates"]["gateway_cleanup_no_leftovers"] is True
    assert acceptance["live_acceptance_gates"]["range_cleanup_complete"] is False
    assert acceptance["range_cleanup"]["status"] == "CLEANUP_FAILED"


def test_happy_path_requires_explicit_successful_range_cleanup(tmp_path: Path) -> None:
    # With NO injected range-cleanup proof the in-process campaign returns NOT_STARTED /
    # no_leftovers None — which must NOT earn observed success.
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake, range_cleanup_override=None)
    assert acceptance["status"] == "LIVE_OBSERVED_FAILED_CLOSED"
    assert acceptance["range_cleanup"]["status"] == "NOT_STARTED"
    assert acceptance["range_cleanup"]["no_leftovers"] is None
    # The explicit successful proof is what earns success.
    ok = _run(tmp_path, FakeCompose())
    assert ok["status"] == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
    assert ok["range_cleanup"]["status"] == "PASS"
    assert ok["range_cleanup"]["no_leftovers"] is True


def test_exception_after_range_creation_persists_range_cleanup(tmp_path: Path) -> None:
    fake = FakeCompose(mismatch_at=1)  # aborts at provider call 1, after range creation
    ranges: list[_FakeRange] = []

    def stack_factory(campaign_id: str) -> Phase29GatewayStack:
        return Phase29GatewayStack(campaign_id=campaign_id, runner=fake)

    def factory(
        base_dir: Path, model: Any, authorization_reference: str
    ) -> ConsolidatedOpsCampaign:
        rng = _FakeRange(clean=True)
        ranges.append(rng)
        return ConsolidatedOpsCampaign(
            base_dir=base_dir,
            containerized=True,
            model=model,
            authorization_reference=authorization_reference,
            container_factory=lambda: rng,  # type: ignore[arg-type,return-value]
        )

    acceptance = run_live_campaign(
        authorization_ref=ARMED_AUTHORIZATION_REF,
        out_root=tmp_path / "out",
        stack_factory=stack_factory,
        campaign_factory=factory,
        build=False,
    )
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "PROVIDER_MODEL_MISMATCH"
    # The range was created then torn down in the finally despite the exception.
    assert ranges[0].created is True and ranges[0].torn_down is True
    # The abort artifact contains a persisted range_cleanup.json captured from the finally.
    ev = Path(acceptance["evidence_dir"])
    assert (ev / "range_cleanup.json").exists()
    rc = json.loads((ev / "range_cleanup.json").read_text())
    assert rc["status"] == "PASS" and rc["teardown_ran"] is True
    assert acceptance["range_cleanup"]["status"] == "PASS"


# --------------------------------------------------------------------------- #
# CORRECTION 2: a valid retained gateway projection is REQUIRED for every success.
# --------------------------------------------------------------------------- #


def test_missing_projection_fails_closed_and_stops(tmp_path: Path) -> None:
    fake = FakeCompose(projection_missing_at=2)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "GATEWAY_PROJECTION_MISSING"
    assert fake.step_index == 2  # calls 3+ never dispatched
    assert fake.down_calls == 1


def test_malformed_projection_fails_closed(tmp_path: Path) -> None:
    fake = FakeCompose(projection_missing_at=1, projection_missing_malformed=True)
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_ABORTED_FAIL_CLOSED"
    assert acceptance["abort_code"] == "GATEWAY_PROJECTION_MISSING"
    assert fake.step_index == 1


def test_projection_rejection_preserves_known_usage(tmp_path: Path) -> None:
    fake = FakeCompose(projection_missing_at=1)
    stack = Phase29GatewayStack(campaign_id="c1", runner=fake)
    model = Phase29LiveGatewayModel(stack)
    with pytest.raises(Phase29LiveModelError) as ei:
        model.generate(
            AgentRole.LEAD_ORCHESTRATOR,
            "DELEGATE_ADVERSARY_SIMULATION",
            {"target_ref": "range-ops", "capability_catalog": ["x"]},
        )
    assert ei.value.code == "GATEWAY_PROJECTION_MISSING"
    assert ei.value.provider_input == 40  # usage the OK response supplied is preserved
    assert ei.value.provider_output == 60
    assert model.dispatched_attempts[-1]["status"] == "PROJECTION_MISSING"


def test_five_true_correspondence_records_on_success(tmp_path: Path) -> None:
    fake = FakeCompose()
    acceptance = _run(tmp_path, fake)
    assert acceptance["status"] == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
    assert acceptance["projection_correspondence"] == [True, True, True, True, True]
    assert acceptance["live_acceptance_gates"]["projection_correspondence_complete"] is True
