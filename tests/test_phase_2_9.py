"""Phase 2.9 — focused tests for the consolidated end-to-end synthetic acceptance campaign.

These cover the surface Phase 2.9 ADDS on top of the accepted phases: the fail-closed live-execution
guard, the reserve-before-dispatch campaign budget, the deterministic model-boundary double, the
one-continuous-campaign lineage, the artifact bundle + manifest, and the derived per-contract
verdicts. The negative controls already owned by the composed phases (initial-verifier INCOMPLETE,
remediation without CONFIRMED, unknown remediation profile, crash-before/after-dispatch,
outcome-unknown no-auto-retry, report failure -> PARTIAL, cleanup failure -> CLEANUP_FAILED, lease
expiry) live in ``test_phase_2_3.py`` / ``test_phase_2_6.py`` / ``test_phase_2_7.py`` /
``test_phase_2_7_crash.py`` and are exercised through the SAME real components this campaign drives;
the campaign-level compositions are re-proven here.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pydantic
import pytest

from aegis.container_acceptance.docker_cli import daemon_available
from aegis.multi_agent.consolidated_campaign import (
    CANONICAL_MODEL,
    MAX_PROVIDER_CALLS,
    MAX_TOTAL_TOKENS,
    PER_CALL_OUTPUT_CEILING,
    RUN_EPOCH,
    ConsolidatedOpsCampaign,
    Phase29ModelDouble,
    build_phase_2_9_checks,
    build_typed_verdicts,
    is_live_armed,
    proposed_campaign,
    write_campaign_artifacts,
)
from aegis.multi_agent.contracts import (
    AdversaryRemediationRecommendationOutput,
    AdversarySimulationDelegationOutput,
    AdversarySimulationPlanOutput,
    AgentRole,
    AssessmentReportDraftOutput,
)
from aegis.multi_agent.lifecycle import LifecycleError, LifecycleStage
from aegis.multi_agent.live_safety import (
    BudgetStop,
    CampaignProviderBudget,
    InvalidLiveBudget,
    LiveAuthorizationRequired,
    LiveBudgetPolicy,
    LiveExecutionGuard,
    LiveExecutionRequest,
    estimate_input_tokens,
)
from aegis.multi_agent.remediation import RemediationLedgerError

# --------------------------------------------------------------------------- #
# Fixtures: one shared offline campaign (the in-process network double).
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def offline_campaign(tmp_path_factory: pytest.TempPathFactory) -> ConsolidatedOpsCampaign:
    base = tmp_path_factory.mktemp("phase29-offline")
    campaign = ConsolidatedOpsCampaign(base_dir=base, containerized=False)
    campaign.run()
    return campaign


@pytest.fixture(scope="module")
def offline_record(offline_campaign: ConsolidatedOpsCampaign) -> dict:
    return offline_campaign.record


def _guard() -> LiveExecutionGuard:
    return LiveExecutionGuard(
        policy=LiveBudgetPolicy(
            required_max_provider_calls=MAX_PROVIDER_CALLS,
            required_max_total_tokens=MAX_TOTAL_TOKENS,
            per_call_output_ceiling=PER_CALL_OUTPUT_CEILING,
        )
    )


# --------------------------------------------------------------------------- #
# Live-authorization guard (inert by default).
# --------------------------------------------------------------------------- #


def test_default_entry_point_is_inert() -> None:
    assert is_live_armed(LiveExecutionRequest()) is False
    proposed = proposed_campaign()
    assert proposed["mode"] == "PROPOSED_ONLY_INERT"
    assert proposed["model"] == CANONICAL_MODEL


def test_gateway_env_presence_alone_cannot_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A present .env.gateway (and an AI_AUTH_TOKEN env var) must NOT arm execution: the guard is a
    # pure function of the parsed request and reads no filesystem or environment.
    (tmp_path / ".env.gateway").write_text("AI_AUTH_TOKEN=sk-not-a-real-key\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AI_AUTH_TOKEN", "sk-not-a-real-key")
    assert is_live_armed(LiveExecutionRequest()) is False
    assert is_live_armed(LiveExecutionRequest(execute_live=True)) is False


def test_missing_authorization_reference_rejected() -> None:
    with pytest.raises(LiveAuthorizationRequired):
        _guard().evaluate(
            LiveExecutionRequest(
                execute_live=True, max_provider_calls=5, max_total_tokens=15000
            )
        )


def test_secret_like_authorization_reference_rejected() -> None:
    with pytest.raises(LiveAuthorizationRequired):
        _guard().evaluate(
            LiveExecutionRequest(
                execute_live=True, authorization_ref="sk-live-deadbeef01234567",
                max_provider_calls=5, max_total_tokens=15000,
            )
        )


def test_wrong_call_cap_rejected() -> None:
    with pytest.raises(InvalidLiveBudget):
        _guard().evaluate(
            LiveExecutionRequest(
                execute_live=True, authorization_ref="ops-2-9-approval",
                max_provider_calls=4, max_total_tokens=15000,
            )
        )


def test_wrong_token_cap_rejected() -> None:
    with pytest.raises(InvalidLiveBudget):
        _guard().evaluate(
            LiveExecutionRequest(
                execute_live=True, authorization_ref="ops-2-9-approval",
                max_provider_calls=5, max_total_tokens=12000,
            )
        )


def test_exact_flags_arm() -> None:
    armed = _guard().evaluate(
        LiveExecutionRequest(
            execute_live=True, authorization_ref="ops-2-9-approval-001",
            max_provider_calls=5, max_total_tokens=15000,
        )
    )
    assert armed.armed is True
    assert armed.max_provider_calls == 5
    assert armed.max_total_tokens == 15000


# --------------------------------------------------------------------------- #
# Fail-closed campaign budget (reserve before dispatch).
# --------------------------------------------------------------------------- #


def test_provider_call_ceiling_enforced() -> None:
    budget = CampaignProviderBudget(MAX_PROVIDER_CALLS, MAX_TOTAL_TOKENS, PER_CALL_OUTPUT_CEILING)
    for _ in range(MAX_PROVIDER_CALLS):
        reservation = budget.reserve("call", 10, 10)
        budget.record_actual(reservation, 10, 10)
    with pytest.raises(BudgetStop) as exc:
        budget.reserve("over", 10, 10)
    assert "CALL_CEILING" in str(exc.value)


def test_token_ceiling_reserved_worst_case_before_call() -> None:
    budget = CampaignProviderBudget(MAX_PROVIDER_CALLS, 1000, PER_CALL_OUTPUT_CEILING)
    # Worst case = input + per-call output ceiling exceeds the 1000-token campaign ceiling up front.
    with pytest.raises(BudgetStop) as exc:
        budget.reserve("call", 10, PER_CALL_OUTPUT_CEILING)
    assert "TOKEN_CEILING" in str(exc.value)


def test_unknown_usage_fails_closed_no_zero_assumption() -> None:
    budget = CampaignProviderBudget(MAX_PROVIDER_CALLS, MAX_TOTAL_TOKENS, PER_CALL_OUTPUT_CEILING)
    reservation = budget.reserve("call", 10, 10)
    budget.record_actual(reservation, None, None)  # provider usage UNKNOWN
    assert budget.usage_complete is False
    with pytest.raises(BudgetStop) as exc:
        budget.reserve("next", 10, 10)
    assert "PRIOR_USAGE_UNKNOWN" in str(exc.value)


def test_estimate_input_tokens_is_positive() -> None:
    assert estimate_input_tokens({"a": "b" * 400}) >= 1
    assert estimate_input_tokens(object()) >= 1


# --------------------------------------------------------------------------- #
# Deterministic model-boundary double.
# --------------------------------------------------------------------------- #


def test_model_double_emits_typed_non_authoritative_outputs() -> None:
    double = Phase29ModelDouble()
    deleg = AdversarySimulationDelegationOutput.model_validate_json(
        double.generate(
            AgentRole.LEAD_ORCHESTRATOR, "DELEGATE_ADVERSARY_SIMULATION", {"t": 1}
        ).payload_json
    )
    assert deleg.to_agent == "RECON_AGENT" and deleg.unconfirmed is True
    plan = AdversarySimulationPlanOutput.model_validate_json(
        double.generate(AgentRole.RECON_AGENT, "PLAN_ADVERSARY_SIMULATION", {}).payload_json
    )
    assert plan.probe.concurrency == 1 and plan.unconfirmed is True
    rec = AdversaryRemediationRecommendationOutput.model_validate_json(
        double.generate(AgentRole.RECON_AGENT, "RECOMMEND_ADVERSARY_REMEDIATION", {}).payload_json
    )
    assert rec.remediation_authoritative is False and rec.unconfirmed is True
    draft = AssessmentReportDraftOutput.model_validate_json(
        double.generate(
            AgentRole.REPORT_AGENT, "GENERATE_ASSESSMENT_REPORT", {"finding_id": "find-x"}
        ).payload_json
    )
    assert draft.authoritative is False and draft.unconfirmed is True
    assert double.reported_models == [CANONICAL_MODEL] * 4  # exact identity, provenance = double


def test_model_double_rejects_unknown_task() -> None:
    with pytest.raises(ValueError, match="TASK_UNSUPPORTED"):
        Phase29ModelDouble().generate(AgentRole.RECON_AGENT, "EXECUTE_SHELL", {})


def test_model_cannot_emit_raw_shell_url_or_redirect() -> None:
    # The typed plan contract structurally forbids a raw URL / command / redirect (extra=forbid).
    for extra in ("raw_url", "argv", "redirect_to", "target_override"):
        with pytest.raises(pydantic.ValidationError):
            AdversarySimulationPlanOutput.model_validate(
                {
                    "capability_id": "aegis.ops.detection_control_probe",
                    "target_ref": "range-ops",
                    "technique_class": "HTTP_DETECTION_CONTROL_BYPASS",
                    "probe": {"probe_profile_id": "http_detection_control_probe_v1"},
                    "rationale": "x",
                    extra: "http://attacker.example/redirect",
                }
            )


# --------------------------------------------------------------------------- #
# One continuous offline campaign lineage + derived verdicts (in-process double).
# --------------------------------------------------------------------------- #


def test_offline_campaign_completed_lineage(offline_record: dict) -> None:
    assert offline_record["lifecycle"]["final_state"] == "COMPLETED"
    assert offline_record["lifecycle"]["required_stages_complete"] is True
    # Fresh lineage, distinct from the Phase 2.7 integration campaign/epoch.
    assert offline_record["campaign_id"].startswith("phase-2.9-consolidated-")
    assert offline_record["campaign_id"] != "phase-2.7-integration"
    assert offline_record["run_epoch"] == RUN_EPOCH and RUN_EPOCH != 7
    assert offline_record["assessment_id"].startswith("asmt-")


def test_offline_campaign_five_calls_within_ceilings(offline_record: dict) -> None:
    snap = offline_record["budget"]["snapshot"]
    assert snap["calls_recorded"] == MAX_PROVIDER_CALLS
    assert snap["tokens_recorded"] <= MAX_TOTAL_TOKENS
    assert snap["within_ceilings"] is True
    assert len(offline_record["budget"]["attempts"]) == MAX_PROVIDER_CALLS
    assert offline_record["model"]["reported_models"] == [CANONICAL_MODEL]


def test_offline_verifier_owns_confirmation_and_pass(offline_record: dict) -> None:
    assert offline_record["verifier"]["initial_status"] == "CONFIRMED"
    assert offline_record["verifier"]["retest_state"] == "RETEST_PASS"
    # The verifier generated no substitute probe traffic on either adjudication.
    assert offline_record["verifier"]["initial_facts"]["verifier_probe_requests"] == 0
    assert offline_record["verifier"]["retest_facts"]["verifier_probe_requests"] == 0


def test_offline_remediation_non_authoritative_and_controller_applied(offline_record: dict) -> None:
    rem = offline_record["remediation"]
    assert rem["recommendation_authoritative"] is False
    assert rem["recommended_profile_id"] == "enforce_uniform_detection_control_v1"
    assert rem["applied_profile_id"] == "enforce_uniform_detection_control_v1"
    assert rem["target_state_changed"] is True
    assert rem["receipt_consumed"] is True


def test_offline_report_truth_controller_owned(offline_record: dict) -> None:
    report = offline_record["report"]
    assert report["finding_state"] == "CONFIRMED"
    assert report["finding_severity_authority"] in ("VERIFIER", "GROUND_TRUTH")
    assert report["retest_state"] == "PASS"
    assert report["live_report_agent_status"] == "NOT_EVALUATED"
    # Model prose is used only where it maps to a controller id; the draft is non-authoritative.
    assert offline_record["model_outputs"]["report_draft_authoritative"] is False


def test_offline_checks_and_verdicts(
    offline_campaign: ConsolidatedOpsCampaign, tmp_path: Path
) -> None:
    record = offline_campaign.record
    artifacts = write_campaign_artifacts(tmp_path / "ev", offline_campaign, record)
    checks = build_phase_2_9_checks(
        record,
        guard_enforced=True,
        artifact_manifest_verified=artifacts["manifest_verified"],
        report_outputs_persisted=artifacts["report_outputs_persisted"],
    )
    # No evaluable check is False. Offline: container-only checks stay NOT_EVALUATED (never False).
    assert [k for k, v in checks.items() if v is False] == []
    assert set(k for k, v in checks.items() if v == "NOT_EVALUATED") == {
        "no_public_egress",
        "no_leftovers",
    }
    verdicts = build_typed_verdicts(record, checks)
    for contract in ("phase_2_3", "phase_2_6", "phase_2_7", "phase_2_9"):
        assert verdicts[contract]["satisfied"] is True
        assert verdicts[contract]["live_status"] == "NOT_EVALUATED"
    assert verdicts["phase_2_9"]["unevaluated_checks"] == ["no_leftovers", "no_public_egress"]


# --------------------------------------------------------------------------- #
# Campaign-level compositions (stale evidence, receipt replay, retest ordering, artifacts).
# --------------------------------------------------------------------------- #


def test_stale_evidence_reuse_blocked(offline_record: dict) -> None:
    assert offline_record["verifier"]["stale_evidence_reuse_blocked"] is True


def test_patch_receipt_replay_blocked(offline_campaign: ConsolidatedOpsCampaign) -> None:
    # The receipt was consumed once by the retest; cleanup invalidated it. A replay fails closed.
    receipt_id = offline_campaign.record["remediation"]["receipt_id"]
    ledger = offline_campaign.asm.remediation_ledger
    assert ledger.receipt_consumed(receipt_id) is True
    with pytest.raises(RemediationLedgerError, match="RECEIPT_ALREADY_CONSUMED"):
        ledger.consume_receipt(receipt_id)


def test_retest_before_patch_is_structurally_blocked(tmp_path: Path) -> None:
    # A fresh lifecycle: RETEST cannot run before its REMEDIATE dependency is DONE.
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c", containerized=False)
    asm = campaign.asm
    now = datetime.now().astimezone()
    asm.lifecycle.create_assessment(asm.spec)
    asm.lifecycle.authorize(
        asm.spec.assessment_id, authorization_reference=asm.spec.authorization_reference, now=now
    )
    asm.lifecycle.mark_ready(
        asm.spec.assessment_id,
        activated_capabilities=("aegis.ops.detection_control_probe",),
        now=now,
    )
    with pytest.raises(LifecycleError, match="STAGE_DEP_NOT_DONE"):
        asm.lifecycle.run_external_stage(
            asm.spec.assessment_id, LifecycleStage.RETEST, asm.retest_dispatcher,
            idempotency_key="early-retest", now=now,
        )


def test_artifact_manifest_detects_tampering(
    offline_campaign: ConsolidatedOpsCampaign, tmp_path: Path
) -> None:
    art_dir = tmp_path / "ev"
    result = write_campaign_artifacts(art_dir, offline_campaign, offline_campaign.record)
    assert result["manifest_verified"] is True
    # Tamper with a checksummed evidence file; a re-verification against SHA256SUMS must fail.
    tampered = art_dir / "finding_record.json"
    tampered.write_text(tampered.read_text() + "\n// tampered\n")
    import hashlib

    recorded = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in (art_dir / "SHA256SUMS").read_text().splitlines()
        if line.strip()
    }
    digest = hashlib.sha256((art_dir / "finding_record.json").read_bytes()).hexdigest()
    assert digest != recorded["finding_record.json"]


def test_no_raw_sentinel_in_worker_evidence(offline_record: dict) -> None:
    # Only 64-hex SHA-256 digests ever appear; the raw 32-char sentinel never leaves the worker.
    for slot in ("baseline", "alternate"):
        for phase in ("initial", "retest"):
            evidence = offline_record["worker_evidence"][phase][slot]
            digest = str(evidence["sentinel_digest"])
            assert digest == "" or len(digest) == 64


# --------------------------------------------------------------------------- #
# Real-container dry run (skipped when the docker daemon is unavailable).
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not daemon_available(), reason="docker daemon unavailable")
def test_containerized_dry_run_passes_and_cleans_up(tmp_path: Path) -> None:
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c", containerized=True)
    record = campaign.run()
    assert record["range_backend"] == "CONTAINERIZED_SYNTHETIC"
    assert record["lifecycle"]["final_state"] == "COMPLETED"
    # Real container behaviour: baseline denied, alternate reached the sentinel (vulnerable), then
    # denied after the patch; egress blocked on an internal network; zero leftovers.
    assert record["worker_evidence"]["initial"]["baseline"]["blocked"] is True
    assert record["worker_evidence"]["initial"]["alternate"]["sentinel_present"] is True
    assert record["worker_evidence"]["retest"]["alternate"]["blocked"] is True
    assert record["cleanup"]["network_was_internal"] is True
    assert str(record["cleanup"]["egress_blocked_proof"]).startswith("EGRESS_BLOCKED")
    assert record["cleanup"]["no_leftovers"] is True
    artifacts = write_campaign_artifacts(tmp_path / "ev", campaign, record)
    checks = build_phase_2_9_checks(
        record,
        guard_enforced=True,
        artifact_manifest_verified=artifacts["manifest_verified"],
        report_outputs_persisted=artifacts["report_outputs_persisted"],
    )
    # In the containerized run EVERY required check is evaluable and True (nothing NOT_EVALUATED).
    assert [k for k, v in checks.items() if v is not True] == []
