"""Phase 2.9 — post-cleanup report-truth tests.

The controller-authoritative FINAL report must reflect the ACTUAL cleanup result, assembled ONLY
after the cleanup ledger + range teardown complete — never a cleanup success assumed at REPORT-stage
time. These tests exercise the real campaign, the pure cleanup-derivation, and the report assembler
with no provider call and no docker.
"""

from __future__ import annotations

from pathlib import Path

from aegis.multi_agent.consolidated_campaign import (
    CLEANUP_OBLIGATIONS,
    ConsolidatedOpsCampaign,
    derive_source_cleanup,
    write_campaign_artifacts,
)
from aegis.multi_agent.report_agent import (
    assemble_report,
    render_report_markdown,
)

_PASS = {"status": "PASS"}


# --------------------------------------------------------------------------- #
# derive_source_cleanup — the pure controller-ledger + range-snapshot fact map.
# --------------------------------------------------------------------------- #


def _entries(*, all_ok: bool = True, failing: str | None = None) -> list[tuple[str, bool]]:
    return [(o, o != failing and all_ok) for o in CLEANUP_OBLIGATIONS]


def test_derive_cleanup_success_in_process() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(), range_cleanup={"status": "NOT_STARTED"}, containerized=False
    )
    assert sc.succeeded is True
    assert sc.failures == ()
    assert set(sc.obligations) == set(CLEANUP_OBLIGATIONS)


def test_derive_cleanup_success_containerized_pass() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(), range_cleanup=_PASS, containerized=True
    )
    assert sc.succeeded is True
    assert sc.failures == ()


def test_derive_cleanup_controller_failure() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(failing="REVOKE_REFERENCES"),
        range_cleanup=_PASS,
        containerized=True,
    )
    assert sc.succeeded is False
    assert "REVOKE_REFERENCES" in sc.failures


def test_derive_cleanup_range_teardown_failure_is_false() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(),
        range_cleanup={"status": "CLEANUP_FAILED"},
        containerized=True,
    )
    assert sc.succeeded is False
    assert "RANGE_CLEANUP_CLEANUP_FAILED" in sc.failures


def test_derive_cleanup_leftover_query_unknown_is_never_success() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(),
        range_cleanup={"status": "COLLECT_FAILED"},
        containerized=True,
    )
    assert sc.succeeded == "UNKNOWN"  # never True
    assert "RANGE_LEFTOVER_QUERY_UNKNOWN" in sc.failures


def test_derive_cleanup_not_started_containerized_is_false() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=_entries(), range_cleanup={"status": "NOT_STARTED"}, containerized=True
    )
    assert sc.succeeded is False
    assert "RANGE_CLEANUP_NOT_STARTED" in sc.failures


def test_derive_cleanup_empty_ledger_is_false() -> None:
    sc = derive_source_cleanup(
        cleanup_entries=[], range_cleanup=_PASS, containerized=True
    )
    assert sc.succeeded is False


# --------------------------------------------------------------------------- #
# End-to-end offline campaign: truthful COMPLETE report, one report call, manifest.
# --------------------------------------------------------------------------- #


def _report_calls(campaign: ConsolidatedOpsCampaign) -> int:
    return sum(
        1 for a in campaign.model.attempts if a["task_type"] == "GENERATE_ASSESSMENT_REPORT"
    )


def test_offline_success_produces_complete_truthful_final_report(tmp_path: Path) -> None:
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c")
    record = campaign.run()
    report = campaign.final_report
    assert report is not None
    # Cleanup genuinely succeeded (in-process): the final report is COMPLETE and says so truthfully.
    assert report.status == "COMPLETE"
    assert report.cleanup.succeeded is True
    assert report.cleanup.failures == ()
    assert record["report"]["status"] == "COMPLETE"
    assert record["report"]["finalized_after_cleanup"] is True
    assert record["report"]["cleanup_succeeded"] is True


def test_exactly_one_report_agent_model_call_and_none_during_finalize(tmp_path: Path) -> None:
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c")
    campaign.run()
    # Exactly one REPORT_AGENT provider call for the whole campaign; the five total calls are the
    # planned five. The post-cleanup final assembly reuses the retained draft — no extra call.
    assert _report_calls(campaign) == 1
    assert len(campaign.model.attempts) == 5


def test_final_report_not_assembled_before_cleanup_ledger(tmp_path: Path) -> None:
    # The final report is assembled only after the cleanup ledger produced entries; at assembly time
    # the durable range-cleanup snapshot is already populated (never the pre-run default).
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c")
    campaign.run()
    entries = list(campaign.asm.lifecycle.ledger.cleanup_entries(campaign.asm.assessment_id))
    assert entries, "cleanup ledger must have run before the report was finalized"
    assert campaign.final_report is not None
    # The report's cleanup obligations are exactly the ledger's — proof it came from the ledger.
    assert set(campaign.final_report.cleanup.obligations) == {e.obligation for e in entries}


def test_artifact_manifest_covers_post_cleanup_report(tmp_path: Path) -> None:
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c")
    record = campaign.run()
    result = write_campaign_artifacts(tmp_path / "ev", campaign, record)
    assert result["manifest_verified"] is True
    assert result["report_outputs_persisted"] is True
    # The rendered report bundle matches the FINAL report content.
    md = (tmp_path / "ev" / "report" / "report.md").read_text()
    assert "Succeeded: `True`" in md
    manifest = (tmp_path / "ev" / "SHA256SUMS").read_text()
    assert "report/report.json" in manifest


def test_offline_run_is_deterministic(tmp_path: Path) -> None:
    a = ConsolidatedOpsCampaign(base_dir=tmp_path / "a")
    a.run()
    b = ConsolidatedOpsCampaign(base_dir=tmp_path / "b")
    b.run()
    assert a.final_report is not None and b.final_report is not None
    # Offline dry-run behavior is deterministic: identical outcome, cleanup truth, generation mode,
    # finding/retest states and provider-call shape (the per-run campaign/assessment id is the only
    # thing that varies — no provider is called and nothing is assumed).
    assert a.final_report.status == b.final_report.status == "COMPLETE"
    assert a.final_report.cleanup.succeeded is b.final_report.cleanup.succeeded is True
    assert a.final_report.generation_mode == "OFFLINE_DETERMINISTIC"
    assert b.final_report.generation_mode == "OFFLINE_DETERMINISTIC"
    assert _report_calls(a) == _report_calls(b) == 1
    assert len(a.model.attempts) == len(b.model.attempts) == 5


# --------------------------------------------------------------------------- #
# End-to-end controller cleanup FAILURE: PARTIAL, visible failures, never success.
# --------------------------------------------------------------------------- #


class _CleanupFailingCampaign(ConsolidatedOpsCampaign):
    """A campaign whose controller cleanup fails one obligation (in-process range)."""

    def _compensate(self, obligation: str, receipt_id: str) -> bool:
        if obligation == "REVOKE_REFERENCES":
            return False  # controller compensation genuinely fails
        return super()._compensate(obligation, receipt_id)


def test_controller_cleanup_failure_yields_partial_visible_failure(tmp_path: Path) -> None:
    campaign = _CleanupFailingCampaign(base_dir=tmp_path / "c")
    record = campaign.run()
    report = campaign.final_report
    assert report is not None
    # The report reflects the ACTUAL failed cleanup — it can NOT claim success.
    assert report.status == "PARTIAL"
    assert report.cleanup.succeeded is False
    assert "REVOKE_REFERENCES" in report.cleanup.failures
    assert record["report"]["cleanup_succeeded"] is False
    # The failure is visible in the rendered evidence.
    md = render_report_markdown(report)
    assert "Succeeded: `False`" in md
    assert "REVOKE_REFERENCES" in md
    # The lifecycle verdict is CLEANUP_FAILED, not COMPLETED.
    assert record["lifecycle"]["final_state"] == "CLEANUP_FAILED"


def test_range_teardown_failure_report_is_partial(tmp_path: Path) -> None:
    # Assemble a final report from a controller-clean ledger but a FAILED range teardown snapshot;
    # the report must be PARTIAL and surface the range failure (no cleanup-success claim).
    campaign = ConsolidatedOpsCampaign(base_dir=tmp_path / "c")
    campaign.run()  # builds the finding/receipt records the source needs
    cleanup = derive_source_cleanup(
        cleanup_entries=_entries(),
        range_cleanup={"status": "CLEANUP_FAILED"},
        containerized=True,
    )
    source = campaign.asm.build_report_source(
        cleanup_succeeded=cleanup.succeeded,
        cleanup_obligations=cleanup.obligations,
        cleanup_failures=cleanup.failures,
        usage=campaign._report_usage(),
    )
    report = assemble_report(
        source=source, model_output=None, report_id="rpt-" + "a" * 16, version=1
    )
    assert report.status == "PARTIAL"
    assert report.cleanup.succeeded is False
    assert "RANGE_CLEANUP_CLEANUP_FAILED" in report.cleanup.failures
