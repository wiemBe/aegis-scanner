"""Targeted tests for the offline Phase 1.8 report agent."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.reporting import (
    SQLI_REMEDIATION,
    XSS_REMEDIATION,
    ReportDocument,
    ReportInputError,
    _state_from_controller,
    build_report,
    render_markdown,
    write_report_bundle,
)


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture
def report(repo_root: Path) -> ReportDocument:
    return build_report(
        repo_root=repo_root,
        verifier_results_path=(
            repo_root
            / "artifacts/phase-1.7b-offline-20260923T085928Z/verifier-results.json"
        ),
        live_acceptance_path=(
            repo_root
            / "artifacts/phase-1.7d-live-e2e-recon-20260923T153518Z/acceptance.json"
        ),
        delegation_queue_path=(
            repo_root
            / "artifacts/phase-1.7d-live-e2e-recon-20260923T153518Z/delegation_queue.sqlite3"
        ),
        generated_at=datetime(2026, 9, 23, tzinfo=UTC),
    )


def test_report_transports_verifier_findings_and_ground_truth_severity(
    report: ReportDocument,
) -> None:
    findings = report.verified_security_findings
    assert [finding.gate for finding in findings] == ["xss", "sqli"]
    assert [finding.severity.value for finding in findings] == ["MEDIUM", "HIGH"]
    assert all(finding.severity.authority == "GROUND_TRUTH" for finding in findings)
    assert all(
        finding.verification_provenance == "OFFLINE_VERIFIED_SYNTHETIC"
        for finding in findings
    )
    assert all(finding.evidence for finding in findings)
    assert all(finding.evidence[0].source_evidence_sha256 for finding in findings)
    assert [finding.remediation for finding in findings] == [
        XSS_REMEDIATION,
        SQLI_REMEDIATION,
    ]
    assert all(finding.remediation_authority == "CONTROLLER_DETERMINISTIC" for finding in findings)


def test_chain_is_workflow_validation_not_a_duplicate_finding(
    report: ReportDocument,
) -> None:
    assert all(finding.gate != "chain" for finding in report.verified_security_findings)
    chain = [
        item
        for item in report.platform_phase_assurance_checks
        if item.classification == "DELEGATION_WORKFLOW_CHAIN"
    ]
    assert [(item.state, item.source_state) for item in chain] == [
        ("CONFIRMED", "CONFIRMED"),
        ("PASS", "PASS"),
    ]
    assert all(item.target_security_implication == "NONE" for item in chain)


def test_pass_unknown_and_not_evaluated_are_first_class(report: ReportDocument) -> None:
    assert any(item.state == "PASS" for item in report.target_security_validation_outcomes)
    patched = {
        (item.evaluation_id, item.state)
        for item in report.target_security_validation_outcomes
        if "patched" in item.evaluation_id
    }
    assert (
        "verifier-xss-patched-shop-promotion-preview-v1",
        "PASS",
    ) in patched
    assert ("verifier-sqli-patched-shop-catalog-query-v1", "PASS") in patched
    assert _state_from_controller("UNKNOWN") == "UNKNOWN"
    assert _state_from_controller("NOT_EVALUATED") == "NOT_EVALUATED"
    assert report.model_usage.identity_exact_deepseek_v4_pro == "NOT_EVALUATED"
    assert report.verdict.supports_pass_state is True
    assert report.verdict.supports_unknown_not_evaluated_state is True


def test_unconfirmed_delegation_is_hypothesis_not_finding(
    report: ReportDocument,
) -> None:
    assert len(report.unconfirmed_hypotheses) == 1
    hypothesis = report.unconfirmed_hypotheses[0]
    assert hypothesis.confirmed is False
    assert hypothesis.state == "HYPOTHESIS"
    assert hypothesis.severity == "UNKNOWN"
    assert hypothesis.queue_address == (
        "agentqueue://INJECTION_AGENT/delg-bb6dc915960a7d7f"
    )
    assert hypothesis.evidence[0].source_evidence_sha256 == (
        "7526e1a1894b7096a4a80c0e76845ee4d45b4351b66832fa10d3921907a2b773"
    )
    assert hypothesis.hypothesis_id not in {
        item.finding_id for item in report.verified_security_findings
    }


def test_report_agent_makes_no_model_calls_and_passes_verdict(
    report: ReportDocument,
) -> None:
    assert report.model_usage.provider_calls_total == 0
    assert report.model_usage.provider_tokens_total == 0
    assert report.verdict.identity_exact_deepseek_v4_pro == "NOT_EVALUATED"
    assert report.verdict.within_call_ceiling is True
    assert report.verdict.within_token_ceiling is True
    assert report.verdict.no_fabricated_metrics is True
    assert report.reporting_pipeline_status == "OFFLINE_PASS"
    assert report.live_report_agent_status == "NOT_EVALUATED"
    assert report.verdict.reporting_pipeline_status == "OFFLINE_PASS"
    assert report.verdict.live_report_agent_status == "NOT_EVALUATED"
    assert report.verdict.chain_classified_as_workflow_validation is True
    assert report.verdict.target_and_platform_outcomes_separated is True
    assert report.verdict.passed is True


def test_human_and_machine_report_preserve_evidence_links(
    report: ReportDocument, tmp_path: Path
) -> None:
    rendered = render_markdown(report)
    assert "## VERIFIED SECURITY FINDINGS" in rendered
    assert "## TARGET SECURITY VALIDATION OUTCOMES" in rendered
    assert "## PLATFORM / PHASE ASSURANCE CHECKS" in rendered
    assert "## UNCONFIRMED HYPOTHESES" in rendered
    assert "never implies that the target is secure" in rendered
    assert "source evidence SHA-256" in rendered
    output = tmp_path / "report"
    write_report_bundle(output, report)
    machine = json.loads((output / "report.json").read_text(encoding="utf-8"))
    verdict = json.loads((output / "verdict.json").read_text(encoding="utf-8"))
    assert machine["verified_security_findings"][0]["evidence"][0]["path"].endswith(
        "verifier-results.json"
    )
    assert verdict["passed"] is True
    assert (output / "SHA256SUMS").is_file()


def test_checksum_mismatch_fails_closed(repo_root: Path, tmp_path: Path) -> None:
    source = (
        repo_root / "artifacts/phase-1.7b-offline-20260923T085928Z/verifier-results.json"
    )
    verifier_dir = tmp_path / "verifier"
    verifier_dir.mkdir()
    copied = verifier_dir / "verifier-results.json"
    copied.write_bytes(source.read_bytes())
    (verifier_dir / "SHA256SUMS").write_text(
        f"{'0' * 64}  verifier-results.json\n", encoding="utf-8"
    )
    with pytest.raises(ReportInputError, match="checksum mismatch"):
        build_report(
            repo_root=repo_root,
            verifier_results_path=copied,
            live_acceptance_path=(
                repo_root
                / "artifacts/phase-1.7d-live-e2e-recon-20260923T153518Z/acceptance.json"
            ),
            delegation_queue_path=(
                repo_root
                / "artifacts/phase-1.7d-live-e2e-recon-20260923T153518Z/delegation_queue.sqlite3"
            ),
        )
