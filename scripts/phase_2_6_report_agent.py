"""Phase 2.6 — OFFLINE REPORT_AGENT + professional reporting demonstration (no live report model).

Builds one controller-owned :class:`ReportSource`, enqueues a real addressable REPORT_AGENT job
(``agentjob://REPORT_AGENT/…``, QUEUED->CLAIMED->CLOSED), derives the sanitized model-facing
projection, supplies a deterministic prose-only model draft, assembles the controller-authoritative
report, persists it (stable id + version), renders the JSON/Markdown/HTML exports, and emits the
typed verdict.

No live report model is called (``live_report_agent_status = NOT_EVALUATED``). Allowed offline
claim: "OFFLINE PASS for the typed REPORT_AGENT job architecture and controller-authoritative
professional reporting pipeline."
"""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.contracts import (
    AssessmentReportDraftOutput,
    ReportChainExplanationDraft,
    ReportFindingRemediationDraft,
)
from aegis.multi_agent.report_agent import (
    ReportAgentJob,
    ReportAgentQueue,
    ReportSource,
    SourceCausalChain,
    SourceCleanup,
    SourceEvaluation,
    SourceEvidenceRef,
    SourceFinding,
    SourceHypothesis,
    SourceUsage,
    assemble_report,
    build_report_request_projection,
    build_report_verdict,
    projection_sha256,
    render_report_html,
    render_report_markdown,
)

DIGEST = "a" * 64
CAMPAIGN_ID = "phase-2.6-offline"


def build_source() -> ReportSource:
    return ReportSource(
        campaign_id=CAMPAIGN_ID,
        target_ref="range-ops",
        authorized_scope=("range-ops",),
        findings=(
            SourceFinding(
                finding_id="finding-ops-detection-control",
                title="Detection-control bypass (synthetic)",
                gate="detection_control",
                mode="vulnerable",
                scenario_id="ops-detection-control-bypass-v1",
                severity="HIGH",
                severity_authority="GROUND_TRUTH",
                verification_provenance="OFFLINE_VERIFIED_SYNTHETIC",
                verifier_facts={"alternate_reached_sentinel": True, "baseline_denied": True},
                evidence=(
                    SourceEvidenceRef(
                        evidence_sha256=DIGEST,
                        locator="verifier/adjudication/ops-detection-control-bypass-v1",
                        authority="VERIFIER",
                    ),
                ),
            ),
        ),
        target_outcomes=(
            SourceEvaluation(
                evaluation_id="verifier-detection-control-patched",
                state="PASS",
                classification="TARGET_SECURITY_VALIDATION",
                authority="VERIFIER",
                provenance="OFFLINE_VERIFIED_SYNTHETIC",
                facts={"alternate_denied": True},
                evidence=(
                    SourceEvidenceRef(
                        evidence_sha256=DIGEST, locator="verifier/patched", authority="VERIFIER"
                    ),
                ),
            ),
        ),
        platform_checks=(
            SourceEvaluation(
                evaluation_id="controller-phase-2.6-report-pipeline",
                state="PASS",
                classification="PLATFORM_PHASE_ASSURANCE",
                authority="CONTROLLER",
                provenance="OFFLINE_VERIFIED_SYNTHETIC",
                facts={},
                evidence=(
                    SourceEvidenceRef(
                        evidence_sha256=DIGEST, locator="controller/verdict", authority="CONTROLLER"
                    ),
                ),
            ),
        ),
        hypotheses=(
            SourceHypothesis(
                hypothesis_id="delg-0000000000000abc",
                summary="Reference-only recon hypothesis routed to the injection agent.",
                target_ref="range-ops",
                capability_id="aegis.injection.reflected",
                assigned_agent="INJECTION_AGENT",
                queue_address="agentqueue://INJECTION_AGENT/delg-0000000000000abc",
                provenance="OFFLINE_VERIFIED_SYNTHETIC",
                evidence=(
                    SourceEvidenceRef(
                        evidence_sha256=DIGEST, locator="queue/delegation", authority="CONTROLLER"
                    ),
                ),
            ),
        ),
        causal_chains=(
            SourceCausalChain(
                chain_id="cloud-service-chain-v1",
                ordered_primitive_types=(
                    "METADATA_CREDENTIAL_EXPOSURE",
                    "INTERNAL_SERVICE_AUTHORIZATION",
                ),
                verified=True,
                provenance="OFFLINE_VERIFIED_SYNTHETIC",
                evidence=(
                    SourceEvidenceRef(
                        evidence_sha256=DIGEST, locator="chain/ledger", authority="VERIFIER"
                    ),
                ),
            ),
        ),
        retests=(),
        cleanup=SourceCleanup(
            succeeded=True,
            obligations=("RESET_SYNTHETIC_TARGET_TO_BASELINE", "ROTATE_OR_REMOVE_SENTINEL"),
            failures=(),
        ),
        usage=SourceUsage(
            provider_calls="UNKNOWN",
            input_tokens="UNKNOWN",
            output_tokens="UNKNOWN",
            total_tokens="UNKNOWN",
            tool_executions=2,
        ),
        live_run=False,
    )


def build_model_draft() -> AssessmentReportDraftOutput:
    return AssessmentReportDraftOutput(
        executive_summary=(
            "One synthetic detection-control bypass was independently verified on the authorized "
            "range and its patched variant passed retest; one reference-only hypothesis remains "
            "unconfirmed."
        ),
        methodology_and_limitations=(
            "Bounded synthetic range only. Findings are confirmed solely by the independent "
            "deterministic verifier; this report explains adjudicated facts and drafts remediation."
        ),
        finding_remediations=[
            ReportFindingRemediationDraft(
                finding_id="finding-ops-detection-control",
                remediation_text=(
                    "Normalize detection-control matching so alternate request variants are denied "
                    "like the baseline; add a regression probe and re-run the verifier."
                ),
            ),
            # Keyed to a finding the controller does NOT own -> discarded on assembly.
            ReportFindingRemediationDraft(
                finding_id="finding-does-not-exist",
                remediation_text="This should be discarded by the controller.",
            ),
        ],
        chain_explanations=[
            ReportChainExplanationDraft(
                chain_id="cloud-service-chain-v1",
                causal_link_explanation=(
                    "Stage A's captured credential reference enabled Stage B's private operation; "
                    "the patched arm suppressed the reference and broke the chain."
                ),
            )
        ],
        readability_notes="Group findings by severity; keep hypotheses visually distinct.",
    )


def run_offline() -> dict[str, Any]:
    source = build_source()
    projection = build_report_request_projection(source)
    with tempfile.TemporaryDirectory() as scratch:
        queue = ReportAgentQueue(str(Path(scratch) / "report.db"))
        queue.initialize()
        job = ReportAgentJob(
            job_id="rptjob-000000000000a26a",
            campaign_id=CAMPAIGN_ID,
            report_request_id="rptreq-000000000000b26b",
            source_projection_sha256=projection_sha256(projection),
        )
        address = queue.enqueue_job(job)
        queue.claim_job(address)
        report = assemble_report(
            source=source,
            model_output=build_model_draft(),
            report_id="rpt-000000000000c26c",
            version=1,
            generated_at=datetime(2026, 9, 25, tzinfo=UTC),
        )
        queue.save_report(report)
        queue.close_job(address)
        transitions = [t["to"] for t in queue.job_transitions(job.job_id)]
        markdown = render_report_markdown(report)
        html = render_report_html(report)

    verdict = build_report_verdict(source, report)
    verdict["job_lifecycle"] = transitions
    verdict["job_lifecycle_complete"] = transitions == ["QUEUED", "CLAIMED", "CLOSED"]
    verdict["checks"]["job_lifecycle_queued_claimed_closed"] = verdict["job_lifecycle_complete"]
    verdict["passed"] = verdict["passed"] and verdict["job_lifecycle_complete"]
    verdict["report_agent_implementation_status"] = (
        "OFFLINE_PASS" if verdict["passed"] else "OFFLINE_FAIL"
    )
    return {
        "verdict": verdict,
        "report_uri": report.report_uri,
        "content_sha256": report.content_sha256,
        "projection": projection,
        "markdown_len": len(markdown),
        "html_len": len(html),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_offline()
    print(json.dumps(result if args.json else result["verdict"], indent=2, sort_keys=True))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
