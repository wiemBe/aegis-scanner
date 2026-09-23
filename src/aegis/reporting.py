"""Offline, evidence-preserving report construction for Phase 1.8."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from aegis_range.ground_truth import GROUND_TRUTH_BY_SCENARIO

Digest = str
JsonScalar = bool | int | float | str | None
ReportState = Literal["CONFIRMED", "PASS", "FAIL", "UNKNOWN", "NOT_EVALUATED"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]

REPORT_CALL_CEILING = 6
REPORT_TOKEN_CEILING = 30_000
XSS_REMEDIATION = (
    "Apply context-aware output encoding or sanitization at the executable HTML sink, "
    "then run an independent verifier retest."
)
SQLI_REMEDIATION = (
    "Use parameterized queries or prepared statements, remove query-string concatenation, "
    "then run an independent verifier retest."
)


class ReportInputError(ValueError):
    """Raised when source evidence is missing, inconsistent, or fails integrity checks."""


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceLink(StrictModel):
    path: str = Field(min_length=1)
    artifact_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    source_evidence_sha256: Digest | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    authority: Literal["VERIFIER", "CONTROLLER"]
    locator: str = Field(min_length=1)


class SeverityTrace(StrictModel):
    value: Severity
    authority: Literal["VERIFIER", "GROUND_TRUTH", "NO_SOURCE"]
    source_path: str | None = None
    source_sha256: Digest | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    source_id: str | None = None
    rationale: str = Field(min_length=1)


class ReportFinding(StrictModel):
    finding_id: str
    title: str
    state: Literal["CONFIRMED"] = "CONFIRMED"
    confirmed: Literal[True] = True
    gate: str
    mode: str
    scenario_id: str
    verification_provenance: Literal["OFFLINE_VERIFIED_SYNTHETIC"] = (
        "OFFLINE_VERIFIED_SYNTHETIC"
    )
    severity: SeverityTrace
    verifier_facts: dict[str, JsonScalar]
    evidence: list[EvidenceLink] = Field(min_length=1)
    remediation: str = Field(min_length=1)
    remediation_authority: Literal["CONTROLLER_DETERMINISTIC"] = "CONTROLLER_DETERMINISTIC"


class ReportEvaluation(StrictModel):
    evaluation_id: str
    state: ReportState
    source_state: str
    authority: Literal["VERIFIER", "CONTROLLER"]
    classification: Literal[
        "TARGET_SECURITY_VALIDATION",
        "DELEGATION_WORKFLOW_CHAIN",
        "PLATFORM_PHASE_ASSURANCE",
    ]
    target_security_implication: Literal["TARGET_VALIDATION_ONLY", "NONE"]
    facts: dict[str, JsonScalar]
    evidence: list[EvidenceLink] = Field(min_length=1)


class ReportHypothesis(StrictModel):
    hypothesis_id: str
    state: Literal["HYPOTHESIS"] = "HYPOTHESIS"
    confirmed: Literal[False] = False
    summary: str
    target_ref: str
    capability_id: str
    assigned_agent: str
    queue_address: str
    severity: Literal["UNKNOWN"] = "UNKNOWN"
    evidence: list[EvidenceLink] = Field(min_length=1)


class ReportModelUsage(StrictModel):
    live_model_used: Literal[False] = False
    provider_calls_total: Literal[0] = 0
    provider_tokens_total: Literal[0] = 0
    identity_exact_deepseek_v4_pro: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    call_ceiling: Literal[6] = 6
    token_ceiling: Literal[30000] = 30_000


class ReportVerdict(StrictModel):
    reporting_pipeline_status: Literal["OFFLINE_PASS"]
    live_report_agent_status: Literal["NOT_EVALUATED"]
    findings_link_to_evidence: bool
    severity_traces_to_verifier: bool
    supports_pass_state: bool
    supports_unknown_not_evaluated_state: bool
    unconfirmed_rendered_as_hypothesis: bool
    remediation_present_per_finding: bool
    no_fabricated_metrics: bool
    explicit_report_categories: bool
    chain_classified_as_workflow_validation: bool
    offline_finding_provenance_explicit: bool
    target_and_platform_outcomes_separated: bool
    controller_owned_remediation: bool
    delegation_queue_provenance_preserved: bool
    identity_exact_deepseek_v4_pro: bool | Literal["NOT_EVALUATED"]
    within_call_ceiling: bool
    within_token_ceiling: bool
    provider_calls_total: int = Field(ge=0)
    provider_tokens_total: int = Field(ge=0)
    passed: bool


class ReportDocument(StrictModel):
    schema_version: Literal["phase-1.8-report-v2"] = "phase-1.8-report-v2"
    phase: Literal["1.8"] = "1.8"
    reporting_pipeline_status: Literal["OFFLINE_PASS"] = "OFFLINE_PASS"
    live_report_agent_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    generated_at: datetime
    generation_mode: Literal["OFFLINE_DETERMINISTIC"] = "OFFLINE_DETERMINISTIC"
    source_artifacts: list[EvidenceLink] = Field(min_length=1)
    verified_security_findings: list[ReportFinding]
    target_security_validation_outcomes: list[ReportEvaluation]
    platform_phase_assurance_checks: list[ReportEvaluation]
    unconfirmed_hypotheses: list[ReportHypothesis]
    model_usage: ReportModelUsage
    verdict: ReportVerdict


class VerifierRecord(StrictModel):
    gate: str
    mode: str
    scenario_id: str
    verifier_status: str | None
    outcome: str
    false_positive: bool
    evidence_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    facts: dict[str, JsonScalar]


class DelegationAcceptance(BaseModel):
    model_config = ConfigDict(extra="ignore")

    address: str
    confirmed: bool
    unconfirmed: bool
    source_evidence_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")


class LiveRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    artifact_db_path: str
    delegation_enqueue: DelegationAcceptance


class LiveVerdictDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    checks: dict[str, bool | str]
    passed: bool


class LiveAcceptance(BaseModel):
    model_config = ConfigDict(extra="ignore")

    phase: str
    verdict: str
    record: LiveRecord
    verdict_detail: LiveVerdictDetail


class QueuePayload(StrictModel):
    delegation_id: str
    from_agent: str
    to_agent: str
    capability_id: str
    target_ref: str
    route: str
    parameter: str
    rationale: str
    reference_only: bool
    confirmed: bool
    unconfirmed: bool
    status: str
    source_evidence_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    enqueued_at: datetime


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative_path(repo_root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError as exc:
        raise ReportInputError(f"evidence path is outside repository: {path}") from exc


def _verified_artifact_sha256(path: Path) -> str:
    manifest = path.parent / "SHA256SUMS"
    if not path.is_file() or not manifest.is_file():
        raise ReportInputError(f"evidence or SHA256SUMS missing for {path}")
    expected: str | None = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[1].lstrip("*") == path.name:
            expected = parts[0]
            break
    actual = _sha256(path)
    if expected is None or expected != actual:
        raise ReportInputError(f"evidence checksum mismatch for {path}")
    return actual


def _evidence_link(
    repo_root: Path,
    path: Path,
    *,
    artifact_sha256: str,
    source_evidence_sha256: str | None,
    authority: Literal["VERIFIER", "CONTROLLER"],
    locator: str,
) -> EvidenceLink:
    return EvidenceLink(
        path=_relative_path(repo_root, path),
        artifact_sha256=artifact_sha256,
        source_evidence_sha256=source_evidence_sha256,
        authority=authority,
        locator=locator,
    )


def _severity_trace(repo_root: Path, scenario_id: str) -> SeverityTrace:
    truth = GROUND_TRUTH_BY_SCENARIO.get(scenario_id)
    if truth is None:
        return SeverityTrace(
            value="UNKNOWN",
            authority="NO_SOURCE",
            rationale=(
                "No verifier or controller ground-truth severity was present for this scenario."
            ),
        )
    source_path = repo_root / "src" / "aegis_range" / "ground_truth.py"
    if not source_path.is_file():
        raise ReportInputError(f"ground-truth severity source missing: {source_path}")
    return SeverityTrace(
        value=truth.severity,
        authority="GROUND_TRUTH",
        source_path=_relative_path(repo_root, source_path),
        source_sha256=_sha256(source_path),
        source_id=truth.ground_truth_id,
        rationale=truth.severity_rationale,
    )


def _state_from_controller(value: bool | str) -> ReportState:
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    if value == "UNKNOWN":
        return "UNKNOWN"
    if value == "NOT_EVALUATED":
        return "NOT_EVALUATED"
    raise ReportInputError(f"unsupported controller state: {value!r}")


def _queue_payload(queue_path: Path) -> tuple[QueuePayload, str, str]:
    connection = sqlite3.connect(f"file:{queue_path.resolve()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT payload, address, source_evidence_sha256 FROM agent_delegations "
            "ORDER BY enqueued_at, delegation_id"
        ).fetchall()
    except sqlite3.Error as exc:
        raise ReportInputError("delegation queue is unreadable or has an invalid schema") from exc
    finally:
        connection.close()
    if (
        len(rows) != 1
        or not isinstance(rows[0][0], str)
        or not isinstance(rows[0][1], str)
        or not isinstance(rows[0][2], str)
    ):
        raise ReportInputError("expected exactly one typed Phase 1.7-D delegation")
    return QueuePayload.model_validate_json(rows[0][0]), rows[0][1], rows[0][2]


def _controller_remediation(gate: str) -> str:
    if gate == "xss":
        return XSS_REMEDIATION
    if gate == "sqli":
        return SQLI_REMEDIATION
    raise ReportInputError(f"no controller-owned remediation for confirmed gate: {gate}")


def _make_verdict(
    findings: list[ReportFinding],
    target_outcomes: list[ReportEvaluation],
    platform_checks: list[ReportEvaluation],
    hypotheses: list[ReportHypothesis],
    usage: ReportModelUsage,
) -> ReportVerdict:
    links_ok = all(finding.evidence for finding in findings)
    severity_ok = all(
        finding.severity.value == "UNKNOWN"
        or (
            finding.severity.authority in {"VERIFIER", "GROUND_TRUTH"}
            and finding.severity.source_path is not None
            and finding.severity.source_sha256 is not None
        )
        for finding in findings
    )
    hypothesis_ok = all(not item.confirmed and item.state == "HYPOTHESIS" for item in hypotheses)
    remediation_ok = all(bool(item.remediation.strip()) for item in findings)
    supports_pass = any(
        item.state == "PASS" for item in [*target_outcomes, *platform_checks]
    )
    supports_unknown = usage.identity_exact_deepseek_v4_pro == "NOT_EVALUATED" and all(
        item.severity == "UNKNOWN" for item in hypotheses
    )
    categories_ok = bool(findings and target_outcomes and platform_checks and hypotheses)
    chain_ok = any(
        item.classification == "DELEGATION_WORKFLOW_CHAIN"
        and item.target_security_implication == "NONE"
        for item in platform_checks
    ) and all(item.gate != "chain" for item in findings)
    offline_provenance_ok = all(
        item.verification_provenance == "OFFLINE_VERIFIED_SYNTHETIC" for item in findings
    )
    outcomes_separated = all(
        item.classification == "TARGET_SECURITY_VALIDATION"
        and item.target_security_implication == "TARGET_VALIDATION_ONLY"
        for item in target_outcomes
    ) and all(item.target_security_implication == "NONE" for item in platform_checks)
    remediation_owned = all(
        item.remediation_authority == "CONTROLLER_DETERMINISTIC"
        and item.remediation in {XSS_REMEDIATION, SQLI_REMEDIATION}
        for item in findings
    )
    queue_provenance_ok = all(
        bool(item.queue_address)
        and any(link.source_evidence_sha256 is not None for link in item.evidence)
        for item in hypotheses
    )
    within_calls = usage.provider_calls_total <= usage.call_ceiling
    within_tokens = usage.provider_tokens_total <= usage.token_ceiling
    required = (
        links_ok,
        severity_ok,
        supports_pass,
        supports_unknown,
        hypothesis_ok,
        remediation_ok,
        categories_ok,
        chain_ok,
        offline_provenance_ok,
        outcomes_separated,
        remediation_owned,
        queue_provenance_ok,
        within_calls,
        within_tokens,
    )
    return ReportVerdict(
        reporting_pipeline_status="OFFLINE_PASS",
        live_report_agent_status="NOT_EVALUATED",
        findings_link_to_evidence=links_ok,
        severity_traces_to_verifier=severity_ok,
        supports_pass_state=supports_pass,
        supports_unknown_not_evaluated_state=supports_unknown,
        unconfirmed_rendered_as_hypothesis=hypothesis_ok,
        remediation_present_per_finding=remediation_ok,
        no_fabricated_metrics=True,
        explicit_report_categories=categories_ok,
        chain_classified_as_workflow_validation=chain_ok,
        offline_finding_provenance_explicit=offline_provenance_ok,
        target_and_platform_outcomes_separated=outcomes_separated,
        controller_owned_remediation=remediation_owned,
        delegation_queue_provenance_preserved=queue_provenance_ok,
        identity_exact_deepseek_v4_pro=usage.identity_exact_deepseek_v4_pro,
        within_call_ceiling=within_calls,
        within_token_ceiling=within_tokens,
        provider_calls_total=usage.provider_calls_total,
        provider_tokens_total=usage.provider_tokens_total,
        passed=all(required),
    )


def build_report(
    *,
    repo_root: Path,
    verifier_results_path: Path,
    live_acceptance_path: Path,
    delegation_queue_path: Path,
    generated_at: datetime | None = None,
) -> ReportDocument:
    """Build a report exclusively from checksum-verified, controller-owned evidence."""

    verifier_sha = _verified_artifact_sha256(verifier_results_path)
    acceptance_sha = _verified_artifact_sha256(live_acceptance_path)
    queue_sha = _verified_artifact_sha256(delegation_queue_path)
    verifier_records = TypeAdapter(list[VerifierRecord]).validate_json(
        verifier_results_path.read_text(encoding="utf-8")
    )
    acceptance = LiveAcceptance.model_validate_json(
        live_acceptance_path.read_text(encoding="utf-8")
    )
    queue_payload, queue_address, queue_source_sha256 = _queue_payload(delegation_queue_path)

    expected_queue_path = repo_root / acceptance.record.artifact_db_path
    if expected_queue_path.resolve() != delegation_queue_path.resolve():
        raise ReportInputError("acceptance artifact_db_path does not identify the supplied queue")
    accepted_delegation = acceptance.record.delegation_enqueue
    if (
        accepted_delegation.confirmed
        or not accepted_delegation.unconfirmed
        or queue_payload.confirmed
        or not queue_payload.unconfirmed
        or queue_payload.source_evidence_sha256 != accepted_delegation.source_evidence_sha256
        or queue_source_sha256 != accepted_delegation.source_evidence_sha256
        or queue_address != accepted_delegation.address
    ):
        raise ReportInputError("delegation confirmation state or evidence digest is inconsistent")

    findings: list[ReportFinding] = []
    target_outcomes: list[ReportEvaluation] = []
    platform_checks: list[ReportEvaluation] = []
    for index, record in enumerate(verifier_records):
        link = _evidence_link(
            repo_root,
            verifier_results_path,
            artifact_sha256=verifier_sha,
            source_evidence_sha256=record.evidence_sha256,
            authority="VERIFIER",
            locator=f"record[{index}]/{record.gate}/{record.mode}/{record.scenario_id}",
        )
        if record.gate == "chain":
            if record.outcome not in {"CONFIRMED", "PASS", "UNKNOWN", "NOT_EVALUATED", "FAIL"}:
                raise ReportInputError(f"unsupported workflow-chain outcome: {record.outcome}")
            platform_checks.append(
                ReportEvaluation(
                    evaluation_id=(
                        f"workflow-{record.gate}-{record.mode}-{record.scenario_id}"
                    ),
                    state=cast(ReportState, record.outcome),
                    source_state=record.outcome,
                    authority="VERIFIER",
                    classification="DELEGATION_WORKFLOW_CHAIN",
                    target_security_implication="NONE",
                    facts=record.facts,
                    evidence=[link],
                )
            )
            continue
        if record.outcome == "CONFIRMED":
            truth = GROUND_TRUTH_BY_SCENARIO.get(record.scenario_id)
            title = truth.title if truth is not None else record.scenario_id
            findings.append(
                ReportFinding(
                    finding_id=f"finding-{record.gate}-{record.mode}-{record.scenario_id}",
                    title=title,
                    gate=record.gate,
                    mode=record.mode,
                    scenario_id=record.scenario_id,
                    severity=_severity_trace(repo_root, record.scenario_id),
                    verifier_facts=record.facts,
                    evidence=[link],
                    remediation=_controller_remediation(record.gate),
                )
            )
        elif record.outcome in {"PASS", "UNKNOWN", "NOT_EVALUATED", "FAIL"}:
            target_outcomes.append(
                ReportEvaluation(
                    evaluation_id=(
                        f"verifier-{record.gate}-{record.mode}-{record.scenario_id}"
                    ),
                    state=cast(ReportState, record.outcome),
                    source_state=record.outcome,
                    authority="VERIFIER",
                    classification="TARGET_SECURITY_VALIDATION",
                    target_security_implication="TARGET_VALIDATION_ONLY",
                    facts=record.facts,
                    evidence=[link],
                )
            )
        else:
            raise ReportInputError(f"unsupported verifier outcome: {record.outcome}")

    acceptance_link = _evidence_link(
        repo_root,
        live_acceptance_path,
        artifact_sha256=acceptance_sha,
        source_evidence_sha256=None,
        authority="CONTROLLER",
        locator="verdict_detail",
    )
    platform_checks.append(
        ReportEvaluation(
            evaluation_id="controller-phase-1.7d-overall",
            state="PASS" if acceptance.verdict_detail.passed else "FAIL",
            source_state=acceptance.verdict,
            authority="CONTROLLER",
            classification="PLATFORM_PHASE_ASSURANCE",
            target_security_implication="NONE",
            facts={},
            evidence=[acceptance_link],
        )
    )
    for name, value in sorted(acceptance.verdict_detail.checks.items()):
        platform_checks.append(
            ReportEvaluation(
                evaluation_id=f"controller-phase-1.7d-{name}",
                state=_state_from_controller(value),
                source_state=str(value),
                authority="CONTROLLER",
                classification="PLATFORM_PHASE_ASSURANCE",
                target_security_implication="NONE",
                facts={},
                evidence=[
                    acceptance_link.model_copy(
                        update={"locator": f"verdict_detail.checks.{name}"}
                    )
                ],
            )
        )

    queue_link = _evidence_link(
        repo_root,
        delegation_queue_path,
        artifact_sha256=queue_sha,
        source_evidence_sha256=queue_payload.source_evidence_sha256,
        authority="CONTROLLER",
        locator=f"agent_delegations/{queue_payload.delegation_id}",
    )
    hypothesis = ReportHypothesis(
        hypothesis_id=queue_payload.delegation_id,
        summary=queue_payload.rationale,
        target_ref=queue_payload.target_ref,
        capability_id=queue_payload.capability_id,
        assigned_agent=queue_payload.to_agent,
        queue_address=queue_address,
        evidence=[
            queue_link,
            acceptance_link.model_copy(update={"locator": "record.delegation_enqueue"}),
        ],
    )
    usage = ReportModelUsage()
    verdict = _make_verdict(findings, target_outcomes, platform_checks, [hypothesis], usage)
    return ReportDocument(
        generated_at=generated_at or datetime.now(UTC),
        source_artifacts=[
            _evidence_link(
                repo_root,
                verifier_results_path,
                artifact_sha256=verifier_sha,
                source_evidence_sha256=None,
                authority="VERIFIER",
                locator="all records",
            ),
            acceptance_link,
            queue_link,
        ],
        verified_security_findings=findings,
        target_security_validation_outcomes=target_outcomes,
        platform_phase_assurance_checks=platform_checks,
        unconfirmed_hypotheses=[hypothesis],
        model_usage=usage,
        verdict=verdict,
    )


def render_markdown(report: ReportDocument) -> str:
    """Render only typed report fields; no prose generation or inferred metrics."""

    lines = [
        "# Phase 1.8 Evidence Report",
        "",
        "This offline report transports verifier/controller outcomes and ground-truth severity. "
        "It does not perform scans or model inference.",
        "",
        f"Generated: `{report.generated_at.isoformat()}`  ",
        f"Generation mode: `{report.generation_mode}`  ",
        f"Reporting pipeline status: `{report.reporting_pipeline_status}`  ",
        f"Live Report Agent status: `{report.live_report_agent_status}`  ",
        "Report-agent provider calls/tokens: "
        f"`{report.model_usage.provider_calls_total}` / "
        f"`{report.model_usage.provider_tokens_total}`",
        "",
        "## Verdict",
        "",
        "```json",
        json.dumps(report.verdict.model_dump(mode="json"), indent=2, sort_keys=True),
        "```",
        "",
        "## Source artifacts",
        "",
    ]
    for source in report.source_artifacts:
        lines.append(f"- `{source.path}` — artifact SHA-256 `{source.artifact_sha256}`")

    lines.extend(["", "## VERIFIED SECURITY FINDINGS", ""])
    if not report.verified_security_findings:
        lines.append("No verifier-confirmed findings were present in the supplied evidence.")
    for finding in report.verified_security_findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- State: `{finding.state}`",
                f"- Verification provenance: `{finding.verification_provenance}`",
                f"- Gate / mode / scenario: `{finding.gate}` / `{finding.mode}` / "
                f"`{finding.scenario_id}`",
                f"- Severity: `{finding.severity.value}` "
                f"(authority: `{finding.severity.authority}`; source: "
                f"`{finding.severity.source_id or 'NONE'}`)",
                f"- Severity rationale: {finding.severity.rationale}",
                f"- Remediation (`{finding.remediation_authority}`): {finding.remediation}",
                "- Evidence:",
            ]
        )
        for link in finding.evidence:
            lines.append(
                f"  - `{link.path}` at `{link.locator}`; source evidence SHA-256 "
                f"`{link.source_evidence_sha256 or 'NOT_PRESENT'}`; artifact SHA-256 "
                f"`{link.artifact_sha256}`"
            )
        lines.extend(
            [
                "- Verifier facts:",
                "",
                "```json",
                json.dumps(finding.verifier_facts, indent=2, sort_keys=True),
                "```",
                "",
            ]
        )

    lines.extend(["## TARGET SECURITY VALIDATION OUTCOMES", ""])
    lines.append(
        "These are target-specific verifier outcomes; they do not inherit assurance from "
        "platform checks."
    )
    lines.append("")
    for evaluation in report.target_security_validation_outcomes:
        lines.append(
            f"- `{evaluation.evaluation_id}`: `{evaluation.state}` "
            f"(source state: `{evaluation.source_state}`; evidence: "
            f"`{evaluation.evidence[0].path}` at `{evaluation.evidence[0].locator}`)"
        )

    lines.extend(["", "## PLATFORM / PHASE ASSURANCE CHECKS", ""])
    lines.append(
        "A platform or workflow PASS validates only the named phase mechanism and never implies "
        "that the target is secure."
    )
    lines.append("")
    for evaluation in report.platform_phase_assurance_checks:
        lines.append(
            f"- `{evaluation.evaluation_id}`: `{evaluation.state}`; classification "
            f"`{evaluation.classification}`; target-security implication "
            f"`{evaluation.target_security_implication}` (source state: "
            f"`{evaluation.source_state}`; evidence: `{evaluation.evidence[0].path}` at "
            f"`{evaluation.evidence[0].locator}`)"
        )

    lines.extend(["", "## UNCONFIRMED HYPOTHESES", ""])
    for hypothesis in report.unconfirmed_hypotheses:
        lines.extend(
            [
                f"### {hypothesis.hypothesis_id}",
                "",
                f"- State: `{hypothesis.state}`; confirmed: `{str(hypothesis.confirmed).lower()}`",
                f"- Severity: `{hypothesis.severity}`",
                f"- Target / capability / assigned agent: `{hypothesis.target_ref}` / "
                f"`{hypothesis.capability_id}` / `{hypothesis.assigned_agent}`",
                f"- Queue address: `{hypothesis.queue_address}`",
                f"- Source rationale: {hypothesis.summary}",
                "- Evidence:",
            ]
        )
        for link in hypothesis.evidence:
            lines.append(
                f"  - `{link.path}` at `{link.locator}`; source evidence SHA-256 "
                f"`{link.source_evidence_sha256 or 'NOT_PRESENT'}`; artifact SHA-256 "
                f"`{link.artifact_sha256}`"
            )
    return "\n".join(lines) + "\n"


def write_report_bundle(output_dir: Path, report: ReportDocument) -> None:
    """Write machine-readable report, human report, verdict, and integrity manifest."""

    output_dir.mkdir(parents=True, exist_ok=False)
    payloads = {
        "report.json": report.model_dump_json(indent=2) + "\n",
        "report.md": render_markdown(report),
        "verdict.json": report.verdict.model_dump_json(indent=2) + "\n",
    }
    for name, payload in payloads.items():
        (output_dir / name).write_text(payload, encoding="utf-8")
    checksums = [f"{_sha256(output_dir / name)}  {name}" for name in sorted(payloads)]
    (output_dir / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
