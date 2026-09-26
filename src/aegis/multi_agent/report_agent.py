"""Phase 2.6 — REPORT_AGENT architecture + controller-authoritative professional reporting.

A real, persisted REPORT_AGENT job layer on top of the existing evidence-preserving reporting model.
The REPORT_AGENT *drafts prose* (executive summary, methodology/limitations, per-finding
remediation, per-chain causal explanation, organization); the **controller** owns every fact and
assembles the final report from its own authoritative inputs, discarding or downgrading any
unsupported model claim.

Authority (hard boundaries — enforced structurally + on assembly):

The REPORT_AGENT MAY: summarize adjudicated facts, explain verified causal chains, draft remediation
language, and improve organization/readability.

The REPORT_AGENT CANNOT: confirm a finding, decide PASS/FAIL, change severity, invent evidence,
invent causal links, hide cleanup failures, convert UNKNOWN/HYPOTHESIS into PASS/CONFIRMED, convert
offline evidence into live evidence, expose credentials, or treat role labels as execution evidence.
Those facts come only from the controller-owned :class:`ReportSource`; the model output
(:class:`aegis.multi_agent.contracts.AssessmentReportDraftOutput`) has no field for any of them, and
:func:`assemble_report` re-derives each authoritative fact and drops prose that does not map to a
controller-owned id.

Nothing here calls a live report model (``live_report_agent_status = NOT_EVALUATED``). Report
assembly and exports (JSON / Markdown / HTML) are deterministic and fully offline-testable. PDF
export is intentionally omitted — no PDF dependency is declared in the project — and reported as
``NOT_EVALUATED`` rather than faked.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from aegis.multi_agent.contracts import AssessmentReportDraftOutput, StrictModel, now_utc

Measured = int | Literal["UNKNOWN"]
UNKNOWN: Literal["UNKNOWN"] = "UNKNOWN"

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
FindingState = Literal["CONFIRMED"]
EvaluationState = Literal["CONFIRMED", "PASS", "FAIL", "UNKNOWN", "NOT_EVALUATED"]
# The only provenance labels the controller may stamp. A LIVE label is only ever produced by a live
# controller run; the model can never introduce it (it has no provenance field).
Provenance = Literal[
    "OFFLINE_VERIFIED_SYNTHETIC",
    "CONTAINERIZED_SYNTHETIC",
    "LIVE_VERIFIED",
    "HISTORICAL_ARTIFACT",
]


class FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ReportAgentError(RuntimeError):
    """A report-agent failure (bad id, malformed input, queue error). Fails closed."""


class ReportAgentQueueError(RuntimeError):
    """A queue-level failure (duplicate id, malformed address, illegal transition). Fails closed."""


class ReportProjectionError(ValueError):
    """Raised when a model-facing report projection carries a forbidden token. Fails closed."""


# --------------------------------------------------------------------------- #
# Controller-owned authoritative source facts (the model never sets any of these).
# --------------------------------------------------------------------------- #


class SourceEvidenceRef(StrictModel):
    """A reference to an evidence artifact — a digest + locator, never the raw evidence bytes."""

    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    locator: str = Field(min_length=1, max_length=300)
    authority: Literal["VERIFIER", "CONTROLLER"]


class SourceFinding(StrictModel):
    """One independently-verified finding. Only a CONFIRMED finding is ever a report finding."""

    finding_id: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=1, max_length=300)
    gate: str = Field(min_length=1, max_length=60)
    mode: str = Field(min_length=1, max_length=60)
    scenario_id: str = Field(min_length=1, max_length=120)
    state: FindingState = "CONFIRMED"
    severity: Severity
    severity_authority: Literal["VERIFIER", "GROUND_TRUTH"]
    verification_provenance: Provenance
    verifier_facts: dict[str, bool | int | str] = Field(default_factory=dict)
    evidence: tuple[SourceEvidenceRef, ...] = Field(min_length=1)
    registered_remediation: str | None = Field(default=None, max_length=1200)


class SourceEvaluation(StrictModel):
    """A target-security or platform-assurance evaluation (verifier/controller owned)."""

    evaluation_id: str = Field(min_length=3, max_length=120)
    state: EvaluationState
    classification: Literal[
        "TARGET_SECURITY_VALIDATION",
        "PLATFORM_PHASE_ASSURANCE",
        "DELEGATION_WORKFLOW_CHAIN",
    ]
    authority: Literal["VERIFIER", "CONTROLLER"]
    provenance: Provenance
    facts: dict[str, bool | int | str] = Field(default_factory=dict)
    evidence: tuple[SourceEvidenceRef, ...] = Field(min_length=1)


class SourceHypothesis(StrictModel):
    """An unconfirmed hypothesis — kept clearly separate from findings; severity is UNKNOWN."""

    hypothesis_id: str = Field(min_length=3, max_length=120)
    summary: str = Field(min_length=1, max_length=500)
    target_ref: str = Field(min_length=1, max_length=120)
    capability_id: str = Field(min_length=1, max_length=120)
    assigned_agent: str = Field(min_length=1, max_length=60)
    queue_address: str = Field(min_length=1, max_length=200)
    confirmed: Literal[False] = False
    severity: Literal["UNKNOWN"] = "UNKNOWN"
    provenance: Provenance
    evidence: tuple[SourceEvidenceRef, ...] = Field(min_length=1)


class SourceCausalChain(StrictModel):
    """A causal attack chain. Only a controller-verified chain is rendered as verified."""

    chain_id: str = Field(min_length=3, max_length=120)
    ordered_primitive_types: tuple[str, ...] = Field(min_length=1, max_length=8)
    verified: bool
    provenance: Provenance
    evidence: tuple[SourceEvidenceRef, ...] = Field(min_length=1)


class SourceRetest(StrictModel):
    """A retest outcome (controller/verifier owned)."""

    retest_id: str = Field(min_length=3, max_length=120)
    finding_id: str = Field(min_length=3, max_length=120)
    state: EvaluationState
    provenance: Provenance
    evidence: tuple[SourceEvidenceRef, ...] = Field(min_length=1)


class SourceCleanup(StrictModel):
    """Cleanup / reset status. A failure is NEVER hidden — ``succeeded`` may be False or UNKNOWN."""

    succeeded: bool | Literal["UNKNOWN"]
    obligations: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    failures: tuple[str, ...] = Field(default_factory=tuple, max_length=16)


class SourceUsage(StrictModel):
    """Provider/tool usage. Unmeasured values stay UNKNOWN, never zero."""

    provider_calls: Measured
    input_tokens: Measured
    output_tokens: Measured
    total_tokens: Measured
    tool_executions: Measured
    identity_exact_deepseek_v4_pro: bool | Literal["NOT_EVALUATED"] = "NOT_EVALUATED"


class ReportSource(StrictModel):
    """The complete controller-owned authoritative input to one report. The model never sees the raw
    bytes behind the evidence refs and never sets any adjudicated fact here."""

    campaign_id: str = Field(min_length=3, max_length=120)
    target_ref: str = Field(min_length=1, max_length=120)
    authorized_scope: tuple[str, ...] = Field(min_length=1, max_length=32)
    findings: tuple[SourceFinding, ...] = Field(default_factory=tuple, max_length=128)
    target_outcomes: tuple[SourceEvaluation, ...] = Field(default_factory=tuple, max_length=128)
    platform_checks: tuple[SourceEvaluation, ...] = Field(default_factory=tuple, max_length=128)
    hypotheses: tuple[SourceHypothesis, ...] = Field(default_factory=tuple, max_length=128)
    causal_chains: tuple[SourceCausalChain, ...] = Field(default_factory=tuple, max_length=32)
    retests: tuple[SourceRetest, ...] = Field(default_factory=tuple, max_length=64)
    cleanup: SourceCleanup
    usage: SourceUsage
    live_run: bool = False


# Controller-owned default remediation registry (deterministic; used when a finding has no
# registered remediation and to override an unsupported model draft).
_DEFAULT_REMEDIATION: dict[str, str] = {
    "xss": (
        "Apply context-aware output encoding or sanitization at the executable HTML sink, then run "
        "an independent verifier retest."
    ),
    "sqli": (
        "Use parameterized queries or prepared statements and remove query-string concatenation, "
        "then run an independent verifier retest."
    ),
    "detection_control": (
        "Enforce uniform detection-control recognition so alternate request variants are denied "
        "like the baseline, then run an independent verifier retest."
    ),
}
_GENERIC_REMEDIATION = (
    "Remediate the confirmed control gap per the verifier facts, then run an independent verifier "
    "retest to prove the fix."
)


def controller_remediation(finding: SourceFinding) -> str:
    """Controller-owned remediation for a finding (registered value, gate default or generic)."""

    if finding.registered_remediation:
        return finding.registered_remediation
    return _DEFAULT_REMEDIATION.get(finding.gate, _GENERIC_REMEDIATION)


# --------------------------------------------------------------------------- #
# Model-facing sanitized projection (metadata + booleans; never raw evidence or secrets).
# --------------------------------------------------------------------------- #

_FORBIDDEN_REPORT_TOKENS: tuple[str, ...] = (
    "bearer ",
    "set-cookie",
    "authorization:",
    "password",
    "passcode",
    "lab-token-",
    "credentialref://",  # a projection references findings, not raw credential refs
    "secret-",
    "answer_key",
    "ground_truth_value",
)


def assert_report_projection_clean(projection: dict[str, object]) -> None:
    blob = json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str).lower()
    present = [token for token in _FORBIDDEN_REPORT_TOKENS if token in blob]
    if present:
        raise ReportProjectionError(f"REPORT_PROJECTION_NOT_SANITIZED:{','.join(sorted(present))}")


def build_report_request_projection(source: ReportSource) -> dict[str, object]:
    """The sanitized projection the controller hands to the REPORT_AGENT.

    It carries only ids, titles, typed states/severity as data to *explain* (never to set), scope
    references and evidence digests — never raw evidence bytes, credential values or ground-truth
    answer keys. It is the only report input the model ever sees.
    """

    projection: dict[str, object] = {
        "campaign_id": source.campaign_id,
        "target_ref": source.target_ref,
        "authorized_scope": list(source.authorized_scope),
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "gate": f.gate,
                "scenario_id": f.scenario_id,
                "state": f.state,
                "severity": f.severity,
                "verification_provenance": f.verification_provenance,
                "evidence_digests": [e.evidence_sha256 for e in f.evidence],
            }
            for f in source.findings
        ],
        "hypotheses": [
            {
                "hypothesis_id": h.hypothesis_id,
                "summary": h.summary,
                "state": "HYPOTHESIS",
                "severity": h.severity,
            }
            for h in source.hypotheses
        ],
        "verified_causal_chains": [
            {
                "chain_id": c.chain_id,
                "ordered_primitive_types": list(c.ordered_primitive_types),
                "verified": c.verified,
            }
            for c in source.causal_chains
        ],
        "cleanup_succeeded": source.cleanup.succeeded,
        "cleanup_failures_present": bool(source.cleanup.failures),
        "usage_available": source.usage.provider_calls != UNKNOWN,
    }
    assert_report_projection_clean(projection)
    return projection


# --------------------------------------------------------------------------- #
# The assembled report (controller-authoritative) + verdict.
# --------------------------------------------------------------------------- #

ReportStatus = Literal["COMPLETE", "PARTIAL", "INCOMPLETE"]


class ReportFindingSection(StrictModel):
    finding_id: str
    title: str
    state: FindingState = "CONFIRMED"
    gate: str
    mode: str
    scenario_id: str
    severity: Severity
    severity_authority: Literal["VERIFIER", "GROUND_TRUTH"]
    verification_provenance: Provenance
    verifier_facts: dict[str, bool | int | str]
    evidence: tuple[SourceEvidenceRef, ...]
    remediation: str
    remediation_authority: Literal["CONTROLLER_DETERMINISTIC", "REPORT_AGENT_DRAFT"]


class ReportChainSection(StrictModel):
    chain_id: str
    ordered_primitive_types: tuple[str, ...]
    verified: bool
    provenance: Provenance
    causal_link_explanation: str
    explanation_authority: Literal["REPORT_AGENT_DRAFT", "CONTROLLER_DETERMINISTIC"]
    evidence: tuple[SourceEvidenceRef, ...]


class AssessmentReport(FrozenStrictModel):
    schema_version: Literal["phase-2.6-report-v1"] = "phase-2.6-report-v1"
    report_id: str = Field(pattern=r"^rpt-[a-f0-9]{16}$")
    version: int = Field(ge=1)
    campaign_id: str
    target_ref: str
    generated_at: datetime
    status: ReportStatus
    live_report_agent_status: Literal["NOT_EVALUATED", "LIVE_OBSERVED"] = "NOT_EVALUATED"
    generation_mode: Literal[
        "OFFLINE_DETERMINISTIC", "LIVE_MODEL_ASSISTED", "LIVE_CONTROLLER_FALLBACK"
    ] = "OFFLINE_DETERMINISTIC"
    model_prose_used: bool
    model_prose_downgraded: bool

    # Sections.
    executive_summary: str
    authorized_scope: tuple[str, ...]
    methodology_and_limitations: str
    verified_findings: tuple[ReportFindingSection, ...]
    unconfirmed_hypotheses: tuple[SourceHypothesis, ...]
    verified_attack_chains: tuple[ReportChainSection, ...]
    target_security_validation: tuple[SourceEvaluation, ...]
    platform_phase_assurance: tuple[SourceEvaluation, ...]
    retest_results: tuple[SourceRetest, ...]
    cleanup: SourceCleanup
    usage: SourceUsage

    @property
    def content_sha256(self) -> str:
        material = self.model_dump_json(exclude={"generated_at"})
        return hashlib.sha256(material.encode()).hexdigest()

    @property
    def report_uri(self) -> str:
        return f"report://{self.campaign_id}/{self.report_id}@v{self.version}"


_CONTROLLER_SUMMARY_FALLBACK = (
    "This report transports controller-adjudicated facts only. The REPORT_AGENT narrative was "
    "unavailable or downgraded, so the executive summary is the controller's neutral statement of "
    "the confirmed findings, hypotheses and cleanup status below."
)
_CONTROLLER_METHOD_FALLBACK = (
    "Methodology and limitations are controller-owned. Findings are CONFIRMED only by the "
    "independent deterministic verifier; hypotheses are unconfirmed; provenance and cleanup status "
    "are stated verbatim from the controller record and never inferred by the report agent."
)


def _prose_is_safe(text: str) -> bool:
    lowered = text.lower()
    return not any(token in lowered for token in _FORBIDDEN_REPORT_TOKENS)


_NO_FINDING_CLAIMS = (
    re.compile(r"\bno\s+(?:adjudicated\s+|such\s+)?facts?\b"),
    re.compile(r"\bno\s+(?:substantive\s+)?findings?\b"),
    re.compile(r"\bnone\s+(?:were|was|have been)\s+provided\b"),
    re.compile(r"\bnothing\s+can\s+be\s+stated\b"),
)


def _prose_is_consistent(text: str, source: ReportSource) -> bool:
    """Reject model prose that directly contradicts controller-owned report facts."""

    lowered = text.lower()
    if source.findings and any(pattern.search(lowered) for pattern in _NO_FINDING_CLAIMS):
        return False
    if source.retests and ("no retest" in lowered or "retest was not" in lowered):
        return False
    return True


def assemble_report(
    *,
    source: ReportSource,
    model_output: AssessmentReportDraftOutput | None,
    report_id: str,
    version: int = 1,
    generated_at: datetime | None = None,
) -> AssessmentReport:
    """Assemble the controller-authoritative report.

    Every adjudicated fact (state, severity, provenance, causal truth, cleanup, usage) is taken from
    ``source``. Model prose is used ONLY where it maps to a controller-owned id and is token-clean;
    otherwise it is discarded and the controller fallback is used (``model_prose_downgraded``).
    """

    generated_at = generated_at or now_utc()
    downgraded = False
    model_contributions = 0

    # Executive summary + methodology: use model prose only if present AND token-clean.
    if (
        model_output is not None
        and _prose_is_safe(model_output.executive_summary)
        and _prose_is_consistent(model_output.executive_summary, source)
    ):
        executive_summary = model_output.executive_summary
        model_contributions += 1
    else:
        executive_summary = _CONTROLLER_SUMMARY_FALLBACK
        downgraded = downgraded or model_output is not None
    if (
        model_output is not None
        and _prose_is_safe(model_output.methodology_and_limitations)
        and _prose_is_consistent(model_output.methodology_and_limitations, source)
    ):
        methodology = model_output.methodology_and_limitations
        model_contributions += 1
    else:
        methodology = _CONTROLLER_METHOD_FALLBACK
        downgraded = downgraded or model_output is not None

    # Per-finding remediation drafts, keyed to controller-owned ids only.
    draft_remediation: dict[str, str] = {}
    if model_output is not None:
        valid_ids = {f.finding_id for f in source.findings}
        for draft in model_output.finding_remediations:
            if draft.finding_id in valid_ids and _prose_is_safe(draft.remediation_text):
                draft_remediation[draft.finding_id] = draft.remediation_text
                model_contributions += 1
            else:
                # A remediation keyed to an unknown finding, or carrying a forbidden token, is
                # discarded — the controller default is used instead.
                downgraded = True

    findings: list[ReportFindingSection] = []
    for f in source.findings:
        drafted = draft_remediation.get(f.finding_id)
        if drafted is not None:
            remediation = drafted
            authority: Literal["CONTROLLER_DETERMINISTIC", "REPORT_AGENT_DRAFT"] = (
                "REPORT_AGENT_DRAFT"
            )
        else:
            remediation = controller_remediation(f)
            authority = "CONTROLLER_DETERMINISTIC"
        findings.append(
            ReportFindingSection(
                finding_id=f.finding_id,
                title=f.title,
                gate=f.gate,
                mode=f.mode,
                scenario_id=f.scenario_id,
                severity=f.severity,
                severity_authority=f.severity_authority,
                verification_provenance=f.verification_provenance,
                verifier_facts=f.verifier_facts,
                evidence=f.evidence,
                remediation=remediation,
                remediation_authority=authority,
            )
        )

    # Chain explanations, keyed to controller-owned VERIFIED chains only.
    draft_explanation: dict[str, str] = {}
    if model_output is not None:
        verified_ids = {c.chain_id for c in source.causal_chains if c.verified}
        for chain_draft in model_output.chain_explanations:
            if chain_draft.chain_id in verified_ids and _prose_is_safe(
                chain_draft.causal_link_explanation
            ):
                draft_explanation[chain_draft.chain_id] = chain_draft.causal_link_explanation
                model_contributions += 1
            else:
                downgraded = True

    chains: list[ReportChainSection] = []
    for c in source.causal_chains:
        # An unverified chain is never explained as verified; its explanation is a neutral note.
        if c.verified and c.chain_id in draft_explanation:
            explanation = draft_explanation[c.chain_id]
            expl_authority: Literal["REPORT_AGENT_DRAFT", "CONTROLLER_DETERMINISTIC"] = (
                "REPORT_AGENT_DRAFT"
            )
        else:
            explanation = (
                "Controller-owned causal record; see the linked evidence. "
                + ("Chain verified by the independent verifier." if c.verified else
                   "Chain NOT verified — presented as an unconfirmed hypothesis only.")
            )
            expl_authority = "CONTROLLER_DETERMINISTIC"
        chains.append(
            ReportChainSection(
                chain_id=c.chain_id,
                ordered_primitive_types=c.ordered_primitive_types,
                verified=c.verified,
                provenance=c.provenance,
                causal_link_explanation=explanation,
                explanation_authority=expl_authority,
                evidence=c.evidence,
            )
        )

    status = _report_status(source)
    model_used = model_contributions > 0
    if source.live_run:
        live_report_agent_status: Literal["NOT_EVALUATED", "LIVE_OBSERVED"] = "LIVE_OBSERVED"
        generation_mode: Literal[
            "OFFLINE_DETERMINISTIC", "LIVE_MODEL_ASSISTED", "LIVE_CONTROLLER_FALLBACK"
        ] = "LIVE_MODEL_ASSISTED" if model_used else "LIVE_CONTROLLER_FALLBACK"
    else:
        live_report_agent_status = "NOT_EVALUATED"
        generation_mode = "OFFLINE_DETERMINISTIC"
    return AssessmentReport(
        report_id=report_id,
        version=version,
        campaign_id=source.campaign_id,
        target_ref=source.target_ref,
        generated_at=generated_at,
        status=status,
        live_report_agent_status=live_report_agent_status,
        generation_mode=generation_mode,
        model_prose_used=model_used,
        model_prose_downgraded=downgraded,
        executive_summary=executive_summary,
        authorized_scope=source.authorized_scope,
        methodology_and_limitations=methodology,
        verified_findings=tuple(findings),
        unconfirmed_hypotheses=source.hypotheses,
        verified_attack_chains=tuple(chains),
        target_security_validation=source.target_outcomes,
        platform_phase_assurance=source.platform_checks,
        retest_results=source.retests,
        cleanup=source.cleanup,
        usage=source.usage,
    )


def _report_status(source: ReportSource) -> ReportStatus:
    """Controller-owned report status. Cleanup failure or any INCOMPLETE/UNKNOWN input → PARTIAL."""

    if source.cleanup.succeeded is not True or source.cleanup.failures:
        return "PARTIAL"
    eval_states: list[str] = [
        *(e.state for e in source.target_outcomes),
        *(e.state for e in source.platform_checks),
        *(r.state for r in source.retests),
    ]
    if any(state in ("UNKNOWN", "NOT_EVALUATED") for state in eval_states):
        return "PARTIAL"
    if not source.findings and not eval_states and not source.hypotheses:
        return "INCOMPLETE"
    return "COMPLETE"


# --------------------------------------------------------------------------- #
# Deterministic exports (JSON / Markdown / HTML). PDF intentionally omitted (NOT_EVALUATED).
# --------------------------------------------------------------------------- #


def report_json(report: AssessmentReport) -> str:
    return report.model_dump_json(indent=2) + "\n"


# Defensive render-sink ceiling. Some report fields (executive_summary, methodology, campaign_id,
# target_ref) are not individually length-bounded on the model, so a hostile or oversized value is
# truncated at the export sink with a visible, deterministic marker. This bounds worst-case export
# size and never changes report identity (content_sha256 comes from the model, not the render).
MAX_RENDERED_CHARS = 4000


def _bounded(value: object) -> str:
    """Truncate an over-long rendered value deterministically, with a visible marker."""

    text = str(value)
    if len(text) <= MAX_RENDERED_CHARS:
        return text
    dropped = len(text) - MAX_RENDERED_CHARS
    return f"{text[:MAX_RENDERED_CHARS]}…[truncated {dropped} chars]"


def render_report_markdown(report: AssessmentReport) -> str:
    lines = [
        f"# Assessment Report — {_bounded(report.campaign_id)}",
        "",
        f"- Report: `{report.report_uri}`",
        f"- Status: `{report.status}`  ·  Live report-agent status: "
        f"`{report.live_report_agent_status}`",
        f"- Generation mode: `{report.generation_mode}`  ·  Model prose used: "
        f"`{str(report.model_prose_used).lower()}`  ·  downgraded: "
        f"`{str(report.model_prose_downgraded).lower()}`",
        f"- Content SHA-256: `{report.content_sha256}`",
        "",
        "## Executive summary",
        "",
        _bounded(report.executive_summary),
        "",
        "## Authorized scope",
        "",
    ]
    for scope in report.authorized_scope:
        lines.append(f"- `{scope}`")
    lines.extend(
        ["", "## Methodology and limitations", "", _bounded(report.methodology_and_limitations), ""]
    )

    lines.extend(["## Verified findings", ""])
    if not report.verified_findings:
        lines.append("No verifier-confirmed findings in the supplied evidence.")
    for f in report.verified_findings:
        lines.extend(
            [
                f"### {f.title}",
                "",
                f"- State: `{f.state}` · Severity: `{f.severity}` "
                f"(authority `{f.severity_authority}`)",
                f"- Gate/mode/scenario: `{f.gate}` / `{f.mode}` / `{f.scenario_id}`",
                f"- Verification provenance: `{f.verification_provenance}`",
                f"- Remediation (`{f.remediation_authority}`): {f.remediation}",
                "- Evidence:",
            ]
        )
        for e in f.evidence:
            lines.append(f"  - `{e.locator}` — SHA-256 `{e.evidence_sha256}` ({e.authority})")
        lines.append("")

    lines.extend(["## Unconfirmed hypotheses (kept separate from findings)", ""])
    for h in report.unconfirmed_hypotheses:
        lines.append(
            f"- `{h.hypothesis_id}` — state `HYPOTHESIS`, severity `{h.severity}`: {h.summary}"
        )
    lines.append("")

    lines.extend(["## Verified attack chains", ""])
    for c in report.verified_attack_chains:
        lines.append(
            f"- `{c.chain_id}` verified=`{str(c.verified).lower()}` "
            f"({' -> '.join(c.ordered_primitive_types)}): {c.causal_link_explanation}"
        )
    lines.append("")

    lines.extend(["## Retest results", ""])
    for r in report.retest_results:
        lines.append(f"- `{r.retest_id}` for `{r.finding_id}`: `{r.state}` ({r.provenance})")
    lines.append("")

    lines.extend(["## Cleanup / reset status", ""])
    lines.append(f"- Succeeded: `{report.cleanup.succeeded}`")
    if report.cleanup.failures:
        lines.append("- Failures (NOT hidden):")
        for failure in report.cleanup.failures:
            lines.append(f"  - `{failure}`")
    lines.append("")

    lines.extend(["## Provider / tool usage", ""])
    usage = report.usage
    lines.append(
        f"- Provider calls: `{usage.provider_calls}` · total tokens: `{usage.total_tokens}` · "
        f"tool executions: `{usage.tool_executions}` · identity exact: "
        f"`{usage.identity_exact_deepseek_v4_pro}`"
    )
    return "\n".join(lines) + "\n"


def render_report_html(report: AssessmentReport) -> str:
    """A deterministic, escaped HTML rendering. Evidence text is HTML-escaped (injection inert)."""

    def esc(value: object) -> str:
        # Bound first (defensive truncation), then HTML-escape so injection-shaped text is inert.
        return html.escape(_bounded(value))

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>Assessment Report — {esc(report.campaign_id)}</title>",
        "</head><body>",
        f"<h1>Assessment Report — {esc(report.campaign_id)}</h1>",
        f"<p>Report: <code>{esc(report.report_uri)}</code><br>",
        f"Status: <code>{esc(report.status)}</code>; "
        f"live report-agent status: <code>{esc(report.live_report_agent_status)}</code>; "
        f"content SHA-256: <code>{esc(report.content_sha256)}</code></p>",
        "<h2>Executive summary</h2>",
        f"<p>{esc(report.executive_summary)}</p>",
        "<h2>Methodology and limitations</h2>",
        f"<p>{esc(report.methodology_and_limitations)}</p>",
        "<h2>Verified findings</h2>",
    ]
    if not report.verified_findings:
        parts.append("<p>No verifier-confirmed findings.</p>")
    for f in report.verified_findings:
        parts.append(
            f"<h3>{esc(f.title)}</h3><ul>"
            f"<li>State: <code>{esc(f.state)}</code>; severity: <code>{esc(f.severity)}</code> "
            f"(authority <code>{esc(f.severity_authority)}</code>)</li>"
            f"<li>Provenance: <code>{esc(f.verification_provenance)}</code></li>"
            f"<li>Remediation (<code>{esc(f.remediation_authority)}</code>): "
            f"{esc(f.remediation)}</li></ul>"
        )
    parts.append("<h2>Unconfirmed hypotheses</h2><ul>")
    for h in report.unconfirmed_hypotheses:
        parts.append(
            f"<li><code>{esc(h.hypothesis_id)}</code> — HYPOTHESIS, severity "
            f"<code>{esc(h.severity)}</code>: {esc(h.summary)}</li>"
        )
    parts.append("</ul><h2>Cleanup / reset status</h2>")
    parts.append(f"<p>Succeeded: <code>{esc(report.cleanup.succeeded)}</code></p>")
    if report.cleanup.failures:
        parts.append("<ul>")
        for failure in report.cleanup.failures:
            parts.append(f"<li>{esc(failure)}</li>")
        parts.append("</ul>")
    parts.append("</body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------- #
# Report verdict.
# --------------------------------------------------------------------------- #


def build_report_verdict(source: ReportSource, report: AssessmentReport) -> dict[str, object]:
    checks: dict[str, bool] = {
        "findings_all_confirmed": all(f.state == "CONFIRMED" for f in report.verified_findings),
        "every_finding_links_evidence": all(
            len(f.evidence) >= 1 for f in report.verified_findings
        ),
        "severity_traces_to_authority": all(
            f.severity_authority in ("VERIFIER", "GROUND_TRUTH") for f in report.verified_findings
        ),
        "hypotheses_kept_separate": all(
            not h.confirmed and h.severity == "UNKNOWN" for h in report.unconfirmed_hypotheses
        ),
        "remediation_present_per_finding": all(
            bool(f.remediation.strip()) for f in report.verified_findings
        ),
        "cleanup_failures_visible": (
            report.cleanup.succeeded is True or report.status == "PARTIAL"
        ),
        "provenance_preserved": _provenance_preserved(source, report),
        "no_false_live_claims": (source.live_run or not _claims_live(report)),
        "unverified_chains_not_confirmed": all(
            (c.verified or "NOT verified" in c.causal_link_explanation)
            for c in report.verified_attack_chains
        ),
        "usage_unknown_preserved": _usage_unknown_preserved(source, report),
        "stable_report_identity": bool(report.content_sha256) and report.version >= 1,
        "deterministic_offline_generation": report.generation_mode == "OFFLINE_DETERMINISTIC",
    }
    passed = all(checks.values())
    return {
        "phase": "2.6",
        "report_agent_implementation_status": "OFFLINE_PASS" if passed else "OFFLINE_FAIL",
        "live_report_agent_status": "NOT_EVALUATED",
        "pdf_export_status": "NOT_EVALUATED",
        "evidence_type": "OFFLINE_INTEGRATION",
        "checks": checks,
        "report_status": report.status,
        "passed": passed,
    }


def _provenance_preserved(source: ReportSource, report: AssessmentReport) -> bool:
    by_id = {f.finding_id: f.verification_provenance for f in source.findings}
    return all(
        by_id.get(f.finding_id) == f.verification_provenance for f in report.verified_findings
    )


def _claims_live(report: AssessmentReport) -> bool:
    live_finding = any(
        f.verification_provenance == "LIVE_VERIFIED" for f in report.verified_findings
    )
    live_chain = any(c.provenance == "LIVE_VERIFIED" for c in report.verified_attack_chains)
    return live_finding or live_chain


def _usage_unknown_preserved(source: ReportSource, report: AssessmentReport) -> bool:
    return (
        source.usage.provider_calls == report.usage.provider_calls
        and source.usage.total_tokens == report.usage.total_tokens
    )


# --------------------------------------------------------------------------- #
# Real, persisted, addressable REPORT_AGENT job queue (QUEUED -> CLAIMED -> CLOSED).
# --------------------------------------------------------------------------- #

_JOB_ADDRESS_SCHEME = "agentjob"


class ReportAgentJob(StrictModel):
    """A real, persisted, addressable inbound REPORT_AGENT job for one report request."""

    job_id: str = Field(pattern=r"^rptjob-[a-f0-9]{16}$")
    to_agent: Literal["REPORT_AGENT"] = "REPORT_AGENT"
    campaign_id: str = Field(min_length=3, max_length=120)
    report_request_id: str = Field(pattern=r"^rptreq-[a-f0-9]{16}$")
    task_type: Literal["GENERATE_ASSESSMENT_REPORT"] = "GENERATE_ASSESSMENT_REPORT"
    source_projection_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        return f"{_JOB_ADDRESS_SCHEME}://{self.to_agent}/{self.job_id}"


def parse_report_job_address(address: str) -> tuple[str, str]:
    prefix = f"{_JOB_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise ReportAgentQueueError("REPORT_JOB_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, job_id = rest.partition("/")
    if not sep or to_agent != "REPORT_AGENT" or not job_id:
        raise ReportAgentQueueError("REPORT_JOB_ADDRESS_MALFORMED")
    return to_agent, job_id


def projection_sha256(projection: dict[str, object]) -> str:
    material = json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(material).hexdigest()


class ReportAgentQueue:
    """A durable, addressable REPORT_AGENT job queue + report store on SQLite.

    It persists the addressable job (QUEUED->CLAIMED->CLOSED), records every transition, and stores
    the assembled report by (report_id, version). There is no column through which a credential, raw
    evidence or a verdict authority could be persisted."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS report_agent_jobs (
                    job_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    report_request_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS report_agent_job_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assessment_reports (
                    report_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    campaign_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (report_id, version)
                );
                """
            )

    def enqueue_job(self, job: ReportAgentJob) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO report_agent_jobs(
                        job_id, campaign_id, report_request_id, status, address,
                        enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        job.job_id,
                        job.campaign_id,
                        job.report_request_id,
                        job.status,
                        job.address,
                        job.enqueued_at.isoformat(),
                        job.model_dump_json(),
                    ),
                )
                self._record_transition(connection, job.job_id, "NONE", job.status)
            except sqlite3.IntegrityError as exc:
                raise ReportAgentQueueError("REPORT_JOB_ALREADY_ENQUEUED") from exc
        return job.address

    def get_job(self, job_id: str) -> ReportAgentJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM report_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return ReportAgentJob.model_validate_json(row["payload"]) if row else None

    def resolve_job(self, address: str) -> ReportAgentJob | None:
        to_agent, job_id = parse_report_job_address(address)
        job = self.get_job(job_id)
        if job is not None and job.to_agent != to_agent:
            raise ReportAgentQueueError("REPORT_JOB_ADDRESS_ROUTING_MISMATCH")
        return job

    def claim_job(self, address: str) -> ReportAgentJob:
        return self._transition(address, expected="QUEUED", new="CLAIMED")

    def close_job(self, address: str) -> ReportAgentJob:
        return self._transition(address, expected="CLAIMED", new="CLOSED")

    def _transition(self, address: str, *, expected: str, new: str) -> ReportAgentJob:
        to_agent, job_id = parse_report_job_address(address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM report_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise ReportAgentQueueError("REPORT_JOB_NOT_FOUND")
            job = ReportAgentJob.model_validate_json(row["payload"])
            if job.to_agent != to_agent:
                raise ReportAgentQueueError("REPORT_JOB_ADDRESS_ROUTING_MISMATCH")
            if row["status"] != expected:
                raise ReportAgentQueueError(
                    f"REPORT_JOB_ILLEGAL_TRANSITION_{row['status']}_TO_{new}"
                )
            updated = job.model_copy(update={"status": new})
            connection.execute(
                "UPDATE report_agent_jobs SET status = ?, payload = ? WHERE job_id = ?",
                (new, updated.model_dump_json(), job_id),
            )
            self._record_transition(connection, job_id, expected, new)
        return updated

    def job_transitions(self, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_status, to_status, at FROM report_agent_job_transitions
                WHERE job_id = ? ORDER BY id""",
                (job_id,),
            ).fetchall()
        return [{"from": r["from_status"], "to": r["to_status"], "at": r["at"]} for r in rows]

    def save_report(self, report: AssessmentReport) -> str:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT content_sha256 FROM assessment_reports WHERE report_id = ? AND version = ?",
                (report.report_id, report.version),
            ).fetchone()
            if existing is not None and existing["content_sha256"] != report.content_sha256:
                raise ReportAgentError("REPORT_VERSION_IMMUTABLE")
            connection.execute(
                """INSERT INTO assessment_reports(
                    report_id, version, campaign_id, status, content_sha256, created_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(report_id, version) DO NOTHING""",
                (
                    report.report_id,
                    report.version,
                    report.campaign_id,
                    report.status,
                    report.content_sha256,
                    now_utc().isoformat(),
                    report.model_dump_json(),
                ),
            )
        return report.report_uri

    def get_report(self, report_id: str, version: int) -> AssessmentReport | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM assessment_reports WHERE report_id = ? AND version = ?",
                (report_id, version),
            ).fetchone()
        return AssessmentReport.model_validate_json(row["payload"]) if row else None

    def list_reports(self, limit: int = 25) -> list[AssessmentReport]:
        bounded = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM assessment_reports ORDER BY created_at DESC LIMIT ?",
                (bounded,),
            ).fetchall()
        return [AssessmentReport.model_validate_json(row["payload"]) for row in rows]

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection, job_id: str, from_status: str, to_status: str
    ) -> None:
        connection.execute(
            """INSERT INTO report_agent_job_transitions(job_id, from_status, to_status, at)
            VALUES (?, ?, ?, ?)""",
            (job_id, from_status, to_status, now_utc().isoformat()),
        )


def write_report_bundle(output_dir: Path, report: AssessmentReport) -> None:
    """Write the JSON, Markdown and HTML exports + an integrity manifest (deterministic)."""

    output_dir.mkdir(parents=True, exist_ok=False)
    payloads = {
        "report.json": report_json(report),
        "report.md": render_report_markdown(report),
        "report.html": render_report_html(report),
    }
    for name, payload in payloads.items():
        (output_dir / name).write_text(payload, encoding="utf-8")
    checksums = [
        f"{hashlib.sha256((output_dir / name).read_bytes()).hexdigest()}  {name}"
        for name in sorted(payloads)
    ]
    (output_dir / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")


_EXPORT_MEDIA_TYPES = {
    "json": "application/json",
    "md": "text/markdown",
    "html": "text/html",
}
_SAFE_FILENAME_CHARS = re.compile(r"[^a-z0-9._-]+")


def safe_report_filename(report: AssessmentReport, extension: str) -> str:
    """A download filename that cannot traverse paths or inject headers.

    The campaign id and report id are lowercased and reduced to ``[a-z0-9._-]``; any other character
    (path separators, quotes, CRLF, spaces) collapses to a single ``-``. Leading dots are removed so
    the name can never be ``..`` or a dotfile, and the whole name is length-bounded.
    """

    ext = extension.lower().lstrip(".")
    if ext not in _EXPORT_MEDIA_TYPES:
        raise ReportProjectionError(f"unsupported report export extension: {extension!r}")
    campaign = _SAFE_FILENAME_CHARS.sub("-", report.campaign_id.lower()).strip("-.")[:64]
    stem = f"assessment-{campaign or 'report'}-{report.report_id}-v{report.version}"
    stem = _SAFE_FILENAME_CHARS.sub("-", stem.lower()).strip("-.")[:180]
    return f"{stem}.{ext}"


def content_disposition(report: AssessmentReport, extension: str) -> str:
    """A safe ``Content-Disposition`` header value (attachment) for a report export."""

    return f'attachment; filename="{safe_report_filename(report, extension)}"'


def export_media_type(extension: str) -> str:
    ext = extension.lower().lstrip(".")
    if ext not in _EXPORT_MEDIA_TYPES:
        raise ReportProjectionError(f"unsupported report export extension: {extension!r}")
    return _EXPORT_MEDIA_TYPES[ext]


def verify_report_bundle(output_dir: Path) -> bool:
    """Recompute every SHA256SUMS entry and confirm the bundle is byte-intact (fail-closed)."""

    manifest = output_dir / "SHA256SUMS"
    if not manifest.is_file():
        raise ReportProjectionError("report bundle is missing its SHA256SUMS manifest")
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, _, name = line.partition("  ")
        target = output_dir / name
        if not target.is_file():
            raise ReportProjectionError(f"report bundle is missing {name}")
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ReportProjectionError(f"report bundle checksum mismatch for {name}")
    return True
