"""Normalized finding lifecycle + evidence provenance (Phase 1.1).

This module owns the promotion rules. The single invariant it enforces is that an engine result can
NEVER become a confirmed Aegis finding on its own:

    TOOL_REPORTED -> AEGIS_CORRELATED -> VERIFIED (deterministic verifier only)
                                      \\-> REVIEW_REQUIRED (needs a human)
                                      \\-> REJECTED

``severity``/``confidence`` are written only by :func:`record_verifier_conclusion`, only when the
deterministic verifier confirmed, and only for a capability whose verification policy is the
deterministic Aegis verifier.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.engine.adapters import PARSER_VERSION
from aegis.engine.catalog import get_engine_capability
from aegis.engine.contracts import (
    EngineExecution,
    EngineJob,
    EngineReportedFinding,
    EvidenceSourceClass,
    FindingLifecycleState,
    HumanReview,
    NormalizedEvidence,
    NormalizedFinding,
    RetentionClass,
    VerificationPolicy,
    VerifierConclusion,
)

# A conservative bound. A well-formed native execution yields at most the job's request budget of
# observations; anything larger is treated as malformed engine output and fails closed.
MAX_OBSERVATIONS = 64


class MalformedEngineOutput(ValueError):
    """Raised when engine output is malformed or oversized. The controller fails the execution
    closed and promotes nothing."""


def assert_execution_bounded(execution: EngineExecution) -> None:
    """Fail closed on oversized/malformed engine output before anything is normalized."""

    if len(execution.observations) > MAX_OBSERVATIONS:
        raise MalformedEngineOutput("OVERSIZED_ENGINE_OUTPUT")
    if len(execution.reported_findings) > MAX_OBSERVATIONS:
        raise MalformedEngineOutput("OVERSIZED_ENGINE_OUTPUT")
    seen: set[str] = set()
    for observation in execution.observations:
        # Digest shape is already enforced by the model; guard against duplicate request names,
        # which would make evidence ids collide.
        if observation.request_name in seen:
            raise MalformedEngineOutput("MALFORMED_ENGINE_OUTPUT")
        seen.add(observation.request_name)


def normalize_observation_evidence(
    execution: EngineExecution,
    job: EngineJob,
    scan_id: str,
) -> list[NormalizedEvidence]:
    """Build a provenance-complete :class:`NormalizedEvidence` item per engine observation.

    No response body, header value, credential or exception prose is present; only the redacted
    content digest and structured references."""

    assert_execution_bounded(execution)
    capability = get_engine_capability(job.capability_id)
    retention = RetentionClass.STANDARD if capability else RetentionClass.EPHEMERAL
    items: list[NormalizedEvidence] = []
    for observation in execution.observations:
        items.append(
            NormalizedEvidence(
                evidence_id=f"{scan_id}:{observation.request_name}",
                engine=execution.engine,
                adapter_version=execution.adapter_version,
                engine_execution_id=execution.execution_id,
                run_id=job.run_id,
                scan_id=scan_id,
                timestamp=execution.completed_at or execution.started_at,
                capability_id=job.capability_id,
                target_ref=f"{job.target.operation_id}",
                request_refs=[observation.request_name],
                artifact_refs=[f"{scan_id}:{observation.request_name}"],
                redaction_status="REDACTED",
                content_digest=observation.content_digest,
                parser_version=PARSER_VERSION,
                source_class=EvidenceSourceClass.ENGINE_OBSERVATION,
                retention_class=retention,
            )
        )
    return items


def correlate_reported_finding(
    reported: EngineReportedFinding,
    job: EngineJob,
    *,
    ai_hypothesis: str,
    in_scope: bool,
) -> NormalizedFinding:
    """Create the normalized record for one engine-reported finding.

    It always starts life at ``TOOL_REPORTED``. If the reported target is inside the authorized
    job's scope it advances deterministically to ``AEGIS_CORRELATED``; otherwise it is ``REJECTED``.
    Correlation NEVER sets severity, confidence or an Aegis finding id."""

    normalized_id = f"{job.run_id}:{reported.report_key}"
    base = NormalizedFinding(
        normalized_id=normalized_id,
        engine=job.engine,
        adapter_version=job.adapter_version,
        capability_id=job.capability_id,
        run_id=job.run_id,
        lifecycle_state=FindingLifecycleState.TOOL_REPORTED,
        ai_hypothesis=ai_hypothesis[:300],
        controller_authorization=(
            f"job {job.job_id} · {job.capability_id} · {job.target.operation_id}"
        ),
        engine_reported=f"{reported.claimed_category}: {reported.signal}"[:300],
        engine_report_key=reported.report_key,
        evidence_ids=[f"{job.run_id}:{name}" for name in reported.observation_names],
    )
    if in_scope:
        return base.model_copy(
            update={"lifecycle_state": FindingLifecycleState.AEGIS_CORRELATED}
        )
    return base.model_copy(update={"lifecycle_state": FindingLifecycleState.REJECTED})


def dedupe_reported(
    reported: list[EngineReportedFinding],
) -> list[EngineReportedFinding]:
    """Deterministically collapse duplicate engine reports by their stable ``report_key``."""

    seen: dict[str, EngineReportedFinding] = {}
    for item in reported:
        seen.setdefault(item.report_key, item)
    return [seen[key] for key in sorted(seen)]


def record_verifier_conclusion(
    normalized: NormalizedFinding,
    conclusion: VerifierConclusion,
) -> NormalizedFinding:
    """Apply the deterministic verifier's conclusion, respecting the capability's policy.

    Only a ``CONFIRMED`` conclusion under the ``DETERMINISTIC_AEGIS_VERIFIER`` policy may reach
    ``VERIFIED`` and set severity/confidence. Under ``HUMAN_REVIEW_REQUIRED`` a confirmed-looking
    signal can only reach ``REVIEW_REQUIRED``. Anything else is ``REJECTED``."""

    capability = get_engine_capability(normalized.capability_id)
    policy = (
        capability.verification_policy
        if capability
        else VerificationPolicy.HUMAN_REVIEW_REQUIRED
    )

    update: dict[str, object] = {"verifier_conclusion": conclusion}
    if conclusion.status == "CONFIRMED":
        if policy is VerificationPolicy.DETERMINISTIC_AEGIS_VERIFIER:
            update.update(
                lifecycle_state=FindingLifecycleState.VERIFIED,
                aegis_finding_id=conclusion.aegis_finding_id,
                severity="HIGH",
                confidence="CONFIRMED",
                evidence_ids=conclusion.evidence_ids or normalized.evidence_ids,
            )
        else:
            update.update(lifecycle_state=FindingLifecycleState.REVIEW_REQUIRED)
    else:
        # A PASS or INSUFFICIENT verifier result never confirms a reported finding.
        update.update(lifecycle_state=FindingLifecycleState.REJECTED)
    return normalized.model_copy(update=update)


def record_human_review(
    normalized: NormalizedFinding,
    review: HumanReview,
) -> NormalizedFinding:
    """Apply a human-review decision to a ``REVIEW_REQUIRED`` finding.

    A human may accept (promote to ``VERIFIED`` with an explicit review record) or reject. A human
    cannot fabricate a deterministic verifier conclusion; severity/confidence are marked as
    review-derived (``PROBABLE``), never as a deterministic ``CONFIRMED``."""

    if normalized.lifecycle_state is not FindingLifecycleState.REVIEW_REQUIRED:
        return normalized.model_copy(update={"human_review": review})
    if review.decision == "ACCEPTED":
        return normalized.model_copy(
            update={
                "human_review": review,
                "lifecycle_state": FindingLifecycleState.VERIFIED,
                "confidence": "PROBABLE",
            }
        )
    if review.decision == "REJECTED":
        return normalized.model_copy(
            update={"human_review": review, "lifecycle_state": FindingLifecycleState.REJECTED}
        )
    return normalized.model_copy(update={"human_review": review})


def now() -> datetime:
    return datetime.now(UTC)
