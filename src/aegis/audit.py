"""Stable, UI-safe audit projections shared by the API and demo evidence package.

The persisted SQLite ``details`` column remains available to the engineering view.  This module
adds a small read-only projection for downstream consumers: stable event/evidence identifiers,
explicit actor types, relationship links, and evidence references that omit response content.
"""

from typing import Any

ACTOR_AI_MODEL = "AI_MODEL"
ACTOR_CONTROLLER = "CONTROLLER"
ACTOR_VERIFIER = "VERIFIER"
ACTOR_SAFETY = "SAFETY"

_ACTOR_BY_EVENT: dict[str, str] = {
    "SCAN_CREATED": ACTOR_CONTROLLER,
    "SCAN_STARTED": ACTOR_CONTROLLER,
    "TOOL_REQUEST": ACTOR_CONTROLLER,
    "SAFETY_APPROVED": ACTOR_SAFETY,
    "SAFETY_REJECTED": ACTOR_SAFETY,
    "OPENAPI_OBSERVATION": ACTOR_CONTROLLER,
    "PREFLIGHT": ACTOR_CONTROLLER,
    "CANDIDATE_GENERATION_REQUEST": ACTOR_CONTROLLER,
    "CANDIDATE_GENERATED": ACTOR_AI_MODEL,
    "BLOCKER_VALIDATION": ACTOR_CONTROLLER,
    "CANDIDATE_VALIDATION": ACTOR_CONTROLLER,
    "EXECUTION_QUEUE": ACTOR_CONTROLLER,
    "REQUEST_STARTED": ACTOR_CONTROLLER,
    "OBSERVATION": ACTOR_CONTROLLER,
    "RETEST_PLAN": ACTOR_CONTROLLER,
    "VERIFIER_RESULT": ACTOR_VERIFIER,
    # Phase 1.1 security-tool integration kernel. Engine execution and engine-reported findings are
    # attributed to the CONTROLLER boundary here (this projection has no tool-runner actor);
    # crucially they are NEVER attributed to the AI model. Verification stays with the verifier.
    "ENGINE_JOB_CREATED": ACTOR_CONTROLLER,
    "ENGINE_JOB_REJECTED": ACTOR_CONTROLLER,
    "ENGINE_EXECUTION_STARTED": ACTOR_CONTROLLER,
    "ENGINE_EXECUTION_COMPLETED": ACTOR_CONTROLLER,
    "ENGINE_EXECUTION_FAILED": ACTOR_CONTROLLER,
    "ENGINE_FINDING_REPORTED": ACTOR_CONTROLLER,
    "ENGINE_FINDING_CORRELATED": ACTOR_CONTROLLER,
    "ENGINE_FINDING_REJECTED": ACTOR_CONTROLLER,
    "VERIFICATION_STARTED": ACTOR_VERIFIER,
    "VERIFICATION_COMPLETED": ACTOR_VERIFIER,
    "HUMAN_REVIEW_REQUIRED": ACTOR_CONTROLLER,
    # Phase 1.2 Nuclei integration. Runner execution and tool-reported results are attributed to
    # the controller boundary (never the AI); verification belongs to the verifier.
    "NUCLEI_JOB_ADMITTED": ACTOR_CONTROLLER,
    "NUCLEI_JOB_REJECTED": ACTOR_CONTROLLER,
    "NUCLEI_RUNNER_STARTED": ACTOR_CONTROLLER,
    "NUCLEI_TEMPLATE_MANIFEST_VERIFIED": ACTOR_CONTROLLER,
    "NUCLEI_EXECUTION_STARTED": ACTOR_CONTROLLER,
    "NUCLEI_EXECUTION_COMPLETED": ACTOR_CONTROLLER,
    "NUCLEI_EXECUTION_FAILED": ACTOR_CONTROLLER,
    "NUCLEI_RESULT_PARSED": ACTOR_CONTROLLER,
    "NUCLEI_FINDING_REPORTED": ACTOR_CONTROLLER,
    "NUCLEI_FINDING_CORRELATED": ACTOR_CONTROLLER,
    "NUCLEI_VERIFICATION_STARTED": ACTOR_VERIFIER,
    "NUCLEI_VERIFICATION_COMPLETED": ACTOR_VERIFIER,
    "TERMINAL_REASON": ACTOR_CONTROLLER,
    "SCAN_COMPLETED": ACTOR_CONTROLLER,
    "BUDGET_EXHAUSTED": ACTOR_CONTROLLER,
    "PLANNER_REJECTED": ACTOR_CONTROLLER,
    "SCAN_FAILED": ACTOR_CONTROLLER,
    "SCAN_CANCELLED": ACTOR_CONTROLLER,
    "SHUTDOWN_DRAIN_TIMEOUT": ACTOR_CONTROLLER,
    "PROCESS_RESTART": ACTOR_CONTROLLER,
}


def actor_for_event(event: str) -> str:
    """Return the responsible actor; unknown events default to the controller, never the AI."""

    return _ACTOR_BY_EVENT.get(event, ACTOR_CONTROLLER)


def stable_event_id(scan_id: str, audit_id: object) -> str:
    """Build the stable public identifier for a persisted audit event."""

    return f"{scan_id}:{audit_id}"


def redacted_evidence_ref(item: dict[str, Any], scan_id: str | None = None) -> dict[str, Any]:
    """Return metadata sufficient for a safe evidence card, never response content or prose.

    ``credential_profile`` is a synthetic profile label, not a credential value.  Errors are
    represented as a boolean so exception text cannot become an accidental data channel.
    """

    name = item.get("name")
    return {
        "evidence_id": f"{scan_id}:{name}" if scan_id and name is not None else name,
        "name": name,
        "method": item.get("method"),
        "path": item.get("path"),
        "credential_profile": item.get("credential_profile"),
        "status_code": item.get("status_code"),
        "has_error": item.get("error") is not None,
    }
