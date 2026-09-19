"""Read-only Operator Console projections.

This module deliberately sits outside the planner/executor/verifier path.  It translates persisted
Phase 0.9 records into a smaller, typed and redacted Phase 1.0 presentation contract; it never
changes scan state and never replays target requests.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from aegis.engine.catalog import CAPABILITY_CATALOG, PROFILE_CATALOG, EngineProfile
from aegis.engine.contracts import ENGINE_KERNEL_VERSION, EngineHealth, SecurityEngine
from aegis.models import EXECUTION_POLICY_VERSION, PLANNER_CONTRACT_VERSION, ScanResult


class ActorType(StrEnum):
    OPERATOR = "OPERATOR"
    AI_PLANNER = "AI_PLANNER"
    CONTROLLER = "CONTROLLER"
    TOOL_RUNNER = "TOOL_RUNNER"
    VERIFIER = "VERIFIER"
    SYSTEM = "SYSTEM"


# The console's engine identifier is the canonical Phase 1.1 SecurityEngine enum. Re-exported here
# under the historical name so existing imports (`from aegis.operator import Engine`) and the audit
# envelope stay stable while there is a single source of truth for the four supported engines.
Engine = SecurityEngine


class RedactionStatus(StrEnum):
    REDACTED = "REDACTED"
    NOT_REQUIRED = "NOT_REQUIRED"


class AuditEnvelope(BaseModel):
    event_id: str
    sequence: int = Field(ge=1)
    timestamp: datetime
    run_id: str
    scan_id: str
    finding_id: str | None = None
    retest_scan_id: str | None = None
    parent_event_id: str | None = None
    child_event_ids: list[str] = Field(default_factory=list)
    actor_type: ActorType
    event_type: str
    stage: str
    status: str
    engine: Engine = Engine.AEGIS_NATIVE
    summary: str
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    redaction_status: RedactionStatus = RedactionStatus.REDACTED
    metadata: dict[str, Any] = Field(default_factory=dict)
    integrity: dict[str, str] = Field(default_factory=dict)


_ACTORS: dict[str, ActorType] = {
    "SCAN_CREATED": ActorType.OPERATOR,
    "SCAN_STARTED": ActorType.SYSTEM,
    "CANDIDATE_GENERATED": ActorType.AI_PLANNER,
    "REQUEST_STARTED": ActorType.TOOL_RUNNER,
    "OBSERVATION": ActorType.TOOL_RUNNER,
    "VERIFIER_RESULT": ActorType.VERIFIER,
    "PROCESS_RESTART": ActorType.SYSTEM,
    "SCAN_FAILED": ActorType.SYSTEM,
    "SCAN_CANCELLED": ActorType.SYSTEM,
    # Phase 1.1 engine kernel. The engine execution runs under the tool-runner boundary; job
    # construction/correlation is the controller; verification is the verifier. None is the AI.
    "ENGINE_JOB_CREATED": ActorType.CONTROLLER,
    "ENGINE_JOB_REJECTED": ActorType.CONTROLLER,
    "ENGINE_EXECUTION_STARTED": ActorType.TOOL_RUNNER,
    "ENGINE_EXECUTION_COMPLETED": ActorType.TOOL_RUNNER,
    "ENGINE_EXECUTION_FAILED": ActorType.TOOL_RUNNER,
    "ENGINE_FINDING_REPORTED": ActorType.TOOL_RUNNER,
    "ENGINE_FINDING_CORRELATED": ActorType.CONTROLLER,
    "ENGINE_FINDING_REJECTED": ActorType.CONTROLLER,
    "VERIFICATION_STARTED": ActorType.VERIFIER,
    "VERIFICATION_COMPLETED": ActorType.VERIFIER,
    "HUMAN_REVIEW_REQUIRED": ActorType.CONTROLLER,
    # Phase 1.2 Nuclei. The controller admits/rejects and correlates; the isolated runner attests,
    # executes and reports (untrusted); only the verifier verifies. None is the AI.
    "NUCLEI_JOB_ADMITTED": ActorType.CONTROLLER,
    "NUCLEI_JOB_REJECTED": ActorType.CONTROLLER,
    "NUCLEI_RUNNER_STARTED": ActorType.TOOL_RUNNER,
    "NUCLEI_TEMPLATE_MANIFEST_VERIFIED": ActorType.TOOL_RUNNER,
    "NUCLEI_EXECUTION_STARTED": ActorType.TOOL_RUNNER,
    "NUCLEI_EXECUTION_COMPLETED": ActorType.TOOL_RUNNER,
    "NUCLEI_EXECUTION_FAILED": ActorType.TOOL_RUNNER,
    "NUCLEI_RESULT_PARSED": ActorType.CONTROLLER,
    "NUCLEI_FINDING_REPORTED": ActorType.TOOL_RUNNER,
    "NUCLEI_FINDING_CORRELATED": ActorType.CONTROLLER,
    "NUCLEI_VERIFICATION_STARTED": ActorType.VERIFIER,
    "NUCLEI_VERIFICATION_COMPLETED": ActorType.VERIFIER,
    # Phase 1.3 ZAP. The controller projects, authorizes and correlates; runner boot/attestation is
    # lifecycle infrastructure (SYSTEM); ZAP's execution and its untrusted alerts belong to the tool
    # runner; only the verifier reaches a security conclusion. None is the AI.
    "ZAP_JOB_ADMITTED": ActorType.CONTROLLER,
    "ZAP_JOB_REJECTED": ActorType.CONTROLLER,
    "ZAP_PROJECTION_CREATED": ActorType.CONTROLLER,
    "ZAP_PROJECTION_REJECTED": ActorType.CONTROLLER,
    "ZAP_RUNNER_STARTED": ActorType.SYSTEM,
    "ZAP_PLAN_VALIDATED": ActorType.TOOL_RUNNER,
    "ZAP_OPENAPI_IMPORT_STARTED": ActorType.TOOL_RUNNER,
    "ZAP_OPENAPI_IMPORT_COMPLETED": ActorType.TOOL_RUNNER,
    "ZAP_PASSIVE_SCAN_WAIT_STARTED": ActorType.TOOL_RUNNER,
    "ZAP_PASSIVE_SCAN_DRAINED": ActorType.TOOL_RUNNER,
    "ZAP_EXECUTION_COMPLETED": ActorType.TOOL_RUNNER,
    "ZAP_EXECUTION_FAILED": ActorType.TOOL_RUNNER,
    "ZAP_ALERT_REPORTED": ActorType.TOOL_RUNNER,
    "ZAP_ALERT_CORRELATED": ActorType.CONTROLLER,
    "ZAP_VERIFICATION_STARTED": ActorType.VERIFIER,
    "ZAP_VERIFICATION_COMPLETED": ActorType.VERIFIER,
}

_STAGES: dict[str, str] = {
    "SCAN_CREATED": "PREFLIGHT",
    "SCAN_STARTED": "PREFLIGHT",
    "PREFLIGHT": "PREFLIGHT",
    "CANDIDATE_GENERATION_REQUEST": "AI_HYPOTHESIS",
    "CANDIDATE_GENERATED": "AI_HYPOTHESIS",
    "BLOCKER_VALIDATION": "CANDIDATE_VALIDATION",
    "CANDIDATE_VALIDATION": "CANDIDATE_VALIDATION",
    "EXECUTION_QUEUE": "QUEUE_ADMISSION",
    "ENGINE_JOB_CREATED": "ENGINE_JOB",
    "ENGINE_JOB_REJECTED": "EXECUTION_POLICY",
    "TOOL_REQUEST": "REQUEST_COMPILATION",
    "SAFETY_APPROVED": "SAFETY_AUTHORIZATION",
    "SAFETY_REJECTED": "SAFETY_AUTHORIZATION",
    "ENGINE_EXECUTION_STARTED": "EXECUTION",
    "ENGINE_EXECUTION_COMPLETED": "EXECUTION",
    "ENGINE_EXECUTION_FAILED": "FAILED",
    "REQUEST_STARTED": "EXECUTION",
    "OBSERVATION": "EXECUTION",
    "ENGINE_FINDING_REPORTED": "TOOL_FINDING",
    "ENGINE_FINDING_CORRELATED": "CORRELATION",
    "ENGINE_FINDING_REJECTED": "CORRELATION",
    "VERIFICATION_STARTED": "VERIFICATION",
    "VERIFICATION_COMPLETED": "VERIFICATION",
    "VERIFIER_RESULT": "VERIFICATION",
    "HUMAN_REVIEW_REQUIRED": "REVIEW",
    "RETEST_PLAN": "LINKED_RETEST",
    "TERMINAL_REASON": "COMPLETE",
    "SCAN_COMPLETED": "COMPLETE",
    "SCAN_FAILED": "FAILED",
    "SCAN_CANCELLED": "FAILED",
    "BUDGET_EXHAUSTED": "REVIEW",
    "PLANNER_REJECTED": "REVIEW",
    "NUCLEI_JOB_ADMITTED": "ENGINE_JOB",
    "NUCLEI_JOB_REJECTED": "EXECUTION_POLICY",
    "NUCLEI_RUNNER_STARTED": "RUNNER_ATTESTATION",
    "NUCLEI_TEMPLATE_MANIFEST_VERIFIED": "RUNNER_ATTESTATION",
    "NUCLEI_EXECUTION_STARTED": "EXECUTION",
    "NUCLEI_EXECUTION_COMPLETED": "EXECUTION",
    "NUCLEI_EXECUTION_FAILED": "FAILED",
    "NUCLEI_RESULT_PARSED": "RESULT_PARSING",
    "NUCLEI_FINDING_REPORTED": "TOOL_FINDING",
    "NUCLEI_FINDING_CORRELATED": "CORRELATION",
    "NUCLEI_VERIFICATION_STARTED": "VERIFICATION",
    "NUCLEI_VERIFICATION_COMPLETED": "VERIFICATION",
    "ZAP_JOB_ADMITTED": "ENGINE_JOB",
    "ZAP_JOB_REJECTED": "EXECUTION_POLICY",
    "ZAP_PROJECTION_CREATED": "OPENAPI_PROJECTION",
    "ZAP_PROJECTION_REJECTED": "OPENAPI_PROJECTION",
    "ZAP_RUNNER_STARTED": "RUNNER_ATTESTATION",
    "ZAP_PLAN_VALIDATED": "PLAN_VALIDATION",
    "ZAP_OPENAPI_IMPORT_STARTED": "OPENAPI_IMPORT",
    "ZAP_OPENAPI_IMPORT_COMPLETED": "OPENAPI_IMPORT",
    "ZAP_PASSIVE_SCAN_WAIT_STARTED": "PASSIVE_SCAN",
    "ZAP_PASSIVE_SCAN_DRAINED": "PASSIVE_SCAN",
    "ZAP_EXECUTION_COMPLETED": "EXECUTION",
    "ZAP_EXECUTION_FAILED": "FAILED",
    "ZAP_ALERT_REPORTED": "TOOL_FINDING",
    "ZAP_ALERT_CORRELATED": "CORRELATION",
    "ZAP_VERIFICATION_STARTED": "VERIFICATION",
    "ZAP_VERIFICATION_COMPLETED": "VERIFICATION",
}

_SUMMARIES: dict[str, str] = {
    "SCAN_CREATED": "Operator initiated a bounded synthetic scan.",
    "SCAN_STARTED": "Controller started the scan.",
    "PREFLIGHT": "Controller evaluated scope, credentials, capability, and budgets.",
    "CANDIDATE_GENERATION_REQUEST": "Controller requested bounded hypothesis generation.",
    "CANDIDATE_GENERATED": "Local AI proposed a bounded object-authorization direction.",
    "BLOCKER_VALIDATION": "Controller validated structured blocker claims.",
    "CANDIDATE_VALIDATION": "Controller validated candidate scope and semantics.",
    "EXECUTION_QUEUE": "Controller deterministically admitted the candidate to the queue.",
    "ENGINE_JOB_CREATED": "Controller constructed a typed engine job for an approved capability.",
    "ENGINE_JOB_REJECTED": "Execution policy rejected an engine job before any tool traffic.",
    "TOOL_REQUEST": "Controller compiled a typed read-only evidence protocol.",
    "SAFETY_APPROVED": "Safety policy authorized scoped read-only requests.",
    "SAFETY_REJECTED": "Safety policy rejected a request before target traffic.",
    "ENGINE_EXECUTION_STARTED": "Engine adapter began executing the authorized job.",
    "ENGINE_EXECUTION_COMPLETED": "Engine adapter completed the authorized job.",
    "ENGINE_EXECUTION_FAILED": "Engine adapter failed closed with a structured error.",
    "REQUEST_STARTED": "Tool runner sent an authorized read-only request.",
    "OBSERVATION": "Tool runner recorded a redacted response observation.",
    "ENGINE_FINDING_REPORTED": "Engine reported an untrusted observation (not a verified finding).",
    "ENGINE_FINDING_CORRELATED": "Controller correlated the engine observation to scope.",
    "ENGINE_FINDING_REJECTED": "Controller rejected an engine observation; no finding was created.",
    "VERIFICATION_STARTED": "Deterministic verifier began evaluating fresh evidence.",
    "VERIFICATION_COMPLETED": "Deterministic verifier completed its authoritative evaluation.",
    "HUMAN_REVIEW_REQUIRED": "A reported observation requires explicit human review to promote.",
    "RETEST_PLAN": "Controller constructed a linked retest from the confirmed direction.",
    "VERIFIER_RESULT": "Deterministic verifier evaluated fresh evidence.",
    "TERMINAL_REASON": "Controller recorded the terminal decision.",
    "SCAN_COMPLETED": "Scan completed.",
    "SCAN_FAILED": "Scan failed closed.",
    "SCAN_CANCELLED": "Scan was cancelled.",
    "BUDGET_EXHAUSTED": "A bounded budget was exhausted.",
    "PLANNER_REJECTED": "Planner output was rejected by deterministic validation.",
    "PROCESS_RESTART": "Interrupted work was closed conservatively after restart.",
    "NUCLEI_JOB_ADMITTED": "Controller admitted a typed Nuclei job for an approved capability.",
    "NUCLEI_JOB_REJECTED": "Execution policy rejected the Nuclei job before any runner call.",
    "NUCLEI_RUNNER_STARTED": "Isolated nuclei-runner attested its pinned engine and readiness.",
    "NUCLEI_TEMPLATE_MANIFEST_VERIFIED": "Runner attested the pinned, signed template manifest.",
    "NUCLEI_EXECUTION_STARTED": "Isolated runner began the fixed-profile Nuclei execution.",
    "NUCLEI_EXECUTION_COMPLETED": "Isolated runner completed the bounded Nuclei execution.",
    "NUCLEI_EXECUTION_FAILED": "Nuclei execution failed closed; no PASS or finding is possible.",
    "NUCLEI_RESULT_PARSED": "Controller accepted the strict, redacted Nuclei result parse.",
    "NUCLEI_FINDING_REPORTED": "Nuclei reported an untrusted result (TOOL_REPORTED only).",
    "NUCLEI_FINDING_CORRELATED": "Controller correlated the tool result to target and capability.",
    "NUCLEI_VERIFICATION_STARTED": "Independent verifier issued fresh read-only requests.",
    "NUCLEI_VERIFICATION_COMPLETED": "Independent verifier reached its authoritative conclusion.",
    "ZAP_JOB_ADMITTED": "Controller admitted a typed ZAP passive job for an approved capability.",
    "ZAP_JOB_REJECTED": "Execution policy rejected the ZAP job before any runner call.",
    "ZAP_PROJECTION_CREATED": "Controller projected a read-only OpenAPI surface from inventory.",
    "ZAP_PROJECTION_REJECTED": "Controller refused the OpenAPI source; no runner call or traffic.",
    "ZAP_RUNNER_STARTED": "Isolated zap-runner attested its pinned engine, add-ons and guard.",
    "ZAP_PLAN_VALIDATED": "Runner validated the fixed controller-owned Automation Framework plan.",
    "ZAP_OPENAPI_IMPORT_STARTED": "ZAP began importing the local projected OpenAPI file.",
    "ZAP_OPENAPI_IMPORT_COMPLETED": "ZAP imported the approved read-only operations.",
    "ZAP_PASSIVE_SCAN_WAIT_STARTED": "ZAP began waiting for the passive scan queue.",
    "ZAP_PASSIVE_SCAN_DRAINED": "ZAP passive scan queue fully drained.",
    "ZAP_EXECUTION_COMPLETED": "Isolated runner completed the bounded passive ZAP execution.",
    "ZAP_EXECUTION_FAILED": "ZAP execution failed closed; no PASS or finding is possible.",
    "ZAP_ALERT_REPORTED": "ZAP reported an untrusted passive alert (TOOL_REPORTED only).",
    "ZAP_ALERT_CORRELATED": "Controller correlated the alert to the approved operation.",
    "ZAP_VERIFICATION_STARTED": "Independent verifier issued fresh read-only requests.",
    "ZAP_VERIFICATION_COMPLETED": "Independent verifier reached its authoritative conclusion.",
}

_DENIED_KEYS = re.compile(
    r"authorization|cookie|token|secret|password|response_excerpt|response_body|raw|reasoning|"
    r"chain.of.thought|exception|traceback|stack",
    re.IGNORECASE,
)
_SAFE_KEYS = {
    "planner",
    "variant",
    "scenario",
    "retest_of",
    "planner_contract_version",
    "execution_policy_version",
    "stage",
    "constructible",
    "blocker",
    "reason",
    "status",
    "tool",
    "path",
    "method",
    "name",
    "credential_profile",
    "status_code",
    "candidate_id",
    "candidates",
    "validated",
    "rejections",
    "queue",
    "capability",
    "operation_id",
    "owner_principal_ref",
    "alternate_principal_ref",
    "principal_relationship",
    "object_relationship",
    "object_ref",
    "order_index",
    "admitted",
    "finding_id",
    "verification_status",
    "limits",
    "remaining",
    "requests",
    "iterations",
    "model_calls",
    "seconds",
    "token_reservations",
    # Phase 1.1 engine kernel metadata (all non-sensitive: ids, codes, counts, labels).
    "engine",
    "profile_id",
    "job_id",
    "execution_id",
    "adapter_version",
    "request_count",
    "observation_count",
    "reported_finding_count",
    "reported_findings",
    "claimed_category",
    "report_key",
    "normalized_id",
    "lifecycle_state",
    "provenance",
    "confirmed_findings",
    "code",
    "detail",
    "environment",
    "activity",
    # Phase 1.2 Nuclei metadata (ids, digests, versions, counts, codes and labels only).
    "target_ref",
    "template_set_id",
    "manifest_version",
    "manifest_digest",
    "controller_manifest_match",
    "template_ids",
    "template_id",
    "templates",
    "sha256",
    "signature_status",
    "signature_probe",
    "unexpected_template_files",
    "budgets",
    "time_ms",
    "results",
    "output_bytes",
    "reachable",
    "ready",
    "runner_version",
    "nuclei_version",
    "binary_sha256",
    "arch",
    "pinned",
    "failure_codes",
    "exit_class",
    "exit_code",
    "error_code",
    "duration_ms",
    "http_connections",
    "signed_templates_executed",
    "output_sha256",
    "coverage_complete",
    "parser_version",
    "parse_status",
    "lines",
    "records",
    "matched",
    "unmatched",
    "errored",
    "duplicates_collapsed",
    "stripped_fields",
    "redaction_status",
    "correlation",
    "verifier_version",
    "evidence_ids",
    "lifecycle_states",
    "tool_reported",
    "independent",
    "nuclei_inputs_used",
    "runner_contacted",
    "runner_contacted_for_execution",
    "target_requests",
    # Phase 1.3 ZAP metadata (ids, digests, versions, counts, codes and labels only).
    "projection_ref",
    "projection_version",
    "projection_digest",
    "projection_code",
    "allowlist_digest",
    "source_sha256",
    "operation_count",
    "path_count",
    "removed_operations",
    "methods",
    "origin_source",
    "add_on_inventory_digest",
    "addonlist_verified",
    "rule_ids",
    "zap_version",
    "jar_sha256",
    "java_version",
    "guard_version",
    "guard_reachable",
    "plan_digest",
    "job_types",
    "source",
    "api_source",
    "urls_added",
    "expected_requests",
    "observed_requests",
    "import_test_passed",
    "rules_set",
    "drained",
    "max_duration",
    "forwarded",
    "blocked",
    "blocked_reasons",
    "redirects",
    "alerts",
    "report_sha256",
    "session_destroyed",
    "plugin_id",
    "rule_name",
    "claimed_risk",
    "claimed_confidence",
    "claim_trust",
    "zap_inputs_used",
}


def _safe_value(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(key): _safe_value(item, depth + 1)
            for key, item in value.items()
            if str(key) in _SAFE_KEYS and not _DENIED_KEYS.search(str(key))
        }
    if isinstance(value, list):
        return [_safe_value(item, depth + 1) for item in value[:12]]
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, str):
        return value[:160]
    return "[REDACTED]"


def safe_metadata(details: Any) -> dict[str, Any]:
    """Return a strict allowlist projection of persisted details."""

    if not isinstance(details, dict):
        return {}
    projected = _safe_value(details)
    return projected if isinstance(projected, dict) else {}


def _event_status(event: str, details: dict[str, Any]) -> str:
    if event in {"SAFETY_REJECTED", "SCAN_FAILED", "SCAN_CANCELLED"}:
        return "REJECTED" if event == "SAFETY_REJECTED" else "FAILED"
    if event in {"NUCLEI_JOB_REJECTED", "ZAP_JOB_REJECTED", "ZAP_PROJECTION_REJECTED"}:
        return "REJECTED"
    if event in {"NUCLEI_EXECUTION_FAILED", "ZAP_EXECUTION_FAILED"}:
        return "FAILED"
    if event in {"BUDGET_EXHAUSTED", "PLANNER_REJECTED"}:
        return "REVIEW"
    raw = details.get("status")
    if isinstance(raw, str) and raw in {
        "QUEUED",
        "RUNNING",
        "PASS",
        "FAIL",
        "REVIEW",
        "INCOMPLETE",
        "CONFIRMED",
        "INSUFFICIENT",
    }:
        return raw
    return "RECORDED"


def project_event(
    row: dict[str, Any],
    scan: ScanResult | None,
    *,
    parent_event_id: str | None,
) -> AuditEnvelope:
    event = str(row["event"])
    scan_id = str(row["scan_id"])
    sequence = int(row["id"])
    metadata = safe_metadata(row.get("details"))
    evidence_refs: list[dict[str, Any]] = []
    evidence_ref = row.get("evidence_ref")
    if isinstance(evidence_ref, dict):
        evidence_refs.append({k: v for k, v in evidence_ref.items() if k != "has_error"})
    finding_id = scan.findings[0].id if scan and scan.findings else None
    linked_retest = row.get("linked_retest_scan_id")
    payload = {
        "sequence": sequence,
        "scan_id": scan_id,
        "event": event,
        "metadata": metadata,
        "evidence_refs": evidence_refs,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    timestamp = datetime.fromisoformat(str(row["created_at"]).replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return AuditEnvelope(
        event_id=f"evt-{sequence:012d}",
        sequence=sequence,
        timestamp=timestamp,
        run_id=scan_id,
        scan_id=scan_id,
        finding_id=finding_id,
        retest_scan_id=str(linked_retest) if linked_retest else None,
        parent_event_id=parent_event_id,
        child_event_ids=(
            [f"evt-{int(row['child_id']):012d}"] if row.get("child_id") is not None else []
        ),
        actor_type=_ACTORS.get(event, ActorType.CONTROLLER),
        event_type=event,
        engine=(
            Engine.NUCLEI
            if event.startswith("NUCLEI_") or (scan is not None and scan.engine == "NUCLEI")
            else Engine.ZAP
            if event.startswith("ZAP_") or (scan is not None and scan.engine == "ZAP")
            else Engine.AEGIS_NATIVE
        ),
        stage=_STAGES.get(event, "REVIEW"),
        status=_event_status(event, metadata),
        summary=_SUMMARIES.get(event, "Controller recorded a structured audit event."),
        evidence_refs=evidence_refs,
        metadata=metadata,
        integrity={"algorithm": "SHA-256", "digest": digest},
    )


def scan_projection(
    scan: ScanResult,
    linked_retests: list[str],
    *,
    target_request_budget: int = 8,
    model_call_budget: int = 6,
    token_budget: int = 80000,
) -> dict[str, Any]:
    """Build a console-safe scan record without target URLs, errors, or response content."""

    model_digest = scan.provider_metadata.model_digest if scan.provider_metadata else None
    nuclei = scan.engine == Engine.NUCLEI.value
    zap = scan.engine == Engine.ZAP.value
    return {
        "id": scan.id,
        "status": scan.status.value,
        "target_name": scan.target_name,
        "scope": (
            "Synthetic lab / SCM metadata route (read-only)"
            if nuclei
            else "Synthetic lab / projected read-only OpenAPI (passive)"
            if zap
            else "Synthetic Bank API / approved account routes"
        ),
        "planner": scan.planner,
        "mode": scan.mode,
        "model": scan.model,
        "model_digest": model_digest,
        "variant": scan.variant,
        "scenario": scan.scenario.value,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "planner_contract_version": scan.planner_contract_version,
        "execution_policy_version": scan.execution_policy_version or EXECUTION_POLICY_VERSION,
        "usage": scan.usage.model_dump(mode="json"),
        "budgets": {
            "target_requests": target_request_budget,
            "model_calls": model_call_budget,
            "token_reservations": token_budget,
        },
        "candidate_counts": {
            "generated": scan.generated_candidates_total,
            "validated": scan.validated_candidates_total,
            "rejected": scan.rejected_candidates_total,
        },
        "safety_rejections": sum("REJECT" in item for item in scan.safety_events),
        "finding_count": len(scan.findings),
        "finding_ids": [finding.id for finding in scan.findings],
        "retest_of": scan.retest_of,
        "linked_retests": linked_retests,
        "verification": scan.verification.status if scan.verification else None,
        "terminal_reason": scan.terminal_reason,
        "scope_badges": ["SYNTHETIC LAB", "LOCAL LLM", "READ-ONLY", "AUTHORIZED TARGET"],
        "contract_defaults": {
            "planner": PLANNER_CONTRACT_VERSION,
            "execution_policy": EXECUTION_POLICY_VERSION,
        },
        # --- Phase 1.1 security-tool integration kernel (additive) ----------------------------
        "engine": scan.engine,
        "adapter_version": scan.adapter_version,
        "engine_kernel_version": scan.engine_kernel_version,
        "lifecycle_counts": _lifecycle_counts(scan),
        "engine_job_rejections": len(scan.engine_job_rejections),
        "tool_reported_count": len(
            [n for e in scan.engine_executions for n in e.get("reported_findings", [])]
        ),
        "verifier_confirmed_count": len(
            [n for n in scan.normalized_findings if n.get("lifecycle_state") == "VERIFIED"]
        ),
        # --- Phase 1.2 (additive) --------------------------------------------------------------
        "capability_id": scan.capability_id,
        "target_ref": scan.target_ref,
        "nuclei": nuclei_summary(scan) if nuclei else None,
        # --- Phase 1.3 (additive) --------------------------------------------------------------
        "zap": zap_summary(scan) if zap else None,
    }


def nuclei_summary(scan: ScanResult) -> dict[str, Any] | None:
    """Console-safe Nuclei provenance: versions, digests, counts and states. No URL, no output."""

    provenance = scan.nuclei_provenance
    if not provenance:
        return None
    engine = provenance.get("engine") or {}
    counts = provenance.get("counts") or {}
    exit_info = provenance.get("exit") or {}
    return {
        "profile_id": provenance.get("profile_id"),
        "profile_version": provenance.get("profile_version"),
        "adapter_version": provenance.get("adapter_version"),
        "parser_version": provenance.get("parser_version"),
        "runner_version": provenance.get("runner_version"),
        "verifier_version": provenance.get("verifier_version"),
        "engine_version": engine.get("version"),
        "binary_sha256": engine.get("binary_sha256"),
        "engine_pinned": bool(engine.get("pinned")),
        "template_set_id": provenance.get("template_set_id"),
        "manifest_version": provenance.get("manifest_version"),
        "manifest_digest": provenance.get("manifest_digest"),
        "templates": [
            {
                "template_id": t.get("template_id"),
                "sha256": t.get("sha256"),
                "signature_status": t.get("signature_status"),
            }
            for t in provenance.get("templates", [])[:8]
        ],
        "target_ref": provenance.get("target_ref"),
        "request_budget": (provenance.get("budgets") or {}).get("requests"),
        "http_connections": counts.get("http_connections"),
        "records": counts.get("records"),
        "matched": counts.get("matched"),
        "unmatched": counts.get("unmatched"),
        "errored": counts.get("errored"),
        "exit_status": exit_info.get("status"),
        "exit_class": exit_info.get("exit_class"),
        "error_code": exit_info.get("error_code") or exit_info.get("validation_code"),
        "duration_ms": (provenance.get("timing") or {}).get("duration_ms"),
        "coverage_complete": bool(provenance.get("coverage_complete")),
        "redaction_status": provenance.get("redaction_status", "REDACTED"),
    }


def zap_summary(scan: ScanResult) -> dict[str, Any] | None:
    """Console-safe ZAP provenance and coverage: versions, digests, counts and states only. No URL
    origin, HTTP body, header value, report prose or raw ZAP output."""

    provenance = scan.zap_provenance
    if not provenance:
        return None
    engine = provenance.get("engine") or {}
    projection = provenance.get("projection") or {}
    traffic = provenance.get("traffic") or {}
    stages = provenance.get("stages") or {}
    exit_info = provenance.get("exit") or {}
    output = provenance.get("output") or {}
    counts = provenance.get("counts") or {}
    plan = provenance.get("plan") or {}
    lifecycle = _lifecycle_counts(scan)
    return {
        "profile_id": provenance.get("profile_id"),
        "profile_version": provenance.get("profile_version"),
        "adapter_version": provenance.get("adapter_version"),
        "parser_version": provenance.get("parser_version"),
        "projection_version": provenance.get("projection_version"),
        "runner_version": provenance.get("runner_version"),
        "verifier_version": provenance.get("verifier_version"),
        "engine_version": engine.get("version"),
        "image_index_digest": engine.get("image_index_digest"),
        "jar_sha256": engine.get("jar_sha256"),
        "java_runtime_version": engine.get("java_runtime_version"),
        "arch": engine.get("arch"),
        "add_on_inventory_digest": engine.get("add_on_inventory_digest"),
        "engine_pinned": bool(engine.get("pinned")),
        "manifest_digest": provenance.get("manifest_digest"),
        "rules": [
            {"plugin_id": r.get("plugin_id"), "name": r.get("name")}
            for r in provenance.get("rules", [])[:8]
        ],
        "target_ref": provenance.get("target_ref"),
        "projection_digest": projection.get("digest"),
        "allowlist_digest": projection.get("allowlist_digest"),
        "operation_count": projection.get("operation_count"),
        "path_count": projection.get("path_count"),
        "operations": [
            {"method": o.get("method"), "path": o.get("path")}
            for o in projection.get("operations", [])[:8]
        ],
        "plan_digest": plan.get("digest"),
        "plan_validated": bool(plan.get("validated")),
        "imported_urls": counts.get("imported_urls"),
        "expected_requests": traffic.get("expected_requests"),
        "observed_requests": traffic.get("observed_requests"),
        "forwarded_requests": traffic.get("forwarded"),
        "blocked_requests": traffic.get("blocked"),
        "redirects": traffic.get("redirects"),
        "guard_version": traffic.get("guard_version"),
        "passive_queue_drained": bool(stages.get("pscan_drained")),
        "plan_succeeded": bool(stages.get("plan_succeeded")),
        "silent_mode": bool(stages.get("silent_mode")),
        "tool_reported_alerts": counts.get("alerts", 0),
        "correlated_alerts": lifecycle["AEGIS_CORRELATED"]
        + lifecycle["VERIFIED"]
        + lifecycle["REVIEW_REQUIRED"],
        "verifier_confirmed": lifecycle["VERIFIED"],
        "exit_status": exit_info.get("status"),
        "exit_class": exit_info.get("exit_class"),
        "error_code": exit_info.get("error_code") or exit_info.get("validation_code"),
        "duration_ms": (provenance.get("timing") or {}).get("duration_ms"),
        "report_sha256": output.get("report_sha256"),
        "stripped_fields": list(output.get("stripped_fields") or [])[:12],
        "session_destroyed": bool(output.get("session_destroyed")),
        "coverage_complete": bool(provenance.get("coverage_complete")),
        "coverage_state": "COMPLETE" if provenance.get("coverage_complete") else "INCOMPLETE",
        "redaction_status": provenance.get("redaction_status", "REDACTED"),
    }


def _lifecycle_counts(scan: ScanResult) -> dict[str, int]:
    counts = {
        "TOOL_REPORTED": 0,
        "AEGIS_CORRELATED": 0,
        "VERIFIED": 0,
        "REVIEW_REQUIRED": 0,
        "REJECTED": 0,
    }
    for normalized in scan.normalized_findings:
        state = str(normalized.get("lifecycle_state", ""))
        if state in counts:
            counts[state] += 1
    return counts


# The normalized-finding fields safe to surface to the console. All are structured, redacted labels;
# never a credential, header, response body or raw model/tool prose.
_LIFECYCLE_SAFE_FIELDS = (
    "normalized_id",
    "engine",
    "adapter_version",
    "capability_id",
    "run_id",
    "lifecycle_state",
    "ai_hypothesis",
    "controller_authorization",
    "engine_reported",
    "engine_report_key",
    "evidence_ids",
    "aegis_finding_id",
    "severity",
    "confidence",
)


def finding_lifecycle_projection(scan: ScanResult) -> list[dict[str, Any]]:
    """Console-safe view of the normalized finding lifecycle: what the AI proposed, what the
    controller authorized, what the engine reported (untrusted), and what the verifier concluded.

    It makes the tool-reported vs verifier-confirmed distinction explicit and never merges the two:
    ``lifecycle_state`` and ``provenance`` say exactly who owns the current state."""

    items: list[dict[str, Any]] = []
    for normalized in scan.normalized_findings:
        card = {field: normalized.get(field) for field in _LIFECYCLE_SAFE_FIELDS}
        state = str(normalized.get("lifecycle_state", ""))
        card["provenance"] = "VERIFIER" if state == "VERIFIED" else "ENGINE_UNTRUSTED"
        conclusion = normalized.get("verifier_conclusion")
        card["verifier_status"] = (
            conclusion.get("status") if isinstance(conclusion, dict) else None
        )
        items.append(card)
    return items


def execution_policy_projection(scan: ScanResult) -> dict[str, Any]:
    """Console-safe view of the deterministic execution-policy decisions for one scan: the engine
    jobs the controller constructed and the jobs the policy rejected (with a safe reason code)
    before any tool traffic."""

    created = [
        {
            "engine": execution.get("engine"),
            "job_id": execution.get("job_id"),
            "execution_id": execution.get("execution_id"),
            "status": execution.get("status"),
            "observation_count": len(execution.get("observations", [])),
            "reported_finding_count": len(execution.get("reported_findings", [])),
        }
        for execution in scan.engine_executions
    ]
    rejected = [
        {"engine": item.get("engine"), "code": item.get("code"), "detail": item.get("detail")}
        for item in scan.engine_job_rejections
    ]
    return {
        "engine": scan.engine,
        "adapter_version": scan.adapter_version,
        "engine_kernel_version": scan.engine_kernel_version,
        "execution_policy_version": scan.execution_policy_version or EXECUTION_POLICY_VERSION,
        "jobs_created": created,
        "jobs_rejected": rejected,
    }


def engine_readiness(
    healths: list[EngineHealth],
    extras: dict[SecurityEngine, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build honest, four-state engine readiness cards for the console.

    The four states — ``configured``, ``reachable``, ``enabled`` and ``authorized`` — are reported
    independently and never conflated. A disabled engine is shown as ``DISABLED`` and never as
    available; its ``reachable`` is null because it is not probed while disabled."""

    health_by_engine = {health.engine: health for health in healths}
    profiles_by_engine: dict[SecurityEngine, EngineProfile] = {}
    for entry in PROFILE_CATALOG:
        profiles_by_engine.setdefault(entry.engine, entry)
    cards: list[dict[str, Any]] = []
    for engine in SecurityEngine:
        health = health_by_engine.get(engine)
        profile = profiles_by_engine.get(engine)
        caps = [c.projection() for c in CAPABILITY_CATALOG if c.engine is engine]
        cards.append(
            {
                "engine": engine.value,
                "name": profile.title if profile else engine.value,
                "adapter_version": health.adapter_version if health else None,
                "configured": health.configured if health else bool(profile),
                "reachable": health.reachable if health else None,
                "enabled": health.enabled if health else False,
                "authorized": health.authorized if health else False,
                "state": health.state if health else "DISABLED",
                "detail": health.detail if health else "",
                "profile_id": profile.profile_id if profile else None,
                "environment": profile.environment.value if profile else None,
                "isolation_boundary": profile.isolation_boundary if profile else "",
                "capabilities": caps,
                "kernel_version": ENGINE_KERNEL_VERSION,
                "provenance": (extras or {}).get(engine),
            }
        )
    return cards


def _hashed(content: dict[str, Any]) -> dict[str, Any]:
    content["evidence_hash"] = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return content


def nuclei_evidence_cards(scan: ScanResult) -> list[dict[str, Any]]:
    """Safe rendered cards for a Nuclei run: one execution card (tool, untrusted) and one card per
    independent verifier probe. Never a screenshot, response body, header or raw URL."""

    timestamp = (scan.completed_at or scan.created_at).isoformat()
    cards: list[dict[str, Any]] = []
    summary = nuclei_summary(scan)
    if summary is not None:
        template = (summary.get("templates") or [{}])[0]
        cards.append(
            _hashed(
                {
                    "artifact_type": "NUCLEI_EXECUTION_CARD",
                    "artifact_id": f"{scan.id}:nuclei-execution",
                    "scan_id": scan.id,
                    "method": "GET",
                    "normalized_route": "{BaseURL}/.git/config",
                    "principal_profile_name": "anonymous",
                    "object_reference": str(scan.target_ref),
                    "response_status": None,
                    "response_size": None,
                    "response_characteristics": {"bounded": True, "body_redacted": True},
                    "timestamp": timestamp,
                    "request_id": f"{scan.id}:nuclei",
                    "control_probe_role": "TOOL RESULT · UNTRUSTED",
                    "provenance": "TOOL_REPORTED",
                    "template_id": template.get("template_id"),
                    "signature_status": template.get("signature_status"),
                    "engine_version": summary.get("engine_version"),
                    "manifest_digest": summary.get("manifest_digest"),
                    "matched": summary.get("matched"),
                    "unmatched": summary.get("unmatched"),
                    "http_connections": summary.get("http_connections"),
                    "exit_class": summary.get("exit_class"),
                }
            )
        )
    for fact in scan.verifier_evidence:
        role = str(fact.get("role", ""))
        cards.append(
            _hashed(
                {
                    "artifact_type": "VERIFIER_PROBE_CARD",
                    "artifact_id": f"{scan.id}:{fact.get('name')}",
                    "scan_id": scan.id,
                    "method": fact.get("method"),
                    "normalized_route": fact.get("path"),
                    "principal_profile_name": "anonymous",
                    "object_reference": str(scan.target_ref),
                    "response_status": fact.get("status_code"),
                    "response_size": fact.get("body_bytes"),
                    "response_characteristics": {"bounded": True, "body_redacted": True},
                    "timestamp": timestamp,
                    "request_id": str(fact.get("name")),
                    "control_probe_role": (
                        "VERIFIER CONTROL" if role == "BASE_CONTROL" else "VERIFIER PROBE"
                    ),
                    "provenance": "VERIFIER",
                    "content_class": fact.get("content_class"),
                    "property_observed": (
                        "REPOSITORY_METADATA_SERVED"
                        if fact.get("git_config_structure")
                        else "DETERMINISTIC_DENIAL"
                        if fact.get("deliberate_denial")
                        else "SYNTHETIC_ROUTE_MARKER"
                        if fact.get("synthetic_marker_ok")
                        else "NOT_ESTABLISHED"
                    ),
                }
            )
        )
    return cards


_HEADER_PROPERTY = {
    "ABSENT": "HEADER_ABSENT",
    "PRESENT_NOSNIFF": "NOSNIFF_PRESENT",
    "INVALID": "HEADER_INVALID",
    "NOT_OBSERVED": "NOT_ESTABLISHED",
}


def zap_evidence_cards(scan: ScanResult) -> list[dict[str, Any]]:
    """Safe rendered cards for a ZAP run: one execution card (tool, untrusted), one card per
    tool-reported alert (untrusted claims) and one card per independent verifier probe. Never a
    screenshot, response body, header value, alert prose or raw URL."""

    timestamp = (scan.completed_at or scan.created_at).isoformat()
    cards: list[dict[str, Any]] = []
    summary = zap_summary(scan)
    provenance = scan.zap_provenance or {}
    if summary is not None:
        cards.append(
            _hashed(
                {
                    "artifact_type": "ZAP_EXECUTION_CARD",
                    "artifact_id": f"{scan.id}:zap-execution",
                    "scan_id": scan.id,
                    "method": "GET",
                    "normalized_route": "projected OpenAPI (local apiFile)",
                    "principal_profile_name": "anonymous",
                    "object_reference": str(scan.target_ref),
                    "response_status": None,
                    "response_size": None,
                    "response_characteristics": {"bounded": True, "body_redacted": True},
                    "timestamp": timestamp,
                    "request_id": f"{scan.id}:zap",
                    "control_probe_role": "TOOL EXECUTION · UNTRUSTED",
                    "provenance": "TOOL_REPORTED",
                    "engine_version": summary.get("engine_version"),
                    "projection_digest": summary.get("projection_digest"),
                    "operation_count": summary.get("operation_count"),
                    "imported_urls": summary.get("imported_urls"),
                    "expected_requests": summary.get("expected_requests"),
                    "observed_requests": summary.get("observed_requests"),
                    "blocked_requests": summary.get("blocked_requests"),
                    "passive_queue_drained": summary.get("passive_queue_drained"),
                    "coverage_state": summary.get("coverage_state"),
                    "exit_class": summary.get("exit_class"),
                }
            )
        )
    for index, alert in enumerate(provenance.get("alerts", [])[:8]):
        cards.append(
            _hashed(
                {
                    "artifact_type": "ZAP_ALERT_CARD",
                    "artifact_id": f"{scan.id}:zap-alert-{index}",
                    "scan_id": scan.id,
                    "method": alert.get("method"),
                    "normalized_route": alert.get("path"),
                    "principal_profile_name": "anonymous",
                    "object_reference": str(scan.target_ref),
                    "response_status": None,
                    "response_size": None,
                    "response_characteristics": {"bounded": True, "body_redacted": True},
                    "timestamp": timestamp,
                    "request_id": str(alert.get("record_digest", ""))[:24],
                    "control_probe_role": "TOOL ALERT · UNTRUSTED",
                    "provenance": "TOOL_REPORTED",
                    "plugin_id": alert.get("plugin_id"),
                    "rule_name": alert.get("rule_name"),
                    "param": alert.get("param"),
                    "claimed_risk": alert.get("claimed_risk"),
                    "claimed_confidence": alert.get("claimed_confidence"),
                    "claim_trust": "UNTRUSTED_TOOL_METADATA",
                }
            )
        )
    for fact in scan.verifier_evidence:
        role = str(fact.get("role", ""))
        cards.append(
            _hashed(
                {
                    "artifact_type": "VERIFIER_PROBE_CARD",
                    "artifact_id": f"{scan.id}:{fact.get('name')}",
                    "scan_id": scan.id,
                    "method": fact.get("method"),
                    "normalized_route": fact.get("path"),
                    "principal_profile_name": "anonymous",
                    "object_reference": str(scan.target_ref),
                    "response_status": fact.get("status_code"),
                    "response_size": fact.get("body_bytes"),
                    "response_characteristics": {"bounded": True, "body_redacted": True},
                    "timestamp": timestamp,
                    "request_id": str(fact.get("name")),
                    "control_probe_role": (
                        "VERIFIER CONTROL" if role == "BASE_CONTROL" else "VERIFIER PROBE"
                    ),
                    "provenance": "VERIFIER",
                    "content_class": fact.get("content_class"),
                    "property_observed": (
                        _HEADER_PROPERTY.get(str(fact.get("nosniff_header")), "NOT_ESTABLISHED")
                        if fact.get("synthetic_marker_ok")
                        else "NOT_ESTABLISHED"
                    ),
                }
            )
        )
    return cards


def evidence_cards(scan: ScanResult) -> list[dict[str, Any]]:
    if scan.engine == Engine.NUCLEI.value:
        return nuclei_evidence_cards(scan)
    if scan.engine == Engine.ZAP.value:
        return zap_evidence_cards(scan)
    cards: list[dict[str, Any]] = []
    for index, evidence in enumerate(scan.evidence):
        role = ("OWNER CONTROL" if index == 0 else "ALTERNATE CONTROL" if index == 1 else "PROBE")
        content = {
            "artifact_type": "API_EVIDENCE_CARD",
            "artifact_id": f"{scan.id}:{evidence.name}",
            "scan_id": scan.id,
            "method": evidence.method,
            "normalized_route": evidence.path,
            "principal_profile_name": evidence.credential_profile,
            "object_reference": evidence.path.rsplit("/", 1)[-1],
            "response_status": evidence.status_code,
            "response_size": None,
            "response_characteristics": {"bounded": True, "body_redacted": True},
            "timestamp": (
                scan.completed_at.isoformat()
                if scan.completed_at
                else scan.created_at.isoformat()
            ),
            "request_id": evidence.name,
            "control_probe_role": role,
        }
        content["evidence_hash"] = hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        cards.append(content)
    return cards


def _nuclei_finding_projection(
    scan: ScanResult, finding_index: int, linked_retests: list[ScanResult]
) -> dict[str, Any]:
    finding = scan.findings[finding_index]
    retest = linked_retests[0] if linked_retests else None
    summary = nuclei_summary(scan) or {}
    remediated = bool(retest and retest.status.value == "PASS")
    return {
        "id": finding.id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": "REMEDIATED" if remediated else "CONFIRMED",
        "vulnerability_class": finding.category,
        "owasp_mapping": "Not mapped (no automatic OWASP coverage claim)",
        "source_engine": Engine.NUCLEI,
        "affected_operation": "GET /lab/nuclei/vulnerable/.git/config",
        "principal_object_direction": "anonymous → synthetic repository metadata",
        "discovery_scan": scan.id,
        "linked_retest": retest.id if retest else None,
        "evidence_completeness": "COMPLETE" if len(finding.evidence_names) >= 2 else "PARTIAL",
        "created_at": (scan.completed_at or scan.created_at).isoformat(),
        "updated_at": (
            retest.completed_at.isoformat()
            if retest and retest.completed_at
            else (scan.completed_at or scan.created_at).isoformat()
        ),
        "title": finding.title,
        "provenance": "VERIFIER",
        "ai_hypothesis": "None — operator-requested capability; the AI was not involved.",
        "controller_execution": (
            f"Admitted typed job; isolated runner executed signed template "
            f"{(summary.get('templates') or [{}])[0].get('template_id', '—')} "
            f"with Nuclei {summary.get('engine_version', '—')} (TOOL_REPORTED)."
        ),
        "deterministic_evidence": "Verifier: control 200 · metadata 200 (git core config section)",
        "verifier_conclusion": (
            "Independent verifier confirmed exposure from fresh evidence; Nuclei did not confirm."
        ),
        "patched_retest": (
            "Patched: control 200 · metadata 404 (deterministic denial)" if retest else "Not run"
        ),
        "final_state": "PASS" if remediated else "FAIL",
    }


def _zap_finding_projection(
    scan: ScanResult, finding_index: int, linked_retests: list[ScanResult]
) -> dict[str, Any]:
    finding = scan.findings[finding_index]
    retest = linked_retests[0] if linked_retests else None
    summary = zap_summary(scan) or {}
    remediated = bool(retest and retest.status.value == "PASS")
    rule = (summary.get("rules") or [{}])[0]
    return {
        "id": finding.id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": "REMEDIATED" if remediated else "CONFIRMED",
        "vulnerability_class": finding.category,
        "owasp_mapping": "Not mapped (no automatic OWASP coverage claim)",
        "source_engine": Engine.ZAP,
        "affected_operation": "GET /lab/zap/vulnerable/catalog/{catalog_id}",
        "principal_object_direction": "anonymous → synthetic catalog response header",
        "discovery_scan": scan.id,
        "linked_retest": retest.id if retest else None,
        "evidence_completeness": "COMPLETE" if len(finding.evidence_names) >= 2 else "PARTIAL",
        "created_at": (scan.completed_at or scan.created_at).isoformat(),
        "updated_at": (
            retest.completed_at.isoformat()
            if retest and retest.completed_at
            else (scan.completed_at or scan.created_at).isoformat()
        ),
        "title": finding.title,
        "provenance": "VERIFIER",
        "ai_hypothesis": "None — operator-requested capability; the AI was not involved.",
        "controller_execution": (
            f"Projected {summary.get('operation_count', '—')} read-only operations; isolated "
            f"ZAP {summary.get('engine_version', '—')} passively analysed them with rule "
            f"{rule.get('plugin_id', '—')} (TOOL_REPORTED)."
        ),
        "deterministic_evidence": (
            "Verifier: control 200 with nosniff · catalog 200 JSON without X-Content-Type-Options"
        ),
        "verifier_conclusion": (
            "Independent verifier confirmed the missing header from fresh evidence; ZAP did not "
            "confirm."
        ),
        "patched_retest": (
            "Patched: complete passive coverage · catalog 200 with nosniff" if retest else "Not run"
        ),
        "final_state": "PASS" if remediated else "FAIL",
    }


def finding_projection(
    scan: ScanResult, finding_index: int, linked_retests: list[ScanResult]
) -> dict[str, Any]:
    if scan.engine == Engine.NUCLEI.value:
        return _nuclei_finding_projection(scan, finding_index, linked_retests)
    if scan.engine == Engine.ZAP.value:
        return _zap_finding_projection(scan, finding_index, linked_retests)
    finding = scan.findings[finding_index]
    retest = linked_retests[0] if linked_retests else None
    return {
        "id": finding.id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": "REMEDIATED" if retest and retest.status.value == "PASS" else "CONFIRMED",
        "vulnerability_class": finding.category,
        "owasp_mapping": "API1:2023 Broken Object Level Authorization",
        "source_engine": Engine.AEGIS_NATIVE,
        "affected_operation": "GET /api/v1/accounts/{account_id}",
        "principal_object_direction": "user_a → object owned by user_b",
        "discovery_scan": scan.id,
        "linked_retest": retest.id if retest else None,
        "evidence_completeness": "COMPLETE" if len(finding.evidence_names) >= 3 else "PARTIAL",
        "created_at": (
            scan.completed_at.isoformat() if scan.completed_at else scan.created_at.isoformat()
        ),
        "updated_at": (
            retest.completed_at.isoformat()
            if retest and retest.completed_at
            else scan.completed_at.isoformat()
            if scan.completed_at
            else scan.created_at.isoformat()
        ),
        "title": finding.title,
        "provenance": "VERIFIER",
        "ai_hypothesis": "One bounded cross-owner object-authorization direction.",
        "controller_execution": (
            "Validated, admitted, compiled and executed three read-only requests."
        ),
        "deterministic_evidence": "Vulnerable: 200 / 200 / 200",
        "verifier_conclusion": "Fresh evidence confirmed unauthorized cross-owner access.",
        "patched_retest": "Patched: 200 / 200 / 403" if retest else "Not run",
        "final_state": "PASS" if retest and retest.status.value == "PASS" else "FAIL",
    }
