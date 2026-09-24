"""Strict controller-owned contracts for the Phase 1.7 agent runtime.

The contracts intentionally contain references and aliases, never origins, credential values,
provider secrets, response bodies, answer keys, or model reasoning.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AgentRole(StrEnum):
    LEAD_ORCHESTRATOR = "LEAD_ORCHESTRATOR"
    SURFACE_AGENT = "SURFACE_AGENT"
    AUTHORIZATION_AGENT = "AUTHORIZATION_AGENT"
    INJECTION_AGENT = "INJECTION_AGENT"
    CHAIN_AGENT = "CHAIN_AGENT"
    RECON_AGENT = "RECON_AGENT"
    CLOUD_BOUNDARY_AGENT = "CLOUD_BOUNDARY_AGENT"


class AgentRunState(StrEnum):
    QUEUED = "QUEUED"
    RESETTING = "RESETTING"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    CLEANING_UP = "CLEANING_UP"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AgentTaskState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ObservationType(StrEnum):
    SURFACE = "SURFACE"
    AUTHORIZATION_COMPARISON = "AUTHORIZATION_COMPARISON"
    # Phase 2.1: authentication-control observations (rate-limit/lockout responses), kept distinct
    # from AUTHORIZATION_COMPARISON so authentication and authorization findings never conflate.
    AUTHENTICATION_PROBE = "AUTHENTICATION_PROBE"
    VERIFIER_SUMMARY = "VERIFIER_SUMMARY"
    RECON_INVENTORY = "RECON_INVENTORY"
    INJECTION_PROBE = "INJECTION_PROBE"


class EvaluationVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    PASS = "PASS"  # noqa: S105 - evaluation verdict, not a credential
    INCOMPLETE = "INCOMPLETE"
    CANCELLED = "CANCELLED"


def now_utc() -> datetime:
    return datetime.now(UTC)


class BudgetLimit(StrictModel):
    model_calls: int = Field(ge=0, le=100)
    tokens: int = Field(ge=0, le=1_000_000)
    target_requests: int = Field(ge=0, le=10_000)
    commands: int = Field(ge=0, le=1_000)
    elapsed_ms: int = Field(ge=1, le=86_400_000)
    evidence_bytes: int = Field(ge=0, le=100_000_000)


class BudgetUsage(StrictModel):
    model_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    target_requests: int = Field(default=0, ge=0)
    commands: int = Field(default=0, ge=0)
    elapsed_ms: int = Field(default=0, ge=0)
    evidence_bytes: int = Field(default=0, ge=0)

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AgentBudgetLedger(StrictModel):
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    agent_id: str | None = Field(default=None, pattern=r"^agent-[a-f0-9]{16}$")
    limit: BudgetLimit
    usage: BudgetUsage = Field(default_factory=BudgetUsage)


class AgentRun(StrictModel):
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    application_id: str = Field(pattern=r"^aegis-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    execution_mode: Literal["single_agent", "multi_agent"]
    state: AgentRunState = AgentRunState.QUEUED
    created_at: datetime = Field(default_factory=now_utc)
    completed_at: datetime | None = None
    active_role: AgentRole | None = None
    stop_requested: bool = False
    verifier_result_ref: str | None = Field(default=None, max_length=100)
    verdict: EvaluationVerdict | None = None
    cleanup_succeeded: bool | None = None
    reset_generation_before: int | None = None
    reset_generation_after: int | None = None


class AgentTaskContext(StrictModel):
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    scenario_ref: str = Field(pattern=r"^[a-z0-9-]+$")
    allowed_operation_ids: list[str] = Field(max_length=32)
    credential_aliases: list[str] = Field(max_length=8)
    resource_refs: list[str] = Field(max_length=32)
    observation_refs: list[str] = Field(default_factory=list, max_length=32)


class AgentTask(StrictModel):
    task_id: str = Field(pattern=r"^task-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    agent_id: str = Field(pattern=r"^agent-[a-f0-9]{16}$")
    role: AgentRole
    task_type: Literal[
        "PLAN_SURFACE",
        "OBSERVE_SURFACE",
        "PLAN_AUTHORIZATION",
        "TEST_AUTHORIZATION",
        "SINGLE_AGENT_BOLA",
        "RECON_INVENTORY",
        "SELECT_INJECTION",
        "EXECUTE_INJECTION",
        "PLAN_CHAIN",
        "RECON_SERVICE_DISCOVERY",
        "RECON_REVIEWED_EXPOSURE",
        "RECON_PASSIVE_OPENAPI",
        "RECON_HTTP_SURFACE",
        "RECON_ORCHESTRATE",
    ]
    state: AgentTaskState = AgentTaskState.QUEUED
    parent_task_id: str | None = Field(default=None, pattern=r"^task-[a-f0-9]{16}$")
    context: AgentTaskContext
    created_at: datetime = Field(default_factory=now_utc)
    completed_at: datetime | None = None


class AgentObservation(StrictModel):
    observation_id: str = Field(pattern=r"^obs-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    task_id: str = Field(pattern=r"^task-[a-f0-9]{16}$")
    agent_id: str = Field(pattern=r"^agent-[a-f0-9]{16}$")
    observation_type: ObservationType
    summary: str = Field(min_length=1, max_length=500)
    operation_ids: list[str] = Field(default_factory=list, max_length=32)
    resource_refs: list[str] = Field(default_factory=list, max_length=32)
    statuses: dict[str, int] = Field(default_factory=dict)
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_bytes: int = Field(ge=0, le=262_144)
    created_at: datetime = Field(default_factory=now_utc)


class AgentHypothesis(StrictModel):
    hypothesis_id: str = Field(pattern=r"^hyp-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    task_id: str = Field(pattern=r"^task-[a-f0-9]{16}$")
    agent_id: str = Field(pattern=r"^agent-[a-f0-9]{16}$")
    category: Literal["BOLA"]
    operation_id: str = Field(max_length=100)
    owner_credential_alias: str = Field(pattern=r"^cred-[a-z0-9-]+$")
    alternate_credential_alias: str = Field(pattern=r"^cred-[a-z0-9-]+$")
    owner_resource_ref: str = Field(pattern=r"^resource-[a-z0-9-]+$")
    alternate_resource_ref: str = Field(pattern=r"^resource-[a-z0-9-]+$")
    rationale: str = Field(min_length=3, max_length=500)


class AgentActionRequest(StrictModel):
    action_id: str = Field(pattern=r"^action-[a-f0-9]{16}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    task_id: str = Field(pattern=r"^task-[a-f0-9]{16}$")
    agent_id: str = Field(pattern=r"^agent-[a-f0-9]{16}$")
    role: AgentRole
    capability_id: str = Field(pattern=r"^[a-z0-9_.-]+$")
    operation_id: str = Field(max_length=100)
    credential_aliases: list[str] = Field(min_length=1, max_length=4)
    resource_refs: list[str] = Field(min_length=1, max_length=8)
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def expiry_after_issue(self) -> AgentActionRequest:
        if self.expires_at <= self.issued_at:
            raise ValueError("ACTION_EXPIRY_INVALID")
        return self


class AgentActionResult(StrictModel):
    action_id: str = Field(pattern=r"^action-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    task_id: str = Field(pattern=r"^task-[a-f0-9]{16}$")
    agent_id: str = Field(pattern=r"^agent-[a-f0-9]{16}$")
    capability_id: str
    accepted: bool
    observation_ref: str | None = Field(default=None, pattern=r"^obs-[a-f0-9]{16}$")
    rejection_code: str | None = Field(default=None, max_length=100)
    target_requests: int = Field(ge=0, le=32)


class FindingCandidate(StrictModel):
    candidate_id: str = Field(pattern=r"^candidate-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    hypothesis_id: str = Field(pattern=r"^hyp-[a-f0-9]{16}$")
    observation_ref: str = Field(pattern=r"^obs-[a-f0-9]{16}$")
    category: Literal["BOLA"]
    verifier_confirmed: bool = False


class VerifierResultRef(StrictModel):
    reference: str = Field(pattern=r"^verify-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    authority: Literal["DETERMINISTIC_RANGE_VERIFIER"]
    status: Literal["CONFIRMED", "PASS", "INCOMPLETE"]
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_bytes: int = Field(ge=0, le=262_144)
    summary: str = Field(max_length=300)


class AgentAuditEvent(StrictModel):
    event_id: str = Field(pattern=r"^maevt-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^marun-[a-f0-9]{16}$")
    task_id: str | None = Field(default=None, pattern=r"^task-[a-f0-9]{16}$")
    agent_id: str | None = Field(default=None, pattern=r"^agent-[a-f0-9]{16}$")
    actor: Literal["CONTROLLER", "AGENT", "TOOL_BROKER", "VERIFIER"]
    event_type: str = Field(pattern=r"^[A-Z0-9_]+$", max_length=80)
    summary: str = Field(min_length=1, max_length=500)
    created_at: datetime = Field(default_factory=now_utc)


class RunMetrics(StrictModel):
    surface_discovery: int = Field(ge=0)
    valid_hypotheses: int = Field(ge=0)
    verifier_confirmed_findings: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    target_requests: int = Field(ge=0)
    elapsed_ms: int = Field(ge=0)
    adaptation_after_failed_approach: bool
    cleanup_reset_succeeded: bool


class RunEvaluation(StrictModel):
    run: AgentRun
    tasks: list[AgentTask]
    observations: list[AgentObservation]
    hypotheses: list[AgentHypothesis]
    action_requests: list[AgentActionRequest]
    action_results: list[AgentActionResult]
    finding_candidates: list[FindingCandidate]
    verifier_results: list[VerifierResultRef]
    global_budget: AgentBudgetLedger
    agent_budgets: list[AgentBudgetLedger]
    metrics: RunMetrics
    audit_events: list[AgentAuditEvent]


# Model-authored output types. Identity, authority, verdict, URL and raw-request fields are absent.
class LeadTaskOutput(StrictModel):
    task_type: Literal["OBSERVE_SURFACE", "TEST_AUTHORIZATION"]
    objective: str = Field(min_length=3, max_length=300)


class SurfaceAgentOutput(StrictModel):
    summary: str = Field(min_length=3, max_length=500)
    operation_ids: list[str] = Field(min_length=1, max_length=16)
    resource_refs: list[str] = Field(min_length=1, max_length=16)


class AuthorizationAgentOutput(StrictModel):
    category: Literal["BOLA"]
    operation_id: str = Field(max_length=100)
    owner_credential_alias: str = Field(pattern=r"^cred-[a-z0-9-]+$")
    alternate_credential_alias: str = Field(pattern=r"^cred-[a-z0-9-]+$")
    owner_resource_ref: str = Field(pattern=r"^resource-[a-z0-9-]+$")
    alternate_resource_ref: str = Field(pattern=r"^resource-[a-z0-9-]+$")
    rationale: str = Field(min_length=3, max_length=500)
    capability_id: Literal["aegis.authorization.compare"]


class SingleAgentOutput(StrictModel):
    summary: str = Field(min_length=3, max_length=500)
    operation_ids: list[str] = Field(min_length=1, max_length=16)
    resource_refs: list[str] = Field(min_length=1, max_length=16)
    authorization: AuthorizationAgentOutput


# --- Phase 1.7-C controlled Recon Agent gateway output contracts (server-selected schemas) ---
#
# These are the strict schemas the gateway derives for the RECON_AGENT task types. They are the
# ONLY shapes a model may return for those tasks; the caller never supplies or weakens them. The
# model may select only: a registered recon capability id, a registered target reference, typed
# Nmap plan fields, an approved Nuclei/ZAP profile id, and reference-only delegation targets. There
# is NO field through which it can emit a raw shell command, a raw Nmap flag, an arbitrary origin,
# a template path, a ZAP policy, a payload, a credential, or a verdict / PASS / CONFIRMED /
# severity: those are structurally unrepresentable. The controller owns every unsafe decision, and
# aegis.multi_agent.recon re-validates every selection again before any command is produced.
#
# The literal alias values below are kept in lockstep with aegis.multi_agent.recon by a drift-guard
# test (tests/test_phase_1_7c.py). They are duplicated here — not imported — so the isolated gateway
# process never has to import the range inventory, injection templates or capability registry.
ReconCapabilityId = Literal[
    "aegis.recon.network_service_discovery",
    "aegis.recon.nuclei_reviewed_exposure",
    "aegis.recon.zap_passive_openapi",
    "aegis.surface.openapi",
]
_GwTcpPortSpec = Literal["DISCOVERY_TOP_100", "TOP_1000", "FULL_65535"]
_GwUdpPortSpec = Literal["NONE", "TOP_50", "FULL_65535"]
_GwDiscoveryStrategy = Literal["TCP_CONNECT", "TCP_SYN"]
_GwTimingProfile = Literal["T2", "T3", "T4"]
_GwNseCategory = Literal["DISCOVERY", "VERSION", "VULN", "SAFE", "DEFAULT"]
_GwNmapProfileId = Literal["RANGE_FULL_RECON", "AUTHORIZED_ENV_RECON"]
_GwAdmittedNseScriptId = Literal[
    "banner", "http-title", "http-headers", "http-methods", "ssl-cert", "vulners"
]
_GwApprovedScannerProfile = Literal["NUCLEI_LAB_SAFE_HTTP_V1", "ZAP_LAB_PASSIVE_OPENAPI_V1"]
_GwReconObservationKind = Literal[
    "DISCOVERED_SERVICE",
    "HTTP_TECHNOLOGY",
    "DOCUMENTED_OPERATION",
    "PARAMETER_CANDIDATE",
    "NUCLEI_CANDIDATE",
    "ZAP_PASSIVE_CANDIDATE",
    "NO_FINDING",
    "INCOMPLETE_TOOL_ERROR",
]


class GatewayNmapPlanSelection(StrictModel):
    """Typed Nmap plan *selection* fields only.

    No raw flag, host, URL, evasion or credentialed-brute field is representable here (those fields
    from :class:`aegis.multi_agent.recon.NmapScanPlan` are deliberately absent from the gateway
    boundary). ``nse_script_ids`` is restricted to the admitted script-id enum, so the model cannot
    name an arbitrary NSE script. The controller renders argv and rejects anything out of profile.
    """

    transports: list[Literal["TCP", "UDP"]] = Field(min_length=1, max_length=2)
    tcp_port_spec: _GwTcpPortSpec = "TOP_1000"
    udp_port_spec: _GwUdpPortSpec = "NONE"
    discovery_strategy: _GwDiscoveryStrategy = "TCP_CONNECT"
    version_detection: bool = True
    version_intensity: int = Field(default=5, ge=0, le=9)
    os_detection: bool = False
    traceroute: bool = False
    timing_profile: _GwTimingProfile = "T3"
    nse_categories: list[_GwNseCategory] = Field(default_factory=list, max_length=5)
    nse_script_ids: list[_GwAdmittedNseScriptId] = Field(default_factory=list, max_length=6)


class ReconPlanOutput(StrictModel):
    """PLAN_RECON: select one registered recon capability and its typed, approved plan.

    Exactly one plan shape is required for the selected capability: a typed Nmap plan (with a
    registered profile) for network service discovery, or an approved scanner profile id for the
    reused Nuclei / ZAP passive capabilities. The surface capability needs only the target ref.
    """

    capability_id: ReconCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    profile_id: _GwNmapProfileId | None = None
    nmap_plan: GatewayNmapPlanSelection | None = None
    scanner_profile_id: _GwApprovedScannerProfile | None = None
    rationale: str = Field(min_length=3, max_length=300)

    @model_validator(mode="after")
    def _coherent_selection(self) -> ReconPlanOutput:
        is_nmap = self.capability_id == "aegis.recon.network_service_discovery"
        is_scanner = self.capability_id in {
            "aegis.recon.nuclei_reviewed_exposure",
            "aegis.recon.zap_passive_openapi",
        }
        if is_nmap and (self.nmap_plan is None or self.profile_id is None):
            raise ValueError("PLAN_RECON_NMAP_REQUIRES_TYPED_PLAN")
        if not is_nmap and (self.nmap_plan is not None or self.profile_id is not None):
            raise ValueError("PLAN_RECON_NMAP_FIELDS_NOT_ALLOWED")
        if is_scanner and self.scanner_profile_id is None:
            raise ValueError("PLAN_RECON_SCANNER_REQUIRES_PROFILE")
        if not is_scanner and self.scanner_profile_id is not None:
            raise ValueError("PLAN_RECON_SCANNER_PROFILE_NOT_ALLOWED")
        return self


class ReconInterpretationOutput(StrictModel):
    """INTERPRET_RECON_OBSERVATIONS: a bounded, reference-only reading of normalized observations.

    It has no verdict, PASS, CONFIRMED or severity field: recon cannot confirm a vulnerability. The
    ``unconfirmed`` invariant is fixed True so even the schema restates that recon never confirms.
    """

    summary: str = Field(min_length=3, max_length=400)
    salient_observation_kinds: list[_GwReconObservationKind] = Field(
        default_factory=list, max_length=8
    )
    recommended_followups: list[ReconCapabilityId] = Field(default_factory=list, max_length=4)
    unconfirmed: Literal[True] = True


class ReconDelegationOutput(StrictModel):
    """DELEGATE_RECON_HYPOTHESIS: a reference-only hypothesis routed to another registered agent.

    Only references travel: a registered destination agent, an ``aegis.*`` capability id, a target
    reference, and an optional documented route/parameter. There is no payload, no origin and no
    verdict field.
    """

    to_agent: Literal["AUTHORIZATION_AGENT", "INJECTION_AGENT"]
    capability_id: str = Field(pattern=r"^aegis\.[a-z0-9_.]+$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    route: str = Field(default="", max_length=200, pattern=r"^(/[A-Za-z0-9/._{}~-]*)?$")
    parameter: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.-]*$")
    rationale: str = Field(min_length=3, max_length=300)


# --- Phase 1.9 controlled Cloud Boundary Agent gateway output contracts (server-selected) ---
#
# These are the strict schemas the gateway derives for the CLOUD_BOUNDARY_AGENT task types. As with
# the recon contracts, they are reference-only: the model may select only a registered cloud
# capability id, a registered target reference, a typed *boundary class* hypothesis, and a symbolic
# probe destination reference (never a URL, credential, header, raw request body, verdict, PASS,
# CONFIRMED or severity — those are structurally unrepresentable). The Tool Broker
# (aegis.multi_agent.cloud_boundary) resolves the symbolic destination reference to a concrete,
# shell-free HTTP execution controller-side, and re-validates every selection before any request.
# The literal alias values are kept in lockstep with aegis.multi_agent.cloud_boundary by a drift
# guard (tests/test_phase_1_9.py); they are duplicated here, not imported, so the isolated gateway
# process never imports the range inventory or capability registry.
CloudBoundaryCapabilityId = Literal["aegis.cloud.metadata_boundary_probe"]
_GwCloudBoundaryClass = Literal[
    "METADATA_CREDENTIAL_EXPOSURE",
    "INTEGRATION_DESTINATION_SSRF",
    "INTERNAL_SERVICE_AUTHORIZATION",
    "WORKSPACE_CROSS_ORIGIN",
    "XML_EXTERNAL_ENTITY",
]
# Symbolic probe destinations the model may name. Neither is a URL: the broker resolves each to a
# concrete internal origin+path controller-side. INSTANCE_METADATA is the synthetic instance
# -metadata response reachable through the integration-check surface; APPROVED_PARTNER_STATUS is the
# benign approved control destination.
_GwCloudDestinationRef = Literal["INSTANCE_METADATA", "APPROVED_PARTNER_STATUS"]
_GwCloudBoundaryObservationKind = Literal[
    "INTEGRATION_RESPONSE",
    "CREDENTIAL_FIELD_PRESENT",
    "CREDENTIAL_FIELD_ABSENT",
    "NO_FINDING",
    "INCOMPLETE_TOOL_ERROR",
]


class GatewayCloudBoundaryProbeSelection(StrictModel):
    """Typed probe *selection* fields only.

    No raw URL, origin, header, credential or request body is representable here. The model selects
    a bounded HTTP method and a symbolic destination reference; the controller/broker renders the
    concrete, shell-free execution and rejects anything out of the registered capability's scope.
    """

    method: Literal["POST"] = "POST"
    destination_ref: _GwCloudDestinationRef = "INSTANCE_METADATA"


class CloudBoundaryPlanOutput(StrictModel):
    """PLAN_CLOUD_BOUNDARY: select one registered cloud-boundary capability and its typed probe.

    The plan references only a registered capability, an inventory target reference, a typed
    boundary-class hypothesis and a symbolic probe destination. It cannot express a URL, credential,
    header, raw body, verdict or severity.
    """

    capability_id: CloudBoundaryCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    boundary_class: _GwCloudBoundaryClass
    probe: GatewayCloudBoundaryProbeSelection
    rationale: str = Field(min_length=3, max_length=300)


class CloudBoundaryInterpretationOutput(StrictModel):
    """INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS: a bounded, reference-only reading of observations.

    It has no verdict, PASS, CONFIRMED or severity field: the agent cannot confirm a boundary
    violation. ``unconfirmed`` is fixed True so the schema itself restates that the agent never
    confirms — only the independent verifier may.
    """

    summary: str = Field(min_length=3, max_length=400)
    salient_observation_kinds: list[_GwCloudBoundaryObservationKind] = Field(
        default_factory=list, max_length=8
    )
    boundary_hypothesis: _GwCloudBoundaryClass
    unconfirmed: Literal[True] = True


class CloudBoundarySubmissionOutput(StrictModel):
    """SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION: recommend independent verification, never confirm.

    The submission carries only references: the deterministic verifier authority, a registered
    capability id, a target reference and the typed boundary class. There is deliberately no verdict
    field of any kind — the agent structurally cannot self-confirm, and ``unconfirmed`` (fixed True)
    restates that. The controller maps the boundary class to the owned scenario and runs the
    independent verifier. (A ``confirmed`` field is intentionally absent: it would both re-introduce
    a self-confirmation surface and, as a schema property name, trip the gateway's verdict-token
    sanitizer that keeps every outbound projection free of ``"confirmed"``/``"pass"``.)
    """

    to_verifier: Literal["DETERMINISTIC_RANGE_VERIFIER"]
    capability_id: CloudBoundaryCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    boundary_class: _GwCloudBoundaryClass
    unconfirmed: Literal[True] = True
    rationale: str = Field(min_length=3, max_length=300)


# --- Phase 2.0 verified multi-primitive attack-chain gateway output contracts (server-selected) ---
#
# These are the strict schemas the gateway derives for the CHAIN_AGENT / Stage-B agent task types.
# As with the recon and cloud-boundary contracts they are reference-only: the model may select only
# registered chain capability ids, registered target references, typed *primitive-type* hypotheses,
# and symbolic destination references. There is NO field through which it can emit a URL, a
# credential value, a raw request body, a verdict, PASS/CONFIRMED, severity or final impact — those
# are structurally unrepresentable. The model may reason about the *existence and type* of a
# credential reference (a boolean) but never its value. Every ``unconfirmed`` flag is fixed True
# so the schema itself restates that only the independent verifier may confirm. The literal alias
# values are kept in lockstep with aegis.multi_agent.attack_chain by a drift-guard test; they are
# duplicated here, not imported, so the isolated gateway process never imports the range inventory.
ChainCapabilityId = Literal[
    "aegis.cloud.metadata_boundary_probe",
    "aegis.cloud.internal_service_access",
]
_GwChainPrimitiveType = Literal[
    "METADATA_CREDENTIAL_EXPOSURE",
    "INTERNAL_SERVICE_AUTHORIZATION",
]
# Symbolic chain destinations the model may name. Neither is a URL: the broker resolves each to a
# concrete internal origin+route controller-side. INSTANCE_METADATA is the synthetic instance
# -metadata response; PRIVATE_ADMIN_OPERATION is the private administration operation reached with a
# captured credential reference.
_GwChainDestinationRef = Literal["INSTANCE_METADATA", "PRIVATE_ADMIN_OPERATION"]
_GwChainObservationKind = Literal[
    "INTEGRATION_RESPONSE",
    "CREDENTIAL_REFERENCE_PRESENT",
    "CREDENTIAL_REFERENCE_ABSENT",
    "PRIVATE_OPERATION_EFFECT",
    "OPERATION_REJECTED",
    "NO_FINDING",
    "INCOMPLETE_TOOL_ERROR",
]


class GatewayChainStageSelection(StrictModel):
    """One typed chain-stage *selection*: a primitive type, a registered capability, a symbolic
    destination, and whether the stage consumes the prior stage's opaque credential reference.

    No URL, credential value, header or raw body is representable. The controller/broker renders the
    concrete, shell-free execution and rejects anything out of the registered capability's scope.
    """

    primitive_type: _GwChainPrimitiveType
    capability_id: ChainCapabilityId
    destination_ref: _GwChainDestinationRef
    consumes_prior_stage: bool = False


class AttackChainPlanOutput(StrictModel):
    """PLAN_ATTACK_CHAIN: a typed two-primitive chain hypothesis over registered capabilities.

    The plan references only a registered chain, an inventory target reference, two ordered typed
    stages (distinct primitive types) and their symbolic destinations. It cannot express a URL,
    credential, header, raw body, verdict, severity or final impact. The first stage produces an
    artifact; the second consumes it. ``unconfirmed`` is fixed True — only the verifier confirms.
    """

    objective: str = Field(min_length=3, max_length=600)
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    stages: list[GatewayChainStageSelection] = Field(min_length=2, max_length=2)
    rationale: str = Field(min_length=3, max_length=600)
    unconfirmed: Literal[True] = True

    @model_validator(mode="after")
    def _distinct_ordered_primitives(self) -> AttackChainPlanOutput:
        first, second = self.stages[0], self.stages[1]
        if first.primitive_type == second.primitive_type:
            # "multi-primitive" requires two DISTINCT primitives, not repeated use of one.
            raise ValueError("CHAIN_PLAN_PRIMITIVES_NOT_DISTINCT")
        if first.consumes_prior_stage:
            raise ValueError("CHAIN_PLAN_FIRST_STAGE_HAS_NO_INPUT")
        if not second.consumes_prior_stage:
            raise ValueError("CHAIN_PLAN_SECOND_STAGE_MUST_CONSUME_FIRST")
        return self


class ChainStageInterpretationOutput(StrictModel):
    """INTERPRET_CHAIN_STAGE: a bounded, reference-only reading of one independently-verified link.

    It has no verdict, PASS, CONFIRMED, severity or impact field. ``stage_produced_artifact`` is the
    model's reading of whether the stage yielded the artifact the next primitive needs (e.g. a
    credential reference *exists*) — never the artifact's value. ``unconfirmed`` is fixed True.
    """

    summary: str = Field(min_length=3, max_length=600)
    primitive_type: _GwChainPrimitiveType
    salient_observation_kinds: list[_GwChainObservationKind] = Field(
        default_factory=list, max_length=8
    )
    stage_produced_artifact: bool
    unconfirmed: Literal[True] = True


class ChainNextStepOutput(StrictModel):
    """SELECT_NEXT_CHAIN_STEP: select the next registered chain step that consumes the prior link.

    The model selects the next primitive type and registered capability, and declares that it
    consumes the prior link's opaque credential reference (a boolean — never the value). It cannot
    express a URL, credential, verdict or severity. ``unconfirmed`` is fixed True.
    """

    next_primitive_type: _GwChainPrimitiveType
    next_capability_id: ChainCapabilityId
    next_destination_ref: _GwChainDestinationRef
    consumes_prior_link_reference: bool
    rationale: str = Field(min_length=3, max_length=600)
    unconfirmed: Literal[True] = True


class ChainExplanationOutput(StrictModel):
    """EXPLAIN_VERIFIED_CHAIN: explain the independently-verified chain and its remediation.

    It carries only prose and the ordered primitive types. There is deliberately no verdict, PASS,
    CONFIRMED, severity or impact field — those trace to the controller ground truth and the
    independent verifier, not the model. ``unconfirmed`` is fixed True.
    """

    chain_summary: str = Field(min_length=3, max_length=600)
    ordered_primitive_types: list[_GwChainPrimitiveType] = Field(min_length=2, max_length=2)
    causal_link_explanation: str = Field(min_length=3, max_length=600)
    remediation: str = Field(min_length=3, max_length=600)
    unconfirmed: Literal[True] = True

    @model_validator(mode="after")
    def _distinct_primitives(self) -> ChainExplanationOutput:
        if len(set(self.ordered_primitive_types)) != len(self.ordered_primitive_types):
            raise ValueError("CHAIN_EXPLANATION_PRIMITIVES_NOT_DISTINCT")
        return self


# --- Phase 2.1 controlled Authentication-testing gateway output contracts (server-selected) ------
#
# The strict schemas the gateway derives for the LEAD_ORCHESTRATOR delegation and the AUTHORIZATION
# _AGENT authentication-testing task types. As with the recon/cloud/chain contracts these are
# reference-only: the model may select only a registered authentication capability id, a registered
# target reference, a typed *authentication control class*, opaque account / invalid-candidate-set /
# positive-control references, and a bounded invalid-attempt count. There is NO field through which
# it can emit a username, passcode, credential value, raw request body, verdict, PASS/CONFIRMED,
# severity or lockout threshold. ``finding_domain`` is fixed ``AUTHENTICATION`` so an authentication
# finding stays semantically distinct from an authorization (BOLA/BFLA) finding, and every
# ``unconfirmed`` flag is fixed True so only the independent verifier may confirm. The literal alias
# values are kept in lockstep with aegis.multi_agent.authentication by a drift-guard test; they are
# duplicated here, not imported, so the isolated gateway process never imports the range inventory.
AuthCapabilityId = Literal["aegis.bank.auth_rate_limit_probe"]
_GwAuthControlClass = Literal[
    "CREDENTIAL_RATE_LIMIT",
    "ACCOUNT_LOCKOUT",
    "LOGIN_COOLDOWN",
]
# Opaque, symbolic references. None is a username, passcode or candidate value: the broker resolves
# each to a controller-owned synthetic value controller-side, and never to the model.
_GwAuthAccountRef = Literal["PRIMARY_SYNTHETIC_ACCOUNT"]
_GwAuthCandidateSetRef = Literal["INVALID_CANDIDATE_SET_A"]
_GwAuthPositiveControlRef = Literal["POSITIVE_CONTROL_CREDENTIAL"]
_GwAuthObservationKind = Literal[
    "LOGIN_ATTEMPT_RESPONSE",
    "RATE_LIMIT_SIGNAL_PRESENT",
    "RATE_LIMIT_SIGNAL_ABSENT",
    "POSITIVE_CONTROL_USABLE",
    "NO_FINDING",
    "INCOMPLETE_TOOL_ERROR",
]
_GwAuthDomain = Literal["AUTHENTICATION"]


class AuthenticationDelegationOutput(StrictModel):
    """DELEGATE_AUTHENTICATION_TEST (LEAD_ORCHESTRATOR): a typed hand-off to the auth agent.

    The lead references only the downstream agent, the finding domain, a registered authentication
    capability, a target reference and a typed authentication control class. It cannot express a
    URL, a username, a credential value, a verdict or severity. ``unconfirmed`` is fixed True.
    """

    to_agent: Literal["AUTHORIZATION_AGENT"] = "AUTHORIZATION_AGENT"
    finding_domain: _GwAuthDomain = "AUTHENTICATION"
    capability_id: AuthCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    control_class: _GwAuthControlClass
    rationale: str = Field(min_length=3, max_length=300)
    unconfirmed: Literal[True] = True


class GatewayAuthAttemptSelection(StrictModel):
    """Typed attempt-budget *selection* only. No username, passcode or candidate value here.

    The model selects the opaque account and invalid-candidate-set references, an optional positive
    -control reference, and how many invalid attempts to request. ``requested_invalid_attempts`` is
    schema-bounded and clamped again by the controller/broker, so the model can only ever request
    *fewer* attempts than the controller ceiling — never more. ``concurrency`` is fixed at 1.
    """

    method: Literal["POST"] = "POST"
    account_ref: _GwAuthAccountRef = "PRIMARY_SYNTHETIC_ACCOUNT"
    candidate_set_ref: _GwAuthCandidateSetRef = "INVALID_CANDIDATE_SET_A"
    positive_control_ref: _GwAuthPositiveControlRef | None = None
    requested_invalid_attempts: int = Field(ge=1, le=12)
    concurrency: Literal[1] = 1


class AuthenticationPlanOutput(StrictModel):
    """PLAN_AUTHENTICATION_TEST: select the registered auth capability and a bounded attempt set.

    The plan references only a registered authentication capability, an inventory target reference,
    a typed authentication control class and the typed attempt selection (opaque references + a
    bounded invalid-attempt count). It cannot express a URL, username, passcode, credential value,
    raw body, verdict or severity. ``unconfirmed`` is fixed True — only the verifier confirms.
    """

    finding_domain: _GwAuthDomain = "AUTHENTICATION"
    capability_id: AuthCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    control_class: _GwAuthControlClass
    attempt: GatewayAuthAttemptSelection
    rationale: str = Field(min_length=3, max_length=300)
    unconfirmed: Literal[True] = True


class AuthenticationInterpretationOutput(StrictModel):
    """INTERPRET_AUTHENTICATION_OBSERVATIONS: a bounded, reference-only reading of observations.

    It has no verdict, PASS, CONFIRMED or severity field: the agent cannot confirm an authentication
    control gap. ``unconfirmed`` is fixed True so the schema itself restates that only the
    independent verifier may confirm.
    """

    summary: str = Field(min_length=3, max_length=400)
    finding_domain: _GwAuthDomain = "AUTHENTICATION"
    salient_observation_kinds: list[_GwAuthObservationKind] = Field(
        default_factory=list, max_length=8
    )
    control_hypothesis: _GwAuthControlClass
    unconfirmed: Literal[True] = True


class AuthenticationSubmissionOutput(StrictModel):
    """SUBMIT_AUTHENTICATION_FOR_VERIFICATION: recommend independent verification, never confirm.

    The submission carries only references: the deterministic verifier authority, the finding
    domain, a registered capability id, a target reference and the typed authentication control
    class. There is deliberately no verdict field of any kind — the agent structurally cannot
    self-confirm, and ``unconfirmed`` (fixed True) restates that. (A ``confirmed`` field is
    intentionally absent: it would re-introduce a self-confirmation surface and, as a schema
    property name, trip the gateway's verdict-token sanitizer that keeps every outbound projection
    free of the confirmed/pass tokens.)
    """

    to_verifier: Literal["DETERMINISTIC_RANGE_VERIFIER"]
    finding_domain: _GwAuthDomain = "AUTHENTICATION"
    capability_id: AuthCapabilityId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    control_class: _GwAuthControlClass
    unconfirmed: Literal[True] = True
    rationale: str = Field(min_length=3, max_length=300)


class ModelUsage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class ModelResult(StrictModel):
    payload_json: str = Field(min_length=2, max_length=32_768)
    usage: ModelUsage


class AgentGatewayRequest(StrictModel):
    role: Literal[
        "LEAD_ORCHESTRATOR",
        "SURFACE_AGENT",
        "AUTHORIZATION_AGENT",
        "INJECTION_AGENT",
        "CHAIN_AGENT",
        "RECON_AGENT",
        "CLOUD_BOUNDARY_AGENT",
    ]
    task_type: Literal[
        "PLAN_SURFACE",
        "OBSERVE_SURFACE",
        "PLAN_AUTHORIZATION",
        "TEST_AUTHORIZATION",
        "SINGLE_AGENT_BOLA",
        "PLAN_RECON",
        "INTERPRET_RECON_OBSERVATIONS",
        "DELEGATE_RECON_HYPOTHESIS",
        "PLAN_CLOUD_BOUNDARY",
        "INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS",
        "SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION",
        "PLAN_ATTACK_CHAIN",
        "INTERPRET_CHAIN_STAGE",
        "SELECT_NEXT_CHAIN_STEP",
        "EXPLAIN_VERIFIED_CHAIN",
        # Phase 2.1 controlled authentication-testing task types.
        "DELEGATE_AUTHENTICATION_TEST",
        "PLAN_AUTHENTICATION_TEST",
        "INTERPRET_AUTHENTICATION_OBSERVATIONS",
        "SUBMIT_AUTHENTICATION_FOR_VERIFICATION",
    ]
    context: dict[str, Any]
    max_output_tokens: int = Field(ge=64, le=8192)


class AgentGatewayResponse(StrictModel):
    model: str = Field(min_length=1, max_length=200)
    payload_json: str = Field(min_length=2, max_length=32_768)
    usage: ModelUsage
    request_projection: AgentGatewayRequestProjection


class AgentGatewayRequestProjection(StrictModel):
    correlation_id: str = Field(pattern=r"^agreq-[a-f0-9]{24}$")
    projection_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role: AgentRole
    task_type: str = Field(pattern=r"^[A-Z_]+$", max_length=80)
    requested_model: str = Field(min_length=1, max_length=200)
    schema_identifier: str = Field(pattern=r"^[A-Za-z0-9_]+$", max_length=100)
    message_field_classifications: dict[
        str,
        Literal[
            "BOUNDED_SYSTEM_CONTRACT",
            "BOUNDED_REFERENCE_CONTEXT",
            "STRICT_OUTPUT_SCHEMA",
        ],
    ]
    context_field_names: list[str] = Field(max_length=40)
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    system_contract_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    redaction_status: Literal["CLEAN"]
    forbidden_categories_present: list[str] = Field(max_length=8)


class GatewayCallRecord(StrictModel):
    role: AgentRole
    task_type: str = Field(pattern=r"^[A-Z_]+$", max_length=80)
    request_projection: AgentGatewayRequestProjection
    validated_output: dict[str, Any]
    usage: ModelUsage
