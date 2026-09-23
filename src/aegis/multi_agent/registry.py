"""Role and capability policy registries. ZAP Active is deliberately absent."""

from __future__ import annotations

from dataclasses import dataclass

from aegis.multi_agent.contracts import AgentRole, ObservationType


@dataclass(frozen=True)
class RolePolicy:
    role: AgentRole
    system_contract: str
    observation_types: frozenset[ObservationType]
    capabilities: frozenset[str]
    output_contract: str


@dataclass(frozen=True)
class CapabilityPolicy:
    capability_id: str
    roles: frozenset[AgentRole]
    target_requests: int
    read_only: bool
    enabled: bool = True


ROLE_REGISTRY: dict[AgentRole, RolePolicy] = {
    AgentRole.LEAD_ORCHESTRATOR: RolePolicy(
        AgentRole.LEAD_ORCHESTRATOR,
        "Delegate typed tasks; never decide verdict, severity, authority, budget or cleanup.",
        frozenset({ObservationType.SURFACE, ObservationType.VERIFIER_SUMMARY}),
        frozenset(),
        "LeadTaskOutput",
    ),
    AgentRole.SURFACE_AGENT: RolePolicy(
        AgentRole.SURFACE_AGENT,
        "Interpret only controller-observed surface and return approved references.",
        frozenset({ObservationType.SURFACE}),
        frozenset({"aegis.surface.openapi"}),
        "SurfaceAgentOutput",
    ),
    AgentRole.AUTHORIZATION_AGENT: RolePolicy(
        AgentRole.AUTHORIZATION_AGENT,
        "Propose owner comparisons using only supplied aliases and resource references.",
        frozenset({ObservationType.SURFACE, ObservationType.AUTHORIZATION_COMPARISON}),
        # Surface observation is also granted to the equivalent single-agent baseline so both
        # paths receive the same envelope and spend the same target-request budget.
        frozenset({"aegis.surface.openapi", "aegis.authorization.compare"}),
        "AuthorizationAgentOutput",
    ),
    AgentRole.INJECTION_AGENT: RolePolicy(
        AgentRole.INJECTION_AGENT,
        # Phase 1.7-B: select only a registered payload class against a controller-approved "
        # (route, parameter); never author payload strings; never confirm a verdict.
        "Select a registered injection capability and payload class for a controller-approved "
        "parameter. Never author raw payloads, targets, or verdicts.",
        frozenset({ObservationType.RECON_INVENTORY, ObservationType.INJECTION_PROBE}),
        frozenset({"aegis.injection.xss_reflected", "aegis.injection.sql_boolean"}),
        "InjectionAgentOutput",
    ),
    AgentRole.RECON_AGENT: RolePolicy(
        AgentRole.RECON_AGENT,
        # Phase 1.7-C: select only registered recon capabilities and approved profiles; never author
        # a raw flag, template, policy, URL, header or payload; never confirm, PASS or set severity.
        "Select only registered recon capabilities and approved profiles against inventory "
        "references. Never author raw flags, templates, policies, URLs, headers or payloads; never "
        "confirm a vulnerability, emit PASS, severity, or a final finding.",
        frozenset({ObservationType.SURFACE, ObservationType.RECON_INVENTORY}),
        frozenset(
            {
                "aegis.surface.openapi",
                "aegis.recon.network_service_discovery",
                "aegis.recon.nuclei_reviewed_exposure",
                "aegis.recon.zap_passive_openapi",
            }
        ),
        "NormalizedReconReport",
    ),
    AgentRole.CLOUD_BOUNDARY_AGENT: RolePolicy(
        AgentRole.CLOUD_BOUNDARY_AGENT,
        # Phase 1.9: select only a registered cloud-boundary capability and a symbolic probe
        # destination against inventory references; never author a raw URL, credential, header or
        # body; never confirm a violation, emit PASS, severity, or a final finding.
        "Select only registered cloud-boundary capabilities and symbolic probe destinations "
        "against inventory references. Never author raw URLs, credentials, headers or bodies; "
        "never confirm a boundary violation, emit PASS, severity, or a final finding.",
        frozenset({ObservationType.SURFACE, ObservationType.RECON_INVENTORY}),
        frozenset({"aegis.surface.openapi", "aegis.cloud.metadata_boundary_probe"}),
        "CloudBoundaryInterpretationOutput",
    ),
    AgentRole.CHAIN_AGENT: RolePolicy(
        AgentRole.CHAIN_AGENT,
        # Phase 1.7-B: compose only already-approved bounded capabilities within one target scope;
        # never acquire a new capability, broaden scope on failure, or self-recurse.
        "Compose only already-registered recon and injection capabilities within one authorized "
        "target scope. Never acquire new capabilities or broaden scope on a failed step.",
        frozenset(
            {
                ObservationType.SURFACE,
                ObservationType.RECON_INVENTORY,
                ObservationType.INJECTION_PROBE,
                ObservationType.VERIFIER_SUMMARY,
            }
        ),
        frozenset(
            {
                "aegis.surface.openapi",
                "aegis.injection.xss_reflected",
                "aegis.injection.sql_boolean",
            }
        ),
        "ChainPlanOutput",
    ),
}

CAPABILITY_REGISTRY: dict[str, CapabilityPolicy] = {
    "aegis.surface.openapi": CapabilityPolicy(
        "aegis.surface.openapi",
        frozenset(
            {
                AgentRole.SURFACE_AGENT,
                AgentRole.AUTHORIZATION_AGENT,
                AgentRole.CHAIN_AGENT,
                AgentRole.RECON_AGENT,
            }
        ),
        1,
        True,
    ),
    "aegis.authorization.compare": CapabilityPolicy(
        "aegis.authorization.compare", frozenset({AgentRole.AUTHORIZATION_AGENT}), 3, True
    ),
    # Phase 1.7-B non-destructive detection probes. Each sends exactly one benign control request
    # and one controller-materialized probe request; the payload is never model-authored. The
    # independent deterministic range verifier, not this capability, decides CONFIRMED/PASS.
    "aegis.injection.xss_reflected": CapabilityPolicy(
        "aegis.injection.xss_reflected",
        frozenset({AgentRole.INJECTION_AGENT, AgentRole.CHAIN_AGENT}),
        2,
        False,
    ),
    "aegis.injection.sql_boolean": CapabilityPolicy(
        "aegis.injection.sql_boolean",
        frozenset({AgentRole.INJECTION_AGENT, AgentRole.CHAIN_AGENT}),
        2,
        False,
    ),
    # Catalog visibility only; not needed by the BOLA slice and never agent-authorized here.
    "aegis.nuclei.passive": CapabilityPolicy("aegis.nuclei.passive", frozenset(), 0, True),
    "aegis.zap.passive": CapabilityPolicy("aegis.zap.passive", frozenset(), 0, True),
    # Phase 1.7-C controlled Recon Agent capabilities. Network service discovery spends command
    # budget (a typed argv, never a shell); it makes no HTTP target request. The reviewed-exposure
    # and passive-OpenAPI capabilities reuse the Phase 1.2/1.3 pinned controllers; their alerts are
    # unconfirmed candidates only. None of these can confirm, PASS, or set severity.
    "aegis.recon.network_service_discovery": CapabilityPolicy(
        "aegis.recon.network_service_discovery", frozenset({AgentRole.RECON_AGENT}), 0, True
    ),
    "aegis.recon.nuclei_reviewed_exposure": CapabilityPolicy(
        "aegis.recon.nuclei_reviewed_exposure", frozenset({AgentRole.RECON_AGENT}), 4, True
    ),
    "aegis.recon.zap_passive_openapi": CapabilityPolicy(
        "aegis.recon.zap_passive_openapi", frozenset({AgentRole.RECON_AGENT}), 8, True
    ),
    # Phase 1.9 controlled Cloud Boundary Agent capability. It issues exactly one benign control
    # request and one bounded boundary probe against the synthetic aegis-cloud integration-check
    # surface (a typed HTTP request the broker renders shell-free, never a model-authored URL or
    # body). It never confirms, PASSes, or sets severity — only the independent deterministic range
    # verifier does, using controller-owned ground truth.
    "aegis.cloud.metadata_boundary_probe": CapabilityPolicy(
        "aegis.cloud.metadata_boundary_probe",
        frozenset({AgentRole.CLOUD_BOUNDARY_AGENT}),
        2,
        True,
    ),
}


def authorize(role: AgentRole, capability_id: str) -> CapabilityPolicy:
    capability = CAPABILITY_REGISTRY.get(capability_id)
    role_policy = ROLE_REGISTRY[role]
    if (
        capability is None
        or not capability.enabled
        or role not in capability.roles
        or capability_id not in role_policy.capabilities
    ):
        raise ValueError("CAPABILITY_NOT_AUTHORIZED")
    return capability
