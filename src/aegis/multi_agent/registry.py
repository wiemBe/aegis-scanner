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
        frozenset(
            {
                ObservationType.SURFACE,
                ObservationType.AUTHORIZATION_COMPARISON,
                ObservationType.AUTHENTICATION_PROBE,
            }
        ),
        # Surface observation is also granted to the equivalent single-agent baseline so both
        # paths receive the same envelope and spend the same target-request budget. Phase 2.0 adds
        # the bounded credential-backed internal-service access as the Stage-B authorization
        # primitive of the verified multi-primitive chain. Phase 2.1 adds the bounded authentication
        # rate-limit/lockout probe (an authentication control, distinct from the BOLA/BFLA ones).
        frozenset(
            {
                "aegis.surface.openapi",
                "aegis.authorization.compare",
                "aegis.cloud.internal_service_access",
                "aegis.bank.auth_rate_limit_probe",
            }
        ),
        "AuthorizationAgentOutput",
    ),
    AgentRole.INJECTION_AGENT: RolePolicy(
        AgentRole.INJECTION_AGENT,
        # Phase 1.7-B: select only a registered payload class against a controller-approved "
        # (route, parameter); never author payload strings; never confirm a verdict.
        "Select a registered injection capability and payload class for a controller-approved "
        "parameter. Never author raw payloads, targets, or verdicts.",
        frozenset({ObservationType.RECON_INVENTORY, ObservationType.INJECTION_PROBE}),
        # Phase 2.8-B adds the controller-owned bounded SQLMap capability (INJECTION_AGENT only).
        frozenset(
            {
                "aegis.injection.xss_reflected",
                "aegis.injection.sql_boolean",
                "aegis.injection.sqlmap",
            }
        ),
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
        # Phase 2.2 adds a separately registered, more aggressive adversary-simulation capability
        # (a bounded HTTP detection-control probe). It is NOT one of the default recon capabilities;
        # it is granted here so the existing RECON_AGENT can run the bounded adversary simulation
        # without minting a new AI role, and it stays subject to the same never-confirm boundary.
        # Phase 2.8-A adds the Recon Capability Pack: bounded HTTP probe / crawl / content discovery
        # / API-schema discovery / DNS discovery / TLS inspection. Each is a controller-owned Tool
        # Broker capability (not an AI agent); the model selects only a registered profile id and
        # stays subject to the same never-confirm boundary. SQLMap is deliberately NOT here — it
        # belongs to INJECTION_AGENT (Phase 2.8-B).
        frozenset(
            {
                "aegis.surface.openapi",
                "aegis.recon.network_service_discovery",
                "aegis.recon.nuclei_reviewed_exposure",
                "aegis.recon.zap_passive_openapi",
                "aegis.ops.detection_control_probe",
                "aegis.recon.http_probe",
                "aegis.recon.web_crawl",
                "aegis.recon.content_discovery",
                "aegis.recon.api_discovery",
                "aegis.recon.dns_discovery",
                "aegis.recon.tls_inspect",
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
        # Phase 2.0: the Chain Agent also composes the two cloud chain primitives (metadata boundary
        # probe -> credential-backed internal-service access) within one authorized target scope. It
        # only plans/interprets/explains over these; the Stage-A/Stage-B agents execute them.
        frozenset(
            {
                "aegis.surface.openapi",
                "aegis.injection.xss_reflected",
                "aegis.injection.sql_boolean",
                "aegis.cloud.metadata_boundary_probe",
                "aegis.cloud.internal_service_access",
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
        frozenset({AgentRole.CLOUD_BOUNDARY_AGENT, AgentRole.CHAIN_AGENT}),
        2,
        True,
    ),
    # Phase 2.0 Stage-B primitive: bounded credential-backed internal-service access. It issues one
    # benign control request and one credential-backed private-operation request against the
    # synthetic aegis-cloud surface (a typed HTTP pair the broker renders shell-free; the credential
    # is resolved broker-side from an opaque reference, never model-authored). It is not read-only
    # (it invokes a privileged synthetic operation) and it never confirms, PASSes or sets severity —
    # only the independent deterministic range verifier does, from controller-owned ground truth.
    "aegis.cloud.internal_service_access": CapabilityPolicy(
        "aegis.cloud.internal_service_access",
        frozenset({AgentRole.AUTHORIZATION_AGENT, AgentRole.CHAIN_AGENT}),
        2,
        False,
    ),
    # Phase 2.1 controlled authentication-testing capability. It issues one benign positive-control
    # login and a controller-clamped, bounded sequence of invalid credential attempts (plus one post
    # -burst control) against the synthetic aegis-bank login surface — a typed HTTP attempt set the
    # broker renders shell-free at concurrency 1, never a model-authored username, passcode or body.
    # It is not read-only (it mutates the account lockout/attempt state) and it never confirms,
    # PASSes or sets severity — only the independent deterministic range verifier does, from
    # controller-owned ground truth. ``target_requests`` bounds the total attempt budget the
    # capability may ever render.
    "aegis.bank.auth_rate_limit_probe": CapabilityPolicy(
        "aegis.bank.auth_rate_limit_probe",
        frozenset({AgentRole.AUTHORIZATION_AGENT}),
        12,
        False,
    ),
    # Phase 2.2 controlled adversary-simulation capability (bounded HTTP detection-control probe).
    # It issues a controller-owned deterministic sequence — one recognizable baseline probe and one
    # controller-approved alternate probe variant — against the synthetic aegis-ops protected
    # operation, at concurrency 1, following no redirects. The model authors no route, header,
    # payload, source address, decoy or count; the controller-owned profile owns the whole sequence.
    # It is not read-only (the alternate probe may reach the protected operation's sentinel effect)
    # and it never confirms, PASSes or sets severity — only the independent deterministic range
    # verifier does, from controller-owned ground truth. ``target_requests`` bounds the total probe
    # budget the capability may ever render.
    "aegis.ops.detection_control_probe": CapabilityPolicy(
        "aegis.ops.detection_control_probe",
        frozenset({AgentRole.RECON_AGENT}),
        4,
        False,
    ),
    # Phase 2.8-A Recon Capability Pack. Each is a controller-owned bounded discovery tool the
    # RECON_AGENT may select only by registered profile id (never a raw flag, URL, wordlist, header,
    # concurrency, timeout, redirect policy or target override). All are read-only; none can
    # confirm, PASS or set severity. ``target_requests`` bounds the request ceiling the controller
    # profile may ever render. Container/live execution is NOT_EVALUATED this phase.
    "aegis.recon.http_probe": CapabilityPolicy(
        "aegis.recon.http_probe", frozenset({AgentRole.RECON_AGENT}), 4, True
    ),
    "aegis.recon.web_crawl": CapabilityPolicy(
        "aegis.recon.web_crawl", frozenset({AgentRole.RECON_AGENT}), 25, True
    ),
    "aegis.recon.content_discovery": CapabilityPolicy(
        "aegis.recon.content_discovery", frozenset({AgentRole.RECON_AGENT}), 32, True
    ),
    "aegis.recon.api_discovery": CapabilityPolicy(
        "aegis.recon.api_discovery", frozenset({AgentRole.RECON_AGENT}), 6, True
    ),
    "aegis.recon.dns_discovery": CapabilityPolicy(
        "aegis.recon.dns_discovery", frozenset({AgentRole.RECON_AGENT}), 8, True
    ),
    "aegis.recon.tls_inspect": CapabilityPolicy(
        "aegis.recon.tls_inspect", frozenset({AgentRole.RECON_AGENT}), 2, True
    ),
    # Phase 2.8-B controller-owned bounded SQLMap capability (INJECTION_AGENT only; never recon).
    # The model selects only a registered profile id; the controller renders a deterministic,
    # shell-free argv. Default profiles exclude file access, OS shell, unrestricted dumping,
    # persistence and out-of-scope crawling; the canary-impact profile permits only a bounded single
    # -row synthetic read in the synthetic range. It is not read-only (it exercises the param)
    # and it never confirms, PASSes or sets severity — the independent verifier adjudicates worker
    # evidence against controller ground truth. Container/live execution is NOT_EVALUATED.
    "aegis.injection.sqlmap": CapabilityPolicy(
        "aegis.injection.sqlmap", frozenset({AgentRole.INJECTION_AGENT}), 160, False
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
