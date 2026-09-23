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
        "Registered for future work; no capability is currently authorized.",
        frozenset({ObservationType.SURFACE}),
        frozenset(),
        "UNIMPLEMENTED",
    ),
    AgentRole.CHAIN_AGENT: RolePolicy(
        AgentRole.CHAIN_AGENT,
        "Registered for future work; no capability is currently authorized.",
        frozenset({ObservationType.SURFACE}),
        frozenset(),
        "UNIMPLEMENTED",
    ),
}

CAPABILITY_REGISTRY: dict[str, CapabilityPolicy] = {
    "aegis.surface.openapi": CapabilityPolicy(
        "aegis.surface.openapi",
        frozenset({AgentRole.SURFACE_AGENT, AgentRole.AUTHORIZATION_AGENT}),
        1,
        True,
    ),
    "aegis.authorization.compare": CapabilityPolicy(
        "aegis.authorization.compare", frozenset({AgentRole.AUTHORIZATION_AGENT}), 3, True
    ),
    # Catalog visibility only; not needed by the BOLA slice and never agent-authorized here.
    "aegis.nuclei.passive": CapabilityPolicy("aegis.nuclei.passive", frozenset(), 0, True),
    "aegis.zap.passive": CapabilityPolicy("aegis.zap.passive", frozenset(), 0, True),
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
