"""Deterministic engine capability + profile catalog (Phase 1.1).

This catalog is the single source of truth for what each engine may do. It is a set of frozen
dataclasses defined in code; there is no setter, no API and no field on any model the AI can author
that mutates it. The AI can only NAME a capability that already exists here (via the existing
:mod:`aegis.registry` projection); it can never add, widen or re-classify one.

Only ``AEGIS_NATIVE`` has an enabled profile in Phase 1.1. Nuclei, ZAP and Burp DAST have catalog
entries so the console can describe them honestly, but their profiles are ``enabled=False`` and
their adapters fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis.engine.contracts import (
    ENGINE_KERNEL_VERSION,
    EngineActivity,
    EngineEnvironment,
    SecurityEngine,
    VerificationPolicy,
)

# Adapter versions are per-engine and independent of the kernel version. They are recorded on every
# job, execution, evidence item and normalized finding so provenance survives an adapter upgrade.
ADAPTER_VERSIONS: dict[SecurityEngine, str] = {
    SecurityEngine.AEGIS_NATIVE: "aegis-native/1.1.0",
    SecurityEngine.NUCLEI: "nuclei-adapter/0.0.0-disabled",
    SecurityEngine.ZAP: "zap-adapter/0.0.0-disabled",
    SecurityEngine.BURP_DAST: "burp-dast-adapter/0.0.0-disabled",
}


@dataclass(frozen=True)
class EngineCapability:
    """A deterministic description of one engine capability. Immutable and model-inaccessible."""

    capability_id: str
    engine: SecurityEngine
    title: str
    activity: EngineActivity
    supported_methods: tuple[str, ...]
    allowed_environments: tuple[EngineEnvironment, ...]
    requires_authentication: bool
    state_changing_possible: bool
    required_approvals: tuple[str, ...]
    # Deterministic budgets.
    request_budget: int
    concurrency_budget: int
    time_budget_ms: int
    evidence_types: tuple[str, ...]
    verification_policy: VerificationPolicy
    adapter_version: str

    def projection(self) -> dict[str, object]:
        """Non-sensitive projection for the console. No behaviour, no attack sequence."""
        return {
            "capability_id": self.capability_id,
            "engine": self.engine.value,
            "title": self.title,
            "activity": self.activity.value,
            "supported_methods": list(self.supported_methods),
            "allowed_environments": [e.value for e in self.allowed_environments],
            "requires_authentication": self.requires_authentication,
            "state_changing_possible": self.state_changing_possible,
            "required_approvals": list(self.required_approvals),
            "budgets": {
                "requests": self.request_budget,
                "concurrency": self.concurrency_budget,
                "time_ms": self.time_budget_ms,
            },
            "evidence_types": list(self.evidence_types),
            "verification_policy": self.verification_policy.value,
            "adapter_version": self.adapter_version,
        }


@dataclass(frozen=True)
class EngineProfile:
    """A named binding of an engine to a set of catalog capabilities, with an enabled flag."""

    profile_id: str
    engine: SecurityEngine
    title: str
    capability_ids: tuple[str, ...]
    enabled: bool
    environment: EngineEnvironment
    adapter_version: str
    description: str = ""
    # A short, honest note describing the FUTURE credential + network isolation boundary. It is
    # documentation-only for the disabled adapters and never provisions anything.
    isolation_boundary: str = ""

    def projection(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "engine": self.engine.value,
            "title": self.title,
            "capability_ids": list(self.capability_ids),
            "enabled": self.enabled,
            "environment": self.environment.value,
            "adapter_version": self.adapter_version,
            "description": self.description,
            "isolation_boundary": self.isolation_boundary,
        }


# --- capability catalog --------------------------------------------------------------------------
# AEGIS_NATIVE object-authorization read comparison. This is the ONE capability with a deterministic
# Aegis verifier, so it is the only one with a DETERMINISTIC_AEGIS_VERIFIER policy and the only
# capability an enabled profile references in Phase 1.1.

CAPABILITY_CATALOG: tuple[EngineCapability, ...] = (
    EngineCapability(
        capability_id="bola_object_read_v1",
        engine=SecurityEngine.AEGIS_NATIVE,
        title="Object-level authorization read comparison (BOLA)",
        activity=EngineActivity.ACTIVE,
        supported_methods=("GET", "HEAD", "OPTIONS"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=True,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE",),
        request_budget=8,
        concurrency_budget=1,
        time_budget_ms=90_000,
        evidence_types=("API_EVIDENCE_CARD",),
        verification_policy=VerificationPolicy.DETERMINISTIC_AEGIS_VERIFIER,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.AEGIS_NATIVE],
    ),
    # Disabled catalog entries. They exist so the console can describe the planned integrations
    # honestly; no enabled profile references them and no adapter executes them in Phase 1.1.
    EngineCapability(
        capability_id="nuclei_passive_http_templates_v0",
        engine=SecurityEngine.NUCLEI,
        title="Nuclei templated passive HTTP checks (planned)",
        activity=EngineActivity.PASSIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE", "OPERATOR_ENABLE_NUCLEI"),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=("NUCLEI_TEMPLATE_MATCH",),
        verification_policy=VerificationPolicy.HUMAN_REVIEW_REQUIRED,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
    ),
    EngineCapability(
        capability_id="zap_passive_scan_v0",
        engine=SecurityEngine.ZAP,
        title="ZAP passive scan (planned)",
        activity=EngineActivity.PASSIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE", "OPERATOR_ENABLE_ZAP"),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=("ZAP_ALERT",),
        verification_policy=VerificationPolicy.HUMAN_REVIEW_REQUIRED,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
    ),
    EngineCapability(
        capability_id="burp_dast_passive_v0",
        engine=SecurityEngine.BURP_DAST,
        title="Burp DAST passive audit (planned)",
        activity=EngineActivity.PASSIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE", "OPERATOR_ENABLE_BURP"),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=("BURP_ISSUE",),
        verification_policy=VerificationPolicy.HUMAN_REVIEW_REQUIRED,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.BURP_DAST],
    ),
)

_CAPABILITY_BY_ID: dict[str, EngineCapability] = {c.capability_id: c for c in CAPABILITY_CATALOG}


# --- profile catalog -----------------------------------------------------------------------------

PROFILE_CATALOG: tuple[EngineProfile, ...] = (
    EngineProfile(
        profile_id="aegis-native-bola-synthetic",
        engine=SecurityEngine.AEGIS_NATIVE,
        title="Aegis Native — synthetic BOLA",
        capability_ids=("bola_object_read_v1",),
        enabled=True,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.AEGIS_NATIVE],
        description=(
            "The migrated Phase 0.8 read-only object-authorization path. Executes controller-"
            "compiled read-only requests against the authorized synthetic lab; the deterministic "
            "Aegis verifier is the sole authority for confirmation."
        ),
        isolation_boundary=(
            "In-process. Synthetic credentials are resolved only inside the executor connector "
            "boundary; the control plane holds no credential and reaches only the allowlisted lab "
            "origin with deny-all egress otherwise."
        ),
    ),
    EngineProfile(
        profile_id="nuclei-passive-synthetic",
        engine=SecurityEngine.NUCLEI,
        title="Nuclei — passive templates (disabled)",
        capability_ids=("nuclei_passive_http_templates_v0",),
        enabled=False,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        description="Planned Phase 1.2 integration. Not installed, not connected, fail-closed.",
        isolation_boundary=(
            "FUTURE: Nuclei runs as a separate, non-privileged sidecar on an isolated network "
            "segment with egress restricted to the approved synthetic origin only; templates come "
            "from a pinned, reviewed template set (no remote template fetch); no credential is "
            "mounted unless a reviewed synthetic profile is provisioned into the sidecar boundary; "
            "no shell passthrough — the adapter builds the invocation from the typed job only."
        ),
    ),
    EngineProfile(
        profile_id="zap-passive-synthetic",
        engine=SecurityEngine.ZAP,
        title="ZAP — passive scan (disabled)",
        capability_ids=("zap_passive_scan_v0",),
        enabled=False,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        description="Planned integration. Not installed, not connected, fail-closed.",
        isolation_boundary=(
            "FUTURE: ZAP runs as an isolated daemon reached over a pinned internal API; egress is "
            "restricted to the approved origin; the ZAP API key lives only inside the ZAP "
            "connector boundary; active scan is disabled — only passive analysis of "
            "controller-driven traffic is permitted."
        ),
    ),
    EngineProfile(
        profile_id="burp-dast-passive-synthetic",
        engine=SecurityEngine.BURP_DAST,
        title="Burp DAST — passive audit (disabled)",
        capability_ids=("burp_dast_passive_v0",),
        enabled=False,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.BURP_DAST],
        description="Planned integration. Not installed, not connected, no Burp MCP, fail-closed.",
        isolation_boundary=(
            "FUTURE: Burp runs behind its own connector with credentials confined to that "
            "boundary; the Burp MCP surface is NOT invoked; egress is restricted to the approved "
            "origin; only passive audit of controller-driven traffic is permitted and active scan "
            "stays disabled."
        ),
    ),
)

_PROFILE_BY_ID: dict[str, EngineProfile] = {p.profile_id: p for p in PROFILE_CATALOG}


def get_engine_capability(capability_id: str) -> EngineCapability | None:
    return _CAPABILITY_BY_ID.get(capability_id)


def get_engine_profile(profile_id: str) -> EngineProfile | None:
    return _PROFILE_BY_ID.get(profile_id)


def profiles_for_engine(engine: SecurityEngine) -> tuple[EngineProfile, ...]:
    return tuple(p for p in PROFILE_CATALOG if p.engine is engine)


def enabled_profiles() -> tuple[EngineProfile, ...]:
    return tuple(p for p in PROFILE_CATALOG if p.enabled)


def catalog_projection() -> dict[str, object]:
    return {
        "kernel_version": ENGINE_KERNEL_VERSION,
        "capabilities": [c.projection() for c in CAPABILITY_CATALOG],
        "profiles": [p.projection() for p in PROFILE_CATALOG],
    }
