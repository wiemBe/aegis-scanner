"""Deterministic engine capability + profile catalog (Phase 1.1).

This catalog is the single source of truth for what each engine may do. It is a set of frozen
dataclasses defined in code; there is no setter, no API and no field on any model the AI can author
that mutates it. The AI can only NAME a capability that already exists here (via the existing
:mod:`aegis.registry` projection); it can never add, widen or re-classify one.

Phase 1.1 enabled only ``AEGIS_NATIVE``. Phase 1.2 adds ONE enabled Nuclei profile,
``NUCLEI_LAB_SAFE_HTTP_V1``, bound to one capability backed by a pinned, admitted, signed template
and a deterministic Aegis verifier. A catalog-enabled profile is still inert until the operator
enables the Nuclei adapter and the isolated runner attests READY. Two Nuclei capabilities are
catalogued ONLY so that requests for them are rejected with a precise reason (state-changing HTTP,
non-HTTP protocol); no profile references them.

Phase 1.3 adds ONE enabled ZAP profile, ``ZAP_LAB_PASSIVE_OPENAPI_V1``, bound to one PASSIVE
capability: a projected, read-only OpenAPI import analysed by the admitted passive-rule manifest,
with a deterministic Aegis verifier as the only promotion authority. It is inert until the operator
enables the ZAP adapter and the isolated runner attests READY. A ZAP active-scan capability is
catalogued ONLY to be refused. Burp DAST remains disabled and fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

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
    SecurityEngine.NUCLEI: "nuclei-adapter/1.2.0",
    SecurityEngine.ZAP: "zap-adapter/1.3.0",
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
    # Phase 1.2 (additive, defaulted so Phase 1.1 entries are unchanged). ``protocol`` is the only
    # network protocol the capability may use; ``verified_severity`` is the Aegis-owned severity a
    # deterministic verifier assigns on VERIFIED — never an engine's claimed severity.
    protocol: str = "http"
    verified_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"

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
            "protocol": self.protocol,
            "verified_severity": self.verified_severity,
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
        allowed_environments=(
            EngineEnvironment.SYNTHETIC_LAB,
            EngineEnvironment.SYNTHETIC_RANGE,
        ),
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
    # Phase 1.2: the single operational Nuclei capability. One anonymous read-only GET per admitted
    # template (budget = the manifest's declared max requests), a deterministic Aegis verifier
    # (``aegis.scm_verifier``) as the only promotion authority, and an Aegis-owned MEDIUM severity.
    # It is classified ACTIVE honestly: it sends a read-only probe the application did not link to.
    EngineCapability(
        capability_id="nuclei_scm_metadata_exposure_v1",
        engine=SecurityEngine.NUCLEI,
        title="Source-control metadata exposure (Nuclei, signed template, read-only)",
        activity=EngineActivity.ACTIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE", "OPERATOR_ENABLE_NUCLEI"),
        request_budget=1,
        concurrency_budget=1,
        time_budget_ms=30_000,
        evidence_types=("NUCLEI_EXECUTION_CARD", "VERIFIER_PROBE_CARD"),
        verification_policy=VerificationPolicy.DETERMINISTIC_AEGIS_VERIFIER,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        protocol="http",
        verified_severity="MEDIUM",
    ),
    # Catalogued ONLY to be refused: requesting either yields a precise, audited rejection before
    # any runner call. No profile references them and they can never become executable.
    EngineCapability(
        capability_id="nuclei_http_state_changing_v0",
        engine=SecurityEngine.NUCLEI,
        title="State-changing HTTP templates (denied)",
        activity=EngineActivity.ACTIVE,
        supported_methods=("POST", "PUT", "PATCH", "DELETE"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=True,
        required_approvals=("NEVER_APPROVED",),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=(),
        verification_policy=VerificationPolicy.NONE,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        protocol="http",
    ),
    EngineCapability(
        capability_id="nuclei_network_protocol_v0",
        engine=SecurityEngine.NUCLEI,
        title="Non-HTTP (network/TCP) templates (denied)",
        activity=EngineActivity.ACTIVE,
        supported_methods=(),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("NEVER_APPROVED",),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=(),
        verification_policy=VerificationPolicy.NONE,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        protocol="network",
    ),
    # Disabled catalog entries. They exist so the console can describe the planned integrations
    # honestly; no enabled profile references them and no adapter executes them. The Nuclei v0
    # entry is the retired Phase 1.1 placeholder, kept disabled for record continuity.
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
    # Retired Phase 1.1 ZAP placeholder, kept disabled for record continuity (no profile uses it).
    EngineCapability(
        capability_id="zap_passive_scan_v0",
        engine=SecurityEngine.ZAP,
        title="ZAP passive scan (Phase 1.1 placeholder, retired)",
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
    # Phase 1.3: the single operational ZAP capability. ZAP imports a controller-projected, local
    # OpenAPI file of approved anonymous GET/HEAD operations (one request each, budget = the
    # projection's operation count, at most 4) and passively analyses the responses with the
    # admitted rule manifest only. The deterministic Aegis header verifier
    # (``aegis.zap_verifier``) is the only promotion authority and assigns the Aegis-owned LOW
    # severity.
    EngineCapability(
        capability_id="zap_passive_header_openapi_v1",
        engine=SecurityEngine.ZAP,
        title="Missing anti-MIME-sniffing header (ZAP passive, projected OpenAPI, read-only)",
        activity=EngineActivity.PASSIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=("SYNTHETIC_LAB_SCOPE", "OPERATOR_ENABLE_ZAP"),
        request_budget=4,
        concurrency_budget=1,
        time_budget_ms=120_000,
        evidence_types=("ZAP_EXECUTION_CARD", "ZAP_ALERT_CARD", "VERIFIER_PROBE_CARD"),
        verification_policy=VerificationPolicy.DETERMINISTIC_AEGIS_VERIFIER,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        protocol="http",
        verified_severity="LOW",
    ),
    # Phase 1.5: the single operational ZAP ACTIVE capability. One reviewed release reflected-XSS
    # rule (40012) mutates exactly one bounded projected query parameter on one anonymous, read-only
    # GET endpoint in the synthetic lab, under a single-use activation lease, the active scope guard
    # and a fresh deterministic Aegis verifier. Payloads are ZAP-generated inside the admitted
    # policy; the scanner alert is TOOL_REPORTED only.
    EngineCapability(
        capability_id="zap_active_reflected_xss_v1",
        engine=SecurityEngine.ZAP,
        title="Reflected XSS (ZAP active, one rule, one projected query parameter, read-only)",
        activity=EngineActivity.ACTIVE,
        supported_methods=("GET", "HEAD"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=False,
        required_approvals=(
            "SYNTHETIC_LAB_SCOPE",
            "OPERATOR_ENABLE_ZAP",
            "OPERATOR_ACTIVE_SCAN_LEASE",
        ),
        request_budget=200,
        concurrency_budget=1,
        time_budget_ms=300_000,
        evidence_types=("ZAP_EXECUTION_CARD", "ZAP_ALERT_CARD", "VERIFIER_PROBE_CARD"),
        verification_policy=VerificationPolicy.DETERMINISTIC_AEGIS_VERIFIER,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        protocol="http",
        verified_severity="HIGH",
    ),
    # Catalogued ONLY to be refused: broad/arbitrary active scanning is never approved.
    EngineCapability(
        capability_id="zap_active_scan_v0",
        engine=SecurityEngine.ZAP,
        title="ZAP active scan (denied)",
        activity=EngineActivity.ACTIVE,
        supported_methods=("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"),
        allowed_environments=(EngineEnvironment.SYNTHETIC_LAB,),
        requires_authentication=False,
        state_changing_possible=True,
        required_approvals=("NEVER_APPROVED",),
        request_budget=0,
        concurrency_budget=1,
        time_budget_ms=1,
        evidence_types=(),
        verification_policy=VerificationPolicy.NONE,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        protocol="http",
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
        profile_id="NUCLEI_LAB_SAFE_HTTP_V1",
        engine=SecurityEngine.NUCLEI,
        title="Nuclei — lab-safe HTTP (pinned, signed, read-only)",
        capability_ids=("nuclei_scm_metadata_exposure_v1",),
        enabled=True,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        description=(
            "Nuclei v3.11.1 (pinned binary) executing only the admitted, signed template set "
            "aegis-nuclei-lab-safe-http-v1 against inventory-resolved synthetic-lab targets. "
            "Results enter as TOOL_REPORTED; only the deterministic Aegis verifier promotes."
        ),
        isolation_boundary=(
            "Separate nuclei-runner container: non-root, read-only root filesystem, bounded tmpfs, "
            "all capabilities dropped, no shell, no Docker socket, no host mount, no credential. "
            "Reached only over the internal engine-rpc network; reaches only the synthetic target "
            "network; no internet, planner or model-gateway access. Fixed argv, no shell."
        ),
    ),
    EngineProfile(
        profile_id="nuclei-passive-synthetic",
        engine=SecurityEngine.NUCLEI,
        title="Nuclei — Phase 1.1 placeholder (retired, disabled)",
        capability_ids=("nuclei_passive_http_templates_v0",),
        enabled=False,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.NUCLEI],
        description="Retired Phase 1.1 placeholder. Superseded by NUCLEI_LAB_SAFE_HTTP_V1.",
        isolation_boundary=(
            "SUPERSEDED: Nuclei runs as a separate, non-privileged sidecar on an isolated network "
            "segment with egress restricted to the approved synthetic origin only; templates come "
            "from a pinned, reviewed template set (no remote template fetch); no credential is "
            "mounted unless a reviewed synthetic profile is provisioned into the sidecar boundary; "
            "no shell passthrough — the adapter builds the invocation from the typed job only."
        ),
    ),
    EngineProfile(
        profile_id="ZAP_LAB_PASSIVE_OPENAPI_V1",
        engine=SecurityEngine.ZAP,
        title="ZAP — lab passive OpenAPI (pinned, projected, read-only)",
        capability_ids=("zap_passive_header_openapi_v1",),
        enabled=True,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        description=(
            "ZAP 2.17.0 (pinned image digest and add-on inventory) running one fixed Automation "
            "Framework plan: import a controller-projected local OpenAPI of approved GET/HEAD "
            "operations and passively analyse the responses with the admitted rule manifest. No "
            "active scan, spider, script, authentication or remote OpenAPI source. Alerts enter "
            "as TOOL_REPORTED; only the deterministic Aegis verifier promotes."
        ),
        isolation_boundary=(
            "Separate zap-runner container built from the pinned ZAP image: non-root, read-only "
            "root filesystem, bounded tmpfs for all ZAP state, all capabilities dropped, no shell, "
            "no Docker socket, host mount, credential or published port. Reached only over the "
            "internal zap-rpc network; its only outbound network contains just the scope "
            "guard, which forwards only armed, allowlisted GET/HEAD requests to the synthetic "
            "origin within a hard budget. Fixed argv, no shell."
        ),
    ),
    EngineProfile(
        profile_id="ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        engine=SecurityEngine.ZAP,
        title="ZAP — lab active reflected XSS (pinned, one rule, one query parameter)",
        capability_ids=("zap_active_reflected_xss_v1",),
        enabled=True,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        description=(
            "ZAP 2.17.0 (a separate pinned image with the eight passive add-ons plus "
            "ascanrules-release-83 and its neutralised forced dependencies oast/database) running "
            "one fixed Automation Framework plan: import a controller-projected local OpenAPI "
            "of one GET operation with one bounded query parameter, then an activeScan whose "
            "inline policy disables every rule but the admitted reflected-XSS rule 40012 "
            "(strength LOW, threshold MEDIUM). No spider, script, authentication or remote source. "
            "Requires a single-use activation lease. Alerts enter as TOOL_REPORTED; only the "
            "deterministic Aegis XSS verifier promotes."
        ),
        isolation_boundary=(
            "Separate active zap-runner container from the pinned Phase 1.5 image: non-root, "
            "read-only root filesystem, bounded tmpfs, all capabilities dropped, no shell, no "
            "Docker socket, host mount, credential or published port. Reached only over the "
            "internal active-rpc network; its only outbound network contains just the active scope "
            "guard, which in ACTIVE mode forwards only armed GET/HEAD requests to the one approved "
            "origin+path, permits a query string only on the projected parameter, and enforces a "
            "hard measured request budget. An emergency stop kills the scan mid-flight."
        ),
    ),
    EngineProfile(
        profile_id="zap-passive-synthetic",
        engine=SecurityEngine.ZAP,
        title="ZAP — Phase 1.1 placeholder (retired, disabled)",
        capability_ids=("zap_passive_scan_v0",),
        enabled=False,
        environment=EngineEnvironment.SYNTHETIC_LAB,
        adapter_version=ADAPTER_VERSIONS[SecurityEngine.ZAP],
        description="Retired Phase 1.1 placeholder. Superseded by ZAP_LAB_PASSIVE_OPENAPI_V1.",
        isolation_boundary=(
            "SUPERSEDED: ZAP runs as an isolated daemon reached over a pinned internal API; egress "
            "is restricted to the approved origin; active scan is disabled — only passive analysis "
            "of controller-driven traffic is permitted."
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
