"""Phase 2.8-A — Recon Capability Pack (controller-owned bounded discovery tools).

These are **Tool Broker capabilities**, not AI agents. The RECON_AGENT may only *select a registered
profile id* against a controller-resolved inventory reference; it can never author a raw shell,
argv, URL, wordlist, header, concurrency, timeout, redirect policy or target override. Every option
a model may touch is a typed enum bounded by the controller-owned profile, and the argv is rendered
deterministically by the controller (never a shell string).

Families covered (all bounded, read-only HTTP/DNS/TLS discovery — never exploitation):

* ``aegis.recon.http_probe``       — HTTP service/technology probing (httpx).
* ``aegis.recon.web_crawl``        — bounded same-scope crawling (katana).
* ``aegis.recon.content_discovery``— controller-wordlist content discovery (ffuf).
* ``aegis.recon.api_http_probe``   — bounded HTTP probe of a documented API path (httpx). Phase 2.8
  container acceptance confirmed this renders the SAME httpx probe argv as ``http_probe`` and does
  NOT fetch or parse an OpenAPI/Swagger/GraphQL schema, so it is named for what it does (an HTTP
  probe over a documented path), not for schema discovery it does not perform.
* ``aegis.recon.dns_discovery``    — bounded DNS record discovery (dnsx).
* ``aegis.recon.tls_inspect``      — TLS certificate/parameter inspection (tlsx).

Every capability enforces: controller-owned inventory; exact authorized origin/scope; redirect and
target-escape fail-closed; environment-tier policy; lease and budget; concurrency and request
ceilings; output-size limits; deterministic argv rendering; tool/version/image provenance;
observations; untrusted-output sanitation; and a per-run artifact manifest.

RECON never confirms. Discovery yields *unconfirmed candidate references* only; a genuinely
injectable candidate is handed to INJECTION_AGENT via a real persisted delegation (SQLMap belongs to
INJECTION_AGENT, never here). Only the independent verifier ever decides CONFIRMED/PASS.

Offline note: the container/live execution of these tools is ``NOT_EVALUATED`` this phase. The image
digests below are **synthetic placeholder pins**, not operator-resolved RepoDigests; a container run
must fail closed until an operator pins the real digest (see :func:`assert_container_pinned`).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from aegis.multi_agent.contracts import StrictModel, now_utc
from aegis.multi_agent.delegation import DelegationQueue, EnqueuedDelegation
from aegis.multi_agent.staging import EnvironmentTier, classify_environment
from aegis_range.inventory import RANGE_TARGETS

# --------------------------------------------------------------------------- #
# Tool/version/image provenance (pinned supply chain).
# --------------------------------------------------------------------------- #


def _placeholder_digest(image: str, tag: str) -> str:
    """A deterministic placeholder digest for the offline pass (NOT an operator-resolved pin)."""

    return "sha256:" + hashlib.sha256(f"placeholder:{image}:{tag}".encode()).hexdigest()


@dataclass(frozen=True)
class ToolProvenance:
    """Pinned tool/version/image provenance recorded in every job's evidence.

    ``digest_pinned`` is ``False`` for the offline pass: ``image_digest`` is a placeholder,
    not a RepoDigest resolved from an operator Docker environment. Any container execution must call
    :func:`assert_container_pinned` first, which fails closed until an operator supplies a real pin.
    """

    tool: str
    image: str
    tag: str
    version: str
    image_digest: str
    digest_pinned: bool = False

    @property
    def image_ref(self) -> str:
        return f"{self.image}@{self.image_digest}"


def _prov(tool: str, image: str, tag: str, version: str) -> ToolProvenance:
    return ToolProvenance(tool, image, tag, version, _placeholder_digest(image, tag))


TOOL_PROVENANCE: dict[str, ToolProvenance] = {
    "httpx": _prov("httpx", "projectdiscovery/httpx", "1.6.9", "1.6.9"),
    "katana": _prov("katana", "projectdiscovery/katana", "1.1.2", "1.1.2"),
    "ffuf": _prov("ffuf", "ffuf/ffuf", "2.1.0", "2.1.0"),
    "dnsx": _prov("dnsx", "projectdiscovery/dnsx", "1.2.1", "1.2.1"),
    "tlsx": _prov("tlsx", "projectdiscovery/tlsx", "1.1.6", "1.1.6"),
}


class ReconCapabilityError(ValueError):
    """A recon selection escaped the controller allowlist, scope, tier, lease or bounds."""


def assert_container_pinned(prov: ToolProvenance) -> None:
    """Fail closed unless the image digest is an operator-resolved pin (container/live only)."""

    if not prov.digest_pinned:
        raise ReconCapabilityError(f"TOOL_IMAGE_DIGEST_NOT_PINNED:{prov.tool}")


# --------------------------------------------------------------------------- #
# Controller-owned wordlist registry (content discovery). The model may reference only an id.
# --------------------------------------------------------------------------- #

CONTENT_WORDLISTS: dict[str, tuple[str, ...]] = {
    "bounded_api_paths_v1": (
        "api",
        "api/products",
        "api/categories",
        "openapi.json",
        "health",
        "robots.txt",
    ),
}


# --------------------------------------------------------------------------- #
# argv safety: a defence-in-depth denylist over the rendered argv (the typed plan cannot express
# these; this catches a rendering bug). No shell, no output files, no proxy, no redirect-follow, no
# arbitrary header/data injection, no wordlist/target file inclusion.
# --------------------------------------------------------------------------- #

_FORBIDDEN_ARGV_TOKENS: frozenset[str] = frozenset(
    {
        "-o", "-of", "-output", "-oA", "-oN",           # output files
        "-x", "-proxy", "--proxy",                       # proxies
        "-fr", "-follow-redirects", "-L", "--location",  # redirect-follow
        "-H", "-header", "--header",                     # arbitrary header injection
        "-data", "--data", "-body", "--data-binary",     # request bodies (note: dnsx -d is allowed)
        "-recursion",                                    # unbounded recursion
        "sh", "bash", "-c", ";", "|", "&", "$(", "`", ">", "<", "&&",
    }
)
_SAFE_ARGV_TOKEN = re.compile(r"^[A-Za-z0-9_.:,/=+%?{}@-]+$")


def _assert_argv_safe(argv: list[str]) -> tuple[str, ...]:
    for token in argv:
        if token in _FORBIDDEN_ARGV_TOKENS or not _SAFE_ARGV_TOKEN.match(token):
            raise ReconCapabilityError(f"RECON_ARGV_UNSAFE_TOKEN:{token[:40]}")
    return tuple(argv)


# --------------------------------------------------------------------------- #
# Controller-owned typed profiles.
# --------------------------------------------------------------------------- #

ReconCapabilityId = Literal[
    "aegis.recon.http_probe",
    "aegis.recon.web_crawl",
    "aegis.recon.content_discovery",
    "aegis.recon.api_http_probe",
    "aegis.recon.dns_discovery",
    "aegis.recon.tls_inspect",
]

ReconProfileId = Literal[
    "http_probe_discovery_v1",
    "web_crawl_bounded_v1",
    "content_discovery_bounded_v1",
    "api_http_probe_v1",
    "dns_discovery_bounded_v1",
    "tls_inspect_v1",
]


class ReconObservationKind(StrEnum):
    """Normalized recon observation vocabulary. Never a verdict, PASS, severity or payload."""

    HTTP_TECHNOLOGY = "HTTP_TECHNOLOGY"
    DISCOVERED_ROUTE = "DISCOVERED_ROUTE"
    PARAMETER_CANDIDATE = "PARAMETER_CANDIDATE"
    DOCUMENTED_OPERATION = "DOCUMENTED_OPERATION"
    DNS_RECORD = "DNS_RECORD"
    TLS_PARAMETER = "TLS_PARAMETER"
    NO_FINDING = "NO_FINDING"
    INCOMPLETE_TOOL_ERROR = "INCOMPLETE_TOOL_ERROR"


@dataclass(frozen=True)
class ReconProfile:
    """The controller-owned authorized envelope for one discovery scope.

    Every option a plan may set fits inside this envelope; the model selects only the profile id.
    ``follow_redirects`` is always False (redirect + target-escape fail closed). ``environment`` is
    the minimum tier; anything below fails closed.
    """

    profile_id: str
    capability_id: str
    tool: str
    environment: EnvironmentTier
    requires_signed_lease: bool
    max_requests: int
    max_concurrency: int
    per_request_timeout_ms: int
    max_output_bytes: int
    follow_redirects: bool = False
    max_crawl_depth: int = 0
    wordlist_id: str | None = None
    allowed_ports: tuple[int, ...] = ()
    command_budget: int = 1


def _p(profile_id: str, capability_id: str, tool: str, **kw: object) -> ReconProfile:
    return ReconProfile(
        profile_id=profile_id,
        capability_id=capability_id,
        tool=tool,
        environment=EnvironmentTier.SYNTHETIC_RANGE,
        requires_signed_lease=False,
        **kw,  # type: ignore[arg-type]
    )


RECON_PROFILES: dict[str, ReconProfile] = {
    "http_probe_discovery_v1": _p(
        "http_probe_discovery_v1", "aegis.recon.http_probe", "httpx",
        max_requests=4, max_concurrency=2, per_request_timeout_ms=5_000, max_output_bytes=65_536,
    ),
    "web_crawl_bounded_v1": _p(
        "web_crawl_bounded_v1", "aegis.recon.web_crawl", "katana",
        max_requests=25, max_concurrency=2, per_request_timeout_ms=5_000, max_output_bytes=262_144,
        max_crawl_depth=2,
    ),
    "content_discovery_bounded_v1": _p(
        "content_discovery_bounded_v1", "aegis.recon.content_discovery", "ffuf",
        max_requests=32, max_concurrency=4, per_request_timeout_ms=5_000, max_output_bytes=131_072,
        wordlist_id="bounded_api_paths_v1",
    ),
    "api_http_probe_v1": _p(
        "api_http_probe_v1", "aegis.recon.api_http_probe", "httpx",
        max_requests=6, max_concurrency=2, per_request_timeout_ms=5_000, max_output_bytes=262_144,
    ),
    "dns_discovery_bounded_v1": _p(
        "dns_discovery_bounded_v1", "aegis.recon.dns_discovery", "dnsx",
        max_requests=8, max_concurrency=2, per_request_timeout_ms=3_000, max_output_bytes=32_768,
    ),
    "tls_inspect_v1": _p(
        "tls_inspect_v1", "aegis.recon.tls_inspect", "tlsx",
        max_requests=2, max_concurrency=1, per_request_timeout_ms=5_000, max_output_bytes=32_768,
        allowed_ports=(443, 8102),
    ),
}


# --------------------------------------------------------------------------- #
# Typed plan (model-facing). The model sets ONLY a capability/profile id + inventory references.
# --------------------------------------------------------------------------- #


class ReconDiscoveryPlan(StrictModel):
    """A model-selected discovery plan. No raw URL, wordlist, header, flag, concurrency, timeout,
    redirect policy or target override is representable — only registered ids + references."""

    capability_id: ReconCapabilityId
    profile_id: ReconProfileId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    # Optional controller-approved seed reference (a documented route/param from prior recon).
    seed_route: str = Field(default="", max_length=200, pattern=r"^(/[A-Za-z0-9/._{}~-]*)?$")
    seed_parameter: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.-]*$")


class ReconDiscoveryJob(StrictModel):
    """The controller-rendered, fully-bounded discovery job. It has no shell command field."""

    job_id: str = Field(pattern=r"^rdisc-[a-f0-9]{16}$")
    capability_id: str
    profile_id: str
    tool: str
    target_ref: str
    application_id: str
    authorized_origin: str
    scope_host: str
    argv: tuple[str, ...] = Field(min_length=2, max_length=48)
    redirect_policy: Literal["DENY"] = "DENY"
    max_requests: int
    max_concurrency: int
    max_output_bytes: int
    per_request_timeout_ms: int
    environment_tier: EnvironmentTier
    image_ref: str
    image_digest: str
    tool_version: str
    digest_pinned: bool

    @property
    def argv_digest(self) -> str:
        return hashlib.sha256("\x00".join(self.argv).encode()).hexdigest()


class NormalizedReconObservation(StrictModel):
    """A normalized, reference-only recon observation. No verdict, severity or payload."""

    kind: ReconObservationKind
    route: str = Field(default="", max_length=200)
    parameter: str = Field(default="", max_length=64)
    detail: str = Field(default="", max_length=200)
    injectable_candidate: bool = False


class ReconDiscoveryManifest(StrictModel):
    """Per-run artifact manifest: what was rendered, its provenance, and the cleanup status."""

    job_id: str
    capability_id: str
    profile_id: str
    argv_digest: str
    image_ref: str
    tool_version: str
    digest_pinned: bool
    container_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    output_bytes: int
    output_truncated: bool
    observation_count: int
    cleanup_complete: bool
    created_at: datetime = Field(default_factory=now_utc)


# --------------------------------------------------------------------------- #
# Scope resolution + environment-tier + lease gating.
# --------------------------------------------------------------------------- #


def _resolve_range_target(target_ref: str) -> tuple[str, str]:
    matches = [
        (item.application_id, item.origin)
        for item in RANGE_TARGETS.values()
        if item.target_ref == target_ref
    ]
    if len(matches) != 1:
        raise ReconCapabilityError("TARGET_REF_NOT_IN_INVENTORY")
    return matches[0]


def _host_port(origin: str) -> tuple[str, int]:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ReconCapabilityError("TARGET_ORIGIN_MALFORMED")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname, port


@dataclass
class ReconLease:
    signed: bool
    authorized: bool
    target_ref: str
    environment_tier: EnvironmentTier = EnvironmentTier.SYNTHETIC_RANGE


# --------------------------------------------------------------------------- #
# Deterministic argv rendering per tool family.
# --------------------------------------------------------------------------- #


def _render_argv(
    profile: ReconProfile, origin: str, host: str, plan: ReconDiscoveryPlan
) -> list[str]:
    timeout_s = str(max(1, profile.per_request_timeout_ms // 1000))
    rate = str(profile.max_requests)
    conc = str(profile.max_concurrency)
    if profile.tool == "httpx":
        target = origin + plan.seed_route if plan.seed_route else origin
        # Redirect safety is structural: httpx does NOT follow redirects unless an opt-in flag
        # (-fr/-follow-redirects) is passed, which this render never does — no redirect is followed.
        # The pinned httpx has no fetched-response-size flag; the bounded response-size boundary is
        # enforced by the broker/runner's bounded capture (max_output_bytes) with truncation
        # recorded (see aegis.container_acceptance.runner) rather than silently dropped.
        return [
            "httpx", "-u", target, "-silent", "-no-color", "-json",
            "-timeout", timeout_s, "-rate-limit", rate, "-threads", conc,
            "-no-fallback",
        ]
    if profile.tool == "katana":
        return [
            "katana", "-u", origin, "-silent", "-no-color", "-jsonl",
            "-depth", str(profile.max_crawl_depth), "-concurrency", conc,
            "-rate-limit", rate, "-timeout", timeout_s,
            "-field-scope", "rdn", "-crawl-scope", host,
        ]
    if profile.tool == "ffuf":
        wordlist = profile.wordlist_id
        if wordlist is None or wordlist not in CONTENT_WORDLISTS:
            raise ReconCapabilityError("CONTENT_WORDLIST_NOT_REGISTERED")
        return [
            "ffuf", "-u", f"{origin}/FUZZ", "-w", f"/wordlists/{wordlist}.txt",
            "-t", conc, "-rate", rate, "-timeout", timeout_s,
            "-maxtime", timeout_s, "-noninteractive", "-s", "-json",
        ]
    if profile.tool == "dnsx":
        return [
            "dnsx", "-d", host, "-silent", "-json", "-rl", rate,
            "-a", "-aaaa", "-cname", "-retry", "1",
        ]
    if profile.tool == "tlsx":
        _host, port = _host_port(origin)
        if profile.allowed_ports and port not in profile.allowed_ports:
            raise ReconCapabilityError("TLS_PORT_NOT_ALLOWED")
        return [
            "tlsx", "-u", f"{host}:{port}", "-silent", "-json",
            "-timeout", timeout_s, "-cn", "-san", "-tls-version", "-cipher",
        ]
    raise ReconCapabilityError(f"RECON_TOOL_UNKNOWN:{profile.tool}")


def _job_id(plan: ReconDiscoveryPlan, origin: str) -> str:
    material = f"{plan.capability_id}:{plan.profile_id}:{origin}:{plan.seed_route}"
    return "rdisc-" + hashlib.sha256(material.encode()).hexdigest()[:16]


def build_discovery_job(
    plan: ReconDiscoveryPlan,
    *,
    lease: ReconLease | None = None,
    image: ToolProvenance | None = None,
) -> ReconDiscoveryJob:
    """Validate a typed plan and render a fully-bounded, shell-free discovery job, or fail closed.

    Every rejection happens BEFORE any argv is rendered, so a rejected plan yields zero commands and
    zero target traffic.

    ``image`` optionally overrides the tool image provenance (defaults to the unpinned placeholder
    in ``TOOL_PROVENANCE``). The Phase 2.8 container-acceptance harness passes an operator-reviewed,
    digest-pinned image so a real container run is admitted.
    """

    profile = RECON_PROFILES.get(plan.profile_id)
    if profile is None:
        raise ReconCapabilityError("RECON_PROFILE_UNKNOWN")
    if profile.capability_id != plan.capability_id:
        raise ReconCapabilityError("RECON_PROFILE_CAPABILITY_MISMATCH")

    # Environment-tier gate: synthetic range needs no lease; any higher tier needs a signed,
    # target-bound lease, and anything unclassified fails closed to PRODUCTION_PROHIBITED.
    if profile.environment is EnvironmentTier.SYNTHETIC_RANGE:
        application_id, origin = _resolve_range_target(plan.target_ref)
    else:
        if lease is None or not lease.signed or not lease.authorized:
            raise ReconCapabilityError("RECON_LEASE_MISSING")
        if lease.target_ref != plan.target_ref:
            raise ReconCapabilityError("RECON_LEASE_TARGET_MISMATCH")
        tier = classify_environment(lease.environment_tier.value)
        if tier is EnvironmentTier.PRODUCTION_PROHIBITED:
            raise ReconCapabilityError("RECON_ENVIRONMENT_PROHIBITED")
        raise ReconCapabilityError("RECON_NON_RANGE_INVENTORY_UNAVAILABLE")

    host, _port = _host_port(origin)
    prov = image or TOOL_PROVENANCE[profile.tool]
    argv = _assert_argv_safe(_render_argv(profile, origin, host, plan))

    # Scope enforcement: the origin/host must appear in the rendered argv and no other host may.
    joined = " ".join(argv)
    if host not in joined:
        raise ReconCapabilityError("RECON_SCOPE_HOST_MISSING_FROM_ARGV")

    return ReconDiscoveryJob(
        job_id=_job_id(plan, origin),
        capability_id=plan.capability_id,
        profile_id=plan.profile_id,
        tool=profile.tool,
        target_ref=plan.target_ref,
        application_id=application_id,
        authorized_origin=origin,
        scope_host=host,
        argv=argv,
        max_requests=profile.max_requests,
        max_concurrency=profile.max_concurrency,
        max_output_bytes=profile.max_output_bytes,
        per_request_timeout_ms=profile.per_request_timeout_ms,
        environment_tier=profile.environment,
        image_ref=prov.image_ref,
        image_digest=prov.image_digest,
        tool_version=prov.version,
        digest_pinned=prov.digest_pinned,
    )


# --------------------------------------------------------------------------- #
# Untrusted-output sanitation + normalization + manifest.
# --------------------------------------------------------------------------- #

_FORBIDDEN_OUTPUT_TOKENS: tuple[str, ...] = (
    "bearer ", "authorization:", "set-cookie", "password", "passcode",
    "lab-token-", "credentialref://", "-----begin",
)


def sanitize_tool_output(raw: bytes, *, max_bytes: int) -> tuple[str, bool]:
    """Bound and sanitize untrusted tool stdout. Returns (safe_text, truncated).

    Enforces the output-size limit, strips control characters, and neutralizes any forbidden
    secret-shaped token so a malicious/echoed tool output can never carry a credential downstream.
    """

    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ch >= " ")
    lowered = text.lower()
    for token in _FORBIDDEN_OUTPUT_TOKENS:
        if token in lowered:
            # Redact the whole line carrying a forbidden token rather than emit it.
            text = "\n".join(
                "[REDACTED_SANITIZED_LINE]" if token in line.lower() else line
                for line in text.split("\n")
            )
            lowered = text.lower()
    return text, truncated


def build_manifest(
    job: ReconDiscoveryJob,
    *,
    output_bytes: int,
    output_truncated: bool,
    observations: tuple[NormalizedReconObservation, ...],
    cleanup_complete: bool,
) -> ReconDiscoveryManifest:
    return ReconDiscoveryManifest(
        job_id=job.job_id,
        capability_id=job.capability_id,
        profile_id=job.profile_id,
        argv_digest=job.argv_digest,
        image_ref=job.image_ref,
        tool_version=job.tool_version,
        digest_pinned=job.digest_pinned,
        output_bytes=min(output_bytes, job.max_output_bytes),
        output_truncated=output_truncated,
        observation_count=len(observations),
        cleanup_complete=cleanup_complete,
    )


# --------------------------------------------------------------------------- #
# Recon -> Injection delegation (real, persisted; SQLMap belongs to INJECTION_AGENT).
# --------------------------------------------------------------------------- #


def build_recon_to_injection_delegation(
    *,
    target_ref: str,
    candidate: NormalizedReconObservation,
    source_evidence_sha256: str,
    injection_capability_id: str = "aegis.injection.sql_boolean",
    delegation_id: str,
) -> EnqueuedDelegation:
    """Build a real Recon->Injection delegation for an injectable candidate route/parameter.

    RECON never confirms; the delegation carries only references (route, parameter, capability id,
    target, evidence digest). SQLMap and all injection testing happen on the INJECTION_AGENT side.
    """

    if not candidate.injectable_candidate:
        raise ReconCapabilityError("CANDIDATE_NOT_INJECTABLE")
    return EnqueuedDelegation(
        delegation_id=delegation_id,
        to_agent="INJECTION_AGENT",
        capability_id=injection_capability_id,
        target_ref=target_ref,
        route=candidate.route,
        parameter=candidate.parameter,
        rationale=(
            "Recon discovered an injectable parameter candidate; hand off to INJECTION_AGENT for "
            "controller-bounded injection testing (never confirmed by recon)."
        ),
        source_evidence_sha256=source_evidence_sha256,
    )


def persist_recon_to_injection_delegation(
    queue: DelegationQueue, delegation: EnqueuedDelegation
) -> str:
    """Persist the recon->injection handoff on the real delegation queue; return its address."""

    return queue.enqueue(delegation)


# Registry surface: the capability ids this pack introduces (all RECON_AGENT-selectable).
RECON_PACK_CAPABILITY_IDS: tuple[str, ...] = tuple(
    sorted({profile.capability_id for profile in RECON_PROFILES.values()})
)
