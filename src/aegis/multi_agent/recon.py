"""Phase 1.7-C controlled Recon Agent capabilities.

This module upgrades the Phase 1.7-B ``HTTP_API_SURFACE_RECON`` role into a controlled Recon Agent
with four *registered* capabilities:

* ``aegis.recon.network_service_discovery`` -- a typed, low-to-full Nmap TCP/UDP service-discovery
  plan against the synthetic Docker range. The model only *selects* a registered profile and a
  bounded set of typed options; it never authors a raw flag, template, URL, host, header or
  payload. :func:`build_nmap_job` renders the typed plan into a validated argv array with no shell
  interpretation, or rejects it fail-closed before any command is produced.
* ``aegis.recon.nuclei_reviewed_exposure`` -- reuses the Phase 1.2 controller (``build_nuclei_job``)
  against its pinned, signed template manifest. Nothing is duplicated here.
* ``aegis.recon.zap_passive_openapi`` -- reuses the Phase 1.3 passive controller (``build_zap_job``)
  against its admitted rule/plan. Passive only; no active scan, no agent-authored configuration.
* ``aegis.surface.openapi`` -- the existing documented HTTP/API surface inspection.

Design invariants (do not weaken):

* The Recon Agent receives inventory *references*, never arbitrary origins or IP addresses.
* It selects only registered capabilities and approved profiles; it cannot write raw Nmap flags,
  Nuclei templates, ZAP policies, URLs, headers or payloads.
* It cannot confirm a vulnerability and cannot emit PASS, severity or a final finding. It produces
  typed, bounded observations and hypotheses only. The independent deterministic range verifier
  remains the sole confirming authority.
* It has no access to credentials, answer keys or scenario mode.

Deliberate, categorical refusals (a policy decision, not a missing feature): source spoofing, decoy
scans, fragmentation/evasion experiments, and credentialed brute-force are *representable* in the
plan schema but are always rejected pre-execution with zero traffic. In a range where the operator
owns both endpoints these techniques add no detection capability; their only transferable function
is defeating a third party's attribution, so this lab does not build them. They fail closed exactly
as an out-of-scope target does.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field

from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentRole,
    AgentTask,
    BudgetUsage,
    StrictModel,
)
from aegis.multi_agent.injection import HOSTILE_INSTRUCTION_MARKERS
from aegis.multi_agent.registry import authorize
from aegis_range.inventory import RANGE_TARGETS

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aegis.engine.nuclei import NucleiAdapterResult, NucleiEngineJob
    from aegis.engine.zap import ZapAdapterResult, ZapEngineJob

    # An async executor runs one reused, controller-built job on its attested runner and returns the
    # recon-facing outcome. It is injected by the harness; the broker never constructs it.
    ReconRunnerExecutor = Callable[[object], Awaitable["ReconExecutionOutcome"]]

# Honest capability label for the upgraded role (see docs/phase-1.7-controlled-recon.md).
RECON_AGENT_CLASS = "CONTROLLED_RECON_AGENT"

CAP_NETWORK_SERVICE_DISCOVERY = "aegis.recon.network_service_discovery"
CAP_NUCLEI_REVIEWED_EXPOSURE = "aegis.recon.nuclei_reviewed_exposure"
CAP_ZAP_PASSIVE_OPENAPI = "aegis.recon.zap_passive_openapi"
CAP_HTTP_API_SURFACE_RECON = "aegis.surface.openapi"

RECON_CAPABILITIES: frozenset[str] = frozenset(
    {
        CAP_NETWORK_SERVICE_DISCOVERY,
        CAP_NUCLEI_REVIEWED_EXPOSURE,
        CAP_ZAP_PASSIVE_OPENAPI,
        CAP_HTTP_API_SURFACE_RECON,
    }
)

# Pinned tool/image supply chain for the isolated Nmap worker. The digest is an immutable
# RepoDigest resolved from the operator's Docker environment (2026-09-23, linux/arm64) and recorded
# in evidence; the worker is always referenced by ``NMAP_IMAGE_REF`` (name@digest), never by a
# mutable tag at run time. The ``:7.98`` tag resolved to this same digest at resolution time.
NMAP_TOOL_IMAGE = "instrumentisto/nmap"
NMAP_TOOL_TAG = "7.98"
NMAP_TOOL_VERSION = "7.98"
NMAP_TOOL_DIGEST = "sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827"
NMAP_IMAGE_REF = f"{NMAP_TOOL_IMAGE}@{NMAP_TOOL_DIGEST}"
# The image entrypoint is ``/usr/bin/nmap`` and its default user is root; the controller overrides
# the user per job (see ``nmap_run_profile``). ``NMAP_BINARY`` is the argv[0] used for local
# rendering/validation; when running the container it is dropped (the entrypoint supplies it).
NMAP_BINARY = "nmap"

# NSE script IDs the controller admits. A plan may reference only these; an unknown id fails closed.
ADMITTED_NSE_SCRIPT_IDS: frozenset[str] = frozenset(
    {
        "banner",
        "http-title",
        "http-headers",
        "http-methods",
        "ssl-cert",
        "vulners",
    }
)

# argv tokens that must never appear. The typed plan cannot express them; this denylist is a
# defence-in-depth assertion over the rendered argv so a rendering bug can never emit evasion,
# spoofing, output-file or scripting-shell flags.
_FORBIDDEN_ARGV_TOKENS: frozenset[str] = frozenset(
    {
        "-D",
        "-S",
        "--spoof-mac",
        "--source-port",
        "-g",
        "-f",
        "--mtu",
        "--data",
        "--data-string",
        "--data-length",
        "--ip-options",
        "--proxies",
        "--script-args",
        "-iL",
        "-iR",
        "--exclude",
        "-oN",
        "-oG",
        "-oS",
        "-oA",
        "--interactive",
        "--resume",
    }
)

_SAFE_ARGV_TOKEN = re.compile(r"^[A-Za-z0-9_.:,/=+-]+$")


class ReconRejection(ValueError):
    """Raised when a recon selection escapes the controller allowlist, scope, or lease."""


class ReconObservationKind(StrEnum):
    """The strict, typed recon observation vocabulary. Nothing else is emittable."""

    DISCOVERED_SERVICE = "DISCOVERED_SERVICE"
    HTTP_TECHNOLOGY = "HTTP_TECHNOLOGY"
    DOCUMENTED_OPERATION = "DOCUMENTED_OPERATION"
    PARAMETER_CANDIDATE = "PARAMETER_CANDIDATE"
    NUCLEI_CANDIDATE = "NUCLEI_CANDIDATE"
    ZAP_PASSIVE_CANDIDATE = "ZAP_PASSIVE_CANDIDATE"
    NO_FINDING = "NO_FINDING"
    INCOMPLETE_TOOL_ERROR = "INCOMPLETE_TOOL_ERROR"


# ---------------------------------------------------------------------------
# Typed Nmap scan planning (model selects; controller renders argv, never a shell command).
# ---------------------------------------------------------------------------

TcpPortSpec = Literal["DISCOVERY_TOP_100", "TOP_1000", "FULL_65535"]
UdpPortSpec = Literal["NONE", "TOP_50", "FULL_65535"]
DiscoveryStrategy = Literal["TCP_CONNECT", "TCP_SYN"]
TimingProfile = Literal["T2", "T3", "T4"]
NseCategory = Literal["DISCOVERY", "VERSION", "VULN", "SAFE", "DEFAULT"]
NmapProfileId = Literal["RANGE_FULL_RECON", "AUTHORIZED_ENV_RECON"]

_TCP_PORT_FLAG: dict[str, str] = {
    "DISCOVERY_TOP_100": "--top-ports=100",
    "TOP_1000": "--top-ports=1000",
    "FULL_65535": "-p-",
}
_UDP_PORT_FLAG: dict[str, str] = {
    "TOP_50": "--top-ports=50",
    "FULL_65535": "-p-",
}
_TIMING_FLAG: dict[str, str] = {"T2": "-T2", "T3": "-T3", "T4": "-T4"}


class NmapJobKind(StrEnum):
    """Each recon plan expands into one or more single-purpose jobs, each its own argv."""

    TCP_DISCOVERY = "TCP_DISCOVERY"
    UDP_DISCOVERY = "UDP_DISCOVERY"
    SERVICE_VERSION_NSE = "SERVICE_VERSION_NSE"
    OS_DETECTION = "OS_DETECTION"


class NmapPrivilege(StrEnum):
    """The minimum container privilege a job needs, determined experimentally for this image.

    ``UNPRIVILEGED`` runs as non-root uid 65534 with ``cap_drop: ALL`` and no added capability
    (TCP connect scan, service/version detection, NSE). ``RAW_SOCKET`` runs as root inside the
    container with ``cap_drop: ALL`` + only ``NET_RAW`` (SYN scan, UDP scan, OS detection) — nmap
    requires uid 0 for raw sockets, and NET_RAW alone as non-root is *not* sufficient. RAW_SOCKET is
    granted only for that job, never to the general agent runtime.
    """

    UNPRIVILEGED = "UNPRIVILEGED"
    RAW_SOCKET = "RAW_SOCKET"


@dataclass(frozen=True)
class NmapProfile:
    """The authorized envelope for a scan scope. Every option in a plan must fit inside it.

    ``allow_evasion`` / ``allow_credentialed`` are False in every shipped profile: those techniques
    are unsupported in Phase 1.7-C recon (see :class:`NmapScanPlan`). The fields exist so the
    boundary is explicit and auditable; they are not an architectural prohibition on a future
    dedicated capability enabling them under its own authority.
    """

    profile_id: str
    environment: str
    requires_signed_lease: bool
    allow_tcp: bool
    allow_udp: bool
    max_tcp: str
    max_udp: str
    allow_syn: bool
    allow_os_detection: bool
    allow_traceroute: bool
    max_version_intensity: int
    allowed_nse: frozenset[str]
    allowed_timing: frozenset[str]
    max_rate_pps: int
    per_job_timeout_ms: int
    allow_evasion: bool = False
    allow_credentialed: bool = False
    command_budget: int = 4


_TCP_BREADTH_ORDER: dict[str, int] = {"DISCOVERY_TOP_100": 0, "TOP_1000": 1, "FULL_65535": 2}
_UDP_BREADTH_ORDER: dict[str, int] = {"NONE": 0, "TOP_50": 1, "FULL_65535": 2}


NMAP_PROFILES: dict[str, NmapProfile] = {
    # Full authorized recon, permitted ONLY against controller-owned synthetic-range targets.
    "RANGE_FULL_RECON": NmapProfile(
        profile_id="RANGE_FULL_RECON",
        environment="SYNTHETIC_RANGE",
        requires_signed_lease=False,
        allow_tcp=True,
        allow_udp=True,
        max_tcp="FULL_65535",
        max_udp="FULL_65535",
        allow_syn=True,
        allow_os_detection=True,
        allow_traceroute=True,
        max_version_intensity=9,
        allowed_nse=frozenset({"DISCOVERY", "VERSION", "VULN", "SAFE", "DEFAULT"}),
        allowed_timing=frozenset({"T2", "T3", "T4"}),
        max_rate_pps=2000,
        per_job_timeout_ms=120_000,
    ),
    # Operator-admitted non-range targets. This lab ships NO signed inventory + lease binding, so
    # every AUTHORIZED_ENV_RECON request fails closed until an operator admits a target out of band.
    "AUTHORIZED_ENV_RECON": NmapProfile(
        profile_id="AUTHORIZED_ENV_RECON",
        environment="AUTHORIZED_INVENTORY",
        requires_signed_lease=True,
        allow_tcp=True,
        allow_udp=True,
        max_tcp="TOP_1000",
        max_udp="TOP_50",
        allow_syn=True,
        allow_os_detection=True,
        allow_traceroute=True,
        max_version_intensity=7,
        allowed_nse=frozenset({"DISCOVERY", "VERSION", "SAFE", "DEFAULT"}),
        allowed_timing=frozenset({"T2", "T3"}),
        max_rate_pps=500,
        per_job_timeout_ms=90_000,
    ),
}


class NmapScanPlan(StrictModel):
    """Model-authored scan *selection*. It contains no raw flag, host, URL, header or payload.

    ``evasion_experiments`` and ``credentialed_scripts`` are representable so the phase boundary is
    explicit and testable; :func:`build_nmap_bundle` rejects any plan that populates them with an
    ``…_UNSUPPORTED_IN_PHASE_1_7C`` code (pre-execution, zero traffic). They are unavailable to the
    Recon role and the current lease and reserved for future dedicated capabilities (credentialed
    brute-force → an Authentication Testing capability; spoofing/decoy/fragmentation/evasion → an
    Adversary Simulation capability); they are not architecturally prohibited.
    """

    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    profile_id: NmapProfileId
    transports: list[Literal["TCP", "UDP"]] = Field(min_length=1, max_length=2)
    tcp_port_spec: TcpPortSpec = "TOP_1000"
    udp_port_spec: UdpPortSpec = "NONE"
    discovery_strategy: DiscoveryStrategy = "TCP_CONNECT"
    version_detection: bool = True
    version_intensity: int = Field(default=5, ge=0, le=9)
    os_detection: bool = False
    traceroute: bool = False
    timing_profile: TimingProfile = "T3"
    nse_categories: list[NseCategory] = Field(default_factory=list, max_length=5)
    nse_script_ids: list[str] = Field(default_factory=list, max_length=8)
    evasion_experiments: list[str] = Field(default_factory=list, max_length=8)
    credentialed_scripts: list[str] = Field(default_factory=list, max_length=8)


@dataclass(frozen=True)
class ScanLease:
    """An operator-issued authorization binding a plan to a target for AUTHORIZED_ENV_RECON."""

    target_ref: str
    authorized: bool
    signed: bool


class NmapReconJob(StrictModel):
    """One typed, validated, single-purpose Nmap job. Built ONLY by :func:`build_nmap_bundle`.

    It has no shell command field: :func:`render_nmap_argv` deterministically renders it into an
    argv list. ``host`` and ``ports`` are controller-resolved (from the inventory and from a prior
    discovery job's observed open ports), never from the model. ``image_ref`` pins the tool supply
    chain by digest. ``privilege`` records the minimum container privilege the job needs.
    """

    job_id: str = Field(pattern=r"^nmapjob-[a-f0-9]{16}$")
    kind: NmapJobKind
    privilege: NmapPrivilege
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    application_id: str = Field(pattern=r"^aegis-[a-z0-9-]+$")
    profile_id: NmapProfileId
    host: str = Field(pattern=r"^[a-z0-9.-]{1,120}$")
    argv: tuple[str, ...] = Field(min_length=2, max_length=32)
    ports: tuple[int, ...] = Field(default=(), max_length=64)
    timing_profile: TimingProfile
    max_rate_pps: int = Field(ge=1, le=100_000)
    timeout_ms: int = Field(ge=1_000, le=600_000)
    image_ref: str
    image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    created_by: Literal["CONTROLLER"] = "CONTROLLER"


@dataclass
class NmapJobBundle:
    """The controller-owned expansion of one recon plan into single-purpose jobs.

    Each job has an independent argv, timeout and rate budget, and its own result/error
    classification when executed. The follow-up jobs (version/NSE, OS detection) may be re-derived
    against the open ports a prior discovery job reported via :func:`refine_followups`.
    """

    target_ref: str
    application_id: str
    host: str
    profile_id: str
    image_ref: str
    image_digest: str
    jobs: list[NmapReconJob] = field(default_factory=list)

    def by_kind(self, kind: NmapJobKind) -> NmapReconJob | None:
        return next((j for j in self.jobs if j.kind is kind), None)

    @property
    def total_command_budget(self) -> int:
        return len(self.jobs)


def nmap_run_profile(job: NmapReconJob) -> dict[str, object]:
    """The minimum container run flags for a job's privilege. Consumed by the executor.

    UNPRIVILEGED → non-root uid 65534, no added capability. RAW_SOCKET → uid 0 inside the container
    with ``cap_add: NET_RAW`` only (uid 0 is required by nmap for raw sockets; NET_RAW alone as
    non-root is insufficient in this image). Both drop ALL other capabilities.
    """

    if job.privilege is NmapPrivilege.RAW_SOCKET:
        return {"user": "0:0", "cap_drop": ["ALL"], "cap_add": ["NET_RAW"]}
    return {"user": "65534:65534", "cap_drop": ["ALL"], "cap_add": []}


def _host_of(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ReconRejection("TARGET_ORIGIN_MALFORMED")
    return parsed.hostname


def _resolve_range_target(target_ref: str) -> tuple[str, str]:
    matches = [
        (item.application_id, item.origin)
        for item in RANGE_TARGETS.values()
        if item.target_ref == target_ref
    ]
    if len(matches) != 1:
        raise ReconRejection("TARGET_REF_NOT_IN_INVENTORY")
    return matches[0]


def _assert_argv_safe(argv: list[str]) -> tuple[str, ...]:
    for token in argv:
        if token in _FORBIDDEN_ARGV_TOKENS or not _SAFE_ARGV_TOKEN.match(token):
            raise ReconRejection("NMAP_ARGV_UNSAFE_TOKEN")
    return tuple(argv)


def _common_bounds(profile: NmapProfile, plan: NmapScanPlan) -> list[str]:
    """Timing, rate and host-timeout flags shared by every job. All bounded and nmap-accepted."""

    return [
        _TIMING_FLAG[plan.timing_profile],
        "--max-rate",
        str(profile.max_rate_pps),
        "--host-timeout",
        f"{profile.per_job_timeout_ms // 1000}s",
    ]


def _tail(host: str) -> list[str]:
    # No name resolution, no host discovery, XML to stdout. No output-file/interactive/resume flag.
    return ["-n", "-Pn", "-oX", "-", host]


def _ports_args(ports: tuple[int, ...], fallback: str) -> list[str]:
    """Port selection for a follow-up job: explicit observed ports, else the plan's port spec."""

    if ports:
        return ["-p", ",".join(str(p) for p in sorted(set(ports)))]
    return [fallback]


def build_nmap_bundle(
    plan: NmapScanPlan,
    *,
    lease: ScanLease | None = None,
    observed_open_ports: tuple[int, ...] = (),
) -> NmapJobBundle:
    """Validate a typed plan and expand it into single-purpose jobs, or fail closed.

    Every rejection happens before any argv is rendered, so a rejected plan produces zero commands
    and zero target traffic. Full TCP and UDP are never combined into one argv: each transport is
    its own job, and service/version/NSE and OS detection are their own follow-up jobs.
    """

    profile = NMAP_PROFILES.get(plan.profile_id)
    if profile is None:
        raise ReconRejection("NMAP_PROFILE_UNKNOWN")

    # Phase-scoped boundary (not an architectural prohibition): these techniques are unsupported by
    # the Phase 1.7-C Recon role and current lease, reserved for future dedicated capabilities, and
    # rejected pre-execution with zero traffic.
    if plan.evasion_experiments:
        raise ReconRejection("RECON_EVASION_UNSUPPORTED_IN_PHASE_1_7C")
    if plan.credentialed_scripts:
        raise ReconRejection("RECON_CREDENTIALED_UNSUPPORTED_IN_PHASE_1_7C")

    # Scope + lease gating.
    if profile.environment == "SYNTHETIC_RANGE":
        application_id, origin = _resolve_range_target(plan.target_ref)
    else:
        # AUTHORIZED_ENV_RECON: requires a signed, target-bound operator lease. Absent it, closed.
        if lease is None or not lease.signed or not lease.authorized:
            raise ReconRejection("AUTHORIZED_ENV_LEASE_MISSING")
        if lease.target_ref != plan.target_ref:
            raise ReconRejection("AUTHORIZED_ENV_LEASE_TARGET_MISMATCH")
        # No signed inventory ships with this lab, so resolution still fails closed.
        raise ReconRejection("AUTHORIZED_ENV_INVENTORY_UNAVAILABLE")

    # Transport / breadth gating.
    if "TCP" in plan.transports and not profile.allow_tcp:
        raise ReconRejection("NMAP_TCP_NOT_ALLOWED")
    if "UDP" in plan.transports and not profile.allow_udp:
        raise ReconRejection("NMAP_UDP_NOT_ALLOWED")
    if "TCP" in plan.transports and (
        _TCP_BREADTH_ORDER[plan.tcp_port_spec] > _TCP_BREADTH_ORDER[profile.max_tcp]
    ):
        raise ReconRejection("NMAP_TCP_BREADTH_EXCEEDED")
    if "UDP" in plan.transports:
        if plan.udp_port_spec == "NONE":
            raise ReconRejection("NMAP_UDP_SELECTED_WITHOUT_PORTS")
        if _UDP_BREADTH_ORDER[plan.udp_port_spec] > _UDP_BREADTH_ORDER[profile.max_udp]:
            raise ReconRejection("NMAP_UDP_BREADTH_EXCEEDED")

    if plan.discovery_strategy == "TCP_SYN" and not profile.allow_syn:
        raise ReconRejection("NMAP_SYN_NOT_ALLOWED")
    if plan.os_detection and not profile.allow_os_detection:
        raise ReconRejection("NMAP_OS_DETECTION_NOT_ALLOWED")
    if plan.traceroute and not profile.allow_traceroute:
        raise ReconRejection("NMAP_TRACEROUTE_NOT_ALLOWED")
    if plan.version_intensity > profile.max_version_intensity:
        raise ReconRejection("NMAP_VERSION_INTENSITY_EXCEEDED")
    if plan.timing_profile not in profile.allowed_timing:
        raise ReconRejection("NMAP_TIMING_NOT_ALLOWED")
    for category in plan.nse_categories:
        if category not in profile.allowed_nse:
            raise ReconRejection("NMAP_NSE_CATEGORY_NOT_ALLOWED")
    for script_id in plan.nse_script_ids:
        if script_id not in ADMITTED_NSE_SCRIPT_IDS:
            raise ReconRejection("NMAP_NSE_SCRIPT_NOT_ADMITTED")

    host = _host_of(origin)
    bundle = NmapJobBundle(
        target_ref=plan.target_ref,
        application_id=application_id,
        host=host,
        profile_id=plan.profile_id,
        image_ref=NMAP_IMAGE_REF,
        image_digest=NMAP_TOOL_DIGEST,
    )

    def _job(
        kind: NmapJobKind, privilege: NmapPrivilege, flags: list[str], ports: tuple[int, ...]
    ) -> NmapReconJob:
        argv = _assert_argv_safe(
            [NMAP_BINARY, *flags, *_common_bounds(profile, plan), *_tail(host)]
        )
        return NmapReconJob(
            job_id=f"nmapjob-{_rand()}",
            kind=kind,
            privilege=privilege,
            target_ref=plan.target_ref,
            application_id=application_id,
            profile_id=plan.profile_id,
            host=host,
            argv=argv,
            ports=ports,
            timing_profile=plan.timing_profile,
            max_rate_pps=profile.max_rate_pps,
            timeout_ms=profile.per_job_timeout_ms,
            image_ref=NMAP_IMAGE_REF,
            image_digest=NMAP_TOOL_DIGEST,
        )

    if "TCP" in plan.transports:
        syn = plan.discovery_strategy == "TCP_SYN"
        bundle.jobs.append(
            _job(
                NmapJobKind.TCP_DISCOVERY,
                NmapPrivilege.RAW_SOCKET if syn else NmapPrivilege.UNPRIVILEGED,
                ["-sS" if syn else "-sT", _TCP_PORT_FLAG[plan.tcp_port_spec]],
                (),
            )
        )
    if "UDP" in plan.transports:
        bundle.jobs.append(
            _job(
                NmapJobKind.UDP_DISCOVERY,
                NmapPrivilege.RAW_SOCKET,  # UDP scans need raw sockets (uid 0 + NET_RAW).
                ["-sU", _UDP_PORT_FLAG[plan.udp_port_spec]],
                (),
            )
        )

    # Follow-up jobs run against observed open ports; absent observations they fall back to the
    # plan's TCP port spec so a standalone bundle is still a valid, nmap-accepted argv.
    followup_ports = observed_open_ports
    port_args = _ports_args(followup_ports, _TCP_PORT_FLAG[plan.tcp_port_spec])
    # NSE is rendered from ONLY the pinned, admitted script IDs — never a blanket ``--script
    # <category>``. Broad categories (discovery/vuln/safe/default) pull in hundreds of scripts,
    # including broadcast/slow ones that hang or crash nmap on a bounded single target (verified
    # experimentally: the ``discovery`` category triggers an nse_nsock lua assertion / SIGSEGV).
    # ``nse_categories`` therefore expresses the authorized *scope*; the concrete, targeted script
    # IDs are what actually run.
    script_tokens = sorted(set(plan.nse_script_ids))
    if plan.version_detection or script_tokens:
        flags = [*port_args, "-sV", "--version-intensity", str(plan.version_intensity)]
        if script_tokens:
            flags.extend(["--script", ",".join(script_tokens)])
        bundle.jobs.append(
            _job(NmapJobKind.SERVICE_VERSION_NSE, NmapPrivilege.UNPRIVILEGED, flags, followup_ports)
        )
    if plan.os_detection:
        bundle.jobs.append(
            _job(
                NmapJobKind.OS_DETECTION,
                NmapPrivilege.RAW_SOCKET,  # OS detection needs raw sockets (uid 0 + NET_RAW).
                [*port_args, "-O", "--osscan-limit"],
                followup_ports,
            )
        )
    return bundle


def render_nmap_argv(job: NmapReconJob) -> list[str]:
    """Return the validated argv of a single job (precomputed at build time)."""

    return list(job.argv)


def _rand() -> str:
    from uuid import uuid4

    return uuid4().hex[:16]


# ---------------------------------------------------------------------------
# Normalized observation types. Deterministic, deduplicated, never a verdict.
# ---------------------------------------------------------------------------


class DiscoveredService(StrictModel):
    kind: Literal[ReconObservationKind.DISCOVERED_SERVICE] = (
        ReconObservationKind.DISCOVERED_SERVICE
    )
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65_535)
    state: Literal["open", "filtered", "open|filtered"]
    service: str = Field(min_length=1, max_length=40)
    product: str = Field(default="", max_length=80)


class HttpTechnology(StrictModel):
    kind: Literal[ReconObservationKind.HTTP_TECHNOLOGY] = ReconObservationKind.HTTP_TECHNOLOGY
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    header: str = Field(min_length=1, max_length=60)
    value: str = Field(min_length=1, max_length=120)


class DocumentedOperation(StrictModel):
    kind: Literal[ReconObservationKind.DOCUMENTED_OPERATION] = (
        ReconObservationKind.DOCUMENTED_OPERATION
    )
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    method: str = Field(min_length=1, max_length=10)
    route: str = Field(min_length=1, max_length=200)


class ParameterCandidate(StrictModel):
    kind: Literal[ReconObservationKind.PARAMETER_CANDIDATE] = (
        ReconObservationKind.PARAMETER_CANDIDATE
    )
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    route: str = Field(min_length=1, max_length=200)
    parameter: str = Field(min_length=1, max_length=64)
    injection_capability_hint: str = Field(default="", max_length=64)


class NucleiCandidate(StrictModel):
    kind: Literal[ReconObservationKind.NUCLEI_CANDIDATE] = ReconObservationKind.NUCLEI_CANDIDATE
    target_ref: str = Field(min_length=1, max_length=64)
    template_id: str = Field(min_length=1, max_length=120)
    scanner_severity: str = Field(default="unknown", max_length=20)
    # A candidate is *never* confirmed by recon; only the Phase 1.2 verifier can promote it.
    confirmed: Literal[False] = False


class ZapPassiveCandidate(StrictModel):
    kind: Literal[ReconObservationKind.ZAP_PASSIVE_CANDIDATE] = (
        ReconObservationKind.ZAP_PASSIVE_CANDIDATE
    )
    target_ref: str = Field(min_length=1, max_length=64)
    rule_id: int = Field(ge=0, le=1_000_000)
    scanner_severity: str = Field(default="unknown", max_length=20)
    confirmed: Literal[False] = False


class NoFinding(StrictModel):
    kind: Literal[ReconObservationKind.NO_FINDING] = ReconObservationKind.NO_FINDING
    # A clean/no-finding scope may be a range target or a reused lab scanner target.
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    capability_id: str = Field(min_length=3, max_length=80)
    detail: str = Field(default="", max_length=120)


class IncompleteObservation(StrictModel):
    kind: Literal[ReconObservationKind.INCOMPLETE_TOOL_ERROR] = (
        ReconObservationKind.INCOMPLETE_TOOL_ERROR
    )
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    capability_id: str = Field(min_length=3, max_length=80)
    reason: str = Field(min_length=1, max_length=120)


ReconObservationModel = (
    DiscoveredService
    | HttpTechnology
    | DocumentedOperation
    | ParameterCandidate
    | NucleiCandidate
    | ZapPassiveCandidate
    | NoFinding
    | IncompleteObservation
)


def _dedup_key(obs: ReconObservationModel) -> tuple[str, ...]:
    if isinstance(obs, DiscoveredService):
        return (obs.kind, obs.target_ref, obs.protocol, str(obs.port))
    if isinstance(obs, HttpTechnology):
        return (obs.kind, obs.target_ref, obs.header.lower(), obs.value)
    if isinstance(obs, DocumentedOperation):
        return (obs.kind, obs.target_ref, obs.method.upper(), obs.route)
    if isinstance(obs, ParameterCandidate):
        return (obs.kind, obs.target_ref, obs.route, obs.parameter)
    if isinstance(obs, NucleiCandidate):
        return (obs.kind, obs.target_ref, obs.template_id)
    if isinstance(obs, ZapPassiveCandidate):
        return (obs.kind, obs.target_ref, str(obs.rule_id))
    if isinstance(obs, NoFinding):
        return (obs.kind, obs.target_ref, obs.capability_id)
    return (obs.kind, obs.target_ref, obs.capability_id, obs.reason)


def deduplicate(
    observations: list[ReconObservationModel],
) -> list[ReconObservationModel]:
    """Deterministically deduplicate and order observations by their canonical key."""

    unique: dict[tuple[str, ...], ReconObservationModel] = {}
    for obs in observations:
        unique.setdefault(_dedup_key(obs), obs)
    return [unique[key] for key in sorted(unique)]


@dataclass
class NormalizedReconReport:
    """The bounded recon result. It has no verdict, no PASS, and no severity of its own."""

    target_ref: str
    observations: list[ReconObservationModel] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, observation: ReconObservationModel) -> None:
        self.observations.append(observation)

    def finalize(self) -> None:
        self.observations = deduplicate(self.observations)

    @property
    def incomplete(self) -> bool:
        return any(isinstance(o, IncompleteObservation) for o in self.observations)

    @property
    def evidence_sha256(self) -> str:
        payload = json.dumps(
            [o.model_dump(mode="json") for o in self.observations]
            + [{"warning": w} for w in sorted(set(self.warnings))],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(payload).hexdigest()

    def parameter_candidates(self) -> list[ParameterCandidate]:
        return [o for o in self.observations if isinstance(o, ParameterCandidate)]

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for obs in self.observations:
            tally[obs.kind] = tally.get(obs.kind, 0) + 1
        return tally


# Controller-owned expected service map for the synthetic range. This stands in for what an attested
# nmap-runner would report; it is a fixture, never a claim of a live scan (see the acceptance doc).
RANGE_SERVICE_FIXTURE: dict[str, list[dict[str, object]]] = {
    "range-bank": [{"protocol": "tcp", "port": 8101, "state": "open", "service": "http"}],
    "range-shop": [{"protocol": "tcp", "port": 8102, "state": "open", "service": "http"}],
    "range-ops": [{"protocol": "tcp", "port": 8103, "state": "open", "service": "http"}],
    "range-cloud": [{"protocol": "tcp", "port": 8104, "state": "open", "service": "http"}],
}


def normalize_service_discovery(
    target_ref: str, raw_services: list[dict[str, object]] | None
) -> list[ReconObservationModel]:
    """Normalize an UNTRUSTED runner service list into bounded, typed observations.

    A missing result becomes an INCOMPLETE observation (never a clean/no-finding PASS). Malformed
    entries are dropped and recorded as incomplete; only well-formed open/filtered services become
    :class:`DiscoveredService` records.
    """

    if raw_services is None:
        return [
            IncompleteObservation(
                target_ref=target_ref,
                capability_id=CAP_NETWORK_SERVICE_DISCOVERY,
                reason="no runner result (execution deferred to attested worker)",
            )
        ]
    out: list[ReconObservationModel] = []
    malformed = 0
    for entry in raw_services[:256]:
        try:
            protocol = entry["protocol"]
            port = int(entry["port"])  # type: ignore[call-overload]
            state = entry["state"]
            service = str(entry["service"])[:40]
        except (KeyError, TypeError, ValueError):
            malformed += 1
            continue
        if protocol not in {"tcp", "udp"} or state not in {"open", "filtered", "open|filtered"}:
            malformed += 1
            continue
        out.append(
            DiscoveredService(
                target_ref=target_ref,
                protocol=protocol,  # type: ignore[arg-type]
                port=port,
                state=state,  # type: ignore[arg-type]
                service=service or "unknown",
                product=str(entry.get("product", ""))[:80],
            )
        )
    if malformed:
        out.append(
            IncompleteObservation(
                target_ref=target_ref,
                capability_id=CAP_NETWORK_SERVICE_DISCOVERY,
                reason=f"{malformed} malformed service entries dropped",
            )
        )
    return out


# Bound on the raw nmap XML the parser will accept. The worker also caps its output.
_MAX_NMAP_XML_BYTES = 4_000_000


def parse_nmap_xml(
    xml_bytes: bytes, target_ref: str
) -> tuple[list[dict[str, object]], list[str], bool]:
    """Parse UNTRUSTED nmap XML into service dicts + open TCP ports; ``ok`` False if unusable.

    Returns ``(services, open_tcp_ports_as_str, ok)``. ``ok`` is False when the XML is truncated,
    malformed, contains a DTD/entity (rejected without parsing), or has no ``<runstats finished>`` —
    the caller turns ``ok=False`` into an ``INCOMPLETE_TOOL_ERROR`` observation, never a clean PASS.
    The returned service dicts feed :func:`normalize_service_discovery`.
    """

    if not xml_bytes or len(xml_bytes) > _MAX_NMAP_XML_BYTES:
        return [], [], False
    # nmap emits a benign ``<!DOCTYPE nmaprun>`` with no internal subset and no external identifier;
    # that is safe. Reject only entity *definitions* (XXE / billion-laughs) and external DTDs. Only
    # the prolog before the root element is inspected.
    root_at = xml_bytes.find(b"<nmaprun")
    prolog = xml_bytes[: root_at if root_at != -1 else 8192].lower()
    if b"<!entity" in prolog or b"system" in prolog or b"public" in prolog or b"[" in prolog:
        return [], [], False
    import xml.etree.ElementTree as ET  # noqa: S405 - entities/external DTD rejected; size-bounded

    try:
        root = ET.fromstring(xml_bytes)  # noqa: S314 - hardened: no DTD/entity, bounded size
    except ET.ParseError:
        return [], [], False
    finished = root.find("./runstats/finished")
    ok = finished is not None
    services: list[dict[str, object]] = []
    open_ports: list[str] = []
    for host in root.findall("./host"):
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state not in {"open", "filtered", "open|filtered"}:
                continue
            protocol = port.get("protocol", "")
            portid = port.get("portid", "")
            service_el = port.find("service")
            name = service_el.get("name", "") if service_el is not None else ""
            product = ""
            if service_el is not None:
                product = " ".join(
                    p for p in (service_el.get("product", ""), service_el.get("version", "")) if p
                )
            services.append(
                {
                    "protocol": protocol,
                    "port": portid,
                    "state": state,
                    "service": name or "unknown",
                    "product": product,
                }
            )
            if protocol == "tcp" and state == "open" and portid.isdigit():
                open_ports.append(portid)
    del target_ref  # kept in signature for call-site symmetry; parsing is target-agnostic
    return services, open_ports, ok


# ---------------------------------------------------------------------------
# Reuse of the Phase 1.2 Nuclei and Phase 1.3 ZAP passive controllers. Nothing below duplicates a
# runner, parser, manifest or verification rule -- it calls the existing controller-side builders,
# which gate the request against their own pinned, signed inventories, and turns TOOL_REPORTED
# alerts into unconfirmed candidates.
# ---------------------------------------------------------------------------

# Pinned bindings, discovered from the existing catalog. The Recon Agent may only *select* these; it
# cannot name a template, rule, origin or profile.
NUCLEI_PROFILE_ID = "NUCLEI_LAB_SAFE_HTTP_V1"
NUCLEI_CAPABILITY_ID = "nuclei_scm_metadata_exposure_v1"
ZAP_PROFILE_ID = "ZAP_LAB_PASSIVE_OPENAPI_V1"
ZAP_CAPABILITY_ID = "zap_passive_header_openapi_v1"


def build_reviewed_exposure_job(
    target_variant: Literal["vulnerable", "patched"],
) -> NucleiEngineJob:
    """Build a pinned Nuclei job via the reused Phase 1.2 controller. Raises on any out-of-scope."""

    from aegis.engine.contracts import EngineEnvironment
    from aegis.engine.nuclei import build_nuclei_job
    from aegis_nuclei.targets import NUCLEI_TARGETS

    target_ref = f"synthetic-scm-{target_variant}"
    target = NUCLEI_TARGETS.get(target_ref)
    if target is None:
        raise ReconRejection("NUCLEI_TARGET_UNKNOWN")
    try:
        return build_nuclei_job(
            profile_id=NUCLEI_PROFILE_ID,
            capability_id=NUCLEI_CAPABILITY_ID,
            run_id=f"scan-{_rand()[:12]}",
            environment=EngineEnvironment.SYNTHETIC_LAB,
            target_ref=target_ref,
            remaining_requests=100,
            allowed_origins={target.origin},
            adapter_enabled=True,
        )
    except Exception as exc:  # noqa: BLE001 - normalise any policy rejection to a recon rejection
        raise ReconRejection(f"NUCLEI_JOB_REJECTED:{type(exc).__name__}") from exc


def build_passive_openapi_job(target_variant: Literal["vulnerable", "patched"]) -> ZapEngineJob:
    """Build a pinned passive ZAP job via the reused Phase 1.3 controller. Raises out-of-scope."""

    from aegis.engine.contracts import EngineEnvironment
    from aegis.engine.zap import build_zap_job
    from aegis_zap.inventory import ZAP_TARGETS

    target_ref = f"synthetic-zap-{target_variant}"
    target = ZAP_TARGETS.get(target_ref)
    if target is None:
        raise ReconRejection("ZAP_TARGET_UNKNOWN")
    try:
        job, _projection = build_zap_job(
            profile_id=ZAP_PROFILE_ID,
            capability_id=ZAP_CAPABILITY_ID,
            run_id=f"scan-{_rand()[:12]}",
            environment=EngineEnvironment.SYNTHETIC_LAB,
            target_ref=target_ref,
            remaining_requests=100,
            allowed_origins={target.origin},
            adapter_enabled=True,
        )
    except Exception as exc:  # noqa: BLE001 - normalise any policy rejection to a recon rejection
        raise ReconRejection(f"ZAP_JOB_REJECTED:{type(exc).__name__}") from exc
    return job


def normalize_nuclei_alerts(
    target_ref: str, raw_alerts: list[dict[str, object]] | None
) -> list[ReconObservationModel]:
    """Turn UNTRUSTED Nuclei alerts into unconfirmed candidates. Recon never promotes them."""

    if raw_alerts is None:
        return [
            NoFinding(
                target_ref=target_ref[:64],
                capability_id=CAP_NUCLEI_REVIEWED_EXPOSURE,
                detail="reviewed job built; execution deferred to attested nuclei-runner",
            )
        ]
    out: list[ReconObservationModel] = []
    for entry in raw_alerts[:64]:
        template_id = entry.get("template_id")
        if not isinstance(template_id, str) or not template_id:
            continue
        out.append(
            NucleiCandidate(
                target_ref=target_ref[:64],
                template_id=template_id[:120],
                scanner_severity=str(entry.get("severity", "unknown"))[:20],
            )
        )
    return out


def normalize_zap_alerts(
    target_ref: str, raw_alerts: list[dict[str, object]] | None
) -> list[ReconObservationModel]:
    """Turn UNTRUSTED passive ZAP alerts into unconfirmed candidates. Recon never promotes them."""

    if raw_alerts is None:
        return [
            NoFinding(
                target_ref=target_ref[:64],
                capability_id=CAP_ZAP_PASSIVE_OPENAPI,
                detail="passive job built; execution deferred to attested zap-runner",
            )
        ]
    out: list[ReconObservationModel] = []
    for entry in raw_alerts[:64]:
        rule_id = entry.get("rule_id")
        if not isinstance(rule_id, int):
            continue
        out.append(
            ZapPassiveCandidate(
                target_ref=target_ref[:64],
                rule_id=rule_id,
                scanner_severity=str(entry.get("severity", "unknown"))[:20],
            )
        )
    return out


# ---------------------------------------------------------------------------
# Reused-adapter execution of the Phase 1.2 Nuclei and Phase 1.3 ZAP passive runners.
#
# These helpers call the EXISTING NucleiAdapter / ZapAdapter — their runner RPC client, response
# validation and parser — against the attested runner container, and map the validated, UNTRUSTED
# tool response into the recon alert-dict shape that ``normalize_*_alerts`` already consumes. No
# runner, parser, manifest or verification rule is duplicated here; the adapter remains the single
# execution path, and recon still never promotes an alert.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReconExecutionOutcome:
    """The recon-facing result of executing one reused job on its attested runner.

    ``completed`` is True only when the runner reported COMPLETED with complete coverage. ``alerts``
    is the UNTRUSTED tool-claim list in the shape ``normalize_*_alerts`` consumes: empty on a clean
    complete run, ``None`` when the tool did not complete (mapped to INCOMPLETE_TOOL_ERROR). Recon
    never confirms or promotes a candidate regardless of this outcome.
    """

    completed: bool
    status: str
    detail: str
    alerts: list[dict[str, object]] | None


def nuclei_execution_outcome(result: NucleiAdapterResult) -> ReconExecutionOutcome:
    """Map an UNTRUSTED, already-validated NucleiAdapterResult into a recon execution outcome."""

    response = result.response
    if str(result.execution.status) != "COMPLETED" or response is None:
        code = result.validation_code or (
            result.execution.error.code.value if result.execution.error else "INCOMPLETE"
        )
        return ReconExecutionOutcome(False, "INCOMPLETE", str(code)[:120], None)
    # Only matched templates become candidates; an unmatched template is not an alert.
    alerts: list[dict[str, object]] = [
        {"template_id": record.template_id, "severity": record.claimed_severity}
        for record in response.results
        if record.matcher_status
    ]
    return ReconExecutionOutcome(True, "COMPLETED", "nuclei coverage complete", alerts)


def zap_execution_outcome(result: ZapAdapterResult) -> ReconExecutionOutcome:
    """Map an UNTRUSTED, already-validated ZapAdapterResult into a recon execution outcome."""

    response = result.response
    if (
        str(result.execution.status) != "COMPLETED"
        or response is None
        or not response.coverage_complete
    ):
        code = result.validation_code or (
            result.execution.error.code.value if result.execution.error else "INCOMPLETE"
        )
        return ReconExecutionOutcome(False, "INCOMPLETE", str(code)[:120], None)
    alerts: list[dict[str, object]] = [
        {"rule_id": alert.plugin_id, "severity": alert.claimed_risk}
        for alert in response.alerts
    ]
    return ReconExecutionOutcome(True, "COMPLETED", "zap passive coverage complete", alerts)


# ---------------------------------------------------------------------------
# The Recon Broker. It orchestrates the four capabilities and produces observations only.
# ---------------------------------------------------------------------------


class ReconBroker:
    """Controlled recon over the synthetic range. It never confirms, never PASSes, never mutates."""

    def __init__(
        self,
        budget: AtomicBudget,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self._budget = budget
        self._transports = transports or {}

    def _target(self, target_ref: str) -> tuple[str, str]:
        return _resolve_range_target(target_ref)

    async def _get(self, application_id: str, origin: str, path: str) -> httpx.Response:
        async with httpx.AsyncClient(
            base_url=origin,
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            transport=self._transports.get(application_id),
        ) as client:
            return await client.get(
                path, headers={"User-Agent": "Aegis-Recon-Agent/1.7C"}
            )

    def _require_role(self, task: AgentTask) -> None:
        if task.role is not AgentRole.RECON_AGENT:
            raise ReconRejection("RECON_AGENT_ROLE_REQUIRED")

    async def plan_service_discovery(
        self,
        *,
        task: AgentTask,
        plan: NmapScanPlan,
        lease: ScanLease | None = None,
        runner_result: list[dict[str, object]] | None = None,
    ) -> tuple[NmapJobBundle, NormalizedReconReport]:
        """Validate a plan into a typed job bundle and normalize a (deferred/fixture) runner result.

        Offline, ``runner_result`` is a controller-owned fixture or ``None``; the real execution is
        performed by the attested, isolated nmap worker (see ``scripts/phase_1_7c_containerized.py``
        and the compose overlay). The bundle's command budget is charged up front.
        """

        self._require_role(task)
        authorize(task.role, CAP_NETWORK_SERVICE_DISCOVERY)
        if plan.target_ref != task.context.target_ref:
            raise ReconRejection("PLAN_TARGET_NOT_TASK_TARGET")
        bundle = build_nmap_bundle(plan, lease=lease)
        await self._budget.consume(
            task.agent_id, BudgetUsage(commands=bundle.total_command_budget)
        )
        report = NormalizedReconReport(target_ref=plan.target_ref)
        for obs in normalize_service_discovery(plan.target_ref, runner_result):
            report.add(obs)
        report.finalize()
        await self._budget.consume(
            task.agent_id, BudgetUsage(evidence_bytes=len(report.evidence_sha256))
        )
        return bundle, report

    async def http_surface_recon(
        self, *, task: AgentTask, target_ref: str
    ) -> NormalizedReconReport:
        """Read-only documented HTTP/API surface inventory (reuses the existing openapi surface)."""

        self._require_role(task)
        authorize(task.role, CAP_HTTP_API_SURFACE_RECON)
        application_id, origin = self._target(target_ref)
        report = NormalizedReconReport(target_ref=target_ref)
        await self._budget.consume(task.agent_id, BudgetUsage(target_requests=1))
        try:
            response = await self._get(application_id, origin, "/openapi.json")
        except httpx.HTTPError:
            report.add(
                IncompleteObservation(
                    target_ref=target_ref,
                    capability_id=CAP_HTTP_API_SURFACE_RECON,
                    reason="surface unreachable",
                )
            )
            report.finalize()
            return report
        if response.status_code != 200 or len(response.content) > 262_144:
            report.add(
                IncompleteObservation(
                    target_ref=target_ref,
                    capability_id=CAP_HTTP_API_SURFACE_RECON,
                    reason=f"surface unavailable (status {response.status_code})",
                )
            )
            report.finalize()
            return report
        # Target-controlled text is data. Instruction-like content is flagged, never obeyed.
        lowered = response.text.lower()
        if any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS):
            report.warnings.append(
                "target-controlled instruction-like content observed; treated as data"
            )
        for header in ("server", "x-powered-by", "content-type"):
            value = response.headers.get(header)
            if value:
                report.add(
                    HttpTechnology(target_ref=target_ref, header=header, value=value[:120])
                )
        document: object = response.json()
        if isinstance(document, dict):
            self._collect_operations(report, target_ref, document)
        report.finalize()
        await self._budget.consume(
            task.agent_id, BudgetUsage(evidence_bytes=len(report.evidence_sha256))
        )
        return report

    @staticmethod
    def _collect_operations(
        report: NormalizedReconReport, target_ref: str, document: dict[str, object]
    ) -> None:
        from aegis.multi_agent.injection import PAYLOAD_TEMPLATES

        application_id = report.target_ref.replace("range-", "aegis-")
        paths = document.get("paths", {})
        if not isinstance(paths, dict):
            return
        for route, item in paths.items():
            if not isinstance(route, str) or not isinstance(item, dict):
                continue
            for method, operation in item.items():
                report.add(
                    DocumentedOperation(
                        target_ref=target_ref, method=str(method).upper()[:10], route=route[:200]
                    )
                )
                if not isinstance(operation, dict):
                    continue
                for parameter in operation.get("parameters", []) or []:
                    if not (isinstance(parameter, dict) and isinstance(parameter.get("name"), str)):
                        continue
                    name = parameter["name"]
                    hint = ""
                    for template in PAYLOAD_TEMPLATES.values():
                        if (
                            template.application_id == application_id
                            and template.route == route
                            and template.parameter == name
                        ):
                            hint = template.capability_id
                    report.add(
                        ParameterCandidate(
                            target_ref=target_ref,
                            route=route[:200],
                            parameter=name[:64],
                            injection_capability_hint=hint,
                        )
                    )

    def _apply_execution(
        self,
        report: NormalizedReconReport,
        *,
        capability_id: str,
        target_ref: str,
        outcome: ReconExecutionOutcome,
        normalize: Callable[[str, list[dict[str, object]] | None], list[ReconObservationModel]],
        clean_detail: str,
    ) -> None:
        """Fold a live runner outcome into the report: INCOMPLETE, candidates, or NO_FINDING."""

        if not outcome.completed:
            report.add(
                IncompleteObservation(
                    target_ref=target_ref[:64],
                    capability_id=capability_id,
                    reason=(outcome.detail or "runner did not complete")[:120],
                )
            )
        elif outcome.alerts:
            for obs in normalize(target_ref, outcome.alerts):
                report.add(obs)
        else:
            report.add(
                NoFinding(
                    target_ref=target_ref[:64],
                    capability_id=capability_id,
                    detail=clean_detail[:120],
                )
            )

    async def plan_reviewed_exposure(
        self,
        *,
        task: AgentTask,
        target_variant: Literal["vulnerable", "patched"],
        runner_alerts: list[dict[str, object]] | None = None,
        executor: ReconRunnerExecutor | None = None,
    ) -> tuple[object, NormalizedReconReport]:
        """Reuse the Phase 1.2 Nuclei controller. No runner/parser/manifest is duplicated here.

        When ``executor`` is supplied and no fixture ``runner_alerts`` is passed, the
        controller-built job is executed on the attested nuclei-runner via the existing adapter and
        its UNTRUSTED alerts become unconfirmed candidates (or NO_FINDING / INCOMPLETE).
        """

        self._require_role(task)
        authorize(task.role, CAP_NUCLEI_REVIEWED_EXPOSURE)
        job = build_reviewed_exposure_job(target_variant)
        report = NormalizedReconReport(target_ref=f"nuclei-{target_variant}")
        if executor is not None and runner_alerts is None:
            await self._budget.consume(
                task.agent_id, BudgetUsage(target_requests=1, commands=1)
            )
            self._apply_execution(
                report,
                capability_id=CAP_NUCLEI_REVIEWED_EXPOSURE,
                target_ref=job.target_ref,
                outcome=await executor(job),
                normalize=normalize_nuclei_alerts,
                clean_detail="reviewed run completed on attested runner; no matched template",
            )
        else:
            for obs in normalize_nuclei_alerts(job.target_ref, runner_alerts):
                report.add(obs)
        report.finalize()
        await self._budget.consume(
            task.agent_id, BudgetUsage(evidence_bytes=len(report.evidence_sha256))
        )
        return job, report

    async def plan_passive_openapi(
        self,
        *,
        task: AgentTask,
        target_variant: Literal["vulnerable", "patched"],
        runner_alerts: list[dict[str, object]] | None = None,
        executor: ReconRunnerExecutor | None = None,
    ) -> tuple[object, NormalizedReconReport]:
        """Reuse the Phase 1.3 passive ZAP controller. Passive only; no active scan; no dup.

        When ``executor`` is supplied and no fixture ``runner_alerts`` is passed, the
        controller-built job is executed on the attested zap-runner via the existing adapter and its
        UNTRUSTED alerts are normalized into unconfirmed candidates (or NO_FINDING / INCOMPLETE).
        """

        self._require_role(task)
        authorize(task.role, CAP_ZAP_PASSIVE_OPENAPI)
        job = build_passive_openapi_job(target_variant)
        report = NormalizedReconReport(target_ref=f"zap-{target_variant}")
        if executor is not None and runner_alerts is None:
            await self._budget.consume(
                task.agent_id, BudgetUsage(target_requests=1, commands=1)
            )
            self._apply_execution(
                report,
                capability_id=CAP_ZAP_PASSIVE_OPENAPI,
                target_ref=job.target_ref,
                outcome=await executor(job),
                normalize=normalize_zap_alerts,
                clean_detail="passive run completed on attested runner; no passive alert",
            )
        else:
            for obs in normalize_zap_alerts(job.target_ref, runner_alerts):
                report.add(obs)
        report.finalize()
        await self._budget.consume(
            task.agent_id, BudgetUsage(evidence_bytes=len(report.evidence_sha256))
        )
        return job, report
