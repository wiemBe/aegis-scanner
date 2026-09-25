"""Phase 2.8-B — Injection Capability Pack: controller-owned bounded SQLMap capability.

SQLMap is a **registered Tool Broker capability for INJECTION_AGENT**, not an AI agent and never a
recon tool. The model may only *select a registered profile id* against a controller-approved
(target, route, parameter); it can never author a raw shell, argv, URL, SQLMap option, payload,
header, concurrency, risk/level, technique, timeout or target override. The controller renders the
argv deterministically.

Three controller-owned profiles:

* ``sqlmap_sqli_detect_v1``         — boolean-based detection only (level 1 / risk 1).
* ``sqlmap_sqli_confirm_bounded_v1``— bounded confirmation + DBMS banner (level 2 / risk 1).
* ``sqlmap_sqli_canary_impact_v1``  — bounded single-canary read, **synthetic range only**.

Default profiles exclude arbitrary file access, OS shell, unrestricted dumping, persistence and
out-of-scope crawling — structurally (the typed profile cannot express them) and via a defence-in
-depth argv denylist. The canary profile permits ONLY a bounded, single-row, single-column read of a
seeded synthetic canary, and only in the synthetic range.

Crucially: **SQLMap output alone never sets CONFIRMED or PASS.** The worker produces normalized
boolean-differential evidence; the independent verifier
(``RangeVerifier.adjudicate_sqli_offline``) adjudicates that worker evidence
against controller-owned ground truth and sends no SQL injection traffic of its own. A tool's own
"injectable: yes" claim is recorded for audit but is never a verdict input.

Offline note: container/live SQLMap execution is ``NOT_EVALUATED`` this phase. The digest below
is a synthetic placeholder pin; :func:`assert_container_pinned` fails closed until an operator pins
the real digest.
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
from aegis.multi_agent.staging import EnvironmentTier, classify_environment
from aegis_range.inventory import RANGE_TARGETS

SQLMAP_CAPABILITY_ID: Literal["aegis.injection.sqlmap"] = "aegis.injection.sqlmap"


class SqlmapCapabilityError(ValueError):
    """A SQLMap selection escaped the controller allowlist, scope, tier, lease or bounds."""


# --------------------------------------------------------------------------- #
# Tool/version/image provenance (self-contained placeholder pin; container NOT_EVALUATED).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SqlmapToolImage:
    tool: str
    image: str
    tag: str
    version: str
    image_digest: str
    digest_pinned: bool = False

    @property
    def image_ref(self) -> str:
        return f"{self.image}@{self.image_digest}"


SQLMAP_PROVENANCE = SqlmapToolImage(
    tool="sqlmap",
    image="sqlmapproject/sqlmap",
    tag="1.8.9",
    version="1.8.9",
    image_digest="sha256:" + hashlib.sha256(b"placeholder:sqlmapproject/sqlmap:1.8.9").hexdigest(),
)


def assert_container_pinned(image: SqlmapToolImage) -> None:
    """Fail closed unless the image digest is an operator-resolved pin (container/live only)."""

    if not image.digest_pinned:
        raise SqlmapCapabilityError("TOOL_IMAGE_DIGEST_NOT_PINNED:sqlmap")


# --------------------------------------------------------------------------- #
# argv denylist: SQLMap flags that must NEVER appear (arbitrary file access, OS shell, unrestricted
# dumping, persistence, out-of-scope crawling, proxying, request-file inclusion, arbitrary SQL).
# --------------------------------------------------------------------------- #

_FORBIDDEN_SQLMAP_TOKENS: frozenset[str] = frozenset(
    {
        "--os-shell", "--os-cmd", "--os-pwn", "--os-bof", "--os-smbrelay",
        "--file-read", "--file-write", "--file-dest", "--sql-shell", "--sql-query",
        "--dump-all", "--dbs", "--passwords", "--privileges", "--roles", "--all",
        "--crawl", "--forms", "--eval", "--tamper", "--proxy", "--proxy-file",
        "--second-url", "--load-cookies", "--shell", "-r", "--reg-add", "--reg-del",
        "--purge", "--udf-inject", "--commonfiles",
        "sh", "bash", "-c", ";", "|", "&", "$(", "`", ">", "<", "&&",
    }
)
# Argv tokens may contain a single quote (needed for a bounded --where clause) but never a space,
# shell metacharacter or NUL. Deliberately narrow.
_SAFE_SQLMAP_TOKEN = re.compile(r"^[A-Za-z0-9_.:,/=+%?'@-]+$")


def _assert_argv_safe(argv: list[str]) -> tuple[str, ...]:
    for token in argv:
        if token in _FORBIDDEN_SQLMAP_TOKENS or not _SAFE_SQLMAP_TOKEN.match(token):
            raise SqlmapCapabilityError(f"SQLMAP_ARGV_UNSAFE_TOKEN:{token[:40]}")
    return tuple(argv)


# --------------------------------------------------------------------------- #
# Controller-owned typed profiles.
# --------------------------------------------------------------------------- #

SqlmapProfileId = Literal[
    "sqlmap_sqli_detect_v1",
    "sqlmap_sqli_confirm_bounded_v1",
    "sqlmap_sqli_canary_impact_v1",
    "sqlmap_sqli_detect_boolean_v1",
]

SqlmapTechnique = Literal["B", "BE"]  # boolean / error-based only. No time/stacked/union/inline.


@dataclass(frozen=True)
class SqlmapProfile:
    """A controller-owned bounded SQLMap envelope. The model selects only the profile id."""

    profile_id: str
    environment: EnvironmentTier
    technique: SqlmapTechnique
    level: int
    risk: int
    threads: int
    per_request_timeout_ms: int
    retries: int
    max_requests: int
    max_output_bytes: int
    dbms_banner: bool = False
    canary_read: bool = False
    synthetic_range_only: bool = False
    # Controller-owned HARD runtime ceilings for a containerized run. ``max_requests`` is the max
    # HTTP request count the SQLMap process may emit; ``max_duration_seconds`` the wall-clock cap.
    # Neither is representable on the model-facing ``SqlmapPlan`` (strict ``extra="forbid"``), so
    # the model can select only a profile id and can never widen a ceiling.
    max_duration_seconds: int = 120


SQLMAP_PROFILES: dict[str, SqlmapProfile] = {
    "sqlmap_sqli_detect_v1": SqlmapProfile(
        profile_id="sqlmap_sqli_detect_v1",
        environment=EnvironmentTier.SYNTHETIC_RANGE,
        technique="B", level=1, risk=1, threads=1,
        per_request_timeout_ms=8_000, retries=1, max_requests=64, max_output_bytes=131_072,
    ),
    "sqlmap_sqli_confirm_bounded_v1": SqlmapProfile(
        profile_id="sqlmap_sqli_confirm_bounded_v1",
        environment=EnvironmentTier.SYNTHETIC_RANGE,
        technique="BE", level=2, risk=1, threads=1,
        per_request_timeout_ms=8_000, retries=1, max_requests=128, max_output_bytes=262_144,
        dbms_banner=True,
    ),
    "sqlmap_sqli_canary_impact_v1": SqlmapProfile(
        profile_id="sqlmap_sqli_canary_impact_v1",
        environment=EnvironmentTier.SYNTHETIC_RANGE,
        technique="BE", level=2, risk=1, threads=1,
        per_request_timeout_ms=8_000, retries=1, max_requests=160, max_output_bytes=262_144,
        dbms_banner=True, canary_read=True, synthetic_range_only=True,
    ),
    # Boolean-only detection profile tuned to be *honestly compatible with the pinned SQLMap
    # version* against the bounded `LIKE '%…%'` catalog fixture: the low-level detect/confirm
    # profiles cannot break out of the string context, so the pinned binary never self-flags and
    # never emits SQLMap-originated differential traffic. This raises level/risk to 3/2 (still
    # boolean-only — no error/union/time/stacked, no dump, no banner) so a real, bounded SQLMap run
    # generates genuine differential traffic on the vulnerable arm and none on the patched arm.
    "sqlmap_sqli_detect_boolean_v1": SqlmapProfile(
        profile_id="sqlmap_sqli_detect_boolean_v1",
        environment=EnvironmentTier.SYNTHETIC_RANGE,
        technique="B", level=3, risk=2, threads=1,
        per_request_timeout_ms=8_000, retries=1, max_requests=800, max_output_bytes=262_144,
        max_duration_seconds=180, synthetic_range_only=True,
    ),
}

# The bounded synthetic canary the canary-impact profile may read: ONE column of ONE row of
# ONE seeded table. Controller-owned; never model-authored.
CANARY_TABLE = "products"
CANARY_COLUMN = "name"
CANARY_WHERE = "product_id='PRD-100'"


# --------------------------------------------------------------------------- #
# Typed plan (model-facing) + job + evidence + manifest.
# --------------------------------------------------------------------------- #


class SqlmapPlan(StrictModel):
    """A model-selected SQLMap plan. No raw URL, option, payload, header, risk/level, technique,
    timeout, concurrency or target override is representable — only registered ids + references."""

    capability_id: Literal["aegis.injection.sqlmap"]
    profile_id: SqlmapProfileId
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    route: str = Field(pattern=r"^/[A-Za-z0-9/._~-]{1,180}$")
    parameter: str = Field(pattern=r"^[A-Za-z0-9_]{1,64}$")


class SqlmapInjectionJob(StrictModel):
    """The controller-rendered, fully-bounded SQLMap job. It has no shell command field."""

    job_id: str = Field(pattern=r"^sqlmj-[a-f0-9]{16}$")
    capability_id: str
    profile_id: str
    target_ref: str
    application_id: str
    authorized_origin: str
    scope_host: str
    target_url: str
    parameter: str
    argv: tuple[str, ...] = Field(min_length=6, max_length=48)
    technique: str
    level: int
    risk: int
    threads: int
    max_requests: int
    max_output_bytes: int
    per_request_timeout_ms: int
    environment_tier: EnvironmentTier
    allows_canary_read: bool
    image_ref: str
    image_digest: str
    tool_version: str
    digest_pinned: bool

    @property
    def argv_digest(self) -> str:
        return hashlib.sha256("\x00".join(self.argv).encode()).hexdigest()


class SqlmapResultSlot(StrictModel):
    status_code: int
    result_count: int


class SqlmapWorkerEvidence(StrictModel):
    """Normalized worker evidence from a controller-rendered SQLMap run. NOT a verdict.

    ``tool_reported_injectable`` is what SQLMap itself claims; it is recorded for audit but
    is NEVER a verifier CONFIRMED/PASS input (SQLMap output alone sets no verdict).
    """

    job_id: str
    parameter: str
    control: SqlmapResultSlot
    boolean_true: SqlmapResultSlot
    boolean_false: SqlmapResultSlot
    canary_value_present: bool = False
    canary_value_digest: str = ""
    tool_reported_injectable: bool = False
    sanitized_note: str = Field(default="", max_length=300)

    def as_verifier_input(self) -> dict[str, object]:
        """The reference-only differential the verifier adjudicates (no tool verdict)."""

        return {
            "control": self.control.model_dump(),
            "boolean_true": self.boolean_true.model_dump(),
            "boolean_false": self.boolean_false.model_dump(),
        }


class SqlmapManifest(StrictModel):
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
    canary_read_performed: bool
    cleanup_complete: bool
    created_at: datetime = Field(default_factory=now_utc)


# --------------------------------------------------------------------------- #
# Scope resolution + deterministic argv rendering + enforcement.
# --------------------------------------------------------------------------- #


def _resolve_range_target(target_ref: str) -> tuple[str, str]:
    matches = [
        (item.application_id, item.origin)
        for item in RANGE_TARGETS.values()
        if item.target_ref == target_ref
    ]
    if len(matches) != 1:
        raise SqlmapCapabilityError("TARGET_REF_NOT_IN_INVENTORY")
    return matches[0]


def _host(origin: str) -> str:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SqlmapCapabilityError("TARGET_ORIGIN_MALFORMED")
    return parsed.hostname


@dataclass
class SqlmapLease:
    signed: bool
    authorized: bool
    target_ref: str
    environment_tier: EnvironmentTier = EnvironmentTier.SYNTHETIC_RANGE


def render_sqlmap_argv(
    profile: SqlmapProfile,
    target_url: str,
    parameter: str,
    *,
    capture_dir: str | None = None,
) -> tuple[str, ...]:
    """Render a deterministic, bounded, shell-free SQLMap argv. Fails closed on an unsafe token.

    When ``capture_dir`` is given, the run also logs all SQLMap-generated HTTP traffic to
    ``<capture_dir>/traffic.txt`` (``-t``) and writes its session under ``<capture_dir>`` so the
    controller can normalize SQLMap-originated request/response evidence. It is a controller-owned
    container path (never target/model-authored); the argv denylist still rejects unsafe tokens."""

    timeout_s = str(max(1, profile.per_request_timeout_ms // 1000))
    argv = [
        "sqlmap", "-u", target_url, "-p", parameter,
        "--batch", "--disable-coloring", "--flush-session", "--fresh-queries",
        "--technique", profile.technique,
        "--level", str(profile.level), "--risk", str(profile.risk),
        "--threads", str(profile.threads),
        "--timeout", timeout_s, "--retries", str(profile.retries),
    ]
    if capture_dir is not None:
        if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,120}", capture_dir):
            raise SqlmapCapabilityError("SQLMAP_CAPTURE_DIR_UNSAFE")
        argv += ["-t", f"{capture_dir}/traffic.txt", "--output-dir", capture_dir]
    if profile.dbms_banner:
        argv.append("--banner")
    if profile.canary_read:
        # A bounded single-row, single-column read of the seeded synthetic canary. Never --dump-all.
        argv += [
            "--dump", "-T", CANARY_TABLE, "-C", CANARY_COLUMN,
            "--where", CANARY_WHERE, "--start", "1", "--stop", "1", "--no-cast",
        ]
    return _assert_argv_safe(argv)


def _job_id(target_url: str, parameter: str, profile_id: str) -> str:
    material = f"{profile_id}:{target_url}:{parameter}"
    return "sqlmj-" + hashlib.sha256(material.encode()).hexdigest()[:16]


def build_sqlmap_job(
    plan: SqlmapPlan,
    *,
    lease: SqlmapLease | None = None,
    image: SqlmapToolImage | None = None,
    seed_value: str = "1",
    capture_dir: str | None = None,
) -> SqlmapInjectionJob:
    """Validate a typed plan and render a fully-bounded, shell-free SQLMap job, or fail closed.

    Every rejection happens BEFORE any argv is rendered, so a rejected plan yields zero commands and
    zero target traffic.

    ``image`` optionally overrides the tool image provenance. It defaults to the module
    ``SQLMAP_PROVENANCE`` (an unpinned placeholder that keeps the offline path ``NOT_EVALUATED``);
    the Phase 2.8 container-acceptance harness passes an operator-reviewed, digest-pinned image so
    an actual container run is admitted (see :func:`assert_container_pinned`).

    ``seed_value`` is the controller-owned baseline parameter value (default ``"1"``); the container
    harness uses a value that returns a stable non-empty baseline so the pinned SQLMap can honestly
    exhibit a boolean-differential. ``capture_dir`` turns on SQLMap-originated traffic capture. Both
    are controller-owned; neither is model- or target-authored."""

    provenance = image or SQLMAP_PROVENANCE
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", seed_value):
        raise SqlmapCapabilityError("SQLMAP_SEED_VALUE_UNSAFE")

    if plan.capability_id != SQLMAP_CAPABILITY_ID:
        raise SqlmapCapabilityError("SQLMAP_CAPABILITY_MISMATCH")
    profile = SQLMAP_PROFILES.get(plan.profile_id)
    if profile is None:
        raise SqlmapCapabilityError("SQLMAP_PROFILE_UNKNOWN")

    # Environment-tier gate. The canary-impact profile is synthetic-range only. Any non-range tier
    # needs a signed target-bound lease; unclassified fails closed to PRODUCTION_PROHIBITED.
    if profile.environment is EnvironmentTier.SYNTHETIC_RANGE:
        application_id, origin = _resolve_range_target(plan.target_ref)
    else:
        if profile.synthetic_range_only:
            raise SqlmapCapabilityError("CANARY_PROFILE_SYNTHETIC_RANGE_ONLY")
        if lease is None or not lease.signed or not lease.authorized:
            raise SqlmapCapabilityError("SQLMAP_LEASE_MISSING")
        if lease.target_ref != plan.target_ref:
            raise SqlmapCapabilityError("SQLMAP_LEASE_TARGET_MISMATCH")
        tier = classify_environment(lease.environment_tier.value)
        if tier is EnvironmentTier.PRODUCTION_PROHIBITED:
            raise SqlmapCapabilityError("SQLMAP_ENVIRONMENT_PROHIBITED")
        raise SqlmapCapabilityError("SQLMAP_NON_RANGE_INVENTORY_UNAVAILABLE")

    if profile.synthetic_range_only and profile.environment is not EnvironmentTier.SYNTHETIC_RANGE:
        raise SqlmapCapabilityError("CANARY_PROFILE_SYNTHETIC_RANGE_ONLY")

    host = _host(origin)
    target_url = f"{origin}{plan.route}?{plan.parameter}={seed_value}"
    argv = render_sqlmap_argv(profile, target_url, plan.parameter, capture_dir=capture_dir)

    # Scope: the authorized host must appear in the argv and the bounded target-url must match.
    # target url, and the bounded target-url must be the exact controller-composed one.
    if host not in " ".join(argv) or target_url not in argv:
        raise SqlmapCapabilityError("SQLMAP_SCOPE_HOST_MISSING_FROM_ARGV")

    return SqlmapInjectionJob(
        job_id=_job_id(target_url, plan.parameter, plan.profile_id),
        capability_id=plan.capability_id,
        profile_id=plan.profile_id,
        target_ref=plan.target_ref,
        application_id=application_id,
        authorized_origin=origin,
        scope_host=host,
        target_url=target_url,
        parameter=plan.parameter,
        argv=argv,
        technique=profile.technique,
        level=profile.level,
        risk=profile.risk,
        threads=profile.threads,
        max_requests=profile.max_requests,
        max_output_bytes=profile.max_output_bytes,
        per_request_timeout_ms=profile.per_request_timeout_ms,
        environment_tier=profile.environment,
        allows_canary_read=profile.canary_read,
        image_ref=provenance.image_ref,
        image_digest=provenance.image_digest,
        tool_version=provenance.version,
        digest_pinned=provenance.digest_pinned,
    )


# --------------------------------------------------------------------------- #
# Untrusted-output sanitation + manifest.
# --------------------------------------------------------------------------- #

_FORBIDDEN_OUTPUT_TOKENS: tuple[str, ...] = (
    "bearer ", "authorization:", "set-cookie", "password", "passcode",
    "lab-token-", "credentialref://", "-----begin",
)


def sanitize_sqlmap_output(raw: bytes, *, max_bytes: int) -> tuple[str, bool]:
    """Bound and sanitize untrusted SQLMap stdout. Returns (safe_text, truncated)."""

    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    text = "".join(ch for ch in text if ch in "\n\t" or ch >= " ")
    for token in _FORBIDDEN_OUTPUT_TOKENS:
        if token in text.lower():
            text = "\n".join(
                "[REDACTED_SANITIZED_LINE]" if token in line.lower() else line
                for line in text.split("\n")
            )
    return text, truncated


def build_manifest(
    job: SqlmapInjectionJob,
    *,
    output_bytes: int,
    output_truncated: bool,
    canary_read_performed: bool,
    cleanup_complete: bool,
) -> SqlmapManifest:
    return SqlmapManifest(
        job_id=job.job_id,
        capability_id=job.capability_id,
        profile_id=job.profile_id,
        argv_digest=job.argv_digest,
        image_ref=job.image_ref,
        tool_version=job.tool_version,
        digest_pinned=job.digest_pinned,
        output_bytes=min(output_bytes, job.max_output_bytes),
        output_truncated=output_truncated,
        canary_read_performed=canary_read_performed and job.allows_canary_read,
        cleanup_complete=cleanup_complete,
    )


class SqlmapObservationType(StrEnum):
    """The typed injection observation vocabulary. Never a verdict/PASS/CONFIRMED/severity."""

    SQLI_BOOLEAN_DIFFERENTIAL = "SQLI_BOOLEAN_DIFFERENTIAL"
    SQLI_CANARY_READ = "SQLI_CANARY_READ"
    NO_DIFFERENTIAL = "NO_DIFFERENTIAL"
    INCOMPLETE_TOOL_ERROR = "INCOMPLETE_TOOL_ERROR"
