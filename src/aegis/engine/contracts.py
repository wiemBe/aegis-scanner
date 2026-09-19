"""Strict typed contracts for the security-tool integration kernel (Phase 1.1).

Every model here is deliberately narrow. In particular the controller-authored :class:`EngineJob`
carries NO command, argument, CLI flag, raw URL, template id, scan-config blob or credential value
field. Because the models forbid extra properties (``extra="forbid"``), any attempt to smuggle such
a field in — from the AI, from a serialized record, or from a mis-wired caller — is a hard
validation error rather than a silently-accepted instruction. This is the structural half of "the
adapter must not interpret arbitrary model prose"; the deterministic policy in
:mod:`aegis.engine.policy` is the procedural half.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Strict(BaseModel):
    """Base for controller/adapter-authored records.

    ``extra="forbid"`` is the security-critical property: no command, flag, template or scan-config
    field can ever be smuggled onto a job or record — an unexpected key is a hard error. We do NOT
    set ``strict=True`` because these records are serialized to JSON (stored on the scan, streamed
    over the console API) and must round-trip back through ``model_validate``; field patterns, enums
    and numeric bounds still validate every value."""

    model_config = ConfigDict(extra="forbid")


# The Phase 1.1 kernel version. Incremented only when these contracts, the capability catalog policy
# or the deterministic execution policy change in a way that affects recorded evidence.
ENGINE_KERNEL_VERSION = 1


class SecurityEngine(StrEnum):
    """The four supported engine identifiers. Only ``AEGIS_NATIVE`` is enabled in Phase 1.1."""

    AEGIS_NATIVE = "AEGIS_NATIVE"
    NUCLEI = "NUCLEI"
    ZAP = "ZAP"
    BURP_DAST = "BURP_DAST"


class EngineActivity(StrEnum):
    """Whether a capability only observes (PASSIVE) or actively probes/interacts (ACTIVE)."""

    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class EngineEnvironment(StrEnum):
    """Environments a capability may run against. Only the synthetic lab is allowed in Phase 1.1."""

    SYNTHETIC_LAB = "SYNTHETIC_LAB"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class VerificationPolicy(StrEnum):
    """Who may promote an engine observation to a real Aegis result.

    ``DETERMINISTIC_AEGIS_VERIFIER`` — the local deterministic verifier is authoritative (AEGIS
    NATIVE BOLA today). ``HUMAN_REVIEW_REQUIRED`` — no deterministic verifier exists yet, so a
    reported finding may only reach REVIEW_REQUIRED, never VERIFIED, without a human. ``NONE`` —
    the capability produces no promotable finding at all (pure telemetry)."""

    DETERMINISTIC_AEGIS_VERIFIER = "DETERMINISTIC_AEGIS_VERIFIER"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    NONE = "NONE"


class EvidenceSourceClass(StrEnum):
    """Provenance class of a normalized evidence item."""

    ENGINE_OBSERVATION = "ENGINE_OBSERVATION"
    CONTROLLER_DERIVED = "CONTROLLER_DERIVED"
    VERIFIER_DERIVED = "VERIFIER_DERIVED"


class RetentionClass(StrEnum):
    """Retention classification for a normalized evidence item."""

    EPHEMERAL = "EPHEMERAL"
    STANDARD = "STANDARD"
    EXTENDED = "EXTENDED"


class FindingLifecycleState(StrEnum):
    """The normalized finding lifecycle.

    An adapter result enters at ``TOOL_REPORTED`` and can NEVER jump straight to a confirmed Aegis
    finding. Promotion happens only through deterministic correlation + verification or explicit
    human review::

        TOOL_REPORTED -> AEGIS_CORRELATED -> VERIFIED
                                          \\-> REVIEW_REQUIRED
                                          \\-> REJECTED
    """

    TOOL_REPORTED = "TOOL_REPORTED"
    AEGIS_CORRELATED = "AEGIS_CORRELATED"
    VERIFIED = "VERIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


class EngineExecutionStatus(StrEnum):
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EngineErrorCode(StrEnum):
    """Structured, safe error codes. Never carries raw exception prose."""

    ENGINE_DISABLED = "ENGINE_DISABLED"
    ADAPTER_DISABLED = "ADAPTER_DISABLED"
    UNKNOWN_ENGINE = "UNKNOWN_ENGINE"
    UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    OUT_OF_SCOPE_ORIGIN = "OUT_OF_SCOPE_ORIGIN"
    OUT_OF_SCOPE_OPERATION = "OUT_OF_SCOPE_OPERATION"
    UNAPPROVED_STATE_CHANGE = "UNAPPROVED_STATE_CHANGE"
    MISSING_AUTH_CONTEXT = "MISSING_AUTH_CONTEXT"  # noqa: S105 - error code label, not a secret
    UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"
    ARBITRARY_COMMAND_FIELD = "ARBITRARY_COMMAND_FIELD"
    UNKNOWN_TEMPLATE_OR_SCAN_CONFIG = "UNKNOWN_TEMPLATE_OR_SCAN_CONFIG"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    DISALLOWED_ENVIRONMENT = "DISALLOWED_ENVIRONMENT"
    SCOPE_EXPANSION_ATTEMPT = "SCOPE_EXPANSION_ATTEMPT"
    MALFORMED_ENGINE_OUTPUT = "MALFORMED_ENGINE_OUTPUT"
    OVERSIZED_ENGINE_OUTPUT = "OVERSIZED_ENGINE_OUTPUT"


class EngineError(_Strict):
    """A structured, UI-safe engine/policy error. ``detail`` is a bounded, non-sensitive label."""

    code: EngineErrorCode
    engine: SecurityEngine
    detail: str = Field(default="", max_length=200)
    job_id: str | None = Field(default=None, max_length=64)


class TargetReference(_Strict):
    """A controller-owned target reference. Built ONLY from the approved target inventory and scope.

    It is a structured reference to an approved origin + operation, never a free-form URL or a
    model-authored string. ``origin`` is an approved scheme://host[:port]; ``operation_id`` and
    ``normalized_path`` come from the projected surface. ``object_ref`` is an approved synthetic
    object identifier."""

    engine: SecurityEngine
    environment: EngineEnvironment
    origin: str = Field(max_length=200)
    operation_id: str = Field(min_length=1, max_length=100)
    method: Literal["GET", "HEAD", "OPTIONS"]
    normalized_path: str = Field(pattern=r"^/[A-Za-z0-9/_{}-]+$", max_length=200)
    object_ref: str | None = Field(default=None, max_length=100)

    @field_validator("origin")
    @classmethod
    def _origin_is_bounded(cls, value: str) -> str:
        if "?" in value or "#" in value or "@" in value or " " in value:
            raise ValueError("origin must not carry query, fragment, credentials or whitespace")
        return value


class EngineJobRequest(_Strict):
    """One controller-compiled read-only request inside an :class:`EngineJob`.

    This mirrors the shape of :class:`aegis.models.PlannedRequest` but is transported through the
    engine boundary. It references a synthetic credential PROFILE only; the credential value is
    resolved inside the connector boundary and is never present here."""

    name: str = Field(min_length=3, max_length=100)
    method: Literal["GET", "HEAD", "OPTIONS"]
    path: str = Field(pattern=r"^/[A-Za-z0-9/_{}-]+$", max_length=200)
    credential_profile: Literal["anonymous", "user_a", "user_b"]
    object_ref: str | None = Field(default=None, max_length=100)


class EngineBudget(_Strict):
    """Per-job deterministic budgets. The adapter must not exceed any of them."""

    max_requests: int = Field(ge=0, le=64)
    max_concurrency: int = Field(ge=1, le=8)
    time_budget_ms: int = Field(ge=1, le=600_000)


class EngineJob(_Strict):
    """The typed unit of work handed to an adapter. Built ONLY by the deterministic controller.

    Note what is absent by design: no ``command``, ``args``, ``flags``, ``raw_url``, ``template``,
    ``scan_config``, ``headers`` or ``credential`` field. There is nowhere to put an arbitrary
    command line or tool-specific flag, so injecting one is a structural impossibility, not a policy
    that could be forgotten."""

    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    engine: SecurityEngine
    profile_id: str = Field(min_length=1, max_length=100)
    capability_id: str = Field(min_length=1, max_length=100)
    adapter_version: str = Field(min_length=1, max_length=40)
    run_id: str = Field(min_length=1, max_length=64)
    environment: EngineEnvironment
    activity: EngineActivity
    target: TargetReference
    credential_profile_refs: list[Literal["anonymous", "user_a", "user_b"]] = Field(
        min_length=1, max_length=3
    )
    requests: list[EngineJobRequest] = Field(min_length=1, max_length=16)
    budget: EngineBudget
    created_by: Literal["CONTROLLER"] = "CONTROLLER"

    @field_validator("requests")
    @classmethod
    def _requests_unique(cls, value: list[EngineJobRequest]) -> list[EngineJobRequest]:
        names = [r.name for r in value]
        if len(names) != len(set(names)):
            raise ValueError("engine job request names must be unique")
        return value


class EngineObservation(_Strict):
    """A single, redacted observation returned by an engine. UNTRUSTED input.

    It records only bounded, non-sensitive facts: which controller request it answers, the status
    code, timing, a content digest and whether an error occurred. It NEVER carries a response body,
    header values, credentials or exception prose."""

    request_name: str = Field(min_length=1, max_length=100)
    method: Literal["GET", "HEAD", "OPTIONS"]
    path: str = Field(max_length=200)
    credential_profile: Literal["anonymous", "user_a", "user_b"]
    status_code: int | None = Field(default=None, ge=100, le=599)
    duration_ms: int = Field(ge=0, le=600_000)
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    has_error: bool = False


class EngineReportedFinding(_Strict):
    """What an engine CLAIMS it found. UNTRUSTED and non-authoritative.

    Deliberately carries no severity, no confidence, and no CONFIRMED/PASS field: an engine cannot
    self-assign a verdict through this contract. It records the claimed capability/target and the
    observation names that motivated the claim, so the deterministic verifier and reviewer have
    something to correlate against. A stable ``report_key`` makes duplicate reports correlate
    deterministically."""

    report_key: str = Field(min_length=1, max_length=200)
    engine: SecurityEngine
    capability_id: str = Field(min_length=1, max_length=100)
    claimed_category: str = Field(min_length=1, max_length=100)
    target_operation_id: str = Field(min_length=1, max_length=100)
    object_ref: str | None = Field(default=None, max_length=100)
    principal_profile: Literal["anonymous", "user_a", "user_b"]
    observation_names: list[str] = Field(min_length=1, max_length=16)
    # A short, structured description of the raw signal. Never response prose or model reasoning.
    signal: str = Field(min_length=3, max_length=200)


class EngineExecution(_Strict):
    """The recorded result of dispatching one :class:`EngineJob` to an adapter."""

    execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    engine: SecurityEngine
    adapter_version: str = Field(min_length=1, max_length=40)
    status: EngineExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    observations: list[EngineObservation] = Field(default_factory=list)
    reported_findings: list[EngineReportedFinding] = Field(default_factory=list)
    error: EngineError | None = None


class NormalizedEvidence(_Strict):
    """A normalized, provenance-complete evidence item. No secrets, no raw response prose.

    Every field required by the Phase 1.1 evidence-provenance contract is present and mandatory
    (except identifiers that are genuinely optional for a given source)."""

    evidence_id: str = Field(min_length=1, max_length=160)
    engine: SecurityEngine
    adapter_version: str = Field(min_length=1, max_length=40)
    engine_execution_id: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=64)
    scan_id: str = Field(min_length=1, max_length=64)
    timestamp: datetime
    capability_id: str = Field(min_length=1, max_length=100)
    target_ref: str = Field(min_length=1, max_length=200)
    request_refs: list[str] = Field(default_factory=list, max_length=16)
    artifact_refs: list[str] = Field(default_factory=list, max_length=16)
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"] = "REDACTED"
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    parser_version: str = Field(min_length=1, max_length=40)
    source_class: EvidenceSourceClass
    retention_class: RetentionClass


class VerifierConclusion(_Strict):
    """The deterministic verifier's conclusion about a normalized finding."""

    status: Literal["CONFIRMED", "PASS", "INSUFFICIENT"]
    summary: str = Field(min_length=3, max_length=300)
    aegis_finding_id: str | None = Field(default=None, max_length=160)
    evidence_ids: list[str] = Field(default_factory=list, max_length=16)


class HumanReview(_Strict):
    """A recorded human-review decision. Only a human may set this."""

    reviewer: str = Field(min_length=1, max_length=100)
    decision: Literal["ACCEPTED", "REJECTED", "PENDING"]
    note: str = Field(default="", max_length=300)
    reviewed_at: datetime


class NormalizedFinding(_Strict):
    """The single record that threads the finding lifecycle and separates every responsibility.

    It records, distinctly and immutably per stage: what the AI hypothesized, what the controller
    authorized, what the engine reported, which evidence was collected, what the verifier concluded,
    and what a human reviewed. ``severity``/``confidence`` are set ONLY when ``lifecycle_state``
    is ``VERIFIED`` and only from the deterministic verifier — never from the engine."""

    normalized_id: str = Field(min_length=1, max_length=200)
    engine: SecurityEngine
    adapter_version: str = Field(min_length=1, max_length=40)
    capability_id: str = Field(min_length=1, max_length=100)
    run_id: str = Field(min_length=1, max_length=64)
    lifecycle_state: FindingLifecycleState
    # What the AI proposed (structured, redacted).
    ai_hypothesis: str = Field(default="", max_length=300)
    # What the controller authorized (job id + capability/operation).
    controller_authorization: str = Field(default="", max_length=300)
    # What the engine reported (untrusted claim summary).
    engine_reported: str = Field(default="", max_length=300)
    engine_report_key: str | None = Field(default=None, max_length=200)
    # Evidence collected for this finding.
    evidence_ids: list[str] = Field(default_factory=list, max_length=16)
    # What the verifier concluded (None until verification runs).
    verifier_conclusion: VerifierConclusion | None = None
    # What a human reviewed (None unless review happened).
    human_review: HumanReview | None = None
    # The promoted Aegis finding id, set ONLY on VERIFIED.
    aegis_finding_id: str | None = Field(default=None, max_length=160)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    confidence: Literal["CONFIRMED", "PROBABLE", "UNVERIFIED"] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EngineHealth(_Strict):
    """Honest, four-state adapter health for the console. Never forces a disabled engine green.

    The four states are independent and must not be conflated: an engine can be ``configured`` (a
    profile exists) yet not ``enabled`` (adapter is fail-closed), and ``reachable`` (network) is
    distinct from ``authorized`` (a credential boundary is provisioned)."""

    engine: SecurityEngine
    adapter_version: str = Field(min_length=1, max_length=40)
    configured: bool
    reachable: bool | None  # None = not probed / not applicable while disabled
    enabled: bool
    authorized: bool
    # A single summary label derived from the four states, for compact display.
    state: str = Field(min_length=1, max_length=40)
    detail: str = Field(default="", max_length=200)
