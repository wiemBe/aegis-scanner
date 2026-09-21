"""Strict typed contracts for the Phase 1.5 active reflected-XSS integration.

Separate from the passive ``aegis_zap.contracts`` because active scanning has different bounds: a
much larger (but still hard-capped and measured) request budget, a longer wall-clock budget, an
inter-request delay, a single-use lease token, and an alert record that carries a REDACTED
classification and digest of ZAP's ``attack`` field — never the raw attack text.

The generic guard/attestation records are imported from the passive contracts unchanged, so the
scope guard and runner attestation shapes stay identical across profiles.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis_zap.contracts import (  # reused unchanged
    AddOnAttestation,
    ExitClass,
    GuardCounters,
    ParseStatus,
    RunnerGuardState,
    ZapEngineAttestation,
)

RPC_SCHEMA: Literal["aegis.zap.active-rpc/1"] = "aegis.zap.active-rpc/1"
RUNNER_VERSION = "zap-active-runner/1.5.0"
MAX_RPC_REQUEST_BYTES = 4_096
MAX_RPC_RESPONSE_BYTES = 262_144

_SHA256 = r"^[a-f0-9]{64}$"
_SCAN_ID = r"^scan-[a-f0-9]{12}$"
_PATH = r"^/[A-Za-z0-9/_.-]{0,200}$"
# The authenticated lease token: fixed version prefix, url-safe base64 claims, 256-bit MAC.
_LEASE_TOKEN = r"^AZL1\.[A-Za-z0-9_-]{32,960}\.[A-Za-z0-9_-]{43}$"  # noqa: S105 - format, not a secret
_LEASE_ID = r"^lease-[a-f0-9]{16}$"

__all__ = [
    "RPC_SCHEMA",
    "RUNNER_VERSION",
    "MAX_RPC_REQUEST_BYTES",
    "MAX_RPC_RESPONSE_BYTES",
    "ZapActiveErrorCode",
    "LeaseState",
    "RedactedLeaseRecord",
    "ActiveLeaseFacts",
    "ZapActiveLeaseArmRequest",
    "ZapActiveLeaseRevokeRequest",
    "ZapActiveLeaseStatusResponse",
    "ZapActiveBudgets",
    "ZapActiveRunRequest",
    "ZapActiveParseSummary",
    "AttackClass",
    "ZapActiveAlertRecord",
    "ActiveStageFacts",
    "ActivePlanFacts",
    "ActiveProjectionFacts",
    "ZapActiveRunResponse",
    "ZapActiveRunnerAttestation",
    "AddOnAttestation",
    "GuardCounters",
    "RunnerGuardState",
    "ZapEngineAttestation",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ZapActiveErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    RUNNER_NOT_READY = "RUNNER_NOT_READY"
    UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
    UNKNOWN_TARGET = "UNKNOWN_TARGET"
    PROJECTION_REJECTED = "PROJECTION_REJECTED"
    PROJECTION_REF_MISMATCH = "PROJECTION_REF_MISMATCH"
    PROJECTION_DIGEST_MISMATCH = "PROJECTION_DIGEST_MISMATCH"
    ALLOWLIST_DIGEST_MISMATCH = "ALLOWLIST_DIGEST_MISMATCH"
    BUDGET_OUT_OF_BOUNDS = "BUDGET_OUT_OF_BOUNDS"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    BUSY = "BUSY"
    # --- lease admission (bounded labels only; never token bytes or crypto detail) ---------
    LEASE_REQUIRED = "LEASE_REQUIRED"  # noqa: S105 - error label, not a secret
    LEASE_INVALID = "LEASE_INVALID"  # noqa: S105 - error label, not a secret
    LEASE_MALFORMED = "LEASE_MALFORMED"  # noqa: S105 - error label, not a secret
    LEASE_UNKNOWN_FORMAT = "LEASE_UNKNOWN_FORMAT"  # noqa: S105 - error label, not a secret
    LEASE_NOT_CANONICAL = "LEASE_NOT_CANONICAL"  # noqa: S105 - error label, not a secret
    LEASE_CLAIMS_INVALID = "LEASE_CLAIMS_INVALID"  # noqa: S105 - error label, not a secret
    LEASE_SIGNATURE_INVALID = "LEASE_SIGNATURE_INVALID"  # noqa: S105 - error label, not a secret
    LEASE_AUDIENCE_MISMATCH = "LEASE_AUDIENCE_MISMATCH"  # noqa: S105 - error label, not a secret
    LEASE_EXPIRED = "LEASE_EXPIRED"  # noqa: S105 - error label, not a secret
    LEASE_NOT_YET_VALID = "LEASE_NOT_YET_VALID"  # noqa: S105 - error label, not a secret
    LEASE_LIFETIME_EXCESSIVE = "LEASE_LIFETIME_EXCESSIVE"  # noqa: S105 - error label, not a secret
    LEASE_BINDING_MISMATCH = "LEASE_BINDING_MISMATCH"  # noqa: S105 - error label, not a secret
    LEASE_NOT_ARMED = "LEASE_NOT_ARMED"  # noqa: S105 - error label, not a secret
    LEASE_ALREADY_CONSUMED = "LEASE_ALREADY_CONSUMED"  # noqa: S105 - error label, not a secret
    LEASE_REVOKED = "LEASE_REVOKED"  # noqa: S105 - error label, not a secret
    LEASE_REGISTRY_UNAVAILABLE = "LEASE_REGISTRY_UNAVAILABLE"  # noqa: S105 - not a secret
    LEASE_SECRET_UNAVAILABLE = "LEASE_SECRET_UNAVAILABLE"  # noqa: S105 - not a secret
    GUARD_BINDING_MISMATCH = "GUARD_BINDING_MISMATCH"
    EMERGENCY_STOP = "EMERGENCY_STOP"
    ENGINE_INTEGRITY_FAILURE = "ENGINE_INTEGRITY_FAILURE"
    ADDON_INVENTORY_DRIFT = "ADDON_INVENTORY_DRIFT"
    PLAN_INVALID = "PLAN_INVALID"
    GUARD_UNAVAILABLE = "GUARD_UNAVAILABLE"
    SPAWN_FAILED = "SPAWN_FAILED"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    OUTPUT_OVERSIZED = "OUTPUT_OVERSIZED"
    NONZERO_EXIT = "NONZERO_EXIT"
    PLAN_FAILED = "PLAN_FAILED"
    ADDON_RUNTIME_MISMATCH = "ADDON_RUNTIME_MISMATCH"
    SILENT_MODE_NOT_CONFIRMED = "SILENT_MODE_NOT_CONFIRMED"
    RULE_SET_MISMATCH = "RULE_SET_MISMATCH"
    ACTIVE_RULE_NOT_LOADED = "ACTIVE_RULE_NOT_LOADED"
    SCOPE_ESCAPE_BLOCKED = "SCOPE_ESCAPE_BLOCKED"
    REDIRECT_OBSERVED = "REDIRECT_OBSERVED"
    REQUEST_BUDGET_EXCEEDED = "REQUEST_BUDGET_EXCEEDED"
    TARGET_TIMEOUT = "TARGET_TIMEOUT"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    IMPORT_INCOMPLETE = "IMPORT_INCOMPLETE"
    ACTIVE_SCAN_INCOMPLETE = "ACTIVE_SCAN_INCOMPLETE"
    PASSIVE_QUEUE_NOT_DRAINED = "PASSIVE_QUEUE_NOT_DRAINED"
    UNEXPECTED_QUERY_PARAM = "UNEXPECTED_QUERY_PARAM"
    REPORT_MISSING = "REPORT_MISSING"
    REPORT_OVERSIZED = "REPORT_OVERSIZED"
    REPORT_TRUNCATED = "REPORT_TRUNCATED"
    REPORT_MALFORMED = "REPORT_MALFORMED"
    UNADMITTED_RULE = "UNADMITTED_RULE"
    ATTACK_FIELD_REJECTED = "ATTACK_FIELD_REJECTED"


# --- controller -> runner --------------------------------------------------------------------


class ZapActiveBudgets(_Strict):
    # Active scanning sends many payloads for the one rule; the ceiling is hard-capped and measured.
    max_requests: int = Field(ge=1, le=512)
    time_budget_ms: int = Field(ge=30_000, le=660_000)
    max_report_bytes: int = Field(ge=4_096, le=262_144)
    max_alerts: int = Field(ge=1, le=16)
    delay_ms: int = Field(ge=0, le=5_000)


class ZapActiveRunRequest(_Strict):
    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    run_id: str = Field(pattern=_SCAN_ID)
    scan_id: str = Field(pattern=_SCAN_ID)
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    projection_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}/[0-9]+\.[0-9]+\.[0-9]+$")
    projection_digest: str = Field(pattern=_SHA256)
    operation_allowlist_digest: str = Field(pattern=_SHA256)
    query_param: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    budgets: ZapActiveBudgets
    # An authenticated, single-use lease. The runner does not merely check its shape: it forwards
    # it to the root-owned admission component, which verifies the MAC and the armed registry.
    lease_token: str = Field(pattern=_LEASE_TOKEN)
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    correlation_id: str = Field(pattern=r"^corr-[a-f0-9]{16}$")


# --- runner -> controller --------------------------------------------------------------------


class ZapActiveParseSummary(_Strict):
    parser_version: str = Field(max_length=48)
    status: ParseStatus
    failure_code: ZapActiveErrorCode | None = None
    sites: int = Field(ge=0)
    alerts: int = Field(ge=0)
    instances: int = Field(ge=0)
    records: int = Field(ge=0)
    duplicates_collapsed: int = Field(ge=0)
    stripped_fields: tuple[str, ...] = Field(default=(), max_length=16)


AttackClass = Literal[
    "SCRIPT_ELEMENT",
    "ATTRIBUTE_BREAKOUT",
    "EVENT_HANDLER",
    "JS_URI",
    "MARKUP_INJECTION",
    "OTHER",
    "NONE",
]


class ZapActiveAlertRecord(_Strict):
    """One parsed, redacted ZAP active alert instance. UNTRUSTED: a tool claim, never a verdict.

    The scanner's ``attack`` field is reduced to a coarse structural CLASS plus a length and SHA-256
    so identical alerts correlate deterministically; the raw attack string is never carried."""

    plugin_id: int = Field(ge=0, le=999_999)
    rule_name: str = Field(max_length=120)
    method: Literal["GET", "HEAD"]
    path: str = Field(pattern=_PATH)
    param: str = Field(max_length=100)
    claimed_risk: Literal["info", "low", "medium", "high"]
    claimed_confidence: Literal["falsepositive", "low", "medium", "high", "confirmed"]
    evidence_sha256: str = Field(pattern=_SHA256)
    evidence_length: int = Field(ge=0, le=4_096)
    attack_class: AttackClass
    attack_sha256: str = Field(pattern=_SHA256)
    attack_length: int = Field(ge=0, le=8_192)
    record_digest: str = Field(pattern=_SHA256)


class LeaseState(StrEnum):
    ARMED = "ARMED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class RedactedLeaseRecord(BaseModel):
    """The only lease projection that ever leaves the admission boundary.

    It carries the bindings an operator needs in order to audit a run and nothing that could be
    replayed: no token, no signature and no nonce."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    lease_id: str = Field(pattern=_LEASE_ID)
    state: LeaseState
    capability_id: str = Field(max_length=100)
    profile_id: str = Field(max_length=64)
    target_ref: str = Field(max_length=64)
    target_origin: str = Field(max_length=200)
    projection_digest: str = Field(pattern=_SHA256)
    allowlist_digest: str = Field(pattern=_SHA256)
    manifest_digest: str = Field(pattern=_SHA256)
    budget_id: str = Field(max_length=32)
    audience: str = Field(max_length=64)
    not_before: str = Field(max_length=40)
    expires_at: str = Field(max_length=40)
    armed_at: str = Field(max_length=40)
    consumed_at: str | None = None
    consumed_by: str | None = None
    terminated_at: str | None = None
    termination_reason: str | None = Field(default=None, max_length=40)


class ActiveLeaseFacts(_Strict):
    """What one execution reports about the lease it ran under. No token, ever."""

    required: bool = True
    presented: bool = False
    consumed: bool = False
    lease_id: str | None = Field(default=None, pattern=_LEASE_ID)
    state: LeaseState | None = None
    expires_at: str | None = Field(default=None, max_length=40)
    budget_id: str | None = Field(default=None, max_length=32)
    guard_binding_confirmed: bool = False
    revoked_after_execution: bool = False
    rejection_code: str | None = Field(default=None, max_length=40)


class ZapActiveLeaseArmRequest(_Strict):
    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    lease_token: str = Field(pattern=_LEASE_TOKEN)


class ZapActiveLeaseRevokeRequest(_Strict):
    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    lease_id: str = Field(pattern=_LEASE_ID)
    reason: str = Field(default="revoked", pattern=r"^[A-Za-z0-9_]{1,40}$")


class ZapActiveLeaseStatusResponse(BaseModel):
    """Redacted lease status for the controller and, through it, the Operator Console."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    admission_reachable: bool
    state_root_owned: bool = False
    armed: RedactedLeaseRecord | None = None
    recent: tuple[RedactedLeaseRecord, ...] = Field(default=(), max_length=16)
    armed_total: int = Field(default=0, ge=0)
    consumed_total: int = Field(default=0, ge=0)
    revoked_total: int = Field(default=0, ge=0)
    rejected_total: int = Field(default=0, ge=0)
    restart_revoked_total: int = Field(default=0, ge=0)


class ActiveProjectionFacts(_Strict):
    projection_ref: str = Field(max_length=80)
    projection_version: str = Field(max_length=16)
    digest: str = Field(pattern=_SHA256)
    allowlist_digest: str = Field(pattern=_SHA256)
    source_sha256: str = Field(pattern=_SHA256)
    operation_count: int = Field(ge=0, le=1)
    path_count: int = Field(ge=0, le=1)
    query_param: str = Field(max_length=32)
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"]


class ActivePlanFacts(_Strict):
    plan_digest: str | None = Field(default=None, pattern=_SHA256)
    validated: bool
    job_types: tuple[str, ...] = Field(default=(), max_length=8)
    admitted_rule_ids: tuple[int, ...] = Field(default=(), max_length=4)
    strength: str = Field(default="", max_length=8)
    threshold: str = Field(default="", max_length=8)


class ActiveStageFacts(_Strict):
    plan_validated: bool = False
    zap_started: bool = False
    import_started: bool = False
    import_completed: bool = False
    urls_added: int | None = Field(default=None, ge=0, le=10_000)
    urls_test_passed: bool = False
    passive_rules_disabled: bool = False
    active_scan_started: bool = False
    active_scan_completed: bool = False
    active_rules_loaded: int = Field(default=0, ge=0)
    admitted_active_rule_ran: bool = False
    pscan_drained: bool = False
    report_generated: bool = False
    plan_succeeded: bool = False
    silent_mode: bool = False
    installed_add_ons: tuple[tuple[str, str], ...] = Field(default=(), max_length=32)
    installed_add_ons_match: bool = False


class ZapActiveRunnerAttestation(_Strict):
    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    runner_version: str = Field(max_length=40)
    ready: bool
    failure_codes: tuple[str, ...] = Field(default=(), max_length=32)
    engine: ZapEngineAttestation
    profile_id: str = Field(max_length=64)
    profile_version: str = Field(max_length=16)
    parser_version: str = Field(max_length=48)
    projection_version: str = Field(max_length=16)
    manifest_version: str = Field(max_length=16)
    manifest_digest: str = Field(pattern=_SHA256)
    add_ons: tuple[AddOnAttestation, ...] = Field(max_length=16)
    unexpected_plugin_files: int = Field(ge=0)
    forbidden_add_ons_present: tuple[str, ...] = Field(default=(), max_length=64)
    neutralised_dependency_ids: tuple[str, ...] = Field(default=(), max_length=8)
    addonlist_verified: bool
    java_verified: bool
    admitted_rule_ids: tuple[int, ...] = Field(max_length=4)
    guard: RunnerGuardState
    booted_at: datetime
    executions_total: int = Field(ge=0)
    rejections_total: int = Field(ge=0)
    last_execution_at: datetime | None = None


class ZapActiveRunResponse(_Strict):
    schema_version: Literal["aegis.zap.active-rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    runner_version: str = Field(max_length=40)
    profile_id: str = Field(max_length=64)
    profile_version: str = Field(max_length=16)
    status: Literal["COMPLETED", "FAILED", "REJECTED", "STOPPED"]
    error_code: ZapActiveErrorCode | None = None
    exit_class: ExitClass
    exit_code: int | None = Field(default=None, ge=-128, le=255)
    engine: ZapEngineAttestation
    projection: ActiveProjectionFacts | None = None
    plan: ActivePlanFacts
    stages: ActiveStageFacts
    traffic: GuardCounters | None = None
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0, le=660_000)
    stdout_bytes: int = Field(ge=0)
    stdout_sha256: str | None = Field(default=None, pattern=_SHA256)
    report_bytes: int = Field(ge=0)
    report_sha256: str | None = Field(default=None, pattern=_SHA256)
    session_destroyed: bool
    parse: ZapActiveParseSummary
    lease: ActiveLeaseFacts = ActiveLeaseFacts()
    alerts: tuple[ZapActiveAlertRecord, ...] = Field(default=(), max_length=16)
    coverage_complete: bool


# --- the runner-side lease admission boundary -------------------------------------------------
#
# These shapes cross the admission boundary (runner supervisor <-> root-owned admission component).
# They live here, in the shared active contracts, so the runner image does not need to carry the
# admission package at all: both sides already depend on ``aegis_zap_active``, and the admission
# package re-exports these names for its own server. No shape below carries a credential: a token
# goes IN, a redacted record comes OUT.

ADMISSION_SCHEMA: Literal["aegis.zap.active-admission/1"] = "aegis.zap.active-admission/1"
ADMISSION_VERSION = "zap-active-admission/1.5.0"
MAX_ADMISSION_REQUEST_BYTES = 4_096
# Sized for a full registry history: RECENT_LIMIT (16) redacted records plus the armed record and
# totals. The bounded client rejects anything larger, so this is a hard ceiling, not an average.
MAX_ADMISSION_RESPONSE_BYTES = 16_384

_EXEC = r"^exec-[a-f0-9]{12}$"


class AdmissionArmRequest(_Strict):
    schema_version: Literal["aegis.zap.active-admission/1"] = ADMISSION_SCHEMA
    token: str = Field(min_length=16, max_length=1024)


class AdmissionConsumeRequest(_Strict):
    """The runner's independently computed execution facts. Every field must equal the claims."""

    schema_version: Literal["aegis.zap.active-admission/1"] = ADMISSION_SCHEMA
    token: str = Field(min_length=16, max_length=1024)
    execution_id: str = Field(pattern=_EXEC)
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    target_origin: str = Field(max_length=200)
    projection_digest: str = Field(pattern=_SHA256)
    allowlist_digest: str = Field(pattern=_SHA256)
    manifest_digest: str = Field(pattern=_SHA256)


class AdmissionRevokeRequest(_Strict):
    schema_version: Literal["aegis.zap.active-admission/1"] = ADMISSION_SCHEMA
    lease_id: str = Field(pattern=_LEASE_ID)
    reason: str = Field(default="revoked", pattern=r"^[A-Za-z0-9_]{1,40}$")


class AdmissionStatus(BaseModel):
    """What ``GET /v1/status`` returns: redacted, bounded, and safe to show an operator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.zap.active-admission/1"] = ADMISSION_SCHEMA
    admission_version: str = ADMISSION_VERSION
    booted_at: str
    state_root_owned: bool
    armed: RedactedLeaseRecord | None = None
    recent: tuple[RedactedLeaseRecord, ...] = Field(default=(), max_length=16)
    armed_total: int = Field(ge=0)
    consumed_total: int = Field(ge=0)
    revoked_total: int = Field(ge=0)
    rejected_total: int = Field(ge=0)
    consumed_nonce_count: int = Field(ge=0)
    restart_revoked_total: int = Field(ge=0)


class AdmissionError(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["aegis.zap.active-admission/1"] = ADMISSION_SCHEMA
    status: Literal["REJECTED"] = "REJECTED"
    error_code: str = Field(max_length=40)
