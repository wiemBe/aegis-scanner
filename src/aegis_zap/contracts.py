"""Strict typed contracts: controller <-> zap-runner RPC and zap-runner <-> scope-guard control.

The controller may send ONLY :class:`ZapRunRequest`: execution/run/scan/job ids, an approved
target REFERENCE, the profile id, the projected-OpenAPI artifact reference and SHA-256, the
operation-allowlist SHA-256, bounded budgets and a nonce/correlation id. There is no field for a
URL, origin, OpenAPI content or URL, Automation Framework YAML, job, ZAP option, add-on, rule
setting, script, header, cookie, credential, output path or report template. ``extra="forbid"``
plus ``strict`` turn any such key, and any type coercion, into a hard validation error.

The runner returns ONLY :class:`ZapRunResponse`: typed execution metadata, runner-derived facts
and bounded, parsed, redacted alert records. Never raw ZAP output, report bytes, HTTP bodies,
headers or exception prose.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RPC_SCHEMA: Literal["aegis.zap.rpc/1"] = "aegis.zap.rpc/1"
GUARD_SCHEMA: Literal["aegis.zap.guard/1"] = "aegis.zap.guard/1"
RUNNER_VERSION = "zap-runner/1.3.0"
GUARD_VERSION = "zap-scope-guard/1.3.0"
MAX_RPC_REQUEST_BYTES = 4_096
MAX_RPC_RESPONSE_BYTES = 131_072

_SHA256 = r"^[a-f0-9]{64}$"
_SCAN_ID = r"^scan-[a-f0-9]{12}$"
_PATH = r"^/[A-Za-z0-9/_.-]{0,200}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ZapRunnerErrorCode(StrEnum):
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
    SCOPE_ESCAPE_BLOCKED = "SCOPE_ESCAPE_BLOCKED"
    REDIRECT_OBSERVED = "REDIRECT_OBSERVED"
    REQUEST_BUDGET_EXCEEDED = "REQUEST_BUDGET_EXCEEDED"
    TARGET_TIMEOUT = "TARGET_TIMEOUT"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    IMPORT_INCOMPLETE = "IMPORT_INCOMPLETE"
    PASSIVE_QUEUE_NOT_DRAINED = "PASSIVE_QUEUE_NOT_DRAINED"
    REPORT_MISSING = "REPORT_MISSING"
    REPORT_OVERSIZED = "REPORT_OVERSIZED"
    REPORT_TRUNCATED = "REPORT_TRUNCATED"
    REPORT_MALFORMED = "REPORT_MALFORMED"
    UNADMITTED_RULE = "UNADMITTED_RULE"


# --- controller -> runner --------------------------------------------------------------------


class ZapBudgets(_Strict):
    max_requests: int = Field(ge=1, le=8)
    time_budget_ms: int = Field(ge=30_000, le=300_000)
    max_report_bytes: int = Field(ge=4_096, le=262_144)
    max_alerts: int = Field(ge=1, le=16)


class ZapRunRequest(_Strict):
    schema_version: Literal["aegis.zap.rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    run_id: str = Field(pattern=_SCAN_ID)
    scan_id: str = Field(pattern=_SCAN_ID)
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    projection_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}/[0-9]+\.[0-9]+\.[0-9]+$")
    projection_digest: str = Field(pattern=_SHA256)
    operation_allowlist_digest: str = Field(pattern=_SHA256)
    budgets: ZapBudgets
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    correlation_id: str = Field(pattern=r"^corr-[a-f0-9]{16}$")


# --- attestation --------------------------------------------------------------------------------


class ZapEngineAttestation(_Strict):
    zap_version: str = Field(max_length=32)
    jar_sha256: str | None = Field(default=None, pattern=_SHA256)
    java_version: str | None = Field(default=None, max_length=32)
    java_runtime_version: str | None = Field(default=None, max_length=60)
    arch: str = Field(max_length=24)
    add_on_inventory_digest: str | None = Field(default=None, pattern=_SHA256)
    pinned: bool


class AddOnAttestation(_Strict):
    id: str = Field(max_length=40)
    version: str = Field(max_length=16)
    file: str = Field(max_length=80)
    sha256: str | None = Field(default=None, pattern=_SHA256)
    pinned: bool


class GuardCounters(_Strict):
    received: int = Field(ge=0)
    forwarded: int = Field(ge=0)
    blocked: int = Field(ge=0)
    blocked_reasons: tuple[tuple[str, int], ...] = Field(default=(), max_length=16)
    redirects: int = Field(ge=0)
    upstream_failures: int = Field(ge=0)
    upstream_timeouts: int = Field(ge=0)
    budget_exceeded: bool
    per_path: tuple[tuple[str, str, int], ...] = Field(default=(), max_length=16)
    statuses: tuple[tuple[str, int], ...] = Field(default=(), max_length=16)


class GuardAttestation(_Strict):
    schema_version: Literal["aegis.zap.guard/1"] = GUARD_SCHEMA
    guard_version: str = Field(max_length=40)
    state: Literal["IDLE", "ARMED"]
    allowed_origins: tuple[str, ...] = Field(max_length=4)
    booted_at: datetime
    executions_total: int = Field(ge=0)
    forwarded_total: int = Field(ge=0)
    blocked_total: int = Field(ge=0)
    blocked_while_idle: int = Field(ge=0)


class GuardArmResponse(_Strict):
    schema_version: Literal["aegis.zap.guard/1"] = GUARD_SCHEMA
    token: str = Field(pattern=r"^[a-f0-9]{32}$")
    execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")


class GuardCountersResponse(_Strict):
    schema_version: Literal["aegis.zap.guard/1"] = GUARD_SCHEMA
    execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    state: Literal["ARMED", "DISARMED"]
    counters: GuardCounters


class RunnerGuardState(_Strict):
    reachable: bool
    guard_version: str | None = Field(default=None, max_length=40)
    state: str | None = Field(default=None, max_length=16)
    allowed_origins: tuple[str, ...] = Field(default=(), max_length=4)
    forwarded_total: int | None = Field(default=None, ge=0)
    blocked_total: int | None = Field(default=None, ge=0)


class ZapRunnerAttestation(_Strict):
    schema_version: Literal["aegis.zap.rpc/1"] = RPC_SCHEMA
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
    addonlist_verified: bool
    java_verified: bool
    admitted_rule_ids: tuple[int, ...] = Field(max_length=8)
    guard: RunnerGuardState
    booted_at: datetime
    executions_total: int = Field(ge=0)
    rejections_total: int = Field(ge=0)
    last_execution_at: datetime | None = None


# --- runner -> controller --------------------------------------------------------------------

ParseStatus = Literal[
    "PARSED", "MISSING", "EMPTY", "MALFORMED", "OVERSIZED", "TRUNCATED", "NOT_PARSED"
]
ExitClass = Literal["OK", "NONZERO_EXIT", "TIMEOUT", "KILLED_BY_GUARD", "SPAWN_FAILED", "NOT_RUN"]


class ZapParseSummary(_Strict):
    parser_version: str = Field(max_length=48)
    status: ParseStatus
    failure_code: ZapRunnerErrorCode | None = None
    sites: int = Field(ge=0)
    alerts: int = Field(ge=0)
    instances: int = Field(ge=0)
    records: int = Field(ge=0)
    duplicates_collapsed: int = Field(ge=0)
    stripped_fields: tuple[str, ...] = Field(default=(), max_length=16)


class ZapAlertRecord(_Strict):
    """One parsed, redacted ZAP alert instance. UNTRUSTED: a tool claim, never a verdict."""

    plugin_id: int = Field(ge=0, le=999_999)
    rule_name: str = Field(max_length=120)
    method: Literal["GET", "HEAD"]
    path: str = Field(pattern=_PATH)
    param: str = Field(max_length=100)
    claimed_risk: Literal["info", "low", "medium", "high"]
    claimed_confidence: Literal["falsepositive", "low", "medium", "high", "confirmed"]
    evidence_sha256: str = Field(pattern=_SHA256)
    evidence_length: int = Field(ge=0, le=1_024)
    record_digest: str = Field(pattern=_SHA256)


class ProjectionFacts(_Strict):
    projection_ref: str = Field(max_length=80)
    projection_version: str = Field(max_length=16)
    digest: str = Field(pattern=_SHA256)
    allowlist_digest: str = Field(pattern=_SHA256)
    source_sha256: str = Field(pattern=_SHA256)
    operation_count: int = Field(ge=0, le=8)
    path_count: int = Field(ge=0, le=8)
    redaction_status: Literal["REDACTED", "NOT_REQUIRED"]


class PlanFacts(_Strict):
    plan_digest: str | None = Field(default=None, pattern=_SHA256)
    validated: bool
    job_types: tuple[str, ...] = Field(default=(), max_length=8)
    admitted_rule_ids: tuple[int, ...] = Field(default=(), max_length=8)


class StageFacts(_Strict):
    """Runner-derived facts about which fixed-plan stages ZAP reached (from its own output)."""

    plan_validated: bool = False
    zap_started: bool = False
    import_started: bool = False
    import_completed: bool = False
    urls_added: int | None = Field(default=None, ge=0, le=10_000)
    urls_test_passed: bool = False
    rules_set: tuple[tuple[int, str], ...] = Field(default=(), max_length=16)
    pscan_wait_started: bool = False
    pscan_drained: bool = False
    report_generated: bool = False
    plan_succeeded: bool = False
    silent_mode: bool = False
    installed_add_ons: tuple[tuple[str, str], ...] = Field(default=(), max_length=32)
    installed_add_ons_match: bool = False
    active_rules_loaded: int = Field(default=0, ge=0)
    openapi_errors: int = Field(default=0, ge=0)


class ZapRunResponse(_Strict):
    schema_version: Literal["aegis.zap.rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    runner_version: str = Field(max_length=40)
    profile_id: str = Field(max_length=64)
    profile_version: str = Field(max_length=16)
    status: Literal["COMPLETED", "FAILED", "REJECTED"]
    error_code: ZapRunnerErrorCode | None = None
    exit_class: ExitClass
    exit_code: int | None = Field(default=None, ge=-128, le=255)
    engine: ZapEngineAttestation
    projection: ProjectionFacts | None = None
    plan: PlanFacts
    stages: StageFacts
    traffic: GuardCounters | None = None
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0, le=600_000)
    stdout_bytes: int = Field(ge=0)
    stdout_sha256: str | None = Field(default=None, pattern=_SHA256)
    report_bytes: int = Field(ge=0)
    report_sha256: str | None = Field(default=None, pattern=_SHA256)
    session_destroyed: bool
    parse: ZapParseSummary
    alerts: tuple[ZapAlertRecord, ...] = Field(default=(), max_length=16)
    coverage_complete: bool
