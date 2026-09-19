"""Strict typed RPC contract between the Aegis controller and the isolated nuclei-runner.

The controller may send ONLY the fields of :class:`NucleiRunRequest`: execution/run/scan/job ids,
an approved target REFERENCE plus the controller-resolved internal origin, the approved profile id,
the admitted template-set id and manifest digest, bounded budgets, and a nonce/correlation id.

There is no field for a command, flag, environment variable, URL path, template id or path, header,
cookie, credential, shell fragment or remote template source. ``extra="forbid"`` plus ``strict``
turn any such key — or any type coercion — into a hard validation error.

The runner returns ONLY :class:`NucleiRunResponse`: typed execution metadata and bounded, parsed,
redacted results. It never returns raw Nuclei output, stderr text or exception prose.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RPC_SCHEMA: Literal["aegis.nuclei.rpc/1"] = "aegis.nuclei.rpc/1"
RUNNER_VERSION = "nuclei-runner/1.2.0"
MAX_RPC_REQUEST_BYTES = 4096
MAX_RPC_RESPONSE_BYTES = 65536

_SHA256 = r"^[a-f0-9]{64}$"
_SCAN_ID = r"^scan-[a-f0-9]{12}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RunnerErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    UNKNOWN_TARGET = "UNKNOWN_TARGET"
    ORIGIN_MISMATCH = "ORIGIN_MISMATCH"
    UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
    UNKNOWN_TEMPLATE_SET = "UNKNOWN_TEMPLATE_SET"
    MANIFEST_DIGEST_MISMATCH = "MANIFEST_DIGEST_MISMATCH"
    TEMPLATE_INTEGRITY_FAILURE = "TEMPLATE_INTEGRITY_FAILURE"
    SIGNATURE_NOT_VERIFIED = "SIGNATURE_NOT_VERIFIED"
    ENGINE_INTEGRITY_FAILURE = "ENGINE_INTEGRITY_FAILURE"
    RUNNER_NOT_READY = "RUNNER_NOT_READY"
    BUDGET_OUT_OF_BOUNDS = "BUDGET_OUT_OF_BOUNDS"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    BUSY = "BUSY"
    SPAWN_FAILED = "SPAWN_FAILED"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    NONZERO_EXIT = "NONZERO_EXIT"
    ENGINE_FATAL = "ENGINE_FATAL"
    UNSIGNED_TEMPLATE_SKIPPED = "UNSIGNED_TEMPLATE_SKIPPED"
    OUTPUT_OVERSIZED = "OUTPUT_OVERSIZED"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    OUTPUT_MALFORMED = "OUTPUT_MALFORMED"
    REQUEST_BUDGET_EXCEEDED = "REQUEST_BUDGET_EXCEEDED"
    COVERAGE_INCOMPLETE = "COVERAGE_INCOMPLETE"


class NucleiBudgets(_Strict):
    max_requests: int = Field(ge=1, le=4)
    max_results: int = Field(ge=1, le=16)
    time_budget_ms: int = Field(ge=5_000, le=120_000)
    max_output_bytes: int = Field(ge=1_024, le=262_144)


class NucleiRunRequest(_Strict):
    schema_version: Literal["aegis.nuclei.rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    run_id: str = Field(pattern=_SCAN_ID)
    scan_id: str = Field(pattern=_SCAN_ID)
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    origin: str = Field(
        min_length=8, max_length=100, pattern=r"^https?://[a-z0-9.-]+(:[0-9]{1,5})?$"
    )
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    template_set_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    manifest_digest: str = Field(pattern=_SHA256)
    budgets: NucleiBudgets
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    correlation_id: str = Field(pattern=r"^corr-[a-f0-9]{16}$")


class EngineAttestation(_Strict):
    nuclei_version: str = Field(max_length=32)
    binary_sha256: str | None = Field(default=None, pattern=_SHA256)
    arch: str = Field(max_length=16)
    pinned: bool


SignatureStatus = Literal["SIGNED_VERIFIED", "SIGNATURE_LINE_PRESENT", "UNVERIFIED", "REJECTED"]


class TemplateAttestation(_Strict):
    template_id: str = Field(max_length=100)
    path: str = Field(max_length=200)
    sha256: str | None = Field(default=None, pattern=_SHA256)
    admitted: bool
    signature_status: SignatureStatus
    violations: tuple[str, ...] = Field(default=(), max_length=32)


class RunnerAttestation(_Strict):
    schema_version: Literal["aegis.nuclei.rpc/1"] = RPC_SCHEMA
    runner_version: str = Field(max_length=40)
    ready: bool
    failure_codes: tuple[str, ...] = Field(default=(), max_length=32)
    engine: EngineAttestation
    profile_id: str = Field(max_length=64)
    profile_version: str = Field(max_length=16)
    parser_version: str = Field(max_length=40)
    template_set_id: str = Field(max_length=64)
    manifest_version: str = Field(max_length=16)
    manifest_digest: str = Field(pattern=_SHA256)
    templates: tuple[TemplateAttestation, ...] = Field(max_length=8)
    unexpected_template_files: int = Field(ge=0)
    signature_probe: Literal["SIGNED_VERIFIED", "FAILED", "NOT_RUN"]
    booted_at: datetime
    executions_total: int = Field(ge=0)
    last_execution_at: datetime | None = None


ErrorClass = Literal["NONE", "TARGET_UNREACHABLE", "TIMEOUT", "OTHER"]
ParseStatus = Literal["PARSED", "EMPTY", "MALFORMED", "OVERSIZED", "TRUNCATED", "NOT_PARSED"]


class NucleiResultRecord(_Strict):
    """One parsed, redacted Nuclei result line. UNTRUSTED: a tool claim, never a verdict."""

    template_id: str = Field(max_length=100)
    target_ref: str = Field(max_length=64)
    matcher_status: bool
    checked_path: str = Field(max_length=200, pattern=r"^/[A-Za-z0-9/._-]*$")
    error_class: ErrorClass
    claimed_severity: Literal["info", "low", "medium", "high", "critical", "unknown"]
    extracted_count: int = Field(ge=0, le=64)
    record_digest: str = Field(pattern=_SHA256)
    observed_at: datetime


class ParseSummary(_Strict):
    parser_version: str = Field(max_length=40)
    status: ParseStatus
    failure_code: RunnerErrorCode | None = None
    lines: int = Field(ge=0)
    records: int = Field(ge=0)
    matched: int = Field(ge=0)
    unmatched: int = Field(ge=0)
    errored: int = Field(ge=0)
    duplicates_collapsed: int = Field(ge=0)
    stripped_fields: tuple[str, ...] = Field(default=(), max_length=16)


ExitClass = Literal["OK", "NONZERO_EXIT", "TIMEOUT", "OUTPUT_OVERSIZED", "SPAWN_FAILED", "NOT_RUN"]


class NucleiRunResponse(_Strict):
    schema_version: Literal["aegis.nuclei.rpc/1"] = RPC_SCHEMA
    engine_execution_id: str = Field(pattern=r"^exec-[a-f0-9]{12}$")
    job_id: str = Field(pattern=r"^job-[a-f0-9]{12}$")
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    runner_version: str = Field(max_length=40)
    profile_id: str = Field(max_length=64)
    profile_version: str = Field(max_length=16)
    status: Literal["COMPLETED", "FAILED", "REJECTED"]
    error_code: RunnerErrorCode | None = None
    exit_class: ExitClass
    exit_code: int | None = Field(default=None, ge=-128, le=255)
    engine: EngineAttestation
    template_set_id: str = Field(max_length=64)
    manifest_digest: str = Field(pattern=_SHA256)
    templates: tuple[TemplateAttestation, ...] = Field(max_length=8)
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0, le=600_000)
    templates_loaded: int | None = Field(default=None, ge=0, le=64)
    signed_templates_executed: int | None = Field(default=None, ge=0, le=64)
    unsigned_templates_skipped: int | None = Field(default=None, ge=0, le=64)
    http_connections: int | None = Field(default=None, ge=0, le=10_000)
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)
    output_bytes: int = Field(ge=0)
    output_sha256: str | None = Field(default=None, pattern=_SHA256)
    stderr_sha256: str | None = Field(default=None, pattern=_SHA256)
    parse: ParseSummary
    results: tuple[NucleiResultRecord, ...] = Field(default=(), max_length=16)
    coverage_complete: bool
