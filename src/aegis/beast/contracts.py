from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

BEAST_PROFILE_ID = "BEAST_ADVERSARY_SANDBOX_V1"
BEAST_CONTRACT_VERSION = 1
BEAST_MAX_LEASE_SECONDS = 900


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvironmentClass(StrEnum):
    SYNTHETIC_LAB = "SYNTHETIC_LAB"
    STAGING_DISPOSABLE = "STAGING_DISPOSABLE"
    PRODUCTION = "PRODUCTION"
    UNKNOWN = "UNKNOWN"


class BeastMode(StrEnum):
    SAFE_PASSIVE = "SAFE_PASSIVE"
    BEAST_ACTIVE = "BEAST_ACTIVE"
    PRODUCTION_SAFE = "PRODUCTION_SAFE"


class LeaseState(StrEnum):
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class RunState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    VERIFIED = "VERIFIED"
    PASS = "PASS"  # noqa: S105 - verification status, not a password
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    INCOMPLETE = "INCOMPLETE"
    STOPPED = "STOPPED"


class ResourceEnvelope(StrictModel):
    total_wall_time_seconds: int = Field(default=180, ge=10, le=600)
    per_command_timeout_seconds: int = Field(default=20, ge=1, le=60)
    max_commands: int = Field(default=8, ge=2, le=20)
    max_target_connections: int = Field(default=40, ge=1, le=100)
    max_request_rate_per_second: int = Field(default=4, ge=1, le=10)
    max_concurrency: int = Field(default=2, ge=1, le=4)
    max_transmitted_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    max_received_bytes: int = Field(default=1_048_576, ge=4096, le=4_194_304)
    max_processes: int = Field(default=32, ge=4, le=64)
    max_open_files: int = Field(default=64, ge=16, le=256)
    cpu_quota: float = Field(default=1.0, gt=0, le=2.0)
    memory_bytes: int = Field(default=268_435_456, ge=67_108_864, le=536_870_912)
    writable_disk_bytes: int = Field(default=33_554_432, ge=1_048_576, le=67_108_864)
    stdout_stderr_bytes: int = Field(default=65_536, ge=4096, le=262_144)
    artifact_bytes: int = Field(default=4_194_304, ge=1024, le=16_777_216)


class BeastTarget(StrictModel):
    target_ref: str = Field(pattern=r"^[a-z0-9-]+$", max_length=80)
    name: str = Field(min_length=3, max_length=120)
    origin: str
    base_path: str = Field(pattern=r"^/[A-Za-z0-9/_-]*$", max_length=160)
    environment: EnvironmentClass
    owner: str = Field(min_length=3, max_length=120)
    approval_reference: str = Field(min_length=3, max_length=120)
    active_testing_authorized: bool
    reset_available: bool
    synthetic_data_only: bool
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS"]]
    allowed_path_prefix: str
    prohibited_operations: list[str]
    reset_strategy: str
    synthetic_credential_profiles: list[str]
    expected_impact: str
    max_blast_radius: str
    health: Literal["GREEN", "RED"]


class BeastPreflight(StrictModel):
    profile_id: Literal["BEAST_ADVERSARY_SANDBOX_V1"] = "BEAST_ADVERSARY_SANDBOX_V1"
    mode: Literal["BEAST_ACTIVE"] = "BEAST_ACTIVE"
    target: BeastTarget
    enabled_capabilities: list[str]
    enabled_engines: list[str]
    resources: ResourceEnvelope
    automatic_expiry_seconds: int = Field(le=BEAST_MAX_LEASE_SECONDS)
    emergency_stop: str
    technical_subtitle: str = "Disposable AI Adversary Sandbox"
    boundary_description: str = (
        "Unrestricted attack logic inside a strictly bounded execution environment."
    )


class LeaseRequest(StrictModel):
    operator_id: str = Field(pattern=r"^[A-Za-z0-9._@-]{3,80}$")
    actor_type: Literal["OPERATOR"]
    target_ref: str
    profile_id: Literal["BEAST_ADVERSARY_SANDBOX_V1"]
    confirmation: str = Field(max_length=180)
    requested_resources: ResourceEnvelope | None = None


class BeastLease(StrictModel):
    lease_id: str
    operator_id: str
    target_ref: str
    profile_id: str
    capability_set: list[str]
    resources: ResourceEnvelope
    state: LeaseState
    issued_at: datetime
    expires_at: datetime
    single_run: bool = True
    run_id: str | None = None
    revocation_reason: str | None = None

    def active_at(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return self.state is LeaseState.ACTIVE and current < self.expires_at


class BeastRunRequest(StrictModel):
    lease_id: str
    scenario_id: Literal[
        "endpoint_discovery",
        "information_exposure",
        "bola_readonly",
        "safe_injection",
    ]


class BeastObservation(StrictModel):
    observation_id: str
    command_id: str
    sequence: int
    summary: str
    # The exact command that produced this observation, so the model can see what it already ran
    # and avoid re-issuing a semantically equivalent command.  Not a scripted/suggested command.
    command_text: str = Field(default="", max_length=12_000)
    facts: dict[str, Any] = Field(default_factory=dict)
    stdout: str = Field(default="", max_length=65_536)
    stderr: str = Field(default="", max_length=65_536)
    artifact_previews: dict[str, str] = Field(default_factory=dict)


class BeastCommandDecision(StrictModel):
    decision_type: Literal["command"]
    hypothesis: str = Field(min_length=3, max_length=1000)
    expected_intent: str = Field(min_length=3, max_length=500)
    command_text: str = Field(min_length=1, max_length=12_000)

    @field_validator("command_text")
    @classmethod
    def preserve_non_blank_command(cls, value: str) -> str:
        # Deliberately no syntax, tool, argument, payload, URL or shell-token filtering.  The exact
        # string is hashed/audited and transported as data to the sandbox supervisor.
        if not value.strip():
            raise ValueError("command_text must not be blank")
        return value


class BeastStopDecision(StrictModel):
    decision_type: Literal["stop"]
    hypothesis: str = Field(min_length=3, max_length=1000)
    summary: str = Field(min_length=3, max_length=1000)
    evidence_observation_ids: list[str] = Field(min_length=1, max_length=20)


BeastDecision = Annotated[
    BeastCommandDecision | BeastStopDecision, Field(discriminator="decision_type")
]
BEAST_DECISION_ADAPTER: TypeAdapter[Any] = TypeAdapter(BeastDecision)


class BeastDecisionRequest(StrictModel):
    contract_version: Literal[1] = 1
    run_id: str
    scenario_id: str
    objective: str
    target_origin: str
    target_base_path: str
    synthetic_public_accounts: list[dict[str, str]]
    sequence: int
    remaining_commands: int
    remaining_time_seconds: int
    objective_evidence_sufficient: bool
    decision_requirements: list[str]
    observations: list[BeastObservation]


class BeastDecisionResponse(StrictModel):
    model: str
    decision: BeastDecision
    usage: dict[str, int]
    metadata: dict[str, Any]


class CommandTransport(StrictModel):
    command_id: str
    parent_command_id: str | None
    run_id: str
    sequence: int = Field(ge=1)
    shell: Literal["/bin/bash"] = "/bin/bash"
    command_text: str = Field(min_length=1, max_length=12_000)
    working_directory_reference: str
    timeout_seconds: int = Field(ge=1, le=60)
    output_limit_bytes: int = Field(ge=4096, le=262_144)
    artifact_limit_bytes: int = Field(ge=1024, le=16_777_216)
    expected_intent: str = Field(min_length=3, max_length=500)
    hypothesis_reference: str = Field(min_length=3, max_length=1000)


class CommandResult(StrictModel):
    command_id: str
    exit_code: int | None
    timed_out: bool
    terminated: bool
    duration_ms: int
    stdout: str
    stderr: str
    output_truncated: bool
    artifact_references: list[str]
    artifact_previews: dict[str, str] = Field(default_factory=dict)
    resource_usage: dict[str, int | float]
    network_destinations: list[str]


class BeastRun(StrictModel):
    run_id: str
    lease_id: str
    target_ref: str
    scenario_id: str
    state: RunState
    model: str
    profile_id: str = BEAST_PROFILE_ID
    resources: ResourceEnvelope = Field(default_factory=ResourceEnvelope)
    created_at: datetime
    lease_expires_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    commands: list[CommandTransport] = Field(default_factory=list)
    results: list[CommandResult] = Field(default_factory=list)
    observations: list[BeastObservation] = Field(default_factory=list)
    model_calls: list[dict[str, Any]] = Field(default_factory=list)
    verifier_conclusion: dict[str, Any] | None = None
    stop_reason: str | None = None
    workspace_destroyed: bool = False
    cleanup_verified: bool = False
    emergency_stopped: bool = False


class SandboxSessionRequest(StrictModel):
    run_id: str
    target_origin: str
    allowed_path_prefix: str = Field(pattern=r"^/lab/beast/(vulnerable|patched)$")
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS"]]
    resources: ResourceEnvelope


class SandboxSession(StrictModel):
    run_id: str
    sandbox_instance_id: str
    workspace_reference: str
    ready: bool


class SandboxDestroyResult(StrictModel):
    run_id: str
    destroyed: bool
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
