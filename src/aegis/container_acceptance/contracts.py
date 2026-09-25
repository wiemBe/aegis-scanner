"""Typed contracts and error codes for the Phase 2.8 container-acceptance harness.

The SQLMap capability's own worker-evidence, job and verifier contracts are REUSED from the
preserved Phase 2.8-B module (:mod:`aegis.multi_agent.sqlmap_capability`) and the range verifier;
this module only adds the container-execution and reporting shapes that sit around them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ContainerAcceptanceError(ValueError):
    """A structured, fail-closed error raised by the container-acceptance controller/worker."""


class EvidenceCategory(StrEnum):
    """The separate evidence categories Phase 2.8 must keep distinct (never conflated)."""

    OFFLINE_PASS = "OFFLINE_PASS"  # noqa: S105 - evidence-category label, not a secret
    CONTAINERIZED_SYNTHETIC_PASS = "CONTAINERIZED_SYNTHETIC_PASS"  # noqa: S105 - label, not a secret
    NOT_EVALUATED = "NOT_EVALUATED"
    LIVE_PROVIDER = "LIVE_PROVIDER"


class ToolAcceptanceStatus(StrEnum):
    """Per-tool container-acceptance status recorded in the report and in deploy/PHASES.md."""

    CONTAINERIZED_SYNTHETIC_PASS = "CONTAINERIZED_SYNTHETIC_PASS"  # noqa: S105 - label, not a secret
    # A tool container executed but did not yield functional tool-originated evidence sufficient to
    # confirm the capability (e.g. a helper/control probe cannot substitute for the tool itself).
    CONTAINER_EXECUTED_INCONCLUSIVE = "CONTAINER_EXECUTED_INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"


class BudgetStopReason(StrEnum):
    """Typed outcome of the controller-owned SQLMap request/duration budget enforcement."""

    COMPLETED = "COMPLETED"  # tool finished within both ceilings
    REQUEST_CEILING = "REQUEST_CEILING"  # BUDGET_STOP: HTTP-request ceiling reached, process killed
    DURATION_CEILING = "DURATION_CEILING"  # BUDGET_STOP: wall-clock ceiling reached, process killed


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SqlmapBudgetOutcome(_Strict):
    """The result of a budgeted SQLMap container run under hard controller-owned ceilings."""

    max_http_requests: int = Field(ge=1)
    max_duration_seconds: int = Field(ge=1)
    observed_requests: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)
    stop_reason: BudgetStopReason
    container_terminated: bool
    container_removed: bool

    @property
    def budget_stop(self) -> bool:
        return self.stop_reason is not BudgetStopReason.COMPLETED


class GroundTruth(_Strict):
    """The controller-owned ground truth handed to the independent verifier.

    It is what the controller *set* on the range control plane, never something read back from the
    tool. ``expected_injectable`` is derived from the arm the controller selected."""

    scenario_id: str = Field(min_length=1, max_length=100)
    arm: str  # "vulnerable" | "patched"
    control_generation: int = Field(ge=0)
    seeded_total: int = Field(ge=0)
    control_selective_count: int = Field(ge=0)
    expected_injectable: bool


class ContainerRunResult(_Strict):
    """The bounded, redacted outcome of one ``docker run`` of a tool container."""

    image_reference: str = Field(min_length=1, max_length=200)
    argv_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    exit_code: int
    timed_out: bool = False
    duration_ms: int = Field(ge=0)
    stdout_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_bytes: int = Field(ge=0)
    output_truncated: bool = False


class CleanupProof(_Strict):
    """Post-run leftover checks for the stack, its volumes and its network."""

    stack_containers_remaining: int = Field(ge=0)
    volumes_remaining: int = Field(ge=0)
    networks_remaining: int = Field(ge=0)
    network_was_internal: bool
    egress_blocked_proof: str = Field(default="", max_length=200)

    @property
    def clean(self) -> bool:
        return (
            self.stack_containers_remaining == 0
            and self.volumes_remaining == 0
            and self.networks_remaining == 0
        )


def assert_arms_fresh(arm_run_labels: list[str], current_run_label: str) -> None:
    """Reject stale evidence reuse: every arm's evidence must be bound to the current run's nonce.

    Each acceptance run stands up a freshly-labelled range (a unique nonce); an arm result carrying
    a different label was produced by another run and must never be counted toward this one."""

    for label in arm_run_labels:
        if label != current_run_label:
            raise ContainerAcceptanceError(f"STALE_EVIDENCE_REUSE:{label}")


class SqlmapTrafficObservation(_Strict):
    """One normalized SQLMap-originated request/response record. No raw payload — digests only."""

    sequence: int = Field(ge=0)
    modified: bool  # True when SQLMap altered the parameter from the controller baseline seed
    status_code: int = Field(ge=100, le=599)
    row_count: int = Field(ge=0)
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    response_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class SqlmapTrafficEvidence(_Strict):
    """Normalized differential evidence derived from SQLMap's OWN captured traffic + correlation.

    Correlation binds every observation to the run: job id, process execution id, timestamps,
    per-request/response digests, target + parameter, tool version and immutable image id. The
    differential (baseline vs the max/min rows across SQLMap's injected requests) is what the
    independent verifier adjudicates; SQLMap's textual claim is not represented here."""

    job_id: str
    process_exec_id: str = Field(min_length=1, max_length=64)
    tool_version: str = Field(min_length=1, max_length=60)
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    target_operation: str = Field(min_length=1, max_length=200)
    parameter: str = Field(min_length=1, max_length=64)
    started_at: str = Field(min_length=1, max_length=40)
    finished_at: str = Field(min_length=1, max_length=40)
    request_count: int = Field(ge=0)
    control_row_count: int = Field(ge=-1)
    injected_request_count: int = Field(ge=0)
    injected_max_row_count: int = Field(ge=-1)
    injected_min_row_count: int = Field(ge=-1)
    evidence_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    observations: list[SqlmapTrafficObservation] = Field(default_factory=list, max_length=32)

    def as_verifier_input(self) -> dict[str, int]:
        """The reference-only differential the verifier adjudicates (no tool verdict/payload)."""

        return {
            "control_row_count": self.control_row_count,
            "injected_request_count": self.injected_request_count,
            "injected_max_row_count": self.injected_max_row_count,
            "injected_min_row_count": self.injected_min_row_count,
        }


class SqlmapArmResult(_Strict):
    """One SQLMap arm's result (vulnerable or patched); verdict from the independent verifier."""

    arm: str
    run_label: str = Field(default="", max_length=64)
    job_id: str
    process_exec_id: str = Field(default="", max_length=64)
    argv_sha256: str
    image_reference: str
    image_id: str = Field(default="", max_length=80)
    digest_pinned: bool
    sqlmap_run: ContainerRunResult
    # SQLMap's own textual claim — audit-only, never a verdict input.
    tool_reported_injectable: bool
    # Differential derived from SQLMap-originated traffic (the functional evidence).
    sqlmap_requests_observed: int = Field(ge=0)
    control_row_count: int
    injected_max_row_count: int
    injected_min_row_count: int
    verifier_status: str  # CONFIRMED | PASS | INCOMPLETE | BUDGET_STOP
    verifier_sent_injection_traffic: bool
    verifier_used_sqlmap_worker_evidence: bool
    normalized_evidence_sha256: str
    # Controller-owned hard budget enforcement for this arm's SQLMap run.
    budget: SqlmapBudgetOutcome
    # Controller OR-style probe kept ONLY as a separate scenario control (not a SQLMap functional
    # input); records that the fixture itself is genuinely vulnerable/patched.
    control_scenario_status: str
    control_probe_is_separate: bool = True


class ToolAcceptanceRecord(_Strict):
    """One tool/capability's container-acceptance outcome for the report and PHASES.md."""

    capability_id: str
    tool: str
    status: ToolAcceptanceStatus
    evidence_category: EvidenceCategory
    image_reference: str = ""
    digest_pinned: bool = False
    reason: str = Field(default="", max_length=300)
    detail: str = Field(default="", max_length=300)
