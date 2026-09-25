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
    NOT_EVALUATED = "NOT_EVALUATED"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


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


class SqlmapArmResult(_Strict):
    """One SQLMap arm's result (vulnerable or patched); verdict from the independent verifier."""

    arm: str
    run_label: str = Field(default="", max_length=64)
    job_id: str
    argv_sha256: str
    image_reference: str
    digest_pinned: bool
    sqlmap_run: ContainerRunResult
    total_http_requests: int = Field(ge=0)
    tool_reported_injectable: bool  # SQLMap's own claim — audit-only, never a verdict input
    control_count: int
    boolean_true_count: int
    boolean_false_count: int
    verifier_status: str  # CONFIRMED | PASS | INCOMPLETE
    verifier_sent_injection_traffic: bool
    normalized_evidence_sha256: str


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
