"""Phase 2.4 — Single-Agent vs Multi-Agent Benchmark framework (controller-owned, deterministic).

This is a *fairness-first* comparison framework. It does NOT run agents itself and it does NOT
mint a composite "winner" score. Its whole job is to make a single-agent run and a multi-agent run
comparable — same authorized target, same scenario, same inventory snapshot, same registered
capabilities, same tool profiles, same ground truth, equivalent budgets, same verifier, same cleanup
requirement — and, only when they are provably comparable, to line their raw controller-owned
metrics up side by side.

Authority (same model as every other phase):

* The controller owns the benchmark specification, the comparability decision, the mode-integrity
  rules and the comparison rules. The AI is never authoritative for any of it.
* A *role label is not agent execution*. The multi-agent mode is only accepted as multi-agent when
  its metrics carry real persisted delegation jobs and hand-offs (``agent_jobs >= 2`` and
  ``handoffs >= 1``); the single-agent baseline must carry no downstream delegation hand-off. Both
  modes must go through the Tool Broker and the independent verifier.
* Unmeasured usage stays ``UNKNOWN`` — never silently ``0``. A metric that is ``UNKNOWN`` on either
  side compares to ``UNKNOWN`` and is listed as an incomplete measurement.
* No superiority is ever declared without live comparable runs. Offline the framework is
  ``OFFLINE_PASS`` and the live single-vs-multi comparison is ``NOT_EVALUATED``; the comparison
  document fixes ``superiority_claim_supported=False`` in that state.

Nothing here calls a provider, opens a socket or touches Docker. Everything is deterministic over
typed, controller-owned inputs so it is fully offline-testable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from aegis.multi_agent.contracts import BudgetLimit, StrictModel, now_utc

# A measured integer, or the explicit UNKNOWN sentinel. Never coerce UNKNOWN to 0.
Measured = int | Literal["UNKNOWN"]
UNKNOWN: Literal["UNKNOWN"] = "UNKNOWN"

Provenance = Literal["OFFLINE", "CONTAINERIZED_SYNTHETIC", "LIVE_PROVIDER"]


class FrozenStrictModel(StrictModel):
    """A strict, immutable model for records that must never mutate after creation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class BenchmarkError(RuntimeError):
    """A benchmark-framework failure (bad id, duplicate record, malformed input). Fails closed."""


class BenchmarkComparabilityError(ValueError):
    """Raised when two runs are declared comparable but are not. Fails closed (no comparison)."""


# --------------------------------------------------------------------------- #
# Benchmark modes.
# --------------------------------------------------------------------------- #


class BenchmarkMode(StrEnum):
    SINGLE_AGENT_BASELINE = "SINGLE_AGENT_BASELINE"
    MULTI_AGENT_DELEGATED = "MULTI_AGENT_DELEGATED"


# --------------------------------------------------------------------------- #
# Typed comparability rejection reasons (controller-owned; a role label is not execution).
# --------------------------------------------------------------------------- #


class ComparabilityRejection(StrEnum):
    MISSING_RUN = "MISSING_RUN"
    MODE_COLLISION = "MODE_COLLISION"  # both runs claim the same mode
    WRONG_MODE_FOR_SLOT = "WRONG_MODE_FOR_SLOT"
    TARGET_SCOPE_MISMATCH = "TARGET_SCOPE_MISMATCH"
    APPLICATION_MISMATCH = "APPLICATION_MISMATCH"
    SCENARIO_MISMATCH = "SCENARIO_MISMATCH"
    INVENTORY_SNAPSHOT_MISMATCH = "INVENTORY_SNAPSHOT_MISMATCH"
    CAPABILITY_SET_MISMATCH = "CAPABILITY_SET_MISMATCH"
    TOOL_PROFILE_MISMATCH = "TOOL_PROFILE_MISMATCH"
    GROUND_TRUTH_MISMATCH = "GROUND_TRUTH_MISMATCH"
    BUDGET_NOT_EQUIVALENT = "BUDGET_NOT_EQUIVALENT"
    VERIFIER_MISMATCH = "VERIFIER_MISMATCH"
    CLEANUP_REQUIREMENT_MISMATCH = "CLEANUP_REQUIREMENT_MISMATCH"
    SPEC_MISMATCH = "SPEC_MISMATCH"  # a run's conditions disagree with the shared spec
    TOOL_BROKER_NOT_USED = "TOOL_BROKER_NOT_USED"
    INDEPENDENT_VERIFIER_NOT_USED = "INDEPENDENT_VERIFIER_NOT_USED"
    SINGLE_AGENT_HAS_DELEGATION = "SINGLE_AGENT_HAS_DELEGATION"
    MULTI_AGENT_MISSING_DELEGATION = "MULTI_AGENT_MISSING_DELEGATION"
    MULTI_AGENT_MISSING_PERSISTED_JOBS = "MULTI_AGENT_MISSING_PERSISTED_JOBS"


# --------------------------------------------------------------------------- #
# Benchmark specification (the shared fairness contract) + immutable run-pair identifier.
# --------------------------------------------------------------------------- #


class BenchmarkSpec(FrozenStrictModel):
    """The single set of conditions both runs of a pair MUST match to be comparable.

    It carries only references and controller-owned constraints — no credential, origin, payload or
    verdict. ``inventory_snapshot_sha256`` binds the pair to one immutable inventory snapshot, so a
    run taken against a different snapshot cannot be compared.
    """

    benchmark_id: str = Field(pattern=r"^bench-[a-f0-9]{16}$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    application_id: str = Field(pattern=r"^aegis-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    inventory_snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    registered_capabilities: tuple[str, ...] = Field(min_length=1, max_length=32)
    tool_profiles: tuple[str, ...] = Field(min_length=1, max_length=32)
    ground_truth_id: str = Field(pattern=r"^GT-[A-Z0-9-]+$")
    budget: BudgetLimit
    verifier_authority: Literal["DETERMINISTIC_RANGE_VERIFIER"] = "DETERMINISTIC_RANGE_VERIFIER"
    cleanup_required: bool = True
    created_at: datetime = Field(default_factory=now_utc)

    @field_validator("registered_capabilities", "tool_profiles")
    @classmethod
    def _sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # A canonical ordering makes the spec digest order-independent and comparisons exact.
        if len(set(value)) != len(value):
            raise ValueError("BENCHMARK_SPEC_DUPLICATE_ENTRY")
        return tuple(sorted(value))

    @property
    def spec_sha256(self) -> str:
        material = json.dumps(
            {
                "benchmark_id": self.benchmark_id,
                "target_ref": self.target_ref,
                "application_id": self.application_id,
                "scenario_id": self.scenario_id,
                "inventory_snapshot_sha256": self.inventory_snapshot_sha256,
                "registered_capabilities": list(self.registered_capabilities),
                "tool_profiles": list(self.tool_profiles),
                "ground_truth_id": self.ground_truth_id,
                "budget": self.budget.model_dump(mode="json"),
                "verifier_authority": self.verifier_authority,
                "cleanup_required": self.cleanup_required,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(material).hexdigest()

    @property
    def benchmark_uri(self) -> str:
        return f"benchmark://{self.target_ref}/{self.benchmark_id}"


class RunPairId(FrozenStrictModel):
    """An immutable identifier binding one single-agent run and one multi-agent run to one spec.

    ``spec_sha256`` freezes the exact fairness contract at pairing time, so if the spec were ever
    re-derived differently the mismatch is detectable.
    """

    pair_id: str = Field(pattern=r"^rpair-[a-f0-9]{16}$")
    benchmark_id: str = Field(pattern=r"^bench-[a-f0-9]{16}$")
    spec_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    single_run_ref: str = Field(min_length=3, max_length=120)
    multi_run_ref: str = Field(min_length=3, max_length=120)
    created_at: datetime = Field(default_factory=now_utc)

    @property
    def pair_address(self) -> str:
        return f"benchmarkpair://{self.benchmark_id}/{self.pair_id}"


# --------------------------------------------------------------------------- #
# Per-run conditions (what a run ACTUALLY ran under) and raw controller-owned metrics.
# --------------------------------------------------------------------------- #


class RunConditions(StrictModel):
    """The actual conditions one benchmark run executed under.

    The fairness validator compares the two runs' conditions to each other and to the shared spec.
    ``uses_tool_broker`` and ``uses_independent_verifier`` are fixed True at the type level: a run
    that bypassed either is structurally not a valid benchmark run.
    """

    mode: BenchmarkMode
    run_ref: str = Field(min_length=3, max_length=120)
    provenance: Provenance
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    application_id: str = Field(pattern=r"^aegis-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    inventory_snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    registered_capabilities: tuple[str, ...] = Field(min_length=1, max_length=32)
    tool_profiles: tuple[str, ...] = Field(min_length=1, max_length=32)
    ground_truth_id: str = Field(pattern=r"^GT-[A-Z0-9-]+$")
    budget: BudgetLimit
    verifier_authority: Literal["DETERMINISTIC_RANGE_VERIFIER"] = "DETERMINISTIC_RANGE_VERIFIER"
    cleanup_required: bool = True
    uses_tool_broker: Literal[True] = True
    uses_independent_verifier: Literal[True] = True

    @field_validator("registered_capabilities", "tool_profiles")
    @classmethod
    def _sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("RUN_CONDITIONS_DUPLICATE_ENTRY")
        return tuple(sorted(value))


class BenchmarkRunMetrics(StrictModel):
    """Raw, controller-owned metrics for ONE benchmark run.

    Every field is either an integer count/flag the controller actually measured, or the explicit
    ``UNKNOWN`` sentinel where it did not. There is deliberately no composite score. ``run_ref``
    ties the metrics back to their :class:`RunConditions`.
    """

    mode: BenchmarkMode
    run_ref: str = Field(min_length=3, max_length=120)
    provenance: Provenance

    # Findings and reasoning (controller/verifier owned; the model never confirms).
    verified_findings: Measured
    false_or_unsupported_findings: Measured
    hypotheses_generated: Measured

    # Tool execution (through the Tool Broker).
    tool_executions: Measured
    successful_tool_actions: Measured
    failed_tool_actions: Measured

    # Provider usage. UNKNOWN when a call was rejected before usage was recorded, per the
    # fail-closed rule; never defaulted to zero.
    provider_calls: Measured
    input_tokens: Measured
    output_tokens: Measured
    total_tokens: Measured

    # Wall clock.
    wall_clock_ms: Measured

    # Real persisted delegation (a role label is not execution).
    agent_jobs: Measured
    handoffs: Measured

    # Verifier + chain + cleanup + budget.
    verifier_confirmed: Measured
    verifier_pass: Measured
    verifier_incomplete: Measured
    causal_chains: Measured
    cleanup_succeeded: bool | Literal["UNKNOWN"]
    budget_violations: Measured

    # Names of measurements that are UNKNOWN, for explicit incomplete-measurement reporting.
    incomplete_measurements: tuple[str, ...] = Field(default_factory=tuple, max_length=32)

    def recompute_incomplete(self) -> BenchmarkRunMetrics:
        """Return a copy whose ``incomplete_measurements`` lists every UNKNOWN field by name."""

        unknown: list[str] = []
        for name, value in self.model_dump().items():
            if name in {"mode", "run_ref", "provenance", "incomplete_measurements"}:
                continue
            if value == UNKNOWN:
                unknown.append(name)
        return self.model_copy(update={"incomplete_measurements": tuple(sorted(unknown))})


# --------------------------------------------------------------------------- #
# Fairness validator + mode-integrity rules (controller-owned).
# --------------------------------------------------------------------------- #


def _conditions_match_spec(conditions: RunConditions, spec: BenchmarkSpec) -> list[
    ComparabilityRejection
]:
    rejections: list[ComparabilityRejection] = []
    if conditions.target_ref != spec.target_ref:
        rejections.append(ComparabilityRejection.TARGET_SCOPE_MISMATCH)
    if conditions.application_id != spec.application_id:
        rejections.append(ComparabilityRejection.APPLICATION_MISMATCH)
    if conditions.scenario_id != spec.scenario_id:
        rejections.append(ComparabilityRejection.SCENARIO_MISMATCH)
    if conditions.inventory_snapshot_sha256 != spec.inventory_snapshot_sha256:
        rejections.append(ComparabilityRejection.INVENTORY_SNAPSHOT_MISMATCH)
    if conditions.registered_capabilities != spec.registered_capabilities:
        rejections.append(ComparabilityRejection.CAPABILITY_SET_MISMATCH)
    if conditions.tool_profiles != spec.tool_profiles:
        rejections.append(ComparabilityRejection.TOOL_PROFILE_MISMATCH)
    if conditions.ground_truth_id != spec.ground_truth_id:
        rejections.append(ComparabilityRejection.GROUND_TRUTH_MISMATCH)
    if conditions.budget != spec.budget:
        rejections.append(ComparabilityRejection.BUDGET_NOT_EQUIVALENT)
    if conditions.verifier_authority != spec.verifier_authority:
        rejections.append(ComparabilityRejection.VERIFIER_MISMATCH)
    if conditions.cleanup_required != spec.cleanup_required:
        rejections.append(ComparabilityRejection.CLEANUP_REQUIREMENT_MISMATCH)
    return rejections


def _mode_integrity(
    conditions: RunConditions, metrics: BenchmarkRunMetrics
) -> list[ComparabilityRejection]:
    """Enforce that the run really is what its mode claims: a role label is not agent execution."""

    rejections: list[ComparabilityRejection] = []
    if not conditions.uses_tool_broker:
        rejections.append(ComparabilityRejection.TOOL_BROKER_NOT_USED)
    if not conditions.uses_independent_verifier:
        rejections.append(ComparabilityRejection.INDEPENDENT_VERIFIER_NOT_USED)
    if conditions.mode is BenchmarkMode.SINGLE_AGENT_BASELINE:
        # The baseline may use LEAD_ORCHESTRATOR but performs NO downstream delegation hand-off.
        if isinstance(metrics.handoffs, int) and metrics.handoffs > 0:
            rejections.append(ComparabilityRejection.SINGLE_AGENT_HAS_DELEGATION)
    else:
        # Multi-agent requires REAL persisted delegation jobs + hand-offs, not role labels.
        if not (isinstance(metrics.handoffs, int) and metrics.handoffs >= 1):
            rejections.append(ComparabilityRejection.MULTI_AGENT_MISSING_DELEGATION)
        if not (isinstance(metrics.agent_jobs, int) and metrics.agent_jobs >= 2):
            rejections.append(ComparabilityRejection.MULTI_AGENT_MISSING_PERSISTED_JOBS)
    return rejections


class FairnessValidator:
    """Decides whether one single-agent run and one multi-agent run are comparable.

    It never mutates state and never declares a winner. It returns the (possibly empty) ordered set
    of typed rejection reasons; an empty result means comparable.
    """

    def __init__(self, spec: BenchmarkSpec) -> None:
        self.spec = spec

    def check(
        self,
        *,
        single_conditions: RunConditions | None,
        single_metrics: BenchmarkRunMetrics | None,
        multi_conditions: RunConditions | None,
        multi_metrics: BenchmarkRunMetrics | None,
    ) -> list[ComparabilityRejection]:
        rejections: list[ComparabilityRejection] = []
        if (
            single_conditions is None
            or single_metrics is None
            or multi_conditions is None
            or multi_metrics is None
        ):
            rejections.append(ComparabilityRejection.MISSING_RUN)
            return _dedupe(rejections)

        # Each run must be in the correct slot.
        if single_conditions.mode is not BenchmarkMode.SINGLE_AGENT_BASELINE:
            rejections.append(ComparabilityRejection.WRONG_MODE_FOR_SLOT)
        if multi_conditions.mode is not BenchmarkMode.MULTI_AGENT_DELEGATED:
            rejections.append(ComparabilityRejection.WRONG_MODE_FOR_SLOT)
        if single_conditions.mode is multi_conditions.mode:
            rejections.append(ComparabilityRejection.MODE_COLLISION)

        # Metrics must reference their conditions' run.
        if single_metrics.mode is not single_conditions.mode:
            rejections.append(ComparabilityRejection.WRONG_MODE_FOR_SLOT)
        if multi_metrics.mode is not multi_conditions.mode:
            rejections.append(ComparabilityRejection.WRONG_MODE_FOR_SLOT)

        # Each run's conditions must match the shared spec ...
        for conditions in (single_conditions, multi_conditions):
            if _conditions_match_spec(conditions, self.spec):
                rejections.append(ComparabilityRejection.SPEC_MISMATCH)

        # ... and the two runs must agree on every invariant fairness condition.
        rejections.extend(_pairwise_condition_mismatches(single_conditions, multi_conditions))

        # Mode integrity (real persisted delegation for multi; none for single).
        rejections.extend(_mode_integrity(single_conditions, single_metrics))
        rejections.extend(_mode_integrity(multi_conditions, multi_metrics))
        return _dedupe(rejections)

    def is_comparable(self, **kwargs: RunConditions | BenchmarkRunMetrics | None) -> bool:
        return not self.check(**kwargs)  # type: ignore[arg-type]


def _pairwise_condition_mismatches(
    single: RunConditions, multi: RunConditions
) -> list[ComparabilityRejection]:
    rejections: list[ComparabilityRejection] = []
    if single.target_ref != multi.target_ref:
        rejections.append(ComparabilityRejection.TARGET_SCOPE_MISMATCH)
    if single.application_id != multi.application_id:
        rejections.append(ComparabilityRejection.APPLICATION_MISMATCH)
    if single.scenario_id != multi.scenario_id:
        rejections.append(ComparabilityRejection.SCENARIO_MISMATCH)
    if single.inventory_snapshot_sha256 != multi.inventory_snapshot_sha256:
        rejections.append(ComparabilityRejection.INVENTORY_SNAPSHOT_MISMATCH)
    if single.registered_capabilities != multi.registered_capabilities:
        rejections.append(ComparabilityRejection.CAPABILITY_SET_MISMATCH)
    if single.tool_profiles != multi.tool_profiles:
        rejections.append(ComparabilityRejection.TOOL_PROFILE_MISMATCH)
    if single.ground_truth_id != multi.ground_truth_id:
        rejections.append(ComparabilityRejection.GROUND_TRUTH_MISMATCH)
    if single.budget != multi.budget:
        rejections.append(ComparabilityRejection.BUDGET_NOT_EQUIVALENT)
    if single.verifier_authority != multi.verifier_authority:
        rejections.append(ComparabilityRejection.VERIFIER_MISMATCH)
    if single.cleanup_required != multi.cleanup_required:
        rejections.append(ComparabilityRejection.CLEANUP_REQUIREMENT_MISMATCH)
    return rejections


def _dedupe(items: list[ComparabilityRejection]) -> list[ComparabilityRejection]:
    seen: dict[ComparabilityRejection, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


# --------------------------------------------------------------------------- #
# Deterministic comparison (no composite winner; UNKNOWN stays UNKNOWN).
# --------------------------------------------------------------------------- #

MetricDirection = Literal["SINGLE_LOWER", "MULTI_LOWER", "EQUAL", "UNKNOWN"]

# Metrics whose raw counts are directly comparable side by side. Order is stable for determinism.
_COMPARABLE_METRICS: tuple[str, ...] = (
    "verified_findings",
    "false_or_unsupported_findings",
    "hypotheses_generated",
    "tool_executions",
    "successful_tool_actions",
    "failed_tool_actions",
    "provider_calls",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "wall_clock_ms",
    "agent_jobs",
    "handoffs",
    "verifier_confirmed",
    "verifier_pass",
    "verifier_incomplete",
    "causal_chains",
    "budget_violations",
)


class MetricComparison(StrictModel):
    """One metric compared side by side. Direction reports which side is *lower* — never a winner.

    Whether "lower is better" depends on the metric (fewer provider calls is good; fewer verified
    findings may be bad), so the framework deliberately does not judge; it only reports the raw
    values and their ordering, and leaves interpretation to the human reviewer.
    """

    metric: str
    single_value: Measured
    multi_value: Measured
    direction: MetricDirection


class BenchmarkComparison(StrictModel):
    """A deterministic, controller-owned side-by-side comparison of two comparable runs.

    ``superiority_claim_supported`` is False whenever the provenance is not a live comparable pair:
    the framework never declares one architecture superior without live comparable runs.
    """

    benchmark_id: str
    pair_id: str
    spec_sha256: str
    comparable: bool
    rejection_reasons: tuple[ComparabilityRejection, ...]
    single_provenance: Provenance | None
    multi_provenance: Provenance | None
    metrics: tuple[MetricComparison, ...]
    incomplete_measurements: tuple[str, ...]
    superiority_claim_supported: bool
    superiority_claim_reason: str


def _direction(single: Measured, multi: Measured) -> MetricDirection:
    if single == UNKNOWN or multi == UNKNOWN:
        return "UNKNOWN"
    assert isinstance(single, int) and isinstance(multi, int)
    if single == multi:
        return "EQUAL"
    return "SINGLE_LOWER" if single < multi else "MULTI_LOWER"


def compare_runs(
    *,
    spec: BenchmarkSpec,
    pair: RunPairId,
    single_conditions: RunConditions | None,
    single_metrics: BenchmarkRunMetrics | None,
    multi_conditions: RunConditions | None,
    multi_metrics: BenchmarkRunMetrics | None,
) -> BenchmarkComparison:
    """Produce the deterministic comparison document. Fails closed to non-comparable on rejection.

    When the runs are not comparable, no metric rows are produced (comparing incomparable runs would
    itself be a fairness violation) and ``superiority_claim_supported`` is False.
    """

    validator = FairnessValidator(spec)
    rejections = validator.check(
        single_conditions=single_conditions,
        single_metrics=single_metrics,
        multi_conditions=multi_conditions,
        multi_metrics=multi_metrics,
    )
    comparable = not rejections

    rows: list[MetricComparison] = []
    incomplete: set[str] = set()
    if comparable and single_metrics is not None and multi_metrics is not None:
        single_dump = single_metrics.model_dump()
        multi_dump = multi_metrics.model_dump()
        for name in _COMPARABLE_METRICS:
            single_value: Measured = single_dump[name]
            multi_value: Measured = multi_dump[name]
            direction = _direction(single_value, multi_value)
            if direction == "UNKNOWN":
                incomplete.add(name)
            rows.append(
                MetricComparison(
                    metric=name,
                    single_value=single_value,
                    multi_value=multi_value,
                    direction=direction,
                )
            )

    # Superiority is only ever supported by a LIVE comparable pair. Offline / containerized pairs
    # never support a superiority claim.
    live_pair = (
        comparable
        and single_conditions is not None
        and multi_conditions is not None
        and single_conditions.provenance == "LIVE_PROVIDER"
        and multi_conditions.provenance == "LIVE_PROVIDER"
    )
    if not comparable:
        reason = "runs are not comparable; no superiority may be inferred"
    elif not live_pair:
        reason = (
            "comparable but not a live provider pair; superiority requires live comparable runs "
            "(NOT_EVALUATED)"
        )
    elif incomplete:
        reason = "live comparable pair has UNKNOWN measurements; superiority not supported"
    else:
        # Even a complete live pair does not *auto*-declare superiority here; a human reviewer reads
        # the raw side-by-side rows. The framework only records that the *evidence* would support a
        # human comparison.
        reason = "live comparable pair with complete measurements; raw side-by-side available"

    return BenchmarkComparison(
        benchmark_id=spec.benchmark_id,
        pair_id=pair.pair_id,
        spec_sha256=spec.spec_sha256,
        comparable=comparable,
        rejection_reasons=tuple(rejections),
        single_provenance=single_conditions.provenance if single_conditions else None,
        multi_provenance=multi_conditions.provenance if multi_conditions else None,
        metrics=tuple(rows),
        incomplete_measurements=tuple(sorted(incomplete)),
        # Offline sprint: never True. Reserved for a future authorized live comparable pair, and
        # even then this framework reports evidence sufficiency; it does not itself crown a winner.
        superiority_claim_supported=False,
        superiority_claim_reason=reason,
    )


# --------------------------------------------------------------------------- #
# Durable result store (SQLite): specs, conditions, metrics, immutable pairs, comparisons.
# --------------------------------------------------------------------------- #


class BenchmarkResultStore:
    """A durable store for benchmark specs, per-run conditions/metrics, immutable pairs and
    comparison documents. There is no field through which a payload, credential or verdict authority
    could be persisted — only references, controller-owned constraints and raw counts."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS benchmark_specs (
                    benchmark_id TEXT PRIMARY KEY,
                    spec_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS benchmark_runs (
                    run_ref TEXT PRIMARY KEY,
                    benchmark_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    conditions_payload TEXT NOT NULL,
                    metrics_payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS benchmark_pairs (
                    pair_id TEXT PRIMARY KEY,
                    benchmark_id TEXT NOT NULL,
                    spec_sha256 TEXT NOT NULL,
                    single_run_ref TEXT NOT NULL,
                    multi_run_ref TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS benchmark_comparisons (
                    pair_id TEXT PRIMARY KEY,
                    benchmark_id TEXT NOT NULL,
                    comparable INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_benchmark_runs_bench
                    ON benchmark_runs(benchmark_id, mode);
                """
            )

    def save_spec(self, spec: BenchmarkSpec) -> str:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT spec_sha256 FROM benchmark_specs WHERE benchmark_id = ?",
                (spec.benchmark_id,),
            ).fetchone()
            if existing is not None and existing["spec_sha256"] != spec.spec_sha256:
                raise BenchmarkError("BENCHMARK_SPEC_IMMUTABLE")
            connection.execute(
                """INSERT INTO benchmark_specs(benchmark_id, spec_sha256, created_at, payload)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(benchmark_id) DO NOTHING""",
                (
                    spec.benchmark_id,
                    spec.spec_sha256,
                    spec.created_at.isoformat(),
                    spec.model_dump_json(),
                ),
            )
        return spec.benchmark_uri

    def get_spec(self, benchmark_id: str) -> BenchmarkSpec | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM benchmark_specs WHERE benchmark_id = ?", (benchmark_id,)
            ).fetchone()
        return BenchmarkSpec.model_validate_json(row["payload"]) if row else None

    def save_run(
        self, benchmark_id: str, conditions: RunConditions, metrics: BenchmarkRunMetrics
    ) -> str:
        if conditions.run_ref != metrics.run_ref:
            raise BenchmarkError("BENCHMARK_RUN_REF_MISMATCH")
        if conditions.mode is not metrics.mode:
            raise BenchmarkError("BENCHMARK_RUN_MODE_MISMATCH")
        normalized = metrics.recompute_incomplete()
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO benchmark_runs(
                        run_ref, benchmark_id, mode, provenance,
                        conditions_payload, metrics_payload, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        conditions.run_ref,
                        benchmark_id,
                        conditions.mode.value,
                        conditions.provenance,
                        conditions.model_dump_json(),
                        normalized.model_dump_json(),
                        now_utc().isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise BenchmarkError("BENCHMARK_RUN_ALREADY_PERSISTED") from exc
        return conditions.run_ref

    def get_run(
        self, run_ref: str
    ) -> tuple[RunConditions, BenchmarkRunMetrics] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT conditions_payload, metrics_payload FROM benchmark_runs WHERE run_ref = ?",
                (run_ref,),
            ).fetchone()
        if row is None:
            return None
        return (
            RunConditions.model_validate_json(row["conditions_payload"]),
            BenchmarkRunMetrics.model_validate_json(row["metrics_payload"]),
        )

    def save_pair(self, pair: RunPairId) -> str:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT payload FROM benchmark_pairs WHERE pair_id = ?", (pair.pair_id,)
            ).fetchone()
            if existing is not None:
                stored = RunPairId.model_validate_json(existing["payload"])
                if stored.model_dump_json() != pair.model_dump_json():
                    raise BenchmarkError("BENCHMARK_PAIR_IMMUTABLE")
                return pair.pair_address
            connection.execute(
                """INSERT INTO benchmark_pairs(
                    pair_id, benchmark_id, spec_sha256, single_run_ref, multi_run_ref,
                    address, created_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pair.pair_id,
                    pair.benchmark_id,
                    pair.spec_sha256,
                    pair.single_run_ref,
                    pair.multi_run_ref,
                    pair.pair_address,
                    pair.created_at.isoformat(),
                    pair.model_dump_json(),
                ),
            )
        return pair.pair_address

    def get_pair(self, pair_id: str) -> RunPairId | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM benchmark_pairs WHERE pair_id = ?", (pair_id,)
            ).fetchone()
        return RunPairId.model_validate_json(row["payload"]) if row else None

    def save_comparison(self, comparison: BenchmarkComparison) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO benchmark_comparisons(
                    pair_id, benchmark_id, comparable, created_at, payload
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(pair_id) DO UPDATE SET
                    comparable=excluded.comparable, payload=excluded.payload""",
                (
                    comparison.pair_id,
                    comparison.benchmark_id,
                    1 if comparison.comparable else 0,
                    now_utc().isoformat(),
                    comparison.model_dump_json(),
                ),
            )

    def get_comparison(self, pair_id: str) -> BenchmarkComparison | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM benchmark_comparisons WHERE pair_id = ?", (pair_id,)
            ).fetchone()
        return BenchmarkComparison.model_validate_json(row["payload"]) if row else None

    def list_pairs(self, limit: int = 25) -> list[RunPairId]:
        bounded = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM benchmark_pairs ORDER BY created_at DESC LIMIT ?", (bounded,)
            ).fetchall()
        return [RunPairId.model_validate_json(row["payload"]) for row in rows]


# --------------------------------------------------------------------------- #
# Deterministic comparison report (markdown/json). No prose generation, no inferred metrics.
# --------------------------------------------------------------------------- #


def render_comparison_markdown(
    spec: BenchmarkSpec, comparison: BenchmarkComparison
) -> str:
    lines = [
        "# Phase 2.4 Single-Agent vs Multi-Agent Benchmark",
        "",
        "Controller-owned, deterministic side-by-side comparison. No composite winner score; "
        "no superiority is declared without live comparable runs.",
        "",
        f"- Benchmark: `{spec.benchmark_id}`",
        f"- Target / application / scenario: `{spec.target_ref}` / `{spec.application_id}` / "
        f"`{spec.scenario_id}`",
        f"- Ground truth: `{spec.ground_truth_id}`",
        f"- Spec SHA-256: `{comparison.spec_sha256}`",
        f"- Pair: `{comparison.pair_id}`",
        f"- Comparable: `{str(comparison.comparable).lower()}`",
        f"- Single provenance / Multi provenance: `{comparison.single_provenance}` / "
        f"`{comparison.multi_provenance}`",
        f"- Superiority claim supported: `{str(comparison.superiority_claim_supported).lower()}` "
        f"({comparison.superiority_claim_reason})",
        "",
    ]
    if not comparison.comparable:
        lines.extend(
            ["## Not comparable", "", "The runs are not comparable for these reasons:", ""]
        )
        for reason in comparison.rejection_reasons:
            lines.append(f"- `{reason.value}`")
        lines.append("")
        lines.append("No metric comparison is produced for non-comparable runs.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "## Raw metric comparison",
            "",
            "| Metric | Single-agent | Multi-agent | Lower side |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in comparison.metrics:
        lines.append(
            f"| `{row.metric}` | `{row.single_value}` | `{row.multi_value}` | `{row.direction}` |"
        )
    lines.extend(["", "## Incomplete measurements", ""])
    if comparison.incomplete_measurements:
        lines.append(
            "The following measurements were UNKNOWN on at least one side and are NOT counted "
            "as zero:"
        )
        lines.append("")
        for name in comparison.incomplete_measurements:
            lines.append(f"- `{name}`")
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines) + "\n"
