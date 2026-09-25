"""Phase 2.7 — Full Authorized Assessment Lifecycle (controller-governed, resumable workflow/DAG).

One bounded, resumable, controller-owned assessment lifecycle that composes the prior proven pieces:

    authorized inventory -> assessment profile -> lease & budgets -> Lead job -> capability/agent
    delegation -> tool execution -> normalized evidence -> hypotheses -> independent verification ->
    verified findings -> optional verified causal chain -> registered remediation -> fresh retest ->
    professional report -> cleanup/reset -> final audit manifest.

The lifecycle is a controller-owned typed DAG with persisted per-stage state, idempotency (no
duplicate paid/tool execution on resume), cancellation, budget exhaustion, lease expiry, partial
completion, cleanup compensation, an immutable audit trail and a final typed verdict.

Authority (unchanged model): **the model cannot advance the workflow state.** Every transition is a
controller method validated by :func:`assert_state_transition`; stage executors are deterministic
callables the controller invokes, and they can only report an outcome — never set a state, confirm a
finding, or charge a budget themselves. Provider/tool usage is committed atomically with a stage's
``DONE`` record, so an interruption before ``DONE`` records no usage (safe re-execution) and an
interruption after ``DONE`` returns the cached record (no double charge). Unmeasured usage stays
``UNKNOWN`` and a provider stage that reports ``UNKNOWN`` usage fails closed (budget unverifiable) —
usage is never defaulted to zero. A stage whose evidence carries an epoch other than the current run
epoch is rejected (no stale evidence, no historical-artifact reuse as a new execution).

Fully offline and deterministic: nothing here calls a provider, opens a socket or touches Docker.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from aegis.multi_agent.contracts import StrictModel, now_utc

Measured = int | Literal["UNKNOWN"]
UNKNOWN: Literal["UNKNOWN"] = "UNKNOWN"


class FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class LifecycleError(RuntimeError):
    """A lifecycle failure (bad id, missing record, illegal call). Fails closed."""


class LifecycleStateError(RuntimeError):
    """An illegal overall-state transition. Fails closed (the lifecycle cannot advance)."""


class LifecycleBudgetError(RuntimeError):
    """Budget exhausted or unverifiable (UNKNOWN usage). Fails closed."""


class LifecycleLeaseExpired(RuntimeError):
    """The operator lease expired before/at a stage boundary. Fails closed."""


class LifecycleCancelled(RuntimeError):
    """A cancellation was requested; the stage is not run. Fails closed to cleanup."""


class LifecycleFreshnessError(RuntimeError):
    """Stale evidence or a historical-artifact reuse attempt. Fails closed."""


class LifecycleUnreconciledEffect(RuntimeError):
    """A prior external stage attempt was dispatched but its outcome is UNKNOWN (a crash may have
    occurred after the external effect but before the response was persisted locally).

    The controller NEVER silently reissues such an attempt on resume: replaying an external
    provider/tool call could double-execute a side effect (and, for a paid call, double-charge a
    provider). Fails closed until the effect is either reconciled at the broker (see
    :meth:`AssessmentLifecycleController.run_external_stage`) or a NEW attempt is explicitly
    authorized by the controller/operator.
    """


class LifecycleReissueNotAuthorized(RuntimeError):
    """A new external attempt was requested after an UNKNOWN effect without the required explicit
    explicit controller decision (and, for a paid call, new operator authorization). Fails closed.

    Distinct from :class:`LifecycleUnreconciledEffect`: the caller acknowledged the unknown effect
    and asked to try again, but did not supply the authorization a re-attempt requires.
    """


# --------------------------------------------------------------------------- #
# Typed stages + the controller-owned DAG.
# --------------------------------------------------------------------------- #


class LifecycleStage(StrEnum):
    AUTHORIZE = "AUTHORIZE"
    PREPARE = "PREPARE"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    REMEDIATE = "REMEDIATE"
    RETEST = "RETEST"
    REPORT = "REPORT"
    CLEANUP = "CLEANUP"


# Explicit dependencies. REMEDIATE/RETEST are optional (only when a finding needs remediation);
# REPORT depends on VERIFY (and, when present, consumes the retest result). CLEANUP is compensation.
_STAGE_DEPS: dict[LifecycleStage, tuple[LifecycleStage, ...]] = {
    LifecycleStage.AUTHORIZE: (),
    LifecycleStage.PREPARE: (LifecycleStage.AUTHORIZE,),
    LifecycleStage.EXECUTE: (LifecycleStage.PREPARE,),
    LifecycleStage.VERIFY: (LifecycleStage.EXECUTE,),
    LifecycleStage.REMEDIATE: (LifecycleStage.VERIFY,),
    LifecycleStage.RETEST: (LifecycleStage.REMEDIATE,),
    LifecycleStage.REPORT: (LifecycleStage.VERIFY,),
    LifecycleStage.CLEANUP: (),
}

# Stages that produce evidence whose freshness downstream stages must check.
_EVIDENCE_STAGES: frozenset[LifecycleStage] = frozenset(
    {LifecycleStage.EXECUTE, LifecycleStage.VERIFY, LifecycleStage.RETEST}
)


class StageStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    COMPENSATED = "COMPENSATED"


# --------------------------------------------------------------------------- #
# Overall assessment state machine (controller-owned; the model can never advance it).
# --------------------------------------------------------------------------- #


class AssessmentState(StrEnum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    READY = "READY"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    REMEDIATING = "REMEDIATING"
    RETESTING = "RETESTING"
    REPORTING = "REPORTING"
    CLEANING_UP = "CLEANING_UP"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


_TERMINAL_STATES: frozenset[AssessmentState] = frozenset(
    {
        AssessmentState.COMPLETED,
        AssessmentState.PARTIAL,
        AssessmentState.FAILED,
        AssessmentState.CANCELLED,
        AssessmentState.CLEANUP_FAILED,
    }
)

# CLEANING_UP and CANCELLED/FAILED are reachable from most active states (fail-closed exits).
_ACTIVE_EXITS: frozenset[AssessmentState] = frozenset(
    {AssessmentState.CLEANING_UP, AssessmentState.CANCELLED, AssessmentState.FAILED}
)

_STATE_TRANSITIONS: dict[AssessmentState, frozenset[AssessmentState]] = {
    AssessmentState.CREATED: frozenset({AssessmentState.AUTHORIZED}) | _ACTIVE_EXITS,
    AssessmentState.AUTHORIZED: frozenset({AssessmentState.READY}) | _ACTIVE_EXITS,
    AssessmentState.READY: frozenset({AssessmentState.RUNNING}) | _ACTIVE_EXITS,
    AssessmentState.RUNNING: frozenset({AssessmentState.VERIFYING}) | _ACTIVE_EXITS,
    AssessmentState.VERIFYING: frozenset(
        {AssessmentState.REMEDIATING, AssessmentState.REPORTING}
    )
    | _ACTIVE_EXITS,
    AssessmentState.REMEDIATING: frozenset({AssessmentState.RETESTING}) | _ACTIVE_EXITS,
    AssessmentState.RETESTING: frozenset({AssessmentState.REPORTING}) | _ACTIVE_EXITS,
    AssessmentState.REPORTING: frozenset({AssessmentState.CLEANING_UP}) | _ACTIVE_EXITS,
    AssessmentState.CLEANING_UP: frozenset(
        {
            AssessmentState.COMPLETED,
            AssessmentState.PARTIAL,
            AssessmentState.CANCELLED,
            AssessmentState.CLEANUP_FAILED,
            AssessmentState.FAILED,
        }
    ),
    AssessmentState.COMPLETED: frozenset(),
    AssessmentState.PARTIAL: frozenset(),
    AssessmentState.FAILED: frozenset(),
    AssessmentState.CANCELLED: frozenset(),
    AssessmentState.CLEANUP_FAILED: frozenset(),
}

# The overall state a stage's execution drives it into.
_STAGE_ACTIVE_STATE: dict[LifecycleStage, AssessmentState] = {
    LifecycleStage.AUTHORIZE: AssessmentState.AUTHORIZED,
    LifecycleStage.PREPARE: AssessmentState.READY,
    LifecycleStage.EXECUTE: AssessmentState.RUNNING,
    LifecycleStage.VERIFY: AssessmentState.VERIFYING,
    LifecycleStage.REMEDIATE: AssessmentState.REMEDIATING,
    LifecycleStage.RETEST: AssessmentState.RETESTING,
    LifecycleStage.REPORT: AssessmentState.REPORTING,
    LifecycleStage.CLEANUP: AssessmentState.CLEANING_UP,
}


def valid_state_transitions(state: AssessmentState) -> frozenset[AssessmentState]:
    return _STATE_TRANSITIONS[state]


def assert_state_transition(current: AssessmentState, new: AssessmentState) -> None:
    if new not in valid_state_transitions(current):
        raise LifecycleStateError(f"ILLEGAL_STATE_{current.value}_TO_{new.value}")


# --------------------------------------------------------------------------- #
# Typed records: spec, stage usage/outcome, stage record, cleanup, manifest, verdict.
# --------------------------------------------------------------------------- #


class StageUsageDelta(StrictModel):
    """Per-stage provider/tool usage. UNKNOWN where a provider stage cannot measure (fails shut)."""

    provider_calls: Measured = 0
    tokens: Measured = 0
    tool_executions: Measured = 0

    def is_known(self) -> bool:
        return all(v != UNKNOWN for v in (self.provider_calls, self.tokens, self.tool_executions))


class StageContext(StrictModel):
    """The controller-supplied context an executor sees. It cannot mutate lifecycle state."""

    assessment_id: str
    run_epoch: int
    stage: LifecycleStage
    upstream_evidence: dict[str, str] = Field(default_factory=dict)  # stage -> evidence_sha256


class StageOutcome(StrictModel):
    """A deterministic stage executor's report. It never sets a state or a verdict."""

    ok: bool
    produced_epoch: int
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    side_effect_token: str = Field(default="", max_length=120)
    usage: StageUsageDelta = Field(default_factory=StageUsageDelta)
    detail: str = Field(default="", max_length=300)


StageExecutor = Callable[[StageContext], StageOutcome]

# An external dispatcher performs the real provider/tool side effect for one attempt and returns its
# outcome. It receives the stable idempotency key so an idempotency-aware broker can reuse it.
ExternalDispatcher = Callable[[StageContext, str], StageOutcome]

# A reconciler answers "did the external attempt for this idempotency key already complete?" by
# querying the broker after a crash. It returns the completed outcome (dedup: no re-execution), or
# ``None`` when the broker cannot tell (the effect stays UNKNOWN). Only for a broker whose
# attempt was recorded ``reconcilable=True``.
ExternalReconciler = Callable[[str], StageOutcome | None]


class StageRecord(StrictModel):
    assessment_id: str
    stage: LifecycleStage
    status: StageStatus
    produced_epoch: int | None = None
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    side_effect_token: str = ""
    usage: StageUsageDelta = Field(default_factory=StageUsageDelta)
    detail: str = ""
    updated_at: datetime = Field(default_factory=now_utc)


# --------------------------------------------------------------------------- #
# External-effect stage attempts (crash-window semantics for provider/tool dispatch).
# --------------------------------------------------------------------------- #


class AttemptStatus(StrEnum):
    """The lifecycle of ONE external-effect attempt, persisted around a provider/tool dispatch.

    * ``PREPARED``   — the attempt + idempotency key are recorded, but nothing dispatched yet. A
      crash here is safe: no external effect went out, so a fresh attempt can supersede it.
    * ``DISPATCHED`` — the external call was (about to be) sent but no response persisted yet. A
      crash here leaves the outcome **UNKNOWN**: the side effect may or may not have happened
      (at-least-once, never exactly-once). It is NEVER auto-reissued on resume.
    * ``COMPLETED``  — the response was persisted. The external effect happened exactly once and its
      result is cached; the stage's ``DONE`` record (and its usage accounting) is committed from it.
    * ``FAILED``     — the executor reported a clean, pre-dispatch failure (no external effect).
    * ``SUPERSEDED`` — an explicitly-authorized new attempt replaced this one (its UNKNOWN usage is
      never recovered, so it keeps cumulative usage incomplete).
    """

    PREPARED = "PREPARED"
    DISPATCHED = "DISPATCHED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SUPERSEDED = "SUPERSEDED"


# An attempt whose external outcome is unknown on resume (a crash after dispatch, before its
# was persisted). Such an attempt is never silently reissued.
_UNKNOWN_OUTCOME_STATUSES: frozenset[AttemptStatus] = frozenset({AttemptStatus.DISPATCHED})


class ExternalStageAttempt(StrictModel):
    """One persisted attempt at an external-effect stage, keyed by a stable idempotency key.

    The idempotency key is the dedup handle a broker that *supports* reconciliation reuses to
    avoid a second real execution; ``reconcilable`` records whether that broker can be asked
    "did key K already run?" after a crash. When ``reconcilable`` is False a crash after dispatch is
    irreducibly UNKNOWN — the effect may have run once already, so the local record must not be used
    to claim it did *not*.
    """

    assessment_id: str
    stage: LifecycleStage
    idempotency_key: str = Field(min_length=1, max_length=200)
    attempt_no: int = Field(ge=1)
    status: AttemptStatus
    reconcilable: bool = False
    paid: bool = False
    dispatched: bool = False
    response_persisted: bool = False
    produced_epoch: int | None = None
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    side_effect_token: str = ""
    usage: StageUsageDelta = Field(default_factory=StageUsageDelta)
    authorized_by: str = Field(default="", max_length=200)
    operator_authorization: str = Field(default="", max_length=200)
    detail: str = Field(default="", max_length=300)
    updated_at: datetime = Field(default_factory=now_utc)

    def outcome_unknown(self) -> bool:
        return self.status in _UNKNOWN_OUTCOME_STATUSES


class AssessmentSpec(FrozenStrictModel):
    assessment_id: str = Field(pattern=r"^asmt-[a-f0-9]{16}$")
    campaign_id: str = Field(min_length=3, max_length=120)
    target_ref: str = Field(min_length=1, max_length=120)
    scenario_id: str = Field(min_length=1, max_length=120)
    run_epoch: int = Field(ge=1)
    required_stages: tuple[LifecycleStage, ...] = Field(min_length=1, max_length=8)
    cumulative_provider_calls: int = Field(ge=0, le=100)
    cumulative_tokens: int = Field(ge=0, le=1_000_000)
    per_stage_provider_calls: int = Field(ge=0, le=100)
    per_stage_tokens: int = Field(ge=0, le=1_000_000)
    authorization_reference: str = Field(min_length=2, max_length=120)
    lease_ref: str = Field(min_length=2, max_length=120)
    lease_expires_at: datetime
    activation_required_capabilities: tuple[str, ...] = Field(default_factory=tuple, max_length=16)


class CleanupLedgerEntry(StrictModel):
    obligation: str
    compensated: bool
    detail: str = ""


class AssessmentManifest(StrictModel):
    assessment_id: str
    campaign_id: str
    run_epoch: int
    stage_records: tuple[StageRecord, ...]
    cleanup: tuple[CleanupLedgerEntry, ...]
    cumulative_provider_calls: int
    cumulative_tokens: int
    cumulative_tool_executions: int
    usage_complete: bool

    @property
    def manifest_sha256(self) -> str:
        material = self.model_dump_json()
        return hashlib.sha256(material.encode()).hexdigest()


class AssessmentVerdict(StrictModel):
    assessment_id: str
    final_state: AssessmentState
    required_stages_complete: bool
    cleanup_succeeded: bool
    usage_complete: bool
    cumulative_provider_calls: Measured
    cumulative_tokens: Measured
    manifest_sha256: str
    assurance_summary: str


# --------------------------------------------------------------------------- #
# Durable lifecycle ledger (SQLite): assessments, stages, usage, cleanup, audit.
# --------------------------------------------------------------------------- #


class LifecycleLedger:
    """Durable, resumable store for one or more assessment lifecycles."""

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
                CREATE TABLE IF NOT EXISTS lifecycle_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    spec TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_stages (
                    assessment_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, stage)
                );
                CREATE TABLE IF NOT EXISTS lifecycle_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_cleanup (
                    assessment_id TEXT NOT NULL,
                    obligation TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, obligation)
                );
                CREATE TABLE IF NOT EXISTS lifecycle_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS lifecycle_attempts (
                    assessment_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    attempt_no INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (assessment_id, stage, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_lifecycle_attempts_stage
                    ON lifecycle_attempts(assessment_id, stage, attempt_no);
                """
            )

    def create(self, spec: AssessmentSpec) -> None:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO lifecycle_assessments(
                        assessment_id, state, cancel_requested, spec, created_at
                    ) VALUES (?, ?, 0, ?, ?)""",
                    (
                        spec.assessment_id,
                        AssessmentState.CREATED.value,
                        spec.model_dump_json(),
                        now_utc().isoformat(),
                    ),
                )
                self._record_transition(
                    connection, spec.assessment_id, "NONE", AssessmentState.CREATED.value, "created"
                )
                self._audit(connection, spec.assessment_id, "CONTROLLER", "CREATED", "assessment")
            except sqlite3.IntegrityError as exc:
                raise LifecycleError("ASSESSMENT_ALREADY_EXISTS") from exc

    def get_spec(self, assessment_id: str) -> AssessmentSpec | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT spec FROM lifecycle_assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
        return AssessmentSpec.model_validate_json(row["spec"]) if row else None

    def get_state(self, assessment_id: str) -> AssessmentState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM lifecycle_assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
        if row is None:
            raise LifecycleError("ASSESSMENT_NOT_FOUND")
        return AssessmentState(row["state"])

    def cancel_requested(self, assessment_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM lifecycle_assessments WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
        if row is None:
            raise LifecycleError("ASSESSMENT_NOT_FOUND")
        return bool(row["cancel_requested"])

    def request_cancel(self, assessment_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE lifecycle_assessments SET cancel_requested = 1 WHERE assessment_id = ?",
                (assessment_id,),
            )
            self._audit(connection, assessment_id, "CONTROLLER", "CANCEL_REQUESTED", "operator")

    def set_state(self, assessment_id: str, new: AssessmentState, reason: str) -> None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM lifecycle_assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
            if row is None:
                raise LifecycleError("ASSESSMENT_NOT_FOUND")
            current = AssessmentState(row["state"])
            if current == new:
                return
            assert_state_transition(current, new)
            connection.execute(
                "UPDATE lifecycle_assessments SET state = ? WHERE assessment_id = ?",
                (new.value, assessment_id),
            )
            self._record_transition(
                connection, assessment_id, current.value, new.value, reason[:200]
            )

    def upsert_stage(self, record: StageRecord) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO lifecycle_stages(assessment_id, stage, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(assessment_id, stage) DO UPDATE SET payload = excluded.payload""",
                (record.assessment_id, record.stage.value, record.model_dump_json()),
            )

    def get_stage(self, assessment_id: str, stage: LifecycleStage) -> StageRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM lifecycle_stages WHERE assessment_id = ? AND stage = ?",
                (assessment_id, stage.value),
            ).fetchone()
        return StageRecord.model_validate_json(row["payload"]) if row else None

    def all_stages(self, assessment_id: str) -> list[StageRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM lifecycle_stages WHERE assessment_id = ?", (assessment_id,)
            ).fetchall()
        return [StageRecord.model_validate_json(row["payload"]) for row in rows]

    # --------------------------- external attempts --------------------------- #

    def upsert_attempt(self, attempt: ExternalStageAttempt) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO lifecycle_attempts(
                    assessment_id, stage, idempotency_key, attempt_no, status, payload
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(assessment_id, stage, idempotency_key) DO UPDATE SET
                    attempt_no = excluded.attempt_no,
                    status = excluded.status,
                    payload = excluded.payload""",
                (
                    attempt.assessment_id,
                    attempt.stage.value,
                    attempt.idempotency_key,
                    attempt.attempt_no,
                    attempt.status.value,
                    attempt.model_dump_json(),
                ),
            )

    def get_attempt(
        self, assessment_id: str, stage: LifecycleStage, idempotency_key: str
    ) -> ExternalStageAttempt | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload FROM lifecycle_attempts
                WHERE assessment_id = ? AND stage = ? AND idempotency_key = ?""",
                (assessment_id, stage.value, idempotency_key),
            ).fetchone()
        return ExternalStageAttempt.model_validate_json(row["payload"]) if row else None

    def attempts_for(
        self, assessment_id: str, stage: LifecycleStage
    ) -> list[ExternalStageAttempt]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM lifecycle_attempts
                WHERE assessment_id = ? AND stage = ? ORDER BY attempt_no""",
                (assessment_id, stage.value),
            ).fetchall()
        return [ExternalStageAttempt.model_validate_json(row["payload"]) for row in rows]

    def all_attempts(self, assessment_id: str) -> list[ExternalStageAttempt]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM lifecycle_attempts
                WHERE assessment_id = ? ORDER BY stage, attempt_no""",
                (assessment_id,),
            ).fetchall()
        return [ExternalStageAttempt.model_validate_json(row["payload"]) for row in rows]

    def upsert_cleanup(self, assessment_id: str, entry: CleanupLedgerEntry) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO lifecycle_cleanup(assessment_id, obligation, payload)
                VALUES (?, ?, ?)
                ON CONFLICT(assessment_id, obligation) DO UPDATE SET payload = excluded.payload""",
                (assessment_id, entry.obligation, entry.model_dump_json()),
            )

    def cleanup_entries(self, assessment_id: str) -> list[CleanupLedgerEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM lifecycle_cleanup WHERE assessment_id = ? ORDER BY obligation",
                (assessment_id,),
            ).fetchall()
        return [CleanupLedgerEntry.model_validate_json(row["payload"]) for row in rows]

    def audit_trail(self, assessment_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT actor, event_type, summary, at FROM lifecycle_audit
                WHERE assessment_id = ? ORDER BY id""",
                (assessment_id,),
            ).fetchall()
        return [
            {"actor": r["actor"], "event_type": r["event_type"], "summary": r["summary"],
             "at": r["at"]}
            for r in rows
        ]

    def audit(self, assessment_id: str, actor: str, event_type: str, summary: str) -> None:
        with self._connect() as connection:
            self._audit(connection, assessment_id, actor, event_type, summary)

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        assessment_id: str,
        actor: str,
        event_type: str,
        summary: str,
    ) -> None:
        connection.execute(
            """INSERT INTO lifecycle_audit(assessment_id, actor, event_type, summary, at)
            VALUES (?, ?, ?, ?, ?)""",
            (assessment_id, actor, event_type, summary[:300], now_utc().isoformat()),
        )

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection,
        assessment_id: str,
        from_state: str,
        to_state: str,
        reason: str,
    ) -> None:
        connection.execute(
            """INSERT INTO lifecycle_transitions(assessment_id, from_state, to_state, reason, at)
            VALUES (?, ?, ?, ?, ?)""",
            (assessment_id, from_state, to_state, reason, now_utc().isoformat()),
        )


# --------------------------------------------------------------------------- #
# Controller-owned lifecycle orchestration (non-AI).
# --------------------------------------------------------------------------- #


class AssessmentLifecycleController:
    """The non-AI controller that drives the assessment DAG. The model never advances state here.

    It is stateless across calls (everything lives in the ledger), so a fresh controller pointed at
    the same database resumes exactly where a previous process was interrupted.
    """

    def __init__(self, ledger: LifecycleLedger) -> None:
        self.ledger = ledger

    def create_assessment(self, spec: AssessmentSpec) -> None:
        self.ledger.create(spec)

    def request_cancel(self, assessment_id: str) -> None:
        self.ledger.request_cancel(assessment_id)

    def _spec(self, assessment_id: str) -> AssessmentSpec:
        spec = self.ledger.get_spec(assessment_id)
        if spec is None:
            raise LifecycleError("ASSESSMENT_NOT_FOUND")
        return spec

    def _preflight(
        self, assessment_id: str, stage: LifecycleStage, now: datetime
    ) -> AssessmentSpec:
        spec = self._spec(assessment_id)
        state = self.ledger.get_state(assessment_id)
        if state in _TERMINAL_STATES:
            raise LifecycleError(f"ASSESSMENT_TERMINAL_{state.value}")
        if self.ledger.cancel_requested(assessment_id):
            raise LifecycleCancelled("CANCEL_REQUESTED")
        if now >= spec.lease_expires_at:
            self.ledger.audit(assessment_id, "CONTROLLER", "LEASE_EXPIRED", stage.value)
            raise LifecycleLeaseExpired("LEASE_EXPIRED")
        # Dependencies must be DONE.
        for dep in _STAGE_DEPS[stage]:
            dep_record = self.ledger.get_stage(assessment_id, dep)
            if dep_record is None or dep_record.status is not StageStatus.DONE:
                raise LifecycleError(f"STAGE_DEP_NOT_DONE_{dep.value}")
        return spec

    def authorize(
        self, assessment_id: str, *, authorization_reference: str, now: datetime
    ) -> StageRecord:
        spec = self._spec(assessment_id)
        if authorization_reference != spec.authorization_reference:
            raise LifecycleError("AUTHORIZATION_REFERENCE_MISMATCH")
        if now >= spec.lease_expires_at:
            raise LifecycleLeaseExpired("LEASE_EXPIRED")
        return self._commit_control_stage(
            assessment_id, LifecycleStage.AUTHORIZE, spec.run_epoch, "controller authorized"
        )

    def mark_ready(
        self, assessment_id: str, *, activated_capabilities: tuple[str, ...], now: datetime
    ) -> StageRecord:
        spec = self._preflight(assessment_id, LifecycleStage.PREPARE, now)
        missing = [
            c for c in spec.activation_required_capabilities if c not in activated_capabilities
        ]
        if missing:
            raise LifecycleError(f"CAPABILITY_NOT_ACTIVATED:{','.join(sorted(missing))}")
        return self._commit_control_stage(
            assessment_id, LifecycleStage.PREPARE, spec.run_epoch, "capabilities activated; ready"
        )

    def _commit_control_stage(
        self, assessment_id: str, stage: LifecycleStage, epoch: int, reason: str
    ) -> StageRecord:
        existing = self.ledger.get_stage(assessment_id, stage)
        if existing is not None and existing.status is StageStatus.DONE:
            return existing  # idempotent
        self.ledger.set_state(assessment_id, _STAGE_ACTIVE_STATE[stage], reason)
        record = StageRecord(
            assessment_id=assessment_id,
            stage=stage,
            status=StageStatus.DONE,
            produced_epoch=epoch,
        )
        self.ledger.upsert_stage(record)
        self.ledger.audit(assessment_id, "CONTROLLER", f"STAGE_{stage.value}_DONE", reason)
        return record

    def run_stage(
        self,
        assessment_id: str,
        stage: LifecycleStage,
        executor: StageExecutor,
        *,
        now: datetime,
    ) -> StageRecord:
        """Execute one DAG stage idempotently under lease/budget/freshness/cancellation guards.

        Usage is committed atomically with the DONE record: an interruption before DONE records no
        usage (safe re-execution), and a re-run of a DONE stage returns the cached record (no double
        charge, no duplicate paid/tool execution).
        """

        spec = self._preflight(assessment_id, stage, now)

        existing = self.ledger.get_stage(assessment_id, stage)
        if existing is not None and existing.status is StageStatus.DONE:
            return existing  # idempotent resume: no re-execution, no re-charge

        # Freshness of upstream evidence: an upstream evidence stage must have produced at the
        # CURRENT run epoch. A stale (older-epoch) upstream is rejected.
        upstream_evidence: dict[str, str] = {}
        for dep in _STAGE_DEPS[stage]:
            dep_record = self.ledger.get_stage(assessment_id, dep)
            if dep_record is None:
                raise LifecycleError(f"STAGE_DEP_MISSING_{dep.value}")
            if dep in _EVIDENCE_STAGES:
                if dep_record.produced_epoch != spec.run_epoch:
                    raise LifecycleFreshnessError(f"STALE_UPSTREAM_EVIDENCE_{dep.value}")
                if dep_record.evidence_sha256 is not None:
                    upstream_evidence[dep.value] = dep_record.evidence_sha256

        # Enter the active state and mark RUNNING (informational; usage not yet committed).
        self.ledger.set_state(assessment_id, _STAGE_ACTIVE_STATE[stage], f"running {stage.value}")
        self.ledger.upsert_stage(
            StageRecord(assessment_id=assessment_id, stage=stage, status=StageStatus.RUNNING)
        )

        context = StageContext(
            assessment_id=assessment_id,
            run_epoch=spec.run_epoch,
            stage=stage,
            upstream_evidence=upstream_evidence,
        )
        outcome = executor(context)

        # No historical-artifact reuse: the produced epoch MUST be the current run epoch.
        if outcome.produced_epoch != spec.run_epoch:
            self._fail_stage(assessment_id, stage, "HISTORICAL_ARTIFACT_REUSE")
            raise LifecycleFreshnessError("HISTORICAL_ARTIFACT_REUSE")

        if not outcome.ok:
            self._fail_stage(assessment_id, stage, outcome.detail or "stage failed")
            return StageRecord(
                assessment_id=assessment_id,
                stage=stage,
                status=StageStatus.FAILED,
                produced_epoch=outcome.produced_epoch,
                detail=outcome.detail,
            )

        # Budget: usage must be known (never defaulted to zero) and within per-stage + cumulative.
        if not outcome.usage.is_known():
            self._fail_stage(assessment_id, stage, "BUDGET_UNVERIFIABLE_UNKNOWN_USAGE")
            raise LifecycleBudgetError("BUDGET_UNVERIFIABLE_UNKNOWN_USAGE")
        self._check_budget(assessment_id, spec, outcome.usage, stage)

        record = StageRecord(
            assessment_id=assessment_id,
            stage=stage,
            status=StageStatus.DONE,
            produced_epoch=outcome.produced_epoch,
            evidence_sha256=outcome.evidence_sha256,
            side_effect_token=outcome.side_effect_token,
            usage=outcome.usage,
            detail=outcome.detail,
        )
        self.ledger.upsert_stage(record)  # usage committed atomically with DONE
        self.ledger.audit(
            assessment_id, "CONTROLLER", f"STAGE_{stage.value}_DONE", outcome.detail or stage.value
        )
        return record

    # ------------------------- external-effect stages ------------------------- #

    def run_external_stage(
        self,
        assessment_id: str,
        stage: LifecycleStage,
        dispatcher: ExternalDispatcher,
        *,
        idempotency_key: str,
        now: datetime,
        reconcilable: bool = False,
        reconcile: ExternalReconciler | None = None,
        paid: bool = False,
        new_attempt_authorization: str = "",
        operator_authorization: str = "",
    ) -> StageRecord:
        """Execute one external-effect stage (provider/tool dispatch) with crash-safe idempotency.

        The ordering below is the whole point: a *stable stage-attempt record + idempotency key are
        persisted BEFORE anything is dispatched*, then the attempt is marked ``DISPATCHED`` (still
        before the response is persisted), then the response is persisted and the attempt
        ``COMPLETED``, and only then the stage's ``DONE`` record — carrying the usage accounting —
        committed. Each boundary is a crash window with defined resume behaviour:

        * crash before dispatch (``PREPARED``): no external effect went out — a fresh attempt safely
          supersedes it, no authorization required;
        * crash after dispatch, before response persisted (``DISPATCHED``): the outcome is UNKNOWN —
          the side effect may have happened once already (at-least-once, *never* exactly-once);
          NEVER silently reissued. If the broker is ``reconcilable`` a ``reconcile`` callback may
          adopt the already-completed result (deduplicating execution); otherwise the effect stays
          UNKNOWN and a NEW attempt requires an explicit ``new_attempt_authorization`` (and, for a
          ``paid`` call, ``operator_authorization``);
        * crash after response persisted, before completion (``COMPLETED`` attempt, no ``DONE``
          stage): the response is replayed from the local record — NO re-dispatch — and the usage
          accounting is committed exactly once here;
        * resume with a ``DONE`` stage / completed key: idempotent — no re-execution, no re-charge.

        This separates **duplicate-accounting prevention** (usage is committed atomically with the
        ``DONE`` record, so a crash before ``DONE`` charges nothing) from **duplicate-execution
        prevention** (the idempotency key + a reconcilable broker, or an explicit human re-authorize
        decision). The two are not the same and this method never conflates them.
        """

        spec = self._preflight(assessment_id, stage, now)

        existing = self.ledger.get_stage(assessment_id, stage)
        if existing is not None and existing.status is StageStatus.DONE:
            return existing  # idempotent resume: no re-execution, no re-charge

        upstream_evidence = self._upstream_evidence(assessment_id, stage, spec)
        attempts = self.ledger.attempts_for(assessment_id, stage)

        # Resume: a COMPLETED attempt whose stage DONE record was never committed (a crash after the
        # response was persisted but before stage completion). Replay from the local record — the
        # external effect already happened exactly once — and commit the accounting now.
        completed = next((a for a in attempts if a.status is AttemptStatus.COMPLETED), None)
        if completed is not None:
            self.ledger.audit(
                assessment_id, "CONTROLLER", f"STAGE_{stage.value}_RESUMED",
                f"replayed completed attempt {completed.idempotency_key} (no re-dispatch)",
            )
            return self._commit_stage_done(assessment_id, stage, spec, completed)

        # An UNKNOWN (dispatched-but-unconfirmed) attempt exists: fail closed unless reconciled or a
        # new attempt is explicitly authorized.
        unknown = [a for a in attempts if a.outcome_unknown()]
        if unknown:
            latest_unknown = unknown[-1]
            if reconcilable and latest_unknown.reconcilable and reconcile is not None:
                reconciled = reconcile(latest_unknown.idempotency_key)
                if reconciled is not None:
                    adopted = latest_unknown.model_copy(
                        update={
                            "status": AttemptStatus.COMPLETED,
                            "response_persisted": True,
                            "produced_epoch": reconciled.produced_epoch,
                            "evidence_sha256": reconciled.evidence_sha256,
                            "side_effect_token": reconciled.side_effect_token,
                            "usage": reconciled.usage,
                            "detail": "reconciled at broker (idempotency key already completed)",
                            "updated_at": now_utc(),
                        }
                    )
                    self.ledger.upsert_attempt(adopted)
                    self.ledger.audit(
                        assessment_id, "CONTROLLER", f"STAGE_{stage.value}_RECONCILED",
                        f"broker confirmed idempotency key {latest_unknown.idempotency_key}",
                    )
                    return self._commit_stage_done(assessment_id, stage, spec, adopted)
                # reconcile returned None: the broker cannot confirm — the effect stays UNKNOWN.
            if not new_attempt_authorization:
                self.ledger.audit(
                    assessment_id, "CONTROLLER", f"STAGE_{stage.value}_UNRECONCILED",
                    f"unknown external effect for key {latest_unknown.idempotency_key}; "
                    "not auto-reissued",
                )
                raise LifecycleUnreconciledEffect(
                    f"UNRECONCILED_EXTERNAL_EFFECT_{stage.value}:{latest_unknown.idempotency_key}"
                )
            if (paid or latest_unknown.paid) and not operator_authorization:
                raise LifecycleReissueNotAuthorized(
                    f"PAID_REISSUE_REQUIRES_OPERATOR_AUTHORIZATION_{stage.value}"
                )
            # Explicit decision to open a NEW attempt. The abandoned attempt's usage is never
            # recovered, so it is SUPERSEDED and keeps cumulative usage incomplete (fail-closed).
            for stale in unknown:
                self.ledger.upsert_attempt(
                    stale.model_copy(
                        update={"status": AttemptStatus.SUPERSEDED, "updated_at": now_utc()}
                    )
                )
            self.ledger.audit(
                assessment_id, "CONTROLLER", f"STAGE_{stage.value}_REISSUE_AUTHORIZED",
                f"new attempt authorized_by={new_attempt_authorization[:60]} "
                f"operator={operator_authorization[:60]}",
            )

        # A fresh (or authorized-new, or crash-before-dispatch/PREPARED-only) attempt.
        for prepared in attempts:
            if prepared.status is AttemptStatus.PREPARED:
                self.ledger.upsert_attempt(
                    prepared.model_copy(
                        update={"status": AttemptStatus.SUPERSEDED, "updated_at": now_utc()}
                    )
                )
        attempt_no = len(attempts) + 1
        effective_key = idempotency_key if attempt_no == 1 else f"{idempotency_key}#{attempt_no}"

        # 1) Persist the attempt + idempotency key BEFORE any dispatch.
        attempt = ExternalStageAttempt(
            assessment_id=assessment_id,
            stage=stage,
            idempotency_key=effective_key,
            attempt_no=attempt_no,
            status=AttemptStatus.PREPARED,
            reconcilable=reconcilable,
            paid=paid,
            authorized_by=new_attempt_authorization,
            operator_authorization=operator_authorization,
        )
        self.ledger.upsert_attempt(attempt)
        self.ledger.set_state(assessment_id, _STAGE_ACTIVE_STATE[stage], f"running {stage.value}")
        self.ledger.upsert_stage(
            StageRecord(assessment_id=assessment_id, stage=stage, status=StageStatus.RUNNING)
        )

        # 2) Mark DISPATCHED (persisted) — the external effect is about to go out. A crash between
        #    here and the response persist leaves the outcome UNKNOWN.
        attempt = attempt.model_copy(
            update={"status": AttemptStatus.DISPATCHED, "dispatched": True, "updated_at": now_utc()}
        )
        self.ledger.upsert_attempt(attempt)
        self.ledger.audit(
            assessment_id, "CONTROLLER", f"STAGE_{stage.value}_DISPATCHED", effective_key
        )

        context = StageContext(
            assessment_id=assessment_id,
            run_epoch=spec.run_epoch,
            stage=stage,
            upstream_evidence=upstream_evidence,
        )
        outcome = dispatcher(context, effective_key)  # the external effect (may raise = crash)

        if not outcome.ok:
            # A clean executor-reported failure. Record FAILED (no completed effect to replay).
            self.ledger.upsert_attempt(
                attempt.model_copy(
                    update={
                        "status": AttemptStatus.FAILED,
                        "detail": (outcome.detail or "stage failed")[:300],
                        "updated_at": now_utc(),
                    }
                )
            )
            self._fail_stage(assessment_id, stage, outcome.detail or "stage failed")
            return StageRecord(
                assessment_id=assessment_id,
                stage=stage,
                status=StageStatus.FAILED,
                produced_epoch=outcome.produced_epoch,
                detail=outcome.detail,
            )

        # 3) Persist the response and mark the attempt COMPLETED (the effect happened exactly once).
        completed_attempt = attempt.model_copy(
            update={
                "status": AttemptStatus.COMPLETED,
                "response_persisted": True,
                "produced_epoch": outcome.produced_epoch,
                "evidence_sha256": outcome.evidence_sha256,
                "side_effect_token": outcome.side_effect_token,
                "usage": outcome.usage,
                "detail": outcome.detail[:300],
                "updated_at": now_utc(),
            }
        )
        self.ledger.upsert_attempt(completed_attempt)

        # 4) Commit the stage DONE record + usage accounting from the persisted response.
        return self._commit_stage_done(assessment_id, stage, spec, completed_attempt)

    def _commit_stage_done(
        self,
        assessment_id: str,
        stage: LifecycleStage,
        spec: AssessmentSpec,
        attempt: ExternalStageAttempt,
    ) -> StageRecord:
        """Commit a stage DONE record + usage accounting from a COMPLETED attempt's response.

        Shared by fresh completion and crash-resume replay, so neither re-dispatches. Freshness
        and budget are re-validated here; usage is committed atomically with the DONE record.
        """

        if attempt.produced_epoch != spec.run_epoch:
            self._fail_stage(assessment_id, stage, "HISTORICAL_ARTIFACT_REUSE")
            raise LifecycleFreshnessError("HISTORICAL_ARTIFACT_REUSE")
        if not attempt.usage.is_known():
            self._fail_stage(assessment_id, stage, "BUDGET_UNVERIFIABLE_UNKNOWN_USAGE")
            raise LifecycleBudgetError("BUDGET_UNVERIFIABLE_UNKNOWN_USAGE")
        self._check_budget(assessment_id, spec, attempt.usage, stage)
        record = StageRecord(
            assessment_id=assessment_id,
            stage=stage,
            status=StageStatus.DONE,
            produced_epoch=attempt.produced_epoch,
            evidence_sha256=attempt.evidence_sha256,
            side_effect_token=attempt.side_effect_token,
            usage=attempt.usage,
            detail=attempt.detail,
        )
        self.ledger.upsert_stage(record)  # usage committed atomically with DONE
        self.ledger.audit(
            assessment_id, "CONTROLLER", f"STAGE_{stage.value}_DONE", attempt.detail or stage.value
        )
        return record

    def _upstream_evidence(
        self, assessment_id: str, stage: LifecycleStage, spec: AssessmentSpec
    ) -> dict[str, str]:
        """Collect fresh upstream evidence digests; reject a stale (older-epoch) upstream."""

        upstream_evidence: dict[str, str] = {}
        for dep in _STAGE_DEPS[stage]:
            dep_record = self.ledger.get_stage(assessment_id, dep)
            if dep_record is None:
                raise LifecycleError(f"STAGE_DEP_MISSING_{dep.value}")
            if dep in _EVIDENCE_STAGES:
                if dep_record.produced_epoch != spec.run_epoch:
                    raise LifecycleFreshnessError(f"STALE_UPSTREAM_EVIDENCE_{dep.value}")
                if dep_record.evidence_sha256 is not None:
                    upstream_evidence[dep.value] = dep_record.evidence_sha256
        return upstream_evidence

    def has_unreconciled_effect(self, assessment_id: str) -> bool:
        """True if any external attempt is dispatched-but-unconfirmed (UNKNOWN) or was superseded.

        Either keeps cumulative usage incomplete: an UNKNOWN effect never reported its usage, and a
        superseded attempt's usage was never recovered. The verdict reflects it as usage-incomplete.
        """

        return any(
            a.status in (AttemptStatus.DISPATCHED, AttemptStatus.SUPERSEDED)
            for a in self.ledger.all_attempts(assessment_id)
        )

    def _fail_stage(self, assessment_id: str, stage: LifecycleStage, detail: str) -> None:
        self.ledger.upsert_stage(
            StageRecord(
                assessment_id=assessment_id,
                stage=stage,
                status=StageStatus.FAILED,
                detail=detail[:300],
            )
        )
        self.ledger.audit(assessment_id, "CONTROLLER", f"STAGE_{stage.value}_FAILED", detail)

    def _check_budget(
        self,
        assessment_id: str,
        spec: AssessmentSpec,
        delta: StageUsageDelta,
        stage: LifecycleStage,
    ) -> None:
        assert isinstance(delta.provider_calls, int) and isinstance(delta.tokens, int)
        if delta.provider_calls > spec.per_stage_provider_calls:
            raise LifecycleBudgetError(f"PER_STAGE_CALL_BUDGET_{stage.value}")
        if delta.tokens > spec.per_stage_tokens:
            raise LifecycleBudgetError(f"PER_STAGE_TOKEN_BUDGET_{stage.value}")
        calls, tokens, _tools, complete = self._aggregate_usage(assessment_id)
        if not complete:
            raise LifecycleBudgetError("CUMULATIVE_USAGE_INCOMPLETE")
        if calls + delta.provider_calls > spec.cumulative_provider_calls:
            raise LifecycleBudgetError("CUMULATIVE_CALL_BUDGET")
        if tokens + delta.tokens > spec.cumulative_tokens:
            raise LifecycleBudgetError("CUMULATIVE_TOKEN_BUDGET")

    def _aggregate_usage(self, assessment_id: str) -> tuple[int, int, int, bool]:
        calls = tokens = tools = 0
        complete = True
        for record in self.ledger.all_stages(assessment_id):
            if record.status is not StageStatus.DONE:
                continue
            usage = record.usage
            if not usage.is_known():
                complete = False
                continue
            assert isinstance(usage.provider_calls, int) and isinstance(usage.tokens, int)
            assert isinstance(usage.tool_executions, int)
            calls += usage.provider_calls
            tokens += usage.tokens
            tools += usage.tool_executions
        return calls, tokens, tools, complete

    # ------------------------------ cleanup ------------------------------ #

    def run_cleanup(
        self,
        assessment_id: str,
        obligations: tuple[str, ...],
        compensator: Callable[[str], bool],
        *,
        reason: str = "cleanup",
    ) -> bool:
        """Run cleanup compensation for each obligation and record the cleanup ledger.

        Returns True iff every obligation compensated. Transitions the overall state into
        CLEANING_UP first (fail-closed exit from any active state)."""

        state = self.ledger.get_state(assessment_id)
        if state not in _TERMINAL_STATES and state is not AssessmentState.CLEANING_UP:
            self.ledger.set_state(assessment_id, AssessmentState.CLEANING_UP, reason)
        all_ok = True
        for obligation in obligations:
            ok = bool(compensator(obligation))
            all_ok = all_ok and ok
            self.ledger.upsert_cleanup(
                assessment_id,
                CleanupLedgerEntry(
                    obligation=obligation,
                    compensated=ok,
                    detail="compensated" if ok else "COMPENSATION_FAILED",
                ),
            )
        self.ledger.audit(
            assessment_id,
            "CONTROLLER",
            "CLEANUP_COMPLETE" if all_ok else "CLEANUP_FAILED",
            f"{sum(1 for _ in obligations)} obligations",
        )
        # Also mark the CLEANUP stage record.
        self.ledger.upsert_stage(
            StageRecord(
                assessment_id=assessment_id,
                stage=LifecycleStage.CLEANUP,
                status=StageStatus.DONE if all_ok else StageStatus.FAILED,
                produced_epoch=self._spec(assessment_id).run_epoch,
                detail="cleanup complete" if all_ok else "cleanup failed",
            )
        )
        return all_ok

    # ----------------------------- finalize ------------------------------ #

    def finalize(self, assessment_id: str) -> AssessmentVerdict:
        """Compute the final typed verdict. No COMPLETED unless every required stage is DONE and
        cleanup succeeded; cleanup failure -> CLEANUP_FAILED; a cancel request -> CANCELLED."""

        spec = self._spec(assessment_id)
        state = self.ledger.get_state(assessment_id)
        records = {r.stage: r for r in self.ledger.all_stages(assessment_id)}
        cleanup_entries = self.ledger.cleanup_entries(assessment_id)
        cleanup_succeeded = bool(cleanup_entries) and all(e.compensated for e in cleanup_entries)

        required_done = all(
            records.get(stage) is not None and records[stage].status is StageStatus.DONE
            for stage in spec.required_stages
        )
        calls, tokens, tools, usage_complete = self._aggregate_usage(assessment_id)
        # An UNKNOWN (unreconciled) or superseded external attempt never reported its usage, so
        # cumulative usage cannot be claimed complete even if every DONE stage's usage is known.
        usage_complete = usage_complete and not self.has_unreconciled_effect(assessment_id)
        cancelled = self.ledger.cancel_requested(assessment_id)

        if not cleanup_entries:
            final = AssessmentState.PARTIAL
        elif not cleanup_succeeded:
            final = AssessmentState.CLEANUP_FAILED
        elif cancelled:
            final = AssessmentState.CANCELLED
        elif required_done:
            final = AssessmentState.COMPLETED
        else:
            final = AssessmentState.PARTIAL

        if state is not final:
            # From CLEANING_UP the terminal states are reachable; otherwise fail closed to PARTIAL.
            try:
                self.ledger.set_state(assessment_id, final, "finalized")
            except LifecycleStateError:
                if state not in _TERMINAL_STATES:
                    self.ledger.set_state(
                        assessment_id, AssessmentState.CLEANING_UP, "pre-finalize"
                    )
                    self.ledger.set_state(assessment_id, final, "finalized")

        manifest = AssessmentManifest(
            assessment_id=assessment_id,
            campaign_id=spec.campaign_id,
            run_epoch=spec.run_epoch,
            stage_records=tuple(records.values()),
            cleanup=tuple(cleanup_entries),
            cumulative_provider_calls=calls,
            cumulative_tokens=tokens,
            cumulative_tool_executions=tools,
            usage_complete=usage_complete,
        )
        summary = (
            f"{final.value}: {sum(1 for r in records.values() if r.status is StageStatus.DONE)} "
            f"stages done; cleanup {'ok' if cleanup_succeeded else 'incomplete'}; "
            f"required {'complete' if required_done else 'incomplete'}."
        )
        return AssessmentVerdict(
            assessment_id=assessment_id,
            final_state=final,
            required_stages_complete=required_done,
            cleanup_succeeded=cleanup_succeeded,
            usage_complete=usage_complete,
            cumulative_provider_calls=calls if usage_complete else UNKNOWN,
            cumulative_tokens=tokens if usage_complete else UNKNOWN,
            manifest_sha256=manifest.manifest_sha256,
            assurance_summary=summary,
        )


def evidence_digest(payload: object) -> str:
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(material).hexdigest()
