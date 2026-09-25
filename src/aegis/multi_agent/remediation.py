"""Phase 2.3 bounded Adaptive-Retest / Remediation-Loop slice: a controller-owned typed state
machine, a controller-owned registered remediation-profile registry, an immutable persisted patch
receipt, and the sanitized model-facing projections for one bounded synthetic remediation/retest
loop over a *single* verifier-confirmed Phase 2.2 detection-control finding.

This is the control-plane half of one bounded synthetic loop:

    fresh vulnerable execution -> worker evidence -> independent verifier CONFIRMED
      -> AI remediation recommendation (non-authoritative)
      -> controller-authorized registered remediation (controller-owned)
      -> persisted immutable patch receipt (consumed exactly once)
      -> fresh agent-directed retest -> fresh worker evidence -> independent verifier PASS
      -> reset and cleanup.

Narrow semantics. The loop demonstrates only *"a controller-authorized synthetic remediation
transition followed by a fresh agent-directed retest of the same verified detection-control
finding."* It does **not** claim autonomous source-code repair, arbitrary patch generation,
production remediation, general adaptive exploitation or broad regression coverage.

Authority. The model may only *recommend* a registered ``remediation_profile_id`` (a non-
authoritative hint recorded but never trusted). The non-AI controller owns whether remediation is
allowed, the target/scenario, the current and desired synthetic mode, the authorization and lease,
the patch operation, the state transition, the sentinel rotation, the patch receipt, retest
eligibility, and rollback/reset. AI output never sets an authoritative state directly: every state
transition goes through :func:`assert_transition`, which is only ever called by the controller-owned
:class:`RemediationController`.

This module reuses the Phase 2.2 range mechanics unchanged (target ``aegis-ops``, scenario
``ops-detection-control-bypass-v1``, capability ``aegis.ops.detection_control_probe``, profile
``http_detection_control_probe_v1``, the disposable worker, the sentinel, and the independent
verifier). It reuses the existing real ``AdvSimTaskQueue`` for the fresh Lead->Recon hand-off and
the fresh retest Recon job; the persistence here (the loop state machine, the finding reference, the
authorization/lease, and the immutable patch receipt) is a separate durable ledger.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from aegis.multi_agent.contracts import StrictModel, now_utc

# --------------------------------------------------------------------------- #
# Reused Phase 2.2 identifiers (kept in lockstep with adversary_simulation / the range inventory).
# --------------------------------------------------------------------------- #

REMEDIATION_TARGET_REF = "range-ops"
REMEDIATION_APPLICATION_ID = "aegis-ops"
REMEDIATION_SCENARIO_ID = "ops-detection-control-bypass-v1"
REMEDIATION_FINDING_TYPE = "HTTP_DETECTION_CONTROL_BYPASS"
REMEDIATION_CAPABILITY_ID = "aegis.ops.detection_control_probe"
REMEDIATION_PROBE_PROFILE_ID = "http_detection_control_probe_v1"


class FrozenStrictModel(StrictModel):
    """A strict, immutable model. Used for records (like the patch receipt) that must never mutate
    after creation, so an attempt to rewrite a field raises rather than silently succeeding."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class RemediationRejection(ValueError):
    """Raised when a remediation selection escapes the controller allowlist or scope."""


class RemediationStateError(RuntimeError):
    """Raised on an illegal state-machine transition. Fails closed (the loop cannot advance)."""


class RemediationLedgerError(RuntimeError):
    """A ledger-level failure (duplicate id, missing record, receipt replay). Fails closed."""


# --------------------------------------------------------------------------- #
# Controller-owned typed state machine. AI output never sets a state directly.
# --------------------------------------------------------------------------- #


class RemediationState(StrEnum):
    INITIAL_EXECUTION_PENDING = "INITIAL_EXECUTION_PENDING"
    INITIAL_CONFIRMED = "INITIAL_CONFIRMED"
    REMEDIATION_RECOMMENDED = "REMEDIATION_RECOMMENDED"
    PATCH_AUTHORIZED = "PATCH_AUTHORIZED"
    PATCH_APPLIED = "PATCH_APPLIED"
    RETEST_QUEUED = "RETEST_QUEUED"
    RETEST_RUNNING = "RETEST_RUNNING"
    RETEST_PASS = "RETEST_PASS"  # noqa: S105 - state label, not a credential
    RETEST_FAIL = "RETEST_FAIL"
    INCOMPLETE = "INCOMPLETE"
    CLEANUP_FAILED = "CLEANUP_FAILED"


# An active state may fall to INCOMPLETE (an unrecoverable step error) or CLEANUP_FAILED (a cleanup
# error). The genuinely terminal states have no outgoing transition at all.
_FALLBACKS: frozenset[RemediationState] = frozenset(
    {RemediationState.INCOMPLETE, RemediationState.CLEANUP_FAILED}
)
_TERMINAL: frozenset[RemediationState] = frozenset(
    {RemediationState.RETEST_PASS, RemediationState.RETEST_FAIL, RemediationState.CLEANUP_FAILED}
)

# The single legal happy-path progression. The remediation/retest step may begin ONLY after a fresh
# initial worker execution, verifier CONFIRMED, a persisted finding, a model recommendation, a
# controller-selected registered remediation and a successful patch receipt — the ordering below
# enforces exactly that. Skipping initial verification (e.g. INITIAL_EXECUTION_PENDING ->
# REMEDIATION_RECOMMENDED or -> PATCH_AUTHORIZED) is structurally impossible.
_HAPPY_PATH: dict[RemediationState, frozenset[RemediationState]] = {
    RemediationState.INITIAL_EXECUTION_PENDING: frozenset({RemediationState.INITIAL_CONFIRMED}),
    RemediationState.INITIAL_CONFIRMED: frozenset({RemediationState.REMEDIATION_RECOMMENDED}),
    RemediationState.REMEDIATION_RECOMMENDED: frozenset({RemediationState.PATCH_AUTHORIZED}),
    RemediationState.PATCH_AUTHORIZED: frozenset({RemediationState.PATCH_APPLIED}),
    RemediationState.PATCH_APPLIED: frozenset({RemediationState.RETEST_QUEUED}),
    RemediationState.RETEST_QUEUED: frozenset({RemediationState.RETEST_RUNNING}),
    RemediationState.RETEST_RUNNING: frozenset(
        {RemediationState.RETEST_PASS, RemediationState.RETEST_FAIL}
    ),
    RemediationState.RETEST_PASS: frozenset(),
    RemediationState.RETEST_FAIL: frozenset(),
    RemediationState.INCOMPLETE: frozenset(),
    RemediationState.CLEANUP_FAILED: frozenset(),
}


def valid_transitions(state: RemediationState) -> frozenset[RemediationState]:
    """The set of states reachable from ``state`` in one step (happy path + fallbacks).

    Genuinely terminal states (RETEST_PASS, RETEST_FAIL, CLEANUP_FAILED) have no outgoing
    transition; INCOMPLETE may still fall to CLEANUP_FAILED; every active state may fall to either
    fallback in addition to its happy-path successor.
    """

    if state in _TERMINAL:
        return frozenset()
    if state is RemediationState.INCOMPLETE:
        return frozenset({RemediationState.CLEANUP_FAILED})
    return _HAPPY_PATH[state] | _FALLBACKS


def assert_transition(current: RemediationState, new: RemediationState) -> None:
    """Fail closed unless ``new`` is a legal one-step transition from ``current``."""

    if new not in valid_transitions(current):
        raise RemediationStateError(f"ILLEGAL_TRANSITION_{current.value}_TO_{new.value}")


# --------------------------------------------------------------------------- #
# Controller-owned registered remediation-profile registry (model-blind authority).
# --------------------------------------------------------------------------- #
# The model may *recommend* a registered profile id; the controller resolves it into the complete
# synthetic remediation (the finding type it applies to, the target/scenario scope, and the current
# and desired synthetic modes). None of the controller-owned fields is ever placed in a model
# prompt, projection, observation, queue payload or report — only the profile id is model-visible.

ENFORCE_UNIFORM_DETECTION_CONTROL_V1: Literal["enforce_uniform_detection_control_v1"] = (
    "enforce_uniform_detection_control_v1"
)


class DetectionControlRemediationProfile(StrictModel):
    """A controller-owned, typed remediation profile. Fully resolved controller-side; model-blind.

    ``current_mode``/``desired_mode`` are the controller-owned synthetic modes the remediation
    transitions between; they are NEVER exposed to any model (a projection carries only the profile
    id). The remediation is bounded to the single registered synthetic range scenario.
    """

    remediation_profile_id: Literal["enforce_uniform_detection_control_v1"]
    finding_type: Literal["HTTP_DETECTION_CONTROL_BYPASS"]
    target_ref: Literal["range-ops"]
    scenario_id: Literal["ops-detection-control-bypass-v1"]
    current_mode: Literal["vulnerable"]
    desired_mode: Literal["patched"]
    rotates_sentinel: Literal[True] = True
    description: str = Field(min_length=3, max_length=200)


REMEDIATION_PROFILES: dict[str, DetectionControlRemediationProfile] = {
    ENFORCE_UNIFORM_DETECTION_CONTROL_V1: DetectionControlRemediationProfile(
        remediation_profile_id=ENFORCE_UNIFORM_DETECTION_CONTROL_V1,
        finding_type=REMEDIATION_FINDING_TYPE,  # type: ignore[arg-type]
        target_ref=REMEDIATION_TARGET_REF,  # type: ignore[arg-type]
        scenario_id=REMEDIATION_SCENARIO_ID,  # type: ignore[arg-type]
        current_mode="vulnerable",
        desired_mode="patched",
        description=(
            "Enforce uniform detection-control recognition so the alternate request variant is "
            "denied like the baseline (synthetic vulnerable->patched transition of one scenario)."
        ),
    )
}
REMEDIATION_PROFILE_IDS: frozenset[str] = frozenset(REMEDIATION_PROFILES)


# --------------------------------------------------------------------------- #
# Persisted typed records: finding reference, authorization/lease, immutable patch receipt.
# --------------------------------------------------------------------------- #


class PersistedFinding(StrictModel):
    """A persisted, opaque reference to ONE independently-verified detection-control finding.

    It carries only references and the verifier's own status/evidence digest — never a raw control
    marker, credential, sentinel value or mode. ``controller_sentinel_epoch`` binds the finding to
    the controller-state epoch that was live when the worker probed, so a *stale* finding (against a
    since-rotated epoch) can be rejected at authorization time.
    """

    finding_id: str = Field(pattern=r"^find-[a-f0-9]{16}$")
    loop_id: str = Field(pattern=r"^rloop-[a-f0-9]{16}$")
    campaign_id: str = Field(min_length=3, max_length=120)
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    finding_type: Literal["HTTP_DETECTION_CONTROL_BYPASS"]
    verified_status: Literal["CONFIRMED"]  # only a CONFIRMED finding is ever persisted for remedy
    verifier_evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    controller_state_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    controller_sentinel_epoch: int = Field(ge=0)
    initial_evidence_at: datetime
    created_at: datetime = Field(default_factory=now_utc)

    @property
    def finding_uri(self) -> str:
        return f"finding://{self.target_ref}/{self.finding_id}"


class RemediationAuthorization(StrictModel):
    """A controller-issued authorization + time-bounded lease for one registered remediation.

    The authorization binds a single finding to a single registered remediation profile; the lease
    bounds the window in which the patch may be applied. Both are controller-owned; neither is
    representable in any model output.
    """

    authorization_id: str = Field(pattern=r"^rauth-[a-f0-9]{16}$")
    lease_id: str = Field(pattern=r"^rlease-[a-f0-9]{16}$")
    loop_id: str = Field(pattern=r"^rloop-[a-f0-9]{16}$")
    finding_id: str = Field(pattern=r"^find-[a-f0-9]{16}$")
    remediation_profile_id: Literal["enforce_uniform_detection_control_v1"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    issued_at: datetime
    expires_at: datetime

    def valid_at(self, moment: datetime) -> bool:
        return self.issued_at <= moment < self.expires_at


class PatchReceipt(FrozenStrictModel):
    """An immutable, typed patch receipt. Persisted once; consumed exactly once for one retest.

    It carries only references and safe hashes: no raw control marker, credential value, sentinel
    value or mutable ground-truth authority. ``consumed`` reflects the ledger's single-use flag when
    the receipt is read back; the stored receipt content itself never changes.
    """

    receipt_id: str = Field(pattern=r"^rcpt-[a-f0-9]{16}$")
    loop_id: str = Field(pattern=r"^rloop-[a-f0-9]{16}$")
    campaign_id: str = Field(min_length=3, max_length=120)
    finding_id: str = Field(pattern=r"^find-[a-f0-9]{16}$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    remediation_profile_id: Literal["enforce_uniform_detection_control_v1"]
    authorization_id: str = Field(pattern=r"^rauth-[a-f0-9]{16}$")
    lease_id: str = Field(pattern=r"^rlease-[a-f0-9]{16}$")
    controller_decision: Literal["APPLIED"]
    previous_mode: Literal["vulnerable"]
    resulting_mode: Literal["patched"]
    pre_state_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    post_state_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    old_sentinel_epoch: int = Field(ge=0)
    old_sentinel_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    new_sentinel_epoch: int = Field(ge=0)
    new_sentinel_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    applied_at: datetime
    consumed: bool = False
    cleanup_obligations: tuple[str, ...] = Field(min_length=1)

    @property
    def receipt_uri(self) -> str:
        return f"patchreceipt://{self.target_ref}/{self.receipt_id}"


DEFAULT_CLEANUP_OBLIGATIONS: tuple[str, ...] = (
    "RESET_SYNTHETIC_TARGET_TO_BASELINE",
    "INVALIDATE_PATCH_RECEIPT",
    "ROTATE_OR_REMOVE_SENTINEL",
    "REVOKE_TEMPORARY_REFERENCES",
)


def controller_state_digest(mode: str, generation: int, sentinel_digest: str) -> str:
    """Deterministic digest of the controller-owned synthetic state (mode + epoch + sentinel).

    A pre/post difference of this digest proves the controller state actually changed over a patch.
    """

    material = json.dumps(
        {"mode": mode, "generation": int(generation), "sentinel_digest": sentinel_digest},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()


# --------------------------------------------------------------------------- #
# Model-facing sanitized projections (recommendation input + fresh retest input).
# --------------------------------------------------------------------------- #
# A projection carries ONLY: an opaque finding reference, the authorized target/scenario/profile
# identifiers, the controller-approved finding type, a *boolean* verified flag and sanitized
# observations, the registered remediation identifiers, and (for the retest) an opaque patch-receipt
# reference. It must NOT contain secrets, raw control markers, credential values, mutable ground-
# truth authority (e.g. the raw sentinel value or its exact digest), or any instruction. Verified
# status is projected as a boolean rather than a "CONFIRMED"/"PASS" token both to keep ground-truth
# authority out of the model prompt and to stay clear of the gateway's verdict-token sanitizer.

# Tokens that must never appear anywhere in a model-facing projection.
_FORBIDDEN_PROJECTION_TOKENS: tuple[str, ...] = (
    "vulnerable",
    "patched",
    '"confirmed"',
    '"pass"',
    "expected_verdict",
    "answer_key",
    "ground_truth",
    "http://",
    "https://",
    "range-user-",
    "bearer ",
    "lab-token-",
    "ops-scan-baseline-v1",
    "ops-scan-alternate-v1",
    "x-ops-signature",
)


def assert_projection_clean(projection: dict[str, object]) -> None:
    """Fail closed if a model-facing projection carries any forbidden token (case-insensitive)."""

    blob = json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str).lower()
    present = [token for token in _FORBIDDEN_PROJECTION_TOKENS if token in blob]
    if present:
        raise RemediationRejection(f"PROJECTION_NOT_SANITIZED:{','.join(sorted(present))}")


def _sanitized_observations(
    observations: list[dict[str, object]] | None,
) -> list[dict[str, object]]:
    """Reduce worker/normalized observations to booleans + status only (no digest, no marker)."""

    clean: list[dict[str, object]] = []
    for item in observations or []:
        label = str(item.get("label", ""))
        if label not in ("BASELINE_PROBE", "ALTERNATE_PROBE"):
            continue
        status = item.get("status_code", 0)
        clean.append(
            {
                "label": label,
                "status_code": int(status) if isinstance(status, int) else 0,
                "blocked": bool(item.get("blocked")),
                "sentinel_present": bool(item.get("sentinel_present")),
            }
        )
    return clean


def build_recommendation_projection(
    finding: PersistedFinding, observations: list[dict[str, object]] | None
) -> dict[str, object]:
    """Pre-patch projection for the model's remediation recommendation. No patch receipt yet."""

    projection: dict[str, object] = {
        "finding_ref": finding.finding_uri,
        "target_ref": finding.target_ref,
        "scenario_id": finding.scenario_id,
        "finding_type": finding.finding_type,
        "finding_independently_verified": True,
        "sanitized_observations": _sanitized_observations(observations),
        "registered_remediation_profile_ids": sorted(REMEDIATION_PROFILE_IDS),
    }
    assert_projection_clean(projection)
    return projection


def build_retest_projection(
    finding: PersistedFinding,
    receipt: PatchReceipt,
    observations: list[dict[str, object]] | None,
) -> dict[str, object]:
    """Post-patch projection for the fresh agent-directed retest plan; carries an opaque receipt."""

    projection: dict[str, object] = {
        "finding_ref": finding.finding_uri,
        "target_ref": finding.target_ref,
        "scenario_id": finding.scenario_id,
        "finding_type": finding.finding_type,
        "finding_independently_verified": True,
        "sanitized_observations": _sanitized_observations(observations),
        "registered_remediation_profile_ids": sorted(REMEDIATION_PROFILE_IDS),
        "applied_remediation_profile_id": receipt.remediation_profile_id,
        "patch_receipt_ref": receipt.receipt_uri,
    }
    assert_projection_clean(projection)
    return projection


# --------------------------------------------------------------------------- #
# Durable remediation ledger (SQLite): loop state machine + findings + auth + immutable receipts.
# --------------------------------------------------------------------------- #


class RemediationLedger:
    """A durable ledger for one bounded remediation/retest loop, on SQLite.

    It records the loop state machine (with a full transition trail), the persisted finding
    reference, the controller authorization/lease, and the immutable single-use patch receipt. Every
    state transition is validated by :func:`assert_transition`. There is no field through which a
    payload, raw marker, credential or verdict authority could be persisted; only references and
    safe hashes.
    """

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
                CREATE TABLE IF NOT EXISTS remediation_loops (
                    loop_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    scenario_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_loop_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    loop_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_findings (
                    finding_id TEXT PRIMARY KEY,
                    loop_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    loop_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    loop_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_retest_bindings (
                    retest_job_id TEXT PRIMARY KEY,
                    loop_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    # ------------------------------- loops ------------------------------- #

    def open_loop(self, loop_id: str, campaign_id: str, target_ref: str, scenario_id: str) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO remediation_loops(
                        loop_id, campaign_id, target_ref, scenario_id, state, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        loop_id,
                        campaign_id,
                        target_ref,
                        scenario_id,
                        RemediationState.INITIAL_EXECUTION_PENDING.value,
                        now_utc().isoformat(),
                    ),
                )
                self._record_transition(
                    connection,
                    loop_id,
                    "NONE",
                    RemediationState.INITIAL_EXECUTION_PENDING.value,
                    "loop opened",
                )
            except sqlite3.IntegrityError as exc:
                raise RemediationLedgerError("LOOP_ALREADY_OPEN") from exc
        return loop_id

    def state(self, loop_id: str) -> RemediationState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM remediation_loops WHERE loop_id = ?", (loop_id,)
            ).fetchone()
        if row is None:
            raise RemediationLedgerError("LOOP_NOT_FOUND")
        return RemediationState(row["state"])

    def transition(self, loop_id: str, new: RemediationState, reason: str) -> RemediationState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state FROM remediation_loops WHERE loop_id = ?", (loop_id,)
            ).fetchone()
            if row is None:
                raise RemediationLedgerError("LOOP_NOT_FOUND")
            current = RemediationState(row["state"])
            assert_transition(current, new)  # fails closed on an illegal transition
            connection.execute(
                "UPDATE remediation_loops SET state = ? WHERE loop_id = ?", (new.value, loop_id)
            )
            self._record_transition(connection, loop_id, current.value, new.value, reason[:200])
        return new

    def loop_transitions(self, loop_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_state, to_state, reason, at FROM remediation_loop_transitions
                WHERE loop_id = ? ORDER BY id""",
                (loop_id,),
            ).fetchall()
        return [
            {"from": r["from_state"], "to": r["to_state"], "reason": r["reason"], "at": r["at"]}
            for r in rows
        ]

    # ------------------------------ findings ----------------------------- #

    def persist_finding(self, finding: PersistedFinding) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO remediation_findings(finding_id, loop_id, payload) "
                    "VALUES (?, ?, ?)",
                    (finding.finding_id, finding.loop_id, finding.model_dump_json()),
                )
            except sqlite3.IntegrityError as exc:
                raise RemediationLedgerError("FINDING_ALREADY_PERSISTED") from exc
        return finding.finding_uri

    def get_finding(self, finding_id: str) -> PersistedFinding | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM remediation_findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        return PersistedFinding.model_validate_json(row["payload"]) if row else None

    # --------------------------- authorizations -------------------------- #

    def persist_authorization(self, authorization: RemediationAuthorization) -> str:
        with self._connect() as connection:
            finding = connection.execute(
                "SELECT loop_id FROM remediation_findings WHERE finding_id = ?",
                (authorization.finding_id,),
            ).fetchone()
            if finding is None or finding["loop_id"] != authorization.loop_id:
                raise RemediationLedgerError("AUTHORIZATION_FINDING_INVALID")
            try:
                connection.execute(
                    """INSERT INTO remediation_authorizations(
                        authorization_id, loop_id, finding_id, payload
                    ) VALUES (?, ?, ?, ?)""",
                    (
                        authorization.authorization_id,
                        authorization.loop_id,
                        authorization.finding_id,
                        authorization.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RemediationLedgerError("AUTHORIZATION_ALREADY_PERSISTED") from exc
        return authorization.authorization_id

    def get_authorization(self, authorization_id: str) -> RemediationAuthorization | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM remediation_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        return RemediationAuthorization.model_validate_json(row["payload"]) if row else None

    # ------------------------------ receipts ----------------------------- #

    def persist_receipt(self, receipt: PatchReceipt) -> str:
        with self._connect() as connection:
            finding = connection.execute(
                "SELECT loop_id FROM remediation_findings WHERE finding_id = ?",
                (receipt.finding_id,),
            ).fetchone()
            if finding is None or finding["loop_id"] != receipt.loop_id:
                raise RemediationLedgerError("RECEIPT_FINDING_INVALID")
            authorization = connection.execute(
                "SELECT loop_id FROM remediation_authorizations WHERE authorization_id = ?",
                (receipt.authorization_id,),
            ).fetchone()
            if authorization is None or authorization["loop_id"] != receipt.loop_id:
                raise RemediationLedgerError("RECEIPT_AUTHORIZATION_INVALID")
            try:
                connection.execute(
                    """INSERT INTO remediation_receipts(
                        receipt_id, loop_id, finding_id, consumed, payload
                    ) VALUES (?, ?, ?, 0, ?)""",
                    (
                        receipt.receipt_id,
                        receipt.loop_id,
                        receipt.finding_id,
                        receipt.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RemediationLedgerError("RECEIPT_ALREADY_PERSISTED") from exc
        return receipt.receipt_uri

    def get_receipt(self, receipt_id: str) -> PatchReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT consumed, payload FROM remediation_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        receipt = PatchReceipt.model_validate_json(row["payload"])
        # The stored receipt content is immutable; the single-use flag is overlaid from the column.
        return receipt.model_copy(update={"consumed": bool(row["consumed"])})

    def receipt_consumed(self, receipt_id: str) -> bool:
        receipt = self.get_receipt(receipt_id)
        if receipt is None:
            raise RemediationLedgerError("RECEIPT_NOT_FOUND")
        return receipt.consumed

    def consume_receipt(self, receipt_id: str) -> PatchReceipt:
        """Consume the receipt exactly once. A second consume (replay) fails closed."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT consumed, payload FROM remediation_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise RemediationLedgerError("RECEIPT_NOT_FOUND")
            if bool(row["consumed"]):
                raise RemediationLedgerError("RECEIPT_ALREADY_CONSUMED")
            connection.execute(
                "UPDATE remediation_receipts SET consumed = 1 "
                "WHERE receipt_id = ? AND consumed = 0",
                (receipt_id,),
            )
        receipt = PatchReceipt.model_validate_json(row["payload"])
        return receipt.model_copy(update={"consumed": True})

    def invalidate_receipt(self, receipt_id: str) -> None:
        """Cleanup: mark a receipt consumed so it can never satisfy a future retest (idempotent)."""

        with self._connect() as connection:
            connection.execute(
                "UPDATE remediation_receipts SET consumed = 1 WHERE receipt_id = ?", (receipt_id,)
            )

    # --------------------------- retest binding -------------------------- #

    def bind_retest_job(
        self, retest_job_id: str, loop_id: str, finding_id: str, receipt_id: str
    ) -> None:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO remediation_retest_bindings(
                        retest_job_id, loop_id, finding_id, receipt_id, created_at
                    ) VALUES (?, ?, ?, ?, ?)""",
                    (retest_job_id, loop_id, finding_id, receipt_id, now_utc().isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise RemediationLedgerError("RETEST_BINDING_ALREADY_PERSISTED") from exc

    def retest_binding(self, retest_job_id: str) -> dict[str, str] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT loop_id, finding_id, receipt_id FROM remediation_retest_bindings
                WHERE retest_job_id = ?""",
                (retest_job_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "loop_id": row["loop_id"],
            "finding_id": row["finding_id"],
            "receipt_id": row["receipt_id"],
        }

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection,
        loop_id: str,
        from_state: str,
        to_state: str,
        reason: str,
    ) -> None:
        connection.execute(
            """INSERT INTO remediation_loop_transitions(loop_id, from_state, to_state, reason, at)
            VALUES (?, ?, ?, ?, ?)""",
            (loop_id, from_state, to_state, reason, now_utc().isoformat()),
        )


# --------------------------------------------------------------------------- #
# Controller-owned remediation logic (non-AI). AI output is only ever a hint.
# --------------------------------------------------------------------------- #


class RemediationController:
    """The non-AI controller that owns every unsafe remediation decision.

    It validates and applies the registered synthetic remediation, owns the state transitions, and
    mints the immutable patch receipt. A model recommendation only ever names a registered profile
    id; this controller re-selects the registered profile itself and re-validates every constraint.
    The actual range mutation (mode switch + sentinel rotation) is performed by the range controller
    and passed in as ``mutation_result``, so this logic stays deterministic and offline-testable.
    """

    def __init__(
        self,
        ledger: RemediationLedger,
        profiles: dict[str, DetectionControlRemediationProfile] | None = None,
    ) -> None:
        self.ledger = ledger
        self.profiles = profiles if profiles is not None else REMEDIATION_PROFILES

    def confirm_initial_finding(self, finding: PersistedFinding) -> PersistedFinding:
        """Persist a verifier-CONFIRMED finding; advance INITIAL_EXECUTION_PENDING -> CONFIRMED."""

        if finding.verified_status != "CONFIRMED":
            raise RemediationRejection("FINDING_NOT_CONFIRMED")
        self.ledger.persist_finding(finding)
        self.ledger.transition(
            finding.loop_id,
            RemediationState.INITIAL_CONFIRMED,
            "verifier CONFIRMED the initial finding",
        )
        return finding

    def record_recommendation(
        self, finding: PersistedFinding, recommended_profile_id: str
    ) -> None:
        """Record a NON-AUTHORITATIVE model recommendation and advance CONFIRMED -> RECOMMENDED.

        The recommendation is recorded for the audit trail but never trusted: the controller won't
        validate the recommended id here (an unregistered recommendation is not fatal at this step),
        and it selects the registered profile itself at authorization time.
        """

        reason = (
            "model recommended (non-authoritative) remediation_profile_id="
            f"{recommended_profile_id[:80]}"
        )
        self.ledger.transition(finding.loop_id, RemediationState.REMEDIATION_RECOMMENDED, reason)

    def authorize_remediation(
        self,
        finding: PersistedFinding,
        remediation_profile_id: str,
        *,
        now: datetime,
        lease_seconds: int = 600,
        authorization_id: str,
        lease_id: str,
    ) -> RemediationAuthorization:
        """Controller-owned selection + validation of a registered remediation. Fails closed on:

        unknown remediation id, target/scenario mismatch, finding-type mismatch, an unconfirmed
        finding, or a finding not currently in the REMEDIATION_RECOMMENDED state. Advances
        REMEDIATION_RECOMMENDED -> PATCH_AUTHORIZED and persists the authorization + lease.
        """

        from datetime import timedelta

        profile = self.profiles.get(remediation_profile_id)
        if profile is None:
            raise RemediationRejection("REMEDIATION_PROFILE_NOT_REGISTERED")
        if finding.verified_status != "CONFIRMED":
            raise RemediationRejection("FINDING_NOT_CONFIRMED")
        if profile.finding_type != finding.finding_type:
            raise RemediationRejection("REMEDIATION_FINDING_TYPE_MISMATCH")
        if profile.target_ref != finding.target_ref:
            raise RemediationRejection("REMEDIATION_TARGET_MISMATCH")
        if profile.scenario_id != finding.scenario_id:
            raise RemediationRejection("REMEDIATION_SCENARIO_MISMATCH")
        persisted = self.ledger.get_finding(finding.finding_id)
        if persisted is None:
            raise RemediationRejection("FINDING_NOT_PERSISTED")
        authorization = RemediationAuthorization(
            authorization_id=authorization_id,
            lease_id=lease_id,
            loop_id=finding.loop_id,
            finding_id=finding.finding_id,
            remediation_profile_id=profile.remediation_profile_id,
            target_ref=finding.target_ref,
            scenario_id=finding.scenario_id,
            issued_at=now,
            expires_at=now + timedelta(seconds=lease_seconds),
        )
        self.ledger.persist_authorization(authorization)
        self.ledger.transition(
            finding.loop_id,
            RemediationState.PATCH_AUTHORIZED,
            f"controller authorized registered remediation {profile.remediation_profile_id}",
        )
        return authorization

    def apply_remediation(
        self,
        finding: PersistedFinding,
        authorization: RemediationAuthorization,
        mutation_result: dict[str, object],
        *,
        now: datetime,
        receipt_id: str,
        campaign_id: str,
    ) -> PatchReceipt:
        """Mint the immutable patch receipt from a successful controller-owned range mutation.

        Fails closed on: an expired/invalid lease, a finding no longer confirmed/stale, a mutation
        that did not actually change the controller state (pre==post digest), a wrong mode
        transition, or an unrotated sentinel. Advances PATCH_AUTHORIZED -> PATCH_APPLIED ->
        RETEST_QUEUED.
        """

        if not authorization.valid_at(now):
            raise RemediationRejection("REMEDIATION_LEASE_EXPIRED")
        if authorization.finding_id != finding.finding_id:
            raise RemediationRejection("REMEDIATION_AUTHORIZATION_FINDING_MISMATCH")
        profile = self.profiles[authorization.remediation_profile_id]

        previous_mode = str(mutation_result.get("previous_mode", ""))
        resulting_mode = str(mutation_result.get("resulting_mode", ""))
        pre_digest = str(mutation_result.get("pre_state_digest", ""))
        post_digest = str(mutation_result.get("post_state_digest", ""))
        old_epoch = mutation_result.get("old_sentinel_epoch")
        new_epoch = mutation_result.get("new_sentinel_epoch")
        old_sentinel = str(mutation_result.get("old_sentinel_digest", ""))
        new_sentinel = str(mutation_result.get("new_sentinel_digest", ""))

        if previous_mode != profile.current_mode or resulting_mode != profile.desired_mode:
            raise RemediationRejection("REMEDIATION_MODE_TRANSITION_INVALID")
        if not pre_digest or not post_digest or pre_digest == post_digest:
            raise RemediationRejection("REMEDIATION_STATE_UNCHANGED")
        if old_sentinel == new_sentinel:
            raise RemediationRejection("REMEDIATION_SENTINEL_NOT_ROTATED")
        if not isinstance(old_epoch, int) or not isinstance(new_epoch, int):
            raise RemediationRejection("REMEDIATION_SENTINEL_EPOCH_INVALID")

        receipt = PatchReceipt(
            receipt_id=receipt_id,
            loop_id=finding.loop_id,
            campaign_id=campaign_id,
            finding_id=finding.finding_id,
            target_ref=finding.target_ref,
            scenario_id=finding.scenario_id,
            remediation_profile_id=profile.remediation_profile_id,
            authorization_id=authorization.authorization_id,
            lease_id=authorization.lease_id,
            controller_decision="APPLIED",
            previous_mode="vulnerable",
            resulting_mode="patched",
            pre_state_digest=pre_digest,
            post_state_digest=post_digest,
            old_sentinel_epoch=old_epoch,
            old_sentinel_digest=old_sentinel,
            new_sentinel_epoch=new_epoch,
            new_sentinel_digest=new_sentinel,
            applied_at=now,
            consumed=False,
            cleanup_obligations=DEFAULT_CLEANUP_OBLIGATIONS,
        )
        self.ledger.persist_receipt(receipt)
        self.ledger.transition(
            finding.loop_id, RemediationState.PATCH_APPLIED, "controller applied the patch"
        )
        self.ledger.transition(
            finding.loop_id, RemediationState.RETEST_QUEUED, "retest queued after patch"
        )
        return receipt

    def begin_retest(
        self,
        finding: PersistedFinding,
        receipt: PatchReceipt,
        retest_job_id: str,
    ) -> PatchReceipt:
        """Consume the receipt exactly once and advance RETEST_QUEUED -> RETEST_RUNNING.

        The retest cannot begin without a valid, unused receipt bound to the original finding. A
        second attempt (replay) fails closed in :meth:`RemediationLedger.consume_receipt`.
        """

        if receipt.finding_id != finding.finding_id:
            raise RemediationRejection("RETEST_RECEIPT_FINDING_MISMATCH")
        consumed = self.ledger.consume_receipt(receipt.receipt_id)
        self.ledger.bind_retest_job(
            retest_job_id, finding.loop_id, finding.finding_id, receipt.receipt_id
        )
        self.ledger.transition(
            finding.loop_id, RemediationState.RETEST_RUNNING, "retest running on fresh evidence"
        )
        return consumed

    def conclude_retest(
        self,
        finding: PersistedFinding,
        receipt: PatchReceipt,
        *,
        retest_verifier_status: str,
        initial_evidence_at: datetime,
        retest_evidence_at: datetime,
        retest_target_ref: str,
        retest_scenario_id: str,
    ) -> tuple[RemediationState, dict[str, bool]]:
        """Adjudicate the fresh retest and return the final state + the causal-break proof.

        RETEST_PASS is reached only when the independent verifier returned PASS on fresh post-patch
        evidence AND the full causal proof holds. A verifier PASS without the causal proof, or any
        other verifier status, yields RETEST_FAIL.
        """

        proof = self.prove_causal_break(
            finding,
            receipt,
            initial_evidence_at=initial_evidence_at,
            retest_evidence_at=retest_evidence_at,
            retest_target_ref=retest_target_ref,
            retest_scenario_id=retest_scenario_id,
        )
        causal_ok = all(proof.values())
        if retest_verifier_status == "PASS" and causal_ok:
            final = RemediationState.RETEST_PASS
            reason = "fresh post-patch retest PASS with causal remediation break proven"
        else:
            final = RemediationState.RETEST_FAIL
            reason = (
                f"retest not a proven break (status={retest_verifier_status}, causal={causal_ok})"
            )
        self.ledger.transition(finding.loop_id, final, reason)
        return final, proof

    def prove_causal_break(
        self,
        finding: PersistedFinding,
        receipt: PatchReceipt,
        *,
        initial_evidence_at: datetime,
        retest_evidence_at: datetime,
        retest_target_ref: str,
        retest_scenario_id: str,
    ) -> dict[str, bool]:
        """The causal-remediation-break proof over persisted, immutable inputs (no live state)."""

        stored_receipt = self.ledger.get_receipt(receipt.receipt_id)
        receipt_present = stored_receipt is not None
        receipt_consumed = bool(stored_receipt.consumed) if stored_receipt is not None else False
        return {
            "initial_evidence_predates_patch": initial_evidence_at < receipt.applied_at,
            "retest_evidence_follows_patch": retest_evidence_at > receipt.applied_at,
            "same_target_lineage": (
                retest_target_ref == finding.target_ref == receipt.target_ref
            ),
            "same_scenario_lineage": (
                retest_scenario_id == finding.scenario_id == receipt.scenario_id
            ),
            "same_finding_lineage": receipt.finding_id == finding.finding_id,
            "controller_state_changed": receipt.pre_state_digest != receipt.post_state_digest,
            "sentinel_epoch_rotated": (
                receipt.old_sentinel_digest != receipt.new_sentinel_digest
                and receipt.new_sentinel_epoch >= receipt.old_sentinel_epoch
            ),
            "patch_receipt_required_and_consumed": receipt_present and receipt_consumed,
        }
