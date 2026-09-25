"""Phase 2.5 — Authenticated Staging Progression (controller-governed, opaque session handling).

The controlled path from synthetic authenticated testing toward *explicitly authorized* staging.
This sprint does NOT connect to any real staging target: the ``AUTHORIZED_STAGING`` tier is
``DEPLOYMENT_DISABLED`` (a typed, fail-closed state), and the bounded authenticated scenario runs
entirely in-process against a synthetic staging app so the *mechanics* — opaque credential/session
references, origin/redirect binding, positive/negative controls, revocation, reset — are exercised
offline without claiming staging readiness.

Authority (unchanged model):

* The **controller** owns environment classification, the authorization reference, the operator
  lease, the approved assessment profile, the credential/session references, the session policy, the
  capability allowlist, the budgets and the cleanup/reset plan. The AI is authoritative for none of
  it and **cannot change the environment tier** — a plan that tries fails closed.
* Credentials and session material stay **opaque**: the model only ever sees metadata that an
  authorized ``credentialref://…`` / ``sessionref://…`` exists, never a value. The concrete secret
  lives only in the controller/broker secret path and reaches the deterministic session worker
  directly; it never enters a prompt, projection, report or evidence record.
* Fail-closed everywhere: an unclassified environment resolves to ``PRODUCTION_PROHIBITED``; a
  reference used on another target/origin, an expired/revoked session, a redirect that escapes the
  bound origin, a missing gate, or "onboarding presented as execution readiness" are all rejected.

Nothing here opens a real socket or reaches the public internet; the synthetic staging app is an
in-process callable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field

from aegis.multi_agent.contracts import StrictModel, now_utc
from aegis.target_inventory import TargetValidationError, normalize_origin


class FrozenStrictModel(StrictModel):
    """A strict, immutable model for records that must never mutate after creation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class StagingRejection(ValueError):
    """A controller-owned progression rejection. Always fails closed (no progression)."""


class StagingReferenceError(RuntimeError):
    """An opaque-reference failure (misuse, expiry, revocation, cross-target). Fails closed."""


class StagingStateError(RuntimeError):
    """An illegal staging state transition. Fails closed."""


# --------------------------------------------------------------------------- #
# Environment tiers. The model can never set or raise the tier; the controller classifies.
# --------------------------------------------------------------------------- #


class EnvironmentTier(StrEnum):
    SYNTHETIC_RANGE = "SYNTHETIC_RANGE"
    ISOLATED_STAGING = "ISOLATED_STAGING"
    AUTHORIZED_STAGING = "AUTHORIZED_STAGING"
    # A single fail-closed terminal state: anything not explicitly classified lands here and is
    # never executable.
    PRODUCTION_PROHIBITED = "PRODUCTION_PROHIBITED"


# Progression order among the executable tiers. PRODUCTION_PROHIBITED is deliberately absent — it is
# never a step on the ladder, only a fail-closed sink.
_TIER_RANK: dict[EnvironmentTier, int] = {
    EnvironmentTier.SYNTHETIC_RANGE: 0,
    EnvironmentTier.ISOLATED_STAGING: 1,
    EnvironmentTier.AUTHORIZED_STAGING: 2,
}

# Tiers for which a real deployment connection is DISABLED this sprint. AUTHORIZED_STAGING mechanics
# are proven offline only; a real connection is fail-closed until a future authorized deployment.
_DEPLOYMENT_DISABLED_TIERS: frozenset[EnvironmentTier] = frozenset(
    {EnvironmentTier.AUTHORIZED_STAGING}
)


def classify_environment(raw: str | None) -> EnvironmentTier:
    """Controller-owned classification. Anything unknown/None fails closed to PRODUCTION_PROHIBITED.

    ``PRODUCTION`` and every unrecognized label collapse to the single fail-closed sink, so a
    misconfiguration can never accidentally admit a production or unclassified environment.
    """

    mapping = {
        "SYNTHETIC_RANGE": EnvironmentTier.SYNTHETIC_RANGE,
        "SYNTHETIC": EnvironmentTier.SYNTHETIC_RANGE,
        "ISOLATED_STAGING": EnvironmentTier.ISOLATED_STAGING,
        "AUTHORIZED_STAGING": EnvironmentTier.AUTHORIZED_STAGING,
    }
    if raw is None:
        return EnvironmentTier.PRODUCTION_PROHIBITED
    return mapping.get(raw.strip().upper(), EnvironmentTier.PRODUCTION_PROHIBITED)


def tier_is_executable(tier: EnvironmentTier) -> bool:
    return tier in _TIER_RANK


def deployment_disabled(tier: EnvironmentTier) -> bool:
    return tier in _DEPLOYMENT_DISABLED_TIERS


# --------------------------------------------------------------------------- #
# Opaque secret store + typed opaque references (values never leave the secret path).
# --------------------------------------------------------------------------- #


class OpaqueSecretStore:
    """An isolated, in-process secret store keyed by opaque reference id.

    It maps a ``credentialref://`` / ``sessionref://`` id to its concrete value. The value is placed
    here only by the controller/broker and read only by the deterministic session worker; it is
    never serialized into a model prompt, projection, queue payload, report or evidence record. A
    revoked/zeroized entry can never be resolved again.
    """

    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._revoked: set[str] = set()

    def put(self, ref_id: str, value: str) -> None:
        if ref_id in self._values or ref_id in self._revoked:
            raise StagingReferenceError("SECRET_REF_ALREADY_USED")
        self._values[ref_id] = value

    def resolve(self, ref_id: str) -> str:
        if ref_id in self._revoked or ref_id not in self._values:
            raise StagingReferenceError("SECRET_REF_UNRESOLVABLE")
        return self._values[ref_id]

    def revoke(self, ref_id: str) -> None:
        # Zeroize and tombstone. Idempotent; a resolve afterwards fails closed.
        self._values.pop(ref_id, None)
        self._revoked.add(ref_id)

    def is_resolvable(self, ref_id: str) -> bool:
        return ref_id in self._values and ref_id not in self._revoked


class CredentialReference(StrictModel):
    """A target-bound and scenario-bound opaque credential reference. Carries NO value.

    The reference is single-scope (one target + one scenario) and time-bounded. The concrete
    credential lives only in :class:`OpaqueSecretStore` under ``secret_ref_id``.
    """

    credential_ref_id: str = Field(pattern=r"^cred-[a-f0-9]{16}$")
    secret_ref_id: str = Field(pattern=r"^secret-[a-f0-9]{16}$")
    target_ref: str = Field(min_length=3, max_length=120)
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    environment_tier: EnvironmentTier
    issued_at: datetime
    expires_at: datetime
    single_scope_use: Literal[True] = True

    @property
    def credential_uri(self) -> str:
        return f"credentialref://{self.target_ref}/{self.credential_ref_id}"

    def valid_at(self, moment: datetime) -> bool:
        return self.issued_at <= moment < self.expires_at


class SessionReference(StrictModel):
    """An environment-bound opaque session reference. Carries NO cookie/header/token value.

    A session is bound to one environment tier + one canonical origin + the credential it was
    acquired from; it is time-bounded and single-scope, and can be revoked. The concrete session
    material lives only in :class:`OpaqueSecretStore` under ``secret_ref_id``.
    """

    session_ref_id: str = Field(pattern=r"^sess-[a-f0-9]{16}$")
    secret_ref_id: str = Field(pattern=r"^secret-[a-f0-9]{16}$")
    from_credential_ref_id: str = Field(pattern=r"^cred-[a-f0-9]{16}$")
    target_ref: str = Field(min_length=3, max_length=120)
    environment_tier: EnvironmentTier
    bound_origin: str = Field(min_length=3, max_length=200)
    issued_at: datetime
    expires_at: datetime
    single_scope_use: Literal[True] = True

    @property
    def session_uri(self) -> str:
        return f"sessionref://{self.environment_tier.value}/{self.session_ref_id}"

    def valid_at(self, moment: datetime) -> bool:
        return self.issued_at <= moment < self.expires_at


# --------------------------------------------------------------------------- #
# Controller-owned progression gates + typed rejection reasons.
# --------------------------------------------------------------------------- #


class ProgressionRejection(StrEnum):
    MISSING_TARGET_INVENTORY = "MISSING_TARGET_INVENTORY"
    UNCLASSIFIED_OR_PRODUCTION_ENVIRONMENT = "UNCLASSIFIED_OR_PRODUCTION_ENVIRONMENT"
    STAGING_DEPLOYMENT_DISABLED = "STAGING_DEPLOYMENT_DISABLED"
    MISSING_AUTHORIZATION_REFERENCE = "MISSING_AUTHORIZATION_REFERENCE"
    MISSING_OR_EXPIRED_OPERATOR_LEASE = "MISSING_OR_EXPIRED_OPERATOR_LEASE"
    PROFILE_NOT_APPROVED = "PROFILE_NOT_APPROVED"
    MISSING_CREDENTIAL_REFERENCE = "MISSING_CREDENTIAL_REFERENCE"
    MISSING_SESSION_POLICY = "MISSING_SESSION_POLICY"
    CAPABILITY_NOT_ALLOWLISTED = "CAPABILITY_NOT_ALLOWLISTED"
    BUDGET_NOT_DECLARED = "BUDGET_NOT_DECLARED"
    CLEANUP_PLAN_MISSING = "CLEANUP_PLAN_MISSING"
    MODEL_ATTEMPTED_TIER_CHANGE = "MODEL_ATTEMPTED_TIER_CHANGE"
    ONBOARDING_ONLY_NOT_EXECUTION_READY = "ONBOARDING_ONLY_NOT_EXECUTION_READY"
    ILLEGAL_TIER_SKIP = "ILLEGAL_TIER_SKIP"


class SessionPolicy(StrictModel):
    """Controller-owned session policy: origin binding, redirect policy, lifetime, single scope."""

    bound_origin: str = Field(min_length=3, max_length=200)
    follow_cross_origin_redirects: Literal[False] = False
    max_lifetime_seconds: int = Field(ge=1, le=3600)
    single_scope_use: Literal[True] = True
    isolate_cookies_headers_tokens: Literal[True] = True


class StagingProgressionRequest(StrictModel):
    """A controller-assembled progression request. Every gate is a controller-owned reference.

    ``requested_tier`` is what the controller intends to progress to; ``model_requested_tier`` (if
    present) is a NON-AUTHORITATIVE hint — if it disagrees with ``requested_tier`` the request is
    rejected (the model cannot change the tier). ``onboarding_only`` marks a target that has been
    onboarded but not cleared for execution: it can never be execution-ready.
    """

    campaign_id: str = Field(min_length=3, max_length=120)
    target_inventory_ref: str | None = Field(default=None, max_length=120)
    current_tier: EnvironmentTier
    requested_tier: EnvironmentTier
    model_requested_tier: EnvironmentTier | None = None
    authorization_reference: str | None = Field(default=None, max_length=120)
    operator_lease_ref: str | None = Field(default=None, max_length=120)
    lease_valid: bool = False
    approved_profile_id: str | None = Field(default=None, max_length=120)
    credential_reference_id: str | None = Field(default=None, max_length=120)
    session_policy: SessionPolicy | None = None
    capability_allowlist: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    requested_capability_id: str | None = Field(default=None, max_length=120)
    call_budget: int | None = Field(default=None, ge=0, le=100)
    tool_budget: int | None = Field(default=None, ge=0, le=1000)
    cleanup_plan: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    onboarding_only: bool = False


class ProgressionDecision(StrictModel):
    allowed: bool
    resulting_tier: EnvironmentTier
    rejection_reasons: tuple[ProgressionRejection, ...]


# Approved assessment profiles per tier (controller-owned).
APPROVED_STAGING_PROFILES: dict[EnvironmentTier, frozenset[str]] = {
    EnvironmentTier.SYNTHETIC_RANGE: frozenset({"synthetic_authenticated_probe_v1"}),
    EnvironmentTier.ISOLATED_STAGING: frozenset({"isolated_staging_authenticated_probe_v1"}),
    EnvironmentTier.AUTHORIZED_STAGING: frozenset({"authorized_staging_authenticated_probe_v1"}),
}


def evaluate_progression(request: StagingProgressionRequest) -> ProgressionDecision:
    """Controller-owned, fail-closed evaluation of a staging-progression request.

    Returns ``allowed=True`` only when every gate is satisfied. On any failure the resulting tier is
    the fail-closed sink and every failing gate is reported.
    """

    rejections: list[ProgressionRejection] = []

    # The model can never change the tier.
    if (
        request.model_requested_tier is not None
        and request.model_requested_tier is not request.requested_tier
    ):
        rejections.append(ProgressionRejection.MODEL_ATTEMPTED_TIER_CHANGE)

    # Onboarding is not execution readiness.
    if request.onboarding_only:
        rejections.append(ProgressionRejection.ONBOARDING_ONLY_NOT_EXECUTION_READY)

    # The requested tier must be executable (not the fail-closed sink) ...
    if not tier_is_executable(request.requested_tier):
        rejections.append(ProgressionRejection.UNCLASSIFIED_OR_PRODUCTION_ENVIRONMENT)
    else:
        # ... reachable in at most one step up from the current executable tier ...
        current_rank = _TIER_RANK.get(request.current_tier)
        target_rank = _TIER_RANK[request.requested_tier]
        if current_rank is None or target_rank - current_rank > 1 or target_rank < current_rank:
            rejections.append(ProgressionRejection.ILLEGAL_TIER_SKIP)
        # ... and not a deployment-disabled real connection.
        if deployment_disabled(request.requested_tier):
            rejections.append(ProgressionRejection.STAGING_DEPLOYMENT_DISABLED)

    if request.target_inventory_ref is None:
        rejections.append(ProgressionRejection.MISSING_TARGET_INVENTORY)
    if request.authorization_reference is None:
        rejections.append(ProgressionRejection.MISSING_AUTHORIZATION_REFERENCE)
    if request.operator_lease_ref is None or not request.lease_valid:
        rejections.append(ProgressionRejection.MISSING_OR_EXPIRED_OPERATOR_LEASE)

    approved = APPROVED_STAGING_PROFILES.get(request.requested_tier, frozenset())
    if request.approved_profile_id is None or request.approved_profile_id not in approved:
        rejections.append(ProgressionRejection.PROFILE_NOT_APPROVED)

    if request.credential_reference_id is None:
        rejections.append(ProgressionRejection.MISSING_CREDENTIAL_REFERENCE)
    if request.session_policy is None:
        rejections.append(ProgressionRejection.MISSING_SESSION_POLICY)

    if (
        request.requested_capability_id is None
        or request.requested_capability_id not in request.capability_allowlist
    ):
        rejections.append(ProgressionRejection.CAPABILITY_NOT_ALLOWLISTED)

    if request.call_budget is None or request.tool_budget is None:
        rejections.append(ProgressionRejection.BUDGET_NOT_DECLARED)
    if not request.cleanup_plan:
        rejections.append(ProgressionRejection.CLEANUP_PLAN_MISSING)

    allowed = not rejections
    resulting = request.requested_tier if allowed else EnvironmentTier.PRODUCTION_PROHIBITED
    return ProgressionDecision(
        allowed=allowed,
        resulting_tier=resulting,
        rejection_reasons=tuple(_dedupe(rejections)),
    )


def _dedupe(items: list[ProgressionRejection]) -> list[ProgressionRejection]:
    seen: dict[ProgressionRejection, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)


# --------------------------------------------------------------------------- #
# Synthetic staging app + deterministic session worker (offline; origin/redirect bound).
# --------------------------------------------------------------------------- #


class SyntheticStagingResponse(StrictModel):
    """A value-free response from the synthetic staging app (no token/cookie value ever)."""

    status_code: int
    authenticated: bool = False
    redirect_origin: str | None = None
    # Never a token value: only a boolean that a Set-Cookie/token WOULD be issued.
    session_material_issued: bool = False


class SyntheticStagingApp:
    """An in-process synthetic authenticated app for exercising the progression mechanics offline.

    It knows one valid credential value and one origin. It never returns a real token *value* to the
    caller; the deterministic worker mints an opaque session and stores the material in the secret
    store. A login from the wrong origin, or a request that would redirect off-origin, is modelled
    so origin/redirect binding can be proven.
    """

    def __init__(self, *, origin: str, valid_credential_value: str) -> None:
        self.origin = normalize_origin(origin)
        self._valid = valid_credential_value
        self._revoked_sessions: set[str] = set()
        self._locked_out = False

    def login(self, *, origin: str, credential_value: str) -> SyntheticStagingResponse:
        if normalize_origin(origin) != self.origin:
            # A login attempt against the wrong origin never authenticates.
            return SyntheticStagingResponse(status_code=421, authenticated=False)
        if self._locked_out:
            return SyntheticStagingResponse(status_code=423, authenticated=False)
        if credential_value != self._valid:
            return SyntheticStagingResponse(status_code=401, authenticated=False)
        return SyntheticStagingResponse(
            status_code=200, authenticated=True, session_material_issued=True
        )

    def protected_operation(
        self, *, origin: str, session_material: str | None, off_origin_redirect: bool = False
    ) -> SyntheticStagingResponse:
        if normalize_origin(origin) != self.origin:
            return SyntheticStagingResponse(status_code=421, authenticated=False)
        if off_origin_redirect:
            # The app would 302 to a different origin; the worker must NOT follow it.
            return SyntheticStagingResponse(
                status_code=302,
                authenticated=False,
                redirect_origin="https://attacker.example",
            )
        if session_material is None or session_material in self._revoked_sessions:
            return SyntheticStagingResponse(status_code=401, authenticated=False)
        return SyntheticStagingResponse(status_code=200, authenticated=True)

    def revoke_session(self, session_material: str) -> None:
        self._revoked_sessions.add(session_material)

    def reset_account(self) -> None:
        self._locked_out = False
        self._revoked_sessions.clear()


class ControlOutcome(StrictModel):
    """The value-free outcome of the positive/negative controls a session acquisition runs."""

    positive_control_authenticated: bool
    negative_control_rejected: bool
    redirect_escape_blocked: bool


class SessionAcquisitionResult(StrictModel):
    session_reference: SessionReference
    control_outcome: ControlOutcome


def _hash_id(prefix: str, material: str) -> str:
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:16]}"


class SessionWorker:
    """A dedicated, deterministic session-acquisition worker.

    It resolves the opaque credential broker-side, performs the authenticated **positive control**
    and the unauthorized **negative control**, verifies the app will not follow an off-origin
    redirect, mints an opaque :class:`SessionReference` bound to environment + origin + credential
    and stores the session material in the secret store. It returns only references and value-free
    outcomes; no cookie/header/token value ever crosses back to the caller.
    """

    def __init__(self, secret_store: OpaqueSecretStore, app: SyntheticStagingApp) -> None:
        self.secret_store = secret_store
        self.app = app

    def acquire_session(
        self,
        credential: CredentialReference,
        *,
        policy: SessionPolicy,
        now: datetime,
    ) -> SessionAcquisitionResult:
        if not credential.valid_at(now):
            raise StagingReferenceError("CREDENTIAL_REFERENCE_EXPIRED")
        bound_origin = normalize_origin(policy.bound_origin)
        if bound_origin != self.app.origin:
            raise StagingReferenceError("CREDENTIAL_ORIGIN_BINDING_MISMATCH")

        credential_value = self.secret_store.resolve(credential.secret_ref_id)

        # Positive control: a valid login authenticates and would issue session material.
        positive = self.app.login(origin=bound_origin, credential_value=credential_value)
        if not (positive.authenticated and positive.session_material_issued):
            raise StagingReferenceError("POSITIVE_CONTROL_FAILED")

        # Negative control: a deliberately invalid credential must be rejected.
        negative = self.app.login(
            origin=bound_origin, credential_value=credential_value + "-invalid"
        )
        negative_rejected = not negative.authenticated and negative.status_code in (401, 423)

        # Mint opaque session material; store it (never returned to the caller).
        session_ref_id = _hash_id("sess", f"{credential.credential_ref_id}:{now.isoformat()}")
        secret_ref_id = _hash_id("secret", f"session:{session_ref_id}")
        session_material = hashlib.sha256(
            f"material:{session_ref_id}:{credential.secret_ref_id}".encode()
        ).hexdigest()
        self.secret_store.put(secret_ref_id, session_material)

        # Redirect-escape control: with the real session, an off-origin redirect must not be taken.
        redirect = self.app.protected_operation(
            origin=bound_origin, session_material=session_material, off_origin_redirect=True
        )
        redirect_escape_blocked = self._redirect_blocked(redirect, policy)

        lifetime = min(
            policy.max_lifetime_seconds,
            int((credential.expires_at - now).total_seconds()),
        )
        if lifetime <= 0:
            raise StagingReferenceError("SESSION_LIFETIME_NONPOSITIVE")
        session = SessionReference(
            session_ref_id=session_ref_id,
            secret_ref_id=secret_ref_id,
            from_credential_ref_id=credential.credential_ref_id,
            target_ref=credential.target_ref,
            environment_tier=credential.environment_tier,
            bound_origin=bound_origin,
            issued_at=now,
            expires_at=now + timedelta(seconds=lifetime),
        )
        return SessionAcquisitionResult(
            session_reference=session,
            control_outcome=ControlOutcome(
                positive_control_authenticated=True,
                negative_control_rejected=negative_rejected,
                redirect_escape_blocked=redirect_escape_blocked,
            ),
        )

    @staticmethod
    def _redirect_blocked(response: SyntheticStagingResponse, policy: SessionPolicy) -> bool:
        if response.redirect_origin is None:
            return True
        # Policy forbids cross-origin redirects, so an off-origin redirect target is "blocked"
        # precisely because the worker refuses to follow it.
        return not policy.follow_cross_origin_redirects and (
            normalize_origin(response.redirect_origin) != normalize_origin(policy.bound_origin)
        )

    def use_session(
        self,
        session: SessionReference,
        *,
        origin: str,
        now: datetime,
    ) -> SyntheticStagingResponse:
        """Use a session for the protected operation, enforcing expiry + origin binding.

        Fails closed on: expired/revoked session (unresolvable secret), or a request against an
        origin other than the one the session is bound to.
        """

        if not session.valid_at(now):
            raise StagingReferenceError("SESSION_EXPIRED")
        if normalize_origin(origin) != session.bound_origin:
            raise StagingReferenceError("SESSION_ORIGIN_BINDING_MISMATCH")
        material = self.secret_store.resolve(session.secret_ref_id)  # fails closed if revoked
        return self.app.protected_operation(origin=session.bound_origin, session_material=material)

    def revoke_session(self, session: SessionReference) -> None:
        """Revoke a session everywhere: at the app and in the secret store (idempotent)."""

        try:
            material = self.secret_store.resolve(session.secret_ref_id)
            self.app.revoke_session(material)
        except StagingReferenceError:
            pass
        self.secret_store.revoke(session.secret_ref_id)


# --------------------------------------------------------------------------- #
# Model-facing sanitized projection (metadata only; never a value).
# --------------------------------------------------------------------------- #

_FORBIDDEN_STAGING_TOKENS: tuple[str, ...] = (
    "bearer ",
    "set-cookie",
    "authorization:",
    "password",
    "passcode",
    "secret-",
    "session_material",
    "answer_key",
    "ground_truth",
)


def assert_staging_projection_clean(projection: dict[str, object]) -> None:
    """Fail closed if a model-facing staging projection carries any forbidden token."""

    blob = json.dumps(projection, sort_keys=True, separators=(",", ":"), default=str).lower()
    present = [token for token in _FORBIDDEN_STAGING_TOKENS if token in blob]
    if present:
        raise StagingRejection(f"STAGING_PROJECTION_NOT_SANITIZED:{','.join(sorted(present))}")


def build_staging_projection(
    *,
    target_ref: str,
    environment_tier: EnvironmentTier,
    credential: CredentialReference,
    session: SessionReference | None,
    authorized: bool,
) -> dict[str, object]:
    """Metadata-only projection for a model. States that an authorized reference EXISTS, never a
    value; carries only opaque URIs, the tier, and booleans."""

    projection: dict[str, object] = {
        "target_ref": target_ref,
        "environment_tier": environment_tier.value,
        "authorized_credential_reference_present": True,
        "credential_ref": credential.credential_uri,
        "session_reference_present": session is not None,
        "session_ref": session.session_uri if session is not None else None,
        "execution_authorized": bool(authorized),
    }
    assert_staging_projection_clean(projection)
    return projection


# --------------------------------------------------------------------------- #
# Staging capability activation state (typed; DEPLOYMENT_DISABLED by default this sprint).
# --------------------------------------------------------------------------- #


class StagingActivationState(StrEnum):
    DEPLOYMENT_DISABLED = "DEPLOYMENT_DISABLED"
    SYNTHETIC_ACTIVE = "SYNTHETIC_ACTIVE"
    ISOLATED_STAGING_ACTIVE = "ISOLATED_STAGING_ACTIVE"


def staging_capability_state(
    tier: EnvironmentTier, *, gates_satisfied: bool
) -> StagingActivationState:
    """The controller-owned activation state for a tier. Real staging stays DEPLOYMENT_DISABLED."""

    if not gates_satisfied or deployment_disabled(tier):
        return StagingActivationState.DEPLOYMENT_DISABLED
    if tier is EnvironmentTier.SYNTHETIC_RANGE:
        return StagingActivationState.SYNTHETIC_ACTIVE
    if tier is EnvironmentTier.ISOLATED_STAGING:
        return StagingActivationState.ISOLATED_STAGING_ACTIVE
    return StagingActivationState.DEPLOYMENT_DISABLED


# --------------------------------------------------------------------------- #
# Audit events + durable ledger.
# --------------------------------------------------------------------------- #


class StagingAuditEvent(FrozenStrictModel):
    """A typed staging audit event. Carries only references and value-free outcomes."""

    event_id: str = Field(pattern=r"^stgevt-[a-f0-9]{16}$")
    campaign_id: str = Field(min_length=3, max_length=120)
    event_type: str = Field(pattern=r"^[A-Z0-9_]+$", max_length=64)
    environment_tier: EnvironmentTier
    reference_uri: str = Field(default="", max_length=200)
    summary: str = Field(min_length=1, max_length=300)
    created_at: datetime = Field(default_factory=now_utc)


class StagingLedger:
    """A durable ledger for staging progression decisions, opaque references and audit events.

    It persists only references, tiers, booleans and value-free outcomes; there is no column through
    which a credential/session value could be stored.
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
                CREATE TABLE IF NOT EXISTS staging_progressions (
                    campaign_id TEXT NOT NULL,
                    resulting_tier TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS staging_references (
                    reference_uri TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    environment_tier TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS staging_audit_events (
                    event_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )

    def record_progression(
        self, request: StagingProgressionRequest, decision: ProgressionDecision
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO staging_progressions(
                    campaign_id, resulting_tier, allowed, created_at, payload
                ) VALUES (?, ?, ?, ?, ?)""",
                (
                    request.campaign_id,
                    decision.resulting_tier.value,
                    1 if decision.allowed else 0,
                    now_utc().isoformat(),
                    json.dumps(
                        {
                            "request": request.model_dump(mode="json"),
                            "decision": decision.model_dump(mode="json"),
                        },
                        sort_keys=True,
                    ),
                ),
            )

    def record_reference(
        self,
        campaign_id: str,
        kind: Literal["CREDENTIAL", "SESSION"],
        reference: CredentialReference | SessionReference,
    ) -> str:
        uri = (
            reference.credential_uri
            if isinstance(reference, CredentialReference)
            else reference.session_uri
        )
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO staging_references(
                        reference_uri, campaign_id, kind, target_ref, environment_tier, payload
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        uri,
                        campaign_id,
                        kind,
                        reference.target_ref,
                        reference.environment_tier.value,
                        reference.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StagingReferenceError("REFERENCE_ALREADY_RECORDED") from exc
        return uri

    def record_event(self, event: StagingAuditEvent) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO staging_audit_events(
                    event_id, campaign_id, created_at, payload
                ) VALUES (?, ?, ?, ?)""",
                (event.event_id, event.campaign_id, event.created_at.isoformat(),
                 event.model_dump_json()),
            )

    def events(self, campaign_id: str) -> list[StagingAuditEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM staging_audit_events WHERE campaign_id = ? "
                "ORDER BY created_at",
                (campaign_id,),
            ).fetchall()
        return [StagingAuditEvent.model_validate_json(row["payload"]) for row in rows]


__all__ = [
    "APPROVED_STAGING_PROFILES",
    "ControlOutcome",
    "CredentialReference",
    "EnvironmentTier",
    "OpaqueSecretStore",
    "ProgressionDecision",
    "ProgressionRejection",
    "SessionAcquisitionResult",
    "SessionPolicy",
    "SessionReference",
    "SessionWorker",
    "StagingActivationState",
    "StagingAuditEvent",
    "StagingLedger",
    "StagingProgressionRequest",
    "StagingRejection",
    "StagingReferenceError",
    "StagingStateError",
    "SyntheticStagingApp",
    "SyntheticStagingResponse",
    "assert_staging_projection_clean",
    "build_staging_projection",
    "classify_environment",
    "deployment_disabled",
    "evaluate_progression",
    "staging_capability_state",
    "tier_is_executable",
    "TargetValidationError",
]
