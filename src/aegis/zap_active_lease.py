"""Single-use, time-bounded activation lease for a controlled ZAP active scan (Phase 1.5).

Active scanning must not be enabled merely by flipping the passive capability. A run requires a
fresh lease that the operator explicitly authorizes with an exact confirmation phrase. The lease is:

- single-use (consumed by exactly one execution, then terminal);
- target/profile/capability-bound (it authorizes one exact origin + path + parameter, one profile,
  one capability, one budget);
- non-renewable (there is no extend; a new run needs a new lease);
- revoked on completion, failure or emergency stop.

The lease is deliberately small: it is an authorization token with bounds and a lifecycle, not an
approval workflow. ``SAFE_PASSIVE`` remains the default; staging/production classifications fail
closed here and never yield a lease.

Since Phase 1.5's lease hardening the token is no longer an opaque random string that only this
store understands. It is an authenticated :mod:`aegis_zap_active.lease` token whose claims bind the
exact capability, profile, target, origin, projection/allowlist/manifest digests, validity window,
audience, execution budget and a single-use nonce. The runner's root-owned admission component
verifies it independently, so this store is now one of *two* places that must agree before a scan
runs — and neither can authorize alone.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis_zap_active.lease import (
    AUDIENCE,
    MAX_LIFETIME_SECONDS,
    LeaseClaims,
    LeaseRejected,
    normalize_secret,
    sign_lease,
)

CONFIRMATION_PHRASE = "ACTIVATE SYNTHETIC-LAB REFLECTED-XSS ACTIVE SCAN"
DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = MAX_LIFETIME_SECONDS

LeaseState = Literal["ISSUED", "CONSUMED", "COMPLETED", "REVOKED", "EXPIRED"]
Classification = Literal["SYNTHETIC_LAB", "CONTROLLED_TEST_ENV", "STAGING", "PRODUCTION"]
_ACTIVE_CLASSES = frozenset({"SYNTHETIC_LAB", "CONTROLLED_TEST_ENV"})


def new_budget_id() -> str:
    """A per-lease identifier for the exact execution budget this lease authorizes."""

    return f"budget-{secrets.token_hex(6)}"


class LeaseError(ValueError):
    """A structured, UI-safe lease refusal. ``code`` is a bounded label, never a secret."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ActiveScanActivationRequest(BaseModel):
    """The operator's activation request. The token/expiry are minted by the store, never here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    origin: str = Field(max_length=200)
    classification: Classification
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    allowed_methods: tuple[Literal["GET", "HEAD", "OPTIONS"], ...] = Field(
        min_length=1, max_length=3
    )
    allowed_path: str = Field(pattern=r"^/[A-Za-z0-9/_-]{1,200}$")
    query_param: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    max_requests: int = Field(ge=1, le=512)
    rate_per_second: float = Field(gt=0, le=10)
    ttl_seconds: int = Field(default=DEFAULT_TTL_SECONDS, ge=30, le=MAX_TTL_SECONDS)
    confirmation_phrase: str = Field(max_length=120)


class ActiveLeaseBinding(BaseModel):
    """What the controller has already decided this lease may authorize.

    These are not operator inputs: the digests come from the projection the controller just built
    and the manifest it just loaded, so a lease can never be issued for a surface the controller
    has not itself computed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    projection_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowlist_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    budget_id: str = Field(pattern=r"^budget-[a-f0-9]{12}$")
    audience: str = AUDIENCE


class ActiveScanLease(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(pattern=r"^lease-[a-f0-9]{16}$")
    # The signed token. It is held in memory only, sent to exactly one runner, and never written to
    # an audit record, a report, an API response or the Operator Console.
    token: str = Field(min_length=64, max_length=1024, repr=False)
    binding: ActiveLeaseBinding
    target_ref: str
    origin: str
    classification: Classification
    profile_id: str
    capability_id: str
    allowed_methods: tuple[str, ...]
    allowed_path: str
    query_param: str
    max_requests: int
    rate_per_second: float
    state: LeaseState = "ISSUED"
    issued_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    terminated_at: datetime | None = None
    termination_reason: str | None = Field(default=None, max_length=60)

    def is_live(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.state == "ISSUED" and now < self.expires_at

    def redacted(self) -> dict[str, object]:
        """Console projection: never exposes the token."""

        return {
            "lease_id": self.lease_id,
            "target_ref": self.target_ref,
            "origin": self.origin,
            "classification": self.classification,
            "profile_id": self.profile_id,
            "capability_id": self.capability_id,
            "allowed_methods": list(self.allowed_methods),
            "allowed_path": self.allowed_path,
            "query_param": self.query_param,
            "max_requests": self.max_requests,
            "rate_per_second": self.rate_per_second,
            "state": self.state,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "termination_reason": self.termination_reason,
            "projection_digest": self.binding.projection_digest,
            "allowlist_digest": self.binding.allowlist_digest,
            "manifest_digest": self.binding.manifest_digest,
            "budget_id": self.binding.budget_id,
            "audience": self.binding.audience,
            "lifetime_seconds": int((self.expires_at - self.issued_at).total_seconds()),
        }


class ActiveScanLeaseStore:
    """Holds at most one live lease. Thread-safe. Emergency stop revokes and fires a callback."""

    def __init__(
        self,
        signing_secret: str | bytes,
        on_emergency_stop: Callable[[], None] | None = None,
    ) -> None:
        # Refuses a missing, empty, short or placeholder secret here, so a misconfigured deployment
        # fails at construction rather than issuing leases nothing can verify.
        self._secret = normalize_secret(signing_secret)
        self._lock = threading.Lock()
        self._lease: ActiveScanLease | None = None
        self._on_emergency_stop = on_emergency_stop

    def current(self) -> ActiveScanLease | None:
        with self._lock:
            self._expire_if_needed()
            return self._lease

    def _expire_if_needed(self) -> None:
        lease = self._lease
        if lease and lease.state == "ISSUED" and datetime.now(UTC) >= lease.expires_at:
            self._lease = lease.model_copy(
                update={"state": "EXPIRED", "terminated_at": datetime.now(UTC)}
            )

    def issue(
        self, request: ActiveScanActivationRequest, *, binding: ActiveLeaseBinding
    ) -> ActiveScanLease:
        """Mint one signed lease, or raise :class:`LeaseError`. Refuses a live lease present."""

        if request.confirmation_phrase != CONFIRMATION_PHRASE:
            raise LeaseError("CONFIRMATION_PHRASE_MISMATCH")
        if request.classification not in _ACTIVE_CLASSES:
            # SAFE_PASSIVE is the default; staging/production fail closed.
            raise LeaseError("ENVIRONMENT_NOT_AUTHORISED")
        now = datetime.now(UTC)
        with self._lock:
            self._expire_if_needed()
            if self._lease is not None and self._lease.is_live(now):
                raise LeaseError("LEASE_ALREADY_ACTIVE")
            lease_id = f"lease-{secrets.token_hex(8)}"
            expires_at = now + timedelta(seconds=request.ttl_seconds)
            claims = LeaseClaims(
                lease_id=lease_id,
                capability_id=request.capability_id,
                profile_id=request.profile_id,
                target_ref=request.target_ref,
                target_origin=request.origin.rstrip("/"),
                projection_digest=binding.projection_digest,
                allowlist_digest=binding.allowlist_digest,
                manifest_digest=binding.manifest_digest,
                issued_at=int(now.timestamp()),
                not_before=int(now.timestamp()),
                expires_at=int(expires_at.timestamp()),
                nonce=secrets.token_hex(16),
                audience=binding.audience,
                budget_id=binding.budget_id,
            )
            try:
                token = sign_lease(claims, self._secret)
            except LeaseRejected as rejected:  # pragma: no cover - secret validated at construction
                raise LeaseError(rejected.code) from None
            lease = ActiveScanLease(
                lease_id=lease_id,
                token=token,
                binding=binding,
                target_ref=request.target_ref,
                origin=request.origin,
                classification=request.classification,
                profile_id=request.profile_id,
                capability_id=request.capability_id,
                allowed_methods=request.allowed_methods,
                allowed_path=request.allowed_path,
                query_param=request.query_param,
                max_requests=request.max_requests,
                rate_per_second=request.rate_per_second,
                issued_at=now,
                expires_at=expires_at,
            )
            self._lease = lease
            return lease

    def consume(
        self, token: str, *, target_ref: str, profile_id: str, capability_id: str
    ) -> ActiveScanLease:
        """Single-use consume bound to the exact target/profile/capability; raises on mismatch."""

        with self._lock:
            self._expire_if_needed()
            lease = self._lease
            if lease is None or not lease.is_live():
                raise LeaseError("NO_LIVE_LEASE")
            if not secrets.compare_digest(token, lease.token):
                raise LeaseError("LEASE_TOKEN_MISMATCH")
            if (
                lease.target_ref != target_ref
                or lease.profile_id != profile_id
                or lease.capability_id != capability_id
            ):
                raise LeaseError("LEASE_BINDING_MISMATCH")
            self._lease = lease.model_copy(
                update={"state": "CONSUMED", "consumed_at": datetime.now(UTC)}
            )
            return self._lease

    def complete(self, lease_id: str) -> None:
        self._terminate(lease_id, "COMPLETED", "completed")

    def revoke(self, lease_id: str, reason: str = "revoked") -> None:
        self._terminate(lease_id, "REVOKED", reason)

    def _terminate(self, lease_id: str, state: LeaseState, reason: str) -> None:
        with self._lock:
            lease = self._lease
            # Terminal transitions are monotonic.  In particular a delayed completion cannot
            # resurrect a lease the operator has revoked or stopped.
            if (
                lease is not None
                and lease.lease_id == lease_id
                and lease.state in {"ISSUED", "CONSUMED"}
            ):
                self._lease = lease.model_copy(
                    update={
                        "state": state,
                        "terminated_at": datetime.now(UTC),
                        "termination_reason": reason[:60],
                    }
                )

    def emergency_stop(self, reason: str = "emergency_stop") -> bool:
        """Revoke any live/consumed lease and fire the stop callback (which halts the runner)."""

        fired = False
        with self._lock:
            lease = self._lease
            if lease is not None and lease.state in {"ISSUED", "CONSUMED"}:
                self._lease = lease.model_copy(
                    update={
                        "state": "REVOKED",
                        "terminated_at": datetime.now(UTC),
                        "termination_reason": reason[:60],
                    }
                )
                fired = True
        if self._on_emergency_stop is not None:
            self._on_emergency_stop()
        return fired
