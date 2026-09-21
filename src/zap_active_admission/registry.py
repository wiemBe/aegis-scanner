"""The armed-lease registry: the reason a valid signature is not, by itself, permission to scan.

A controller signature proves *who issued* a lease. It cannot prove that the lease has not already
been used, that the operator has not stopped the run, or that the runner has not restarted since.
Those are properties of state, so they live here, in a component that:

- runs as root in its own container, with its state in a root-owned, 0700 directory. The ZAP
  process runs unprivileged inside a *different* container and has no filesystem path to it;
- holds the only runner-side copy of the lease-signing secret, so the container that hosts the
  untrusted engine never contains signing material at all;
- treats a restart as a revocation: any lease still ARMED when the process starts is moved to
  REVOKED(``RUNNER_RESTART``) and its nonce is kept in the consumed set, so a replay after a
  restart fails twice over.

Every mutation happens under one lock, so a concurrent double-consume has exactly one winner. Every
refusal is a bounded :data:`~aegis_zap_active.lease.LeaseRejection` code.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from aegis_zap_active.lease import (
    AUDIENCE,
    LeaseBinding,
    LeaseClaims,
    LeaseRejected,
    normalize_secret,
    verify_lease,
)
from zap_active_admission.contracts import (
    ConsumeRequest,
    LeaseRecord,
    LeaseState,
)

STATE_DIR = Path("/admission")
STATE_FILE = STATE_DIR / "leases.json"
INITIALIZED_FILE = STATE_DIR / ".initialized"
RECENT_LIMIT = 16
NONCE_MEMORY = 4_096
# Fixed for this profile. The admission component admits exactly one capability on one profile and
# is not configurable into admitting another.
EXPECTED_PROFILE_ID = "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"
EXPECTED_CAPABILITY_ID = "zap_active_reflected_xss_v1"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _epoch_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


class AdmissionRegistry:
    """Arm / consume / revoke / status. Fails closed on every ambiguity."""

    def __init__(
        self,
        secret: str | bytes,
        *,
        state_file: Path = STATE_FILE,
        audience: str = AUDIENCE,
    ) -> None:
        # Refuses a missing, empty, short or placeholder secret at construction time, which is what
        # makes the runner refuse to become READY rather than silently accepting unsigned traffic.
        self._secret = normalize_secret(secret)
        self._state_file = state_file
        self._audience = audience
        self._lock = threading.Lock()
        self.booted_at = _now()
        self._armed: LeaseRecord | None = None
        self._recent: list[LeaseRecord] = []
        self._nonces: OrderedDict[str, None] = OrderedDict()
        self.armed_total = 0
        self.consumed_total = 0
        self.revoked_total = 0
        self.rejected_total = 0
        self.restart_revoked_total = 0
        self.healthy = False
        self._recover()

    # --- persistence -------------------------------------------------------------------------

    @property
    def state_root_owned(self) -> bool:
        """True when the state directory is owned by root and not group/world accessible."""

        try:
            info = self._state_file.parent.stat()
        except OSError:
            return False
        return info.st_uid == 0 and not info.st_mode & 0o077

    def _recover(self) -> None:
        """A surviving ARMED lease is a restart, and a restart revokes. Nonces are retained."""

        try:
            raw = self._state_file.read_bytes()
        except OSError:
            # A brand-new root-owned volume is the one allowed empty state.  Once initialized,
            # missing state is corruption/loss and must block admission rather than forget nonces.
            if self._state_file.parent.joinpath(INITIALIZED_FILE.name).exists():
                return
            self.healthy = self._persist(initial=True)
            return
        try:
            saved = json.loads(raw)
        except ValueError:
            return
        if not isinstance(saved, dict):
            return
        if saved.get("schema") != "aegis.zap.active-admission/3":
            return
        supplied_integrity = saved.pop("integrity", None)
        if (
            not isinstance(supplied_integrity, str)
            or len(supplied_integrity) != 64
            or not hmac.compare_digest(supplied_integrity, self._integrity(saved))
        ):
            return
        nonces = saved.get("consumed_nonces")
        recent = saved.get("recent")
        if not isinstance(nonces, list) or not isinstance(recent, list):
            return
        if len(nonces) > NONCE_MEMORY or len(recent) > RECENT_LIMIT:
            return
        for nonce in nonces:
            if not isinstance(nonce, str):
                return
            self._nonces[nonce] = None
        armed_records: list[LeaseRecord] = []
        for item in recent:
            try:
                record = LeaseRecord.model_validate(item)
            except ValueError:
                return
            if record.state is LeaseState.ARMED:
                armed_records.append(record)
                record = record.model_copy(
                    update={
                        "state": LeaseState.REVOKED,
                        "terminated_at": _iso(_now()),
                        "termination_reason": "RUNNER_RESTART",
                    }
                )
                self.restart_revoked_total += 1
                self.revoked_total += 1
            self._recent.append(record)
        if len(armed_records) > 1 or (
            armed_records and saved.get("armed_lease_id") != armed_records[0].lease_id
        ):
            self._recent.clear()
            self._nonces.clear()
            return
        self._armed = None
        self.healthy = self._persist()

    def _integrity(self, payload: dict[str, Any]) -> str:
        """MAC durable state so a torn or modified registry never forgets replay protection."""

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
        return hmac.new(self._secret, canonical, sha256).hexdigest()

    def _persist(self, *, initial: bool = False) -> bool:
        payload: dict[str, Any] = {
            "schema": "aegis.zap.active-admission/3",
            "updated_at": _iso(_now()),
            "armed_lease_id": self._armed.lease_id if self._armed else None,
            "recent": [record.model_dump(mode="json") for record in self._recent[-RECENT_LIMIT:]],
            "consumed_nonces": list(self._nonces),
        }
        payload["integrity"] = self._integrity(payload)
        try:
            self._state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Docker creates a named-volume mountpoint before the process starts, commonly 0755.
            # The admission process is the root owner, so repair that mountpoint before accepting
            # even the first lease; otherwise a healthy-looking registry would be world-readable.
            os.chmod(self._state_file.parent, 0o700)
            temporary = self._state_file.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, separators=(",", ":")))
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._state_file)
            directory = os.open(self._state_file.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            if initial:
                marker = self._state_file.parent / INITIALIZED_FILE.name
                marker.touch(exist_ok=True)
                os.chmod(marker, 0o600)
                directory = os.open(self._state_file.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return True
        except OSError:
            self.healthy = False
            return False

    def _require_healthy(self) -> None:
        if not self.healthy:
            raise LeaseRejected("LEASE_REGISTRY_UNAVAILABLE")

    def _remember(self, record: LeaseRecord) -> None:
        self._recent = [item for item in self._recent if item.lease_id != record.lease_id]
        self._recent.append(record)
        self._recent = self._recent[-RECENT_LIMIT:]

    def _remember_nonce(self, nonce: str) -> None:
        self._nonces[nonce] = None
        while len(self._nonces) > NONCE_MEMORY:
            self._nonces.popitem(last=False)

    # --- verification ------------------------------------------------------------------------

    def _authenticate(self, token: str, binding: LeaseBinding, now: datetime) -> LeaseClaims:
        claims = verify_lease(token, self._secret, binding=binding, now=now)
        if (
            claims.profile_id != EXPECTED_PROFILE_ID
            or claims.capability_id != EXPECTED_CAPABILITY_ID
        ):
            raise LeaseRejected("LEASE_BINDING_MISMATCH")
        return claims

    # --- lifecycle ---------------------------------------------------------------------------

    def arm(self, token: str) -> LeaseRecord:
        """Admit one signed lease into the registry. Refuses while another lease is armed."""

        now = _now()
        with self._lock:
            self._require_healthy()
            self._expire_locked(now)
            try:
                # At arm time the only bindings the registry can assert independently are the ones
                # it owns: its audience, its profile and its capability. The target/projection/
                # manifest bindings are recorded here and enforced at consume time against facts
                # the runner recomputes for itself.
                probe = self._peek(token, now)
            except LeaseRejected:
                self.rejected_total += 1
                raise
            if probe.nonce in self._nonces:
                self.rejected_total += 1
                raise LeaseRejected("LEASE_ALREADY_CONSUMED")
            if self._armed is not None:
                self.rejected_total += 1
                raise LeaseRejected("LEASE_REGISTRY_UNAVAILABLE")
            record = LeaseRecord(
                lease_id=probe.lease_id,
                state=LeaseState.ARMED,
                capability_id=probe.capability_id,
                profile_id=probe.profile_id,
                target_ref=probe.target_ref,
                target_origin=probe.target_origin,
                projection_digest=probe.projection_digest,
                allowlist_digest=probe.allowlist_digest,
                manifest_digest=probe.manifest_digest,
                budget_id=probe.budget_id,
                audience=probe.audience,
                not_before=_epoch_iso(probe.not_before),
                expires_at=_epoch_iso(probe.expires_at),
                armed_at=_iso(now),
            )
            self._armed = record
            self.armed_total += 1
            self._remember(record)
            if not self._persist():
                raise LeaseRejected("LEASE_REGISTRY_UNAVAILABLE")
            return record

    def _peek(self, token: str, now: datetime) -> LeaseClaims:
        """Authenticate a token against its own claimed bindings (signature + time + audience)."""

        unverified = _claims_shape(token)
        binding = LeaseBinding(
            capability_id=unverified["capability_id"],
            profile_id=unverified["profile_id"],
            target_ref=unverified["target_ref"],
            target_origin=unverified["target_origin"],
            projection_digest=unverified["projection_digest"],
            allowlist_digest=unverified["allowlist_digest"],
            manifest_digest=unverified["manifest_digest"],
            audience=self._audience,
        )
        return self._authenticate(token, binding, now)

    def consume(self, request: ConsumeRequest) -> LeaseRecord:
        """Atomically move the armed lease to CONSUMED. Exactly one caller can win."""

        now = _now()
        binding = LeaseBinding(
            capability_id=request.capability_id,
            profile_id=request.profile_id,
            target_ref=request.target_ref,
            target_origin=request.target_origin,
            projection_digest=request.projection_digest,
            allowlist_digest=request.allowlist_digest,
            manifest_digest=request.manifest_digest,
            audience=self._audience,
        )
        with self._lock:
            self._require_healthy()
            self._expire_locked(now)
            try:
                claims = self._authenticate(request.token, binding, now)
            except LeaseRejected:
                self.rejected_total += 1
                raise
            if claims.nonce in self._nonces:
                self.rejected_total += 1
                raise LeaseRejected("LEASE_ALREADY_CONSUMED")
            armed = self._armed
            if armed is None or armed.lease_id != claims.lease_id:
                # A perfectly valid signature with nothing armed is still refused: this is the
                # replay-after-restart and the never-armed case. When the lease IS known but no
                # longer armed, report its precise terminal state: a revoked lease is REVOKED, a
                # spent one is ALREADY_CONSUMED, and an unknown one is NOT_ARMED.
                previous = next(
                    (item for item in reversed(self._recent) if item.lease_id == claims.lease_id),
                    None,
                )
                self.rejected_total += 1
                if previous is not None and previous.state is LeaseState.REVOKED:
                    raise LeaseRejected("LEASE_REVOKED")
                if previous is not None and previous.state is LeaseState.CONSUMED:
                    raise LeaseRejected("LEASE_ALREADY_CONSUMED")
                raise LeaseRejected("LEASE_NOT_ARMED")
            if armed.state is not LeaseState.ARMED:
                self.rejected_total += 1
                raise LeaseRejected(
                    "LEASE_REVOKED"
                    if armed.state is LeaseState.REVOKED
                    else "LEASE_ALREADY_CONSUMED"
                )
            record = armed.model_copy(
                update={
                    "state": LeaseState.CONSUMED,
                    "consumed_at": _iso(now),
                    "consumed_by": request.execution_id,
                }
            )
            self._armed = record
            self._remember_nonce(claims.nonce)
            self.consumed_total += 1
            self._remember(record)
            if not self._persist():
                raise LeaseRejected("LEASE_REGISTRY_UNAVAILABLE")
            return record

    def revoke(self, lease_id: str, reason: str = "revoked") -> LeaseRecord | None:
        """Terminal for this lease. A later completion can never move it back."""

        now = _now()
        with self._lock:
            self._require_healthy()
            current = self._armed
            if current is None or current.lease_id != lease_id:
                for item in reversed(self._recent):
                    if item.lease_id == lease_id:
                        return item
                return None
            record = current.model_copy(
                update={
                    "state": LeaseState.REVOKED,
                    "terminated_at": _iso(now),
                    "termination_reason": reason[:40],
                }
            )
            self._armed = None
            self.revoked_total += 1
            self._remember(record)
            if not self._persist():
                raise LeaseRejected("LEASE_REGISTRY_UNAVAILABLE")
            return record

    def _expire_locked(self, now: datetime) -> None:
        armed = self._armed
        if armed is None:
            return
        if datetime.fromisoformat(armed.expires_at) <= now:
            record = armed.model_copy(
                update={
                    "state": LeaseState.EXPIRED,
                    "terminated_at": _iso(now),
                    "termination_reason": "EXPIRED",
                }
            )
            self._armed = None
            self._remember(record)
            if not self._persist():
                self.healthy = False

    # --- projection --------------------------------------------------------------------------

    def armed_record(self) -> LeaseRecord | None:
        with self._lock:
            self._expire_locked(_now())
            return self._armed

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._expire_locked(_now())
            return {
                "booted_at": _iso(self.booted_at),
                "state_root_owned": self.state_root_owned,
                "armed": self._armed,
                "recent": tuple(self._recent[-RECENT_LIMIT:]),
                "armed_total": self.armed_total,
                "consumed_total": self.consumed_total,
                "revoked_total": self.revoked_total,
                "rejected_total": self.rejected_total,
                "consumed_nonce_count": len(self._nonces),
                "restart_revoked_total": self.restart_revoked_total,
            }


def _claims_shape(token: str) -> dict[str, str]:
    """Read the *unauthenticated* claim strings needed to construct the comparison binding.

    This is not a trust decision: the very next step re-verifies the token against the binding
    built from these values, so a forged token fails the MAC regardless of what it claims. It
    exists only so that the arm path does not have to be told what it is about to admit.
    """

    import base64

    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "AZL1":
        raise LeaseRejected("LEASE_UNKNOWN_FORMAT")
    payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        raise LeaseRejected("LEASE_MALFORMED") from None
    if not isinstance(decoded, dict):
        raise LeaseRejected("LEASE_MALFORMED")
    needed = (
        "capability_id",
        "profile_id",
        "target_ref",
        "target_origin",
        "projection_digest",
        "allowlist_digest",
        "manifest_digest",
    )
    shape: dict[str, str] = {}
    for key in needed:
        value = decoded.get(key)
        if not isinstance(value, str) or len(value) > 200:
            raise LeaseRejected("LEASE_CLAIMS_INVALID")
        shape[key] = value
    return shape
