"""The authenticated, single-use activation lease shared by the controller and the runner admission
component (Phase 1.5).

Before this module the runner accepted any *well-formed* lease token: the lease was enforced only
inside the controller, so a token was a shape, not an authorization. This module makes the lease a
cryptographic object that the runner side verifies independently.

Format (fixed, four deliberate properties):

``AZL1.<b64url(canonical_claims_json)>.<b64url(hmac_sha256)>``

1. ``AZL1`` is the algorithm. It is a literal compiled into this module, compared for exact
   equality, and never used as a *selector*: there is no ``alg`` claim, no algorithm registry and
   therefore no "alg: none" class of downgrade. A token that does not start with exactly ``AZL1.``
   is rejected outright.
2. The claims are canonical JSON (sorted keys, no whitespace, ASCII, no NaN/Infinity). Verification
   re-serialises the decoded object and requires byte equality with what was signed, and rejects
   duplicate object keys, so there is exactly one encoding of any claim set. Signature-stripping,
   claim reordering and shadowed-key attacks all fail before the claims are read.
3. The claim set is exact: :data:`CLAIM_NAMES`. An inserted claim and a removed claim are both
   rejected, so a lease cannot be silently widened.
4. The MAC covers ``AZL1.<payload>``, i.e. the version prefix is inside the signed material, and it
   is compared with :func:`hmac.compare_digest` (constant time).

There is no unsigned mode, no fallback token, no "development" bypass and no renewal. Maximum
lifetime is :data:`MAX_LIFETIME_SECONDS` (15 minutes) and clock skew tolerance is
:data:`MAX_CLOCK_SKEW_SECONDS`; a lease claiming a longer life is rejected as malformed rather than
truncated. Every refusal is one of the bounded :class:`LeaseRejection` codes: no token bytes, no
claim values and no cryptographic detail ever appear in an error, a log line or a response.

Signature verification alone is deliberately NOT sufficient to execute: it only proves the
controller issued the lease. The runner also requires the lease to be present in its own armed
registry (:mod:`zap_active_admission.registry`), which is what makes the lease single-use and
revocable.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TOKEN_PREFIX = "AZL1"  # noqa: S105 - a format label, not a secret
AUDIENCE = "aegis-zap-active-runner"
MAX_LIFETIME_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 60
MAX_TOKEN_BYTES = 1_024
MIN_SECRET_BYTES = 32

# Values a misconfiguration is most likely to leave behind. Startup refuses all of them.
PLACEHOLDER_SECRETS = frozenset(
    {
        "changeme",
        "change-me",
        "placeholder",
        "secret",
        "example",
        "dummy",
        "test",
        "todo",
        "replace-me",
        "xxx",
        "none",
        "null",
        "0",
    }
)

CLAIM_NAMES: tuple[str, ...] = (
    "allowlist_digest",
    "audience",
    "budget_id",
    "capability_id",
    "expires_at",
    "issued_at",
    "lease_id",
    "manifest_digest",
    "nonce",
    "not_before",
    "profile_id",
    "projection_digest",
    "target_origin",
    "target_ref",
)
_CLAIM_SET = frozenset(CLAIM_NAMES)

LeaseRejection = Literal[
    "LEASE_REQUIRED",
    "LEASE_MALFORMED",
    "LEASE_UNKNOWN_FORMAT",
    "LEASE_NOT_CANONICAL",
    "LEASE_CLAIMS_INVALID",
    "LEASE_SIGNATURE_INVALID",
    "LEASE_AUDIENCE_MISMATCH",
    "LEASE_EXPIRED",
    "LEASE_NOT_YET_VALID",
    "LEASE_LIFETIME_EXCESSIVE",
    "LEASE_BINDING_MISMATCH",
    "LEASE_NOT_ARMED",
    "LEASE_ALREADY_CONSUMED",
    "LEASE_REVOKED",
    "LEASE_REGISTRY_UNAVAILABLE",
    "LEASE_SECRET_UNAVAILABLE",
]

_SHA256 = r"^[a-f0-9]{64}$"


class LeaseRejected(Exception):
    """A bounded, UI-safe refusal. ``code`` is a label from :data:`LeaseRejection`, never data."""

    def __init__(self, code: LeaseRejection) -> None:
        super().__init__(code)
        self.code: LeaseRejection = code

    def __str__(self) -> str:  # pragma: no cover - trivial; keeps logs free of detail
        return self.code


class LeaseClaims(BaseModel):
    """The exact signed claim set. Every field is a binding; none is advisory."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    lease_id: str = Field(pattern=r"^lease-[a-f0-9]{16}$")
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    profile_id: str = Field(pattern=r"^[A-Z0-9_]{3,64}$")
    target_ref: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    target_origin: str = Field(pattern=r"^https?://[A-Za-z0-9.-]{1,80}(?::[0-9]{2,5})?$")
    projection_digest: str = Field(pattern=_SHA256)
    allowlist_digest: str = Field(pattern=_SHA256)
    manifest_digest: str = Field(pattern=_SHA256)
    issued_at: int = Field(ge=1_600_000_000, le=4_102_444_800)
    not_before: int = Field(ge=1_600_000_000, le=4_102_444_800)
    expires_at: int = Field(ge=1_600_000_000, le=4_102_444_800)
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    audience: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    budget_id: str = Field(pattern=r"^budget-[a-f0-9]{12}$")

    def canonical(self) -> bytes:
        return canonical_claims(self.model_dump(mode="json"))

    def redacted(self) -> dict[str, Any]:
        """Console/audit projection. The nonce is a single-use credential and is NOT included."""

        return {
            "lease_id": self.lease_id,
            "capability_id": self.capability_id,
            "profile_id": self.profile_id,
            "target_ref": self.target_ref,
            "target_origin": self.target_origin,
            "projection_digest": self.projection_digest,
            "allowlist_digest": self.allowlist_digest,
            "manifest_digest": self.manifest_digest,
            "audience": self.audience,
            "budget_id": self.budget_id,
            "issued_at": _iso(self.issued_at),
            "not_before": _iso(self.not_before),
            "expires_at": _iso(self.expires_at),
            "lifetime_seconds": self.expires_at - self.not_before,
        }


class LeaseBinding(BaseModel):
    """What the caller asserts the lease must authorize. Every field is compared for equality."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str
    profile_id: str
    target_ref: str
    target_origin: str
    projection_digest: str
    allowlist_digest: str
    manifest_digest: str
    audience: str = AUDIENCE


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def canonical_claims(claims: dict[str, Any]) -> bytes:
    """One encoding per claim set: sorted keys, no whitespace, ASCII, no NaN/Infinity."""

    return json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    # Strict: reject any character outside the unpadded url-safe alphabet before decoding, so a
    # token cannot carry two spellings of the same bytes.
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise LeaseRejected("LEASE_MALFORMED")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError):
        raise LeaseRejected("LEASE_MALFORMED") from None


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise LeaseRejected("LEASE_NOT_CANONICAL")
    return dict(pairs)


def normalize_secret(secret: str | bytes | None) -> bytes:
    """Return usable signing key material, or refuse. Missing/empty/placeholder all fail closed."""

    if secret is None:
        raise LeaseRejected("LEASE_SECRET_UNAVAILABLE")
    raw = secret.encode() if isinstance(secret, str) else bytes(secret)
    stripped = raw.strip()
    if not stripped or len(stripped) < MIN_SECRET_BYTES:
        raise LeaseRejected("LEASE_SECRET_UNAVAILABLE")
    if stripped.decode("utf-8", "replace").strip().lower() in PLACEHOLDER_SECRETS:
        raise LeaseRejected("LEASE_SECRET_UNAVAILABLE")
    return stripped


def sign_lease(claims: LeaseClaims, secret: str | bytes) -> str:
    """Mint one token. Controller-side only; the token is never logged or shown to an operator."""

    key = normalize_secret(secret)
    payload = _b64encode(claims.canonical())
    signed = f"{TOKEN_PREFIX}.{payload}"
    mac = hmac.new(key, signed.encode("ascii"), sha256).digest()
    return f"{signed}.{_b64encode(mac)}"


def verify_lease(
    token: str,
    secret: str | bytes,
    *,
    binding: LeaseBinding,
    now: datetime | None = None,
    max_lifetime_seconds: int = MAX_LIFETIME_SECONDS,
    clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> LeaseClaims:
    """Authenticate one token against one exact binding, or raise :class:`LeaseRejected`.

    Order matters: format, canonical decoding and the exact claim set are checked before the MAC so
    that a malformed token never reaches the comparison; the MAC is then checked before any claim is
    *trusted*, so no unauthenticated claim influences a decision.
    """

    key = normalize_secret(secret)
    if not token:
        raise LeaseRejected("LEASE_REQUIRED")
    if len(token) > MAX_TOKEN_BYTES:
        raise LeaseRejected("LEASE_MALFORMED")
    parts = token.split(".")
    if len(parts) != 3:
        raise LeaseRejected("LEASE_MALFORMED")
    version, payload, signature = parts
    if version != TOKEN_PREFIX:
        raise LeaseRejected("LEASE_UNKNOWN_FORMAT")

    raw = _b64decode(payload)
    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError):
        raise LeaseRejected("LEASE_MALFORMED") from None
    if not isinstance(decoded, dict):
        raise LeaseRejected("LEASE_MALFORMED")
    if canonical_claims(decoded) != raw:
        raise LeaseRejected("LEASE_NOT_CANONICAL")
    if frozenset(decoded) != _CLAIM_SET:
        raise LeaseRejected("LEASE_CLAIMS_INVALID")

    expected = hmac.new(key, f"{TOKEN_PREFIX}.{payload}".encode("ascii"), sha256).digest()
    if not hmac.compare_digest(_b64decode(signature), expected):
        raise LeaseRejected("LEASE_SIGNATURE_INVALID")

    try:
        claims = LeaseClaims.model_validate(decoded)
    except ValidationError:
        raise LeaseRejected("LEASE_CLAIMS_INVALID") from None

    # --- only now are the claims trusted ---------------------------------------------------
    if claims.audience != binding.audience:
        raise LeaseRejected("LEASE_AUDIENCE_MISMATCH")
    if not claims.issued_at <= claims.not_before < claims.expires_at:
        raise LeaseRejected("LEASE_MALFORMED")
    if claims.expires_at - claims.not_before > max_lifetime_seconds:
        raise LeaseRejected("LEASE_LIFETIME_EXCESSIVE")
    if claims.expires_at - claims.issued_at > max_lifetime_seconds:
        raise LeaseRejected("LEASE_LIFETIME_EXCESSIVE")

    seconds = int((now or datetime.now(UTC)).timestamp())
    if seconds + clock_skew_seconds < claims.not_before:
        raise LeaseRejected("LEASE_NOT_YET_VALID")
    if seconds - clock_skew_seconds >= claims.expires_at:
        raise LeaseRejected("LEASE_EXPIRED")

    if (
        claims.capability_id != binding.capability_id
        or claims.profile_id != binding.profile_id
        or claims.target_ref != binding.target_ref
        or claims.target_origin.rstrip("/") != binding.target_origin.rstrip("/")
        or claims.projection_digest != binding.projection_digest
        or claims.allowlist_digest != binding.allowlist_digest
        or claims.manifest_digest != binding.manifest_digest
    ):
        raise LeaseRejected("LEASE_BINDING_MISMATCH")
    return claims
