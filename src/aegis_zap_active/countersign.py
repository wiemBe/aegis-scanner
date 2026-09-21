"""Fresh Ed25519 verification of the offline operator authorization."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis_zap_active.manifest import MANIFEST_PATH, ZapActiveManifest, load_manifest

COUNTERSIGN_PATH = Path(__file__).with_name("countersign.json")
OPERATOR_PUBLIC_KEY_PATH = Path(__file__).with_name("operator-public-key.hex")
EXPECTED_RULE_ID = 40012
EXPECTED_RULE_NAME = "Cross Site Scripting (Reflected)"
EXPECTED_CAPABILITY = "zap_active_reflected_xss_v1"
EXPECTED_PROFILE = "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"
EXPECTED_ENVIRONMENT = "SYNTHETIC_LAB"
EXPECTED_SIGNER_KEY_ID = "efe-phase15-operator-20260921"
MAX_COUNTERSIGN_AGE = timedelta(days=7)
MAX_COUNTERSIGN_CLOCK_SKEW = timedelta(minutes=5)
_SHA256 = r"^[a-f0-9]{64}$"

CountersignCode = Literal[
    "VALID",
    "COUNTERSIGN_FILE_MISSING",
    "COUNTERSIGN_MALFORMED",
    "PUBLIC_KEY_UNAVAILABLE",
    "SIGNATURE_INVALID",
    "SIGNER_KEY_UNTRUSTED",
    "AUTHORIZATION_EXPIRED",
    "AUTHORIZATION_STALE",
    "MANIFEST_DIGEST_MISMATCH",
    "PROFILE_MISMATCH",
    "CAPABILITY_MISMATCH",
    "RULE_MISMATCH",
    "STRENGTH_OR_THRESHOLD_MISMATCH",
    "ADDON_DIGEST_MISMATCH",
    "ENVIRONMENT_MISMATCH",
    "TARGET_MISMATCH",
    "METHOD_MISMATCH",
]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CountersignedRule(_Frozen):
    plugin_id: Literal[40012]
    name: Literal["Cross Site Scripting (Reflected)"]
    strength: Literal["LOW"]
    threshold: Literal["MEDIUM"]


class SignedAuthorization(_Frozen):
    schema_: Literal["aegis.zap.active-authorization/2"] = Field(alias="schema")
    record_id: str = Field(pattern=r"^countersign-[a-z0-9-]{3,80}$")
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9._-]{3,80}$")
    issued_at: datetime
    expires_at: datetime | None = None
    release_version: str = Field(pattern=r"^1\.5\.\d+$")
    capability_id: Literal["zap_active_reflected_xss_v1"]
    profile_id: Literal["ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"]
    environment: Literal["SYNTHETIC_LAB"]
    admitted_rule: CountersignedRule
    manifest_sha256: str = Field(pattern=_SHA256)
    add_on_digests: dict[str, str] = Field(min_length=3, max_length=3)
    target_refs: tuple[str, ...] = Field(min_length=1, max_length=2)
    allowed_methods: tuple[Literal["GET"], ...] = Field(min_length=1, max_length=1)

    def canonical(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json", by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")


class SignedCountersign(_Frozen):
    authorization: SignedAuthorization
    signature: str = Field(min_length=86, max_length=88, pattern=r"^[A-Za-z0-9_-]+$")


class CountersignStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    valid: bool
    code: CountersignCode
    record_id: str | None = None
    countersigned_on: str | None = None
    countersigned_by: str | None = None
    capability_id: str | None = None
    profile_id: str | None = None
    rule_id: int | None = None
    rule_name: str | None = None
    strength: str | None = None
    threshold: str | None = None
    environment: str | None = None
    manifest_sha256: str | None = None
    scope_statement: str | None = None
    accepted_residual_risk: str | None = None
    countersigned_add_on_ids: tuple[str, ...] = ()
    signer_key_id: str | None = None


def _fail(code: CountersignCode) -> CountersignStatus:
    return CountersignStatus(valid=False, code=code)


def canonical_authorization(record: SignedAuthorization) -> bytes:
    return record.canonical()


def _public_key(path: Path) -> Ed25519PublicKey:
    raw = bytes.fromhex(path.read_text(encoding="ascii").strip())
    if len(raw) != 32:
        raise ValueError("public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def _signature(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _status(record: SignedAuthorization) -> CountersignStatus:
    return CountersignStatus(
        valid=True,
        code="VALID",
        record_id=record.record_id,
        countersigned_on=record.issued_at.astimezone(UTC).date().isoformat(),
        countersigned_by="ED25519_OPERATOR",
        signer_key_id=record.signer_key_id,
        capability_id=record.capability_id,
        profile_id=record.profile_id,
        rule_id=record.admitted_rule.plugin_id,
        rule_name=record.admitted_rule.name,
        strength=record.admitted_rule.strength,
        threshold=record.admitted_rule.threshold,
        environment=record.environment,
        manifest_sha256=record.manifest_sha256,
        scope_statement="Signed authorization for fixed synthetic-lab reflected-XSS targets.",
        accepted_residual_risk="Pinned OAST/database dependencies are neutralised.",
        countersigned_add_on_ids=tuple(sorted(record.add_on_digests)),
    )


def verify_countersign(
    *,
    capability_id: str,
    profile_id: str,
    environment: str,
    target_ref: str,
    manifest: ZapActiveManifest | None = None,
    manifest_path: Path = MANIFEST_PATH,
    countersign_path: Path = COUNTERSIGN_PATH,
    public_key_path: Path = OPERATOR_PUBLIC_KEY_PATH,
    now: datetime | None = None,
) -> CountersignStatus:
    """Verify signature, fixed scope, and disk digests without caching mutable files."""
    try:
        signed = SignedCountersign.model_validate_json(countersign_path.read_bytes())
    except OSError:
        return _fail("COUNTERSIGN_FILE_MISSING")
    except (ValidationError, ValueError):
        return _fail("COUNTERSIGN_MALFORMED")
    try:
        _public_key(public_key_path).verify(
            _signature(signed.signature), signed.authorization.canonical()
        )
    except (OSError, ValueError):
        return _fail("PUBLIC_KEY_UNAVAILABLE")
    except InvalidSignature:
        return _fail("SIGNATURE_INVALID")
    record = signed.authorization
    if record.signer_key_id != EXPECTED_SIGNER_KEY_ID:
        return _fail("SIGNER_KEY_UNTRUSTED")
    checked_at = now or datetime.now(UTC)
    if (
        record.issued_at.tzinfo is None
        or record.issued_at > checked_at + MAX_COUNTERSIGN_CLOCK_SKEW
    ):
        return _fail("AUTHORIZATION_STALE")
    if checked_at - record.issued_at > MAX_COUNTERSIGN_AGE:
        return _fail("AUTHORIZATION_STALE")
    if record.expires_at is not None and checked_at >= record.expires_at:
        return _fail("AUTHORIZATION_EXPIRED")
    if capability_id != EXPECTED_CAPABILITY or record.capability_id != capability_id:
        return _fail("CAPABILITY_MISMATCH")
    if profile_id != EXPECTED_PROFILE or record.profile_id != profile_id:
        return _fail("PROFILE_MISMATCH")
    if environment != EXPECTED_ENVIRONMENT or record.environment != environment:
        return _fail("ENVIRONMENT_MISMATCH")
    if target_ref not in record.target_refs or target_ref not in {
        "synthetic-zap-active-vulnerable",
        "synthetic-zap-active-patched",
    }:
        return _fail("TARGET_MISMATCH")
    if record.allowed_methods != ("GET",):
        return _fail("METHOD_MISMATCH")
    try:
        on_disk = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError:
        return _fail("MANIFEST_DIGEST_MISMATCH")
    if on_disk != record.manifest_sha256:
        return _fail("MANIFEST_DIGEST_MISMATCH")
    manifest = manifest or load_manifest(manifest_path)
    if manifest.profile_id != record.profile_id:
        return _fail("PROFILE_MISMATCH")
    rules = manifest.rules_for_capability(record.capability_id)
    if (
        len(rules) != 1
        or rules[0].plugin_id != EXPECTED_RULE_ID
        or rules[0].name != EXPECTED_RULE_NAME
    ):
        return _fail("RULE_MISMATCH")
    if rules[0].strength != "LOW" or rules[0].threshold != "MEDIUM":
        return _fail("STRENGTH_OR_THRESHOLD_MISMATCH")
    if set(record.add_on_digests) != {"ascanrules", "oast", "database"}:
        return _fail("ADDON_DIGEST_MISMATCH")
    for add_on_id, digest in record.add_on_digests.items():
        pin = manifest.add_on(add_on_id)
        if pin is None or pin.sha256 != digest:
            return _fail("ADDON_DIGEST_MISMATCH")
    return _status(record)
