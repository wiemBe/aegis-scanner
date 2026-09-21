"""Ed25519 countersign tests use ephemeral keys only; no production authorization is minted."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_zap_active.countersign import (
    COUNTERSIGN_PATH,
    OPERATOR_PUBLIC_KEY_PATH,
    SignedAuthorization,
    verify_countersign,
)
from aegis_zap_active.manifest import MANIFEST_PATH, load_manifest


def _signed(tmp_path: Path, **changes: object) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    manifest = load_manifest()
    payload: dict[str, object] = {
        "schema": "aegis.zap.active-authorization/2",
        "record_id": "countersign-test-40012",
        "signer_key_id": "efe-phase15-operator-20260921",
        "issued_at": datetime.now(UTC).isoformat(),
        "release_version": "1.5.1",
        "capability_id": "zap_active_reflected_xss_v1",
        "profile_id": "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        "environment": "SYNTHETIC_LAB",
        "admitted_rule": {
            "plugin_id": 40012,
            "name": "Cross Site Scripting (Reflected)",
            "strength": "LOW",
            "threshold": "MEDIUM",
        },
        "manifest_sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        "add_on_digests": {
            key: manifest.add_on(key).sha256 for key in ("ascanrules", "oast", "database")
        },  # type: ignore[union-attr]
        "target_refs": ["synthetic-zap-active-vulnerable", "synthetic-zap-active-patched"],
        "allowed_methods": ["GET"],
    }
    payload.update(changes)
    record = SignedAuthorization.model_validate_json(json.dumps(payload))
    signature = base64.urlsafe_b64encode(private.sign(record.canonical())).decode().rstrip("=")
    countersign = tmp_path / "countersign.json"
    countersign.write_text(
        json.dumps(
            {"authorization": record.model_dump(mode="json", by_alias=True), "signature": signature}
        )
    )
    public = tmp_path / "operator-public-key.hex"
    public.write_text(
        private.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return countersign, public


def _verify(countersign: Path, public: Path, **changes: object) -> str:
    target_ref = str(changes.pop("target_ref", "synthetic-zap-active-vulnerable"))
    return verify_countersign(
        capability_id="zap_active_reflected_xss_v1",
        profile_id="ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        environment="SYNTHETIC_LAB",
        target_ref=target_ref,
        countersign_path=countersign,
        public_key_path=public,
        **changes,
    ).code


def test_valid_ed25519_authorization_binds_fixed_scope(tmp_path: Path) -> None:
    countersign, public = _signed(tmp_path)
    assert _verify(countersign, public) == "VALID"
    assert (
        _verify(countersign, public, target_ref="synthetic-zap-active-other") == "TARGET_MISMATCH"
    )


def test_checked_in_operator_authorization_verifies_with_its_public_key_only() -> None:
    """This is an end-to-end verification of the generated artifact, never a private-key read."""

    status = verify_countersign(
        capability_id="zap_active_reflected_xss_v1",
        profile_id="ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        environment="SYNTHETIC_LAB",
        target_ref="synthetic-zap-active-vulnerable",
        countersign_path=COUNTERSIGN_PATH,
        public_key_path=OPERATOR_PUBLIC_KEY_PATH,
    )
    assert status.valid
    assert status.signer_key_id == "efe-phase15-operator-20260921"
    assert status.rule_id == 40012


def test_coordinated_record_and_manifest_edits_fail_without_operator_signature(
    tmp_path: Path,
) -> None:
    countersign, public = _signed(tmp_path)
    raw = json.loads(countersign.read_text())
    raw["authorization"]["signer_key_id"] = "other-test-key"
    countersign.write_text(json.dumps(raw))
    assert _verify(countersign, public) == "SIGNATURE_INVALID"


def test_expired_and_drifted_authorizations_fail_before_use(tmp_path: Path) -> None:
    countersign, public = _signed(
        tmp_path, expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    )
    assert _verify(countersign, public) == "AUTHORIZATION_EXPIRED"
    countersign, public = _signed(tmp_path)
    drift = tmp_path / "manifest.json"
    drift.write_bytes(MANIFEST_PATH.read_bytes() + b"\n")
    assert _verify(countersign, public, manifest_path=drift) == "MANIFEST_DIGEST_MISMATCH"


def test_malformed_unknown_key_and_stale_authorizations_fail_closed(tmp_path: Path) -> None:
    countersign, public = _signed(tmp_path)
    countersign.write_text("{not-json")
    assert _verify(countersign, public) == "COUNTERSIGN_MALFORMED"

    countersign, public = _signed(tmp_path)
    unknown = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public.write_text(unknown.hex())
    assert _verify(countersign, public) == "SIGNATURE_INVALID"

    countersign, public = _signed(tmp_path, signer_key_id="unknown-operator-key")
    assert _verify(countersign, public) == "SIGNER_KEY_UNTRUSTED"

    countersign, public = _signed(
        tmp_path, issued_at=(datetime.now(UTC) - timedelta(days=8)).isoformat()
    )
    assert _verify(countersign, public) == "AUTHORIZATION_STALE"
