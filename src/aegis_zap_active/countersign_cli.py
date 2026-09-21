"""Offline-only Ed25519 signer for the Phase 1.5 authorization record.

This module is never copied into runtime images.  It requires an operator-provided private PEM
file and writes only the public key and signed authorization selected by explicit CLI paths.
"""

from __future__ import annotations

import argparse
import base64
import json
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_zap_active.countersign import SignedAuthorization
from aegis_zap_active.manifest import load_manifest, manifest_digest


def _record(key_id: str, issued_at: str, expiry: str | None) -> SignedAuthorization:
    manifest = load_manifest()
    add_on_digests: dict[str, str] = {}
    for item in ("ascanrules", "oast", "database"):
        pin = manifest.add_on(item)
        if pin is None:
            raise RuntimeError(f"missing mandatory add-on {item}")
        add_on_digests[item] = pin.sha256
    return SignedAuthorization.model_validate_json(
        json.dumps(
            {
                "schema": "aegis.zap.active-authorization/2",
                "record_id": "countersign-zap-active-reflected-xss-v2",
                "signer_key_id": key_id,
                "issued_at": issued_at,
                "expires_at": expiry,
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
                "manifest_sha256": manifest_digest(),
                "add_on_digests": add_on_digests,
                "target_refs": ["synthetic-zap-active-vulnerable", "synthetic-zap-active-patched"],
                "allowed_methods": ["GET"],
            }
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="offline Phase 1.5 Ed25519 authorization signer")
    parser.add_argument(
        "--private-key", type=Path, required=True, help="operator-owned Ed25519 PEM"
    )
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-key-output", type=Path, required=True)
    parser.add_argument("--issued-at", default=datetime.now(UTC).replace(microsecond=0).isoformat())
    parser.add_argument("--expires-at")
    parser.add_argument("--print-canonical", action="store_true")
    args = parser.parse_args()
    private = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise SystemExit("refused: private key is not Ed25519")
    record = _record(args.key_id, args.issued_at, args.expires_at)
    if args.print_canonical:
        print(record.canonical().decode("ascii"))
    signature = (
        base64.urlsafe_b64encode(private.sign(record.canonical())).decode("ascii").rstrip("=")
    )
    signed = {
        "authorization": record.model_dump(mode="json", by_alias=True),
        "signature": signature,
    }
    args.output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    args.public_key_output.write_text(public.hex() + "\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
