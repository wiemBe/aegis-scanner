"""Synthetic reset-scoped credentials shared only by cloud fixture services."""

from __future__ import annotations

import hashlib
import hmac


def credential(generation: int, audience: str) -> str:
    body = f"meta.{generation}.{audience}"
    signature = hashlib.sha256(f"AEGIS-SYNTHETIC-CLOUD:{body}".encode()).hexdigest()[:24]
    return f"{body}.{signature}"


def validate(value: str, generation: int, *, audience: str | None) -> bool:
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != "meta" or parts[1] != str(generation):
        return False
    expected = credential(generation, parts[2])
    return hmac.compare_digest(value, expected) and (audience is None or parts[2] == audience)
