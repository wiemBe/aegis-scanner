"""Structural secret-marker scan reused from the corrected Phase 1.7-A behaviour.

A leaked HTTP Authorization header appears as a STRING value (``"authorization": "<value>"``). The
bounded contracts also define a legitimate structured field named ``authorization`` that is always
an OBJECT (``"authorization": {``), so the string-value form discriminates a real credential leak
from the contract's own field without weakening detection. Actual bearer credentials remain covered
by the ``bearer `` marker.
"""

from __future__ import annotations

SECRET_MARKERS: tuple[str, ...] = (
    "range-user-alex",
    "range-user-blair",
    'authorization": "',
    "bearer ",
    "ai_auth_token",
)


def scan_secret_markers(text: str) -> list[str]:
    """Return the secret markers present in ``text`` (case-insensitive)."""

    lowered = text.lower()
    return [marker for marker in SECRET_MARKERS if marker in lowered]
