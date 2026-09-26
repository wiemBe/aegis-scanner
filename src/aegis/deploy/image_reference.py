"""Immutable production image-reference validation (WP2 / G-ROLL-1).

A production rollout is deterministic only when the image cannot move underneath it. A mutable tag
(``latest``, ``0.2.0``) can be repushed to point at different bits; a ``sha256`` digest cannot. This
module is the single fail-closed gate: it accepts *only* a reference of the form

    registry/repository@sha256:<64 lowercase hex characters>

and rejects everything else — a missing reference, a tag-only reference, ``latest``, a malformed
digest, or a non-``sha256`` digest algorithm. It is a pure function with no I/O and no dependency on
Docker, so it is cheap to unit-test exhaustively and safe to call before any deployment side effect.

The validator never emits registry or provider credentials; it only inspects the reference string it
is given and returns it unchanged when valid.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DIGEST_ALGORITHM = "sha256"

# A single, anchored grammar for an immutable image reference:
#   [registry-host[:port]/] path[/path...] [:tag] @sha256:<64 lowercase hex>
# The digest is REQUIRED, must be sha256, and must be exactly 64 lowercase hex characters. A bare
# name, a tag-only name, ``latest``, an uppercase digest, or a non-sha256 algorithm all fail to
# match this pattern.
_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_REGISTRY_HOST = r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]+)?"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}"
_REFERENCE_RE = re.compile(
    r"^"
    r"(?P<name>"
    rf"(?:{_REGISTRY_HOST}/)?"
    rf"{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*"
    r")"
    rf"(?::(?P<tag>{_TAG}))?"
    rf"@(?P<digest>{DIGEST_ALGORITHM}:[0-9a-f]{{64}})"
    r"$"
)


class ImageReferenceError(ValueError):
    """A production image reference is not a valid immutable ``sha256`` digest reference."""


@dataclass(frozen=True)
class ImmutableImageReference:
    """A validated immutable image reference.

    ``reference`` is the exact, unmodified string the operator supplied (so it can be handed to
    Compose verbatim); ``name`` and ``digest`` are its parsed parts for diagnostics.
    """

    reference: str
    name: str
    digest: str


def parse_immutable_image_reference(raw: str | None) -> ImmutableImageReference:
    """Return the validated reference, or raise :class:`ImageReferenceError` (fail closed).

    Rejects, with a fixed, credential-free message: a missing/empty reference, a reference with no
    ``@sha256`` digest (tag-only, including ``latest``), a non-``sha256`` digest algorithm, and any
    malformed or non-lowercase digest. A valid reference is returned unchanged.
    """

    if raw is None:
        raise ImageReferenceError(
            "image reference is missing; set an immutable registry/repository@sha256:<64 hex>"
        )
    reference = raw.strip()
    if not reference:
        raise ImageReferenceError(
            "image reference is empty; set an immutable registry/repository@sha256:<64 hex>"
        )
    if "@" not in reference:
        raise ImageReferenceError(
            "image reference is tag-only or has no digest; an immutable "
            "registry/repository@sha256:<64 hex> reference is required"
        )
    algorithm = reference.rsplit("@", 1)[1].split(":", 1)[0]
    if algorithm != DIGEST_ALGORITHM:
        raise ImageReferenceError(
            f"image digest algorithm {algorithm!r} is not supported; only "
            f"{DIGEST_ALGORITHM} digests are accepted"
        )
    match = _REFERENCE_RE.fullmatch(reference)
    if match is None:
        raise ImageReferenceError(
            "image reference is malformed; expected registry/repository@sha256: followed by "
            "exactly 64 lowercase hex characters"
        )
    return ImmutableImageReference(
        reference=reference,
        name=match.group("name"),
        digest=match.group("digest"),
    )
