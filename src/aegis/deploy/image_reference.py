"""Immutable production image-reference validation (WP2 / G-ROLL-1).

A production rollout is deterministic only when the image cannot move underneath it. A mutable tag
(``latest``, ``0.2.0``) can be repushed to point at different bits; a ``sha256`` digest cannot. This
module is the single fail-closed gate: it accepts *only* a fully-qualified reference of the form

    registry/repository@sha256:<64 lowercase hex characters>

with an **explicit registry host** (a dotted domain, a ``host:port``, or ``localhost[:port]``) and
at least one repository path component. It rejects everything else — a missing reference, a
bare/local name (``aegis@sha256:...``), a tag-only reference, ``latest``, a tag+digest reference, a
malformed or non-lowercase digest, a non-``sha256`` algorithm, and any leading/trailing whitespace
(rejected, never stripped).

Security: the validator is a pure function with no I/O. It **never** echoes the caller-supplied
reference, its (possibly attacker-controlled) digest algorithm, or any secret-shaped input in an
error message — every diagnostic is a fixed constant. A valid reference is returned byte-for-byte
unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DIGEST_ALGORITHM = "sha256"

# An explicit registry host: a dotted domain, ``localhost``, or any host with an explicit ``:port``.
# A bare single-label name with neither a dot nor a port (Docker's implicit docker.io namespace,
# such as ``library`` in ``library/aegis``) is NOT a registry, so ``aegis/app@...`` is rejected.
_DOTTED_HOST = r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+"
_REGISTRY_HOST = rf"(?:(?:{_DOTTED_HOST}|localhost)(?::[0-9]+)?|[a-z0-9]+(?:-[a-z0-9]+)*:[0-9]+)"
# A repository path component. Lowercase only; no ``:`` (a ``:`` in the final component is a tag).
_REPO_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"

# Anchored grammar: <registry-host>/<repo>[/<repo>...]@sha256:<64 lowercase hex>. No tag is allowed
# (that would be a mutable tag+digest reference), and the digest must be exactly 64 lowercase hex.
_REFERENCE_RE = re.compile(
    r"\A"
    r"(?P<name>"
    rf"(?P<registry>{_REGISTRY_HOST})"
    rf"/(?P<repository>{_REPO_COMPONENT}(?:/{_REPO_COMPONENT})*)"
    r")"
    rf"@(?P<digest>{DIGEST_ALGORITHM}:[0-9a-f]{{64}})"
    r"\Z"
)

# Fixed, credential-free diagnostics. None interpolates the caller's input.
_CONTRACT_HINT = (
    "expected an immutable registry/repository@sha256:<64 lowercase hex> reference "
    "(explicit registry host, at least one repository component, no tag)"
)


class ImageReferenceError(ValueError):
    """A production image reference is not a valid immutable ``sha256`` digest reference."""


@dataclass(frozen=True)
class ImmutableImageReference:
    """A validated immutable image reference.

    ``reference`` is the exact, unmodified string the operator supplied (so it can be handed to
    Compose verbatim); ``name`` and ``digest`` are its parsed parts for internal use only — they are
    never placed in an error message.
    """

    reference: str
    name: str
    digest: str


def parse_immutable_image_reference(raw: str | None) -> ImmutableImageReference:
    """Return the validated reference, or raise :class:`ImageReferenceError` (fail closed).

    Rejects — with a fixed, credential-free message that never echoes the input — a missing/empty
    reference, one with leading/trailing whitespace, a bare/local name, a tag-only or tag+digest
    reference, ``latest``, a non-``sha256`` algorithm, and any malformed or non-lowercase digest. A
    valid reference is returned byte-for-byte unchanged.
    """

    if raw is None:
        raise ImageReferenceError(f"image reference is missing; {_CONTRACT_HINT}")
    if raw == "":
        raise ImageReferenceError(f"image reference is empty; {_CONTRACT_HINT}")
    if raw != raw.strip():
        raise ImageReferenceError(
            f"image reference must not have leading or trailing whitespace; {_CONTRACT_HINT}"
        )
    match = _REFERENCE_RE.fullmatch(raw)
    if match is None:
        raise ImageReferenceError(f"image reference is invalid; {_CONTRACT_HINT}")
    return ImmutableImageReference(
        reference=raw,
        name=match.group("name"),
        digest=match.group("digest"),
    )
