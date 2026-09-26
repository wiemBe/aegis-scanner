"""Production deployment support (WP2 / G-ROLL-1).

A small, typed, fail-closed layer that keeps the production rollout path deterministic:

- :mod:`aegis.deploy.image_reference` validates that a production image reference is an immutable
  ``registry/repository@sha256:<64 lowercase hex>`` digest — no mutable tag, no ``latest``, no
  local-build fallback.
- :mod:`aegis.deploy.preflight` is the operator CLI that validates ``AEGIS_IMAGE`` and proves, from
  the rendered production Compose configuration, that both long-lived services use exactly that
  digest and carry no active ``build:`` fallback. It never pulls the image, never touches secrets.
"""

from aegis.deploy.image_reference import (
    ImageReferenceError,
    ImmutableImageReference,
    parse_immutable_image_reference,
)

__all__ = [
    "ImageReferenceError",
    "ImmutableImageReference",
    "parse_immutable_image_reference",
]
