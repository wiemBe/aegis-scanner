"""Fail-closed production deployment support.

A small, typed, fail-closed layer that keeps the production rollout path deterministic:

- :mod:`aegis.deploy.image_reference` validates that a production image reference is an immutable
  ``registry/repository@sha256:<64 lowercase hex>`` digest — no mutable tag, no ``latest``, no
  local-build fallback.
- :mod:`aegis.deploy.preflight` is the operator CLI that validates ``AEGIS_IMAGE`` and proves, from
  the rendered production Compose configuration, that both long-lived services use exactly that
  digest and carry no active ``build:`` fallback. It never pulls the image, never touches secrets.
- :mod:`aegis.deploy.private_provider_preflight` extends that proof to the company-private gateway,
  credential mount, networks, and immutable loopback ingress.
- :mod:`aegis.deploy.staging_gate` records bounded, read-only healthy/fail-closed observations.
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
