"""Phase 2.8 containerized synthetic capability acceptance.

This package runs *real* tool containers on an internal, no-egress synthetic-range network and
routes their real evidence through the preserved production normalizer and an independent
deterministic verifier. It never calls an AI provider and never widens the offline
authority model: a tool's own claim is always audit-only (``TOOL_REPORTED``/``AEGIS_CORRELATED``);
only the independent verifier, using controller ground truth, can promote a finding to ``VERIFIED``.
"""

from __future__ import annotations

from aegis.container_acceptance.contracts import (
    ContainerAcceptanceError,
    EvidenceCategory,
    ToolAcceptanceStatus,
)
from aegis.container_acceptance.images import (
    PINNED_IMAGES,
    PinnedImage,
    UnpinnedImageError,
    require_pinned,
)

__all__ = [
    "PINNED_IMAGES",
    "ContainerAcceptanceError",
    "EvidenceCategory",
    "PinnedImage",
    "ToolAcceptanceStatus",
    "UnpinnedImageError",
    "require_pinned",
]
