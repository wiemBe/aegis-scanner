"""Operator-reviewed, immutably pinned container image supply chain for Phase 2.8.

Every image the acceptance harness runs is pinned by an *immutable* reference and recorded with its
repository, immutable digest, actual tool version and acquisition/build provenance. A mutable tag
(``:latest`` or any ``name:tag``) is never an acceptable run reference; :func:`require_pinned`
rejects one fail-closed, which is exercised directly by the ``unpinned image`` negative test.

Two provenance shapes appear here, both immutable:

* a **registry** image is pinned by its RepoDigest ``repository@sha256:<64hex>`` resolved from the
  operator's Docker environment;
* a **locally-built** image (the sqlmap worker and the range target) is built egress-free from a
  registry-pinned base plus a sha256-verified artifact, and its immutable run reference is the
  content-addressed image ID ``sha256:<64hex>`` resolved from the local daemon at run time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

# An immutable run reference is either a registry RepoDigest (repository@sha256:...) or a bare
# content-addressed image ID (sha256:...). Anything else — a bare repository, a floating tag, or
# ``latest`` — is mutable and rejected before any container is created.
_DIGEST = r"sha256:[0-9a-f]{64}"
_REPO_DIGEST_RE = re.compile(rf"^[A-Za-z0-9][\w./:-]*@{_DIGEST}$")
_IMAGE_ID_RE = re.compile(rf"^{_DIGEST}$")


class UnpinnedImageError(ValueError):
    """Raised when a container run reference is not an immutable digest/image-id pin."""


def require_pinned(reference: str) -> str:
    """Return ``reference`` iff it is an immutable pin, else raise :class:`UnpinnedImageError`.

    Accepts ``repository@sha256:<64hex>`` (registry RepoDigest) or ``sha256:<64hex>`` (local image
    id). Rejects a bare repository, any floating tag such as ``repo:1.2`` and, explicitly,
    ``latest`` in any position."""

    ref = reference.strip()
    if not ref:
        raise UnpinnedImageError("EMPTY_IMAGE_REFERENCE")
    if "latest" in ref:
        raise UnpinnedImageError(f"MUTABLE_LATEST_TAG_FORBIDDEN:{ref}")
    if _REPO_DIGEST_RE.match(ref) or _IMAGE_ID_RE.match(ref):
        return ref
    raise UnpinnedImageError(f"UNPINNED_IMAGE_REFERENCE:{ref}")


@dataclass(frozen=True)
class PinnedImage:
    """An operator-reviewed, immutable image record.

    ``run_reference`` is what a container is actually started from. For a registry image it is the
    RepoDigest; for a locally-built image it is filled in at run time with the resolved local image
    id (``build_context`` describes how it is produced and from which pinned inputs)."""

    key: str
    repository: str
    digest: str
    tool_version: str
    provenance: str
    kind: str  # "registry" | "local-build"
    build_context: str = ""

    def run_reference(self) -> str:
        """The immutable reference used to run this image (validated fail-closed)."""

        if self.kind == "registry":
            return require_pinned(f"{self.repository}@{self.digest}")
        return require_pinned(self.digest)


# The registry base is the single upstream trust anchor. Its digest was resolved from the operator's
# Docker environment (2026-09-25, linux/amd64) and is the same one baked into both local builds.
_PY_BASE_DIGEST = "sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"

PINNED_IMAGES: dict[str, PinnedImage] = {
    "python-base": PinnedImage(
        key="python-base",
        repository="python",
        digest=_PY_BASE_DIGEST,
        tool_version="CPython 3.12 (Debian 12 slim)",
        provenance=(
            "Official Docker Hub library/python image. Tag `3.12-slim` resolved to this immutable "
            "RepoDigest at pull time on 2026-09-25 (linux/amd64) and is referenced only by digest."
        ),
        kind="registry",
    ),
    "sqlmap-runner": PinnedImage(
        key="sqlmap-runner",
        repository="aegis-sqlmap-runner",
        # Filled from `docker image inspect` at run time; the immutable inputs below are the pin.
        digest="",
        tool_version="sqlmap 1.10.9",
        provenance=(
            "Locally built (deploy/sqlmap-runner/Dockerfile) from python-base@"
            f"{_PY_BASE_DIGEST} plus the sqlmap 1.10.9 pure-python wheel "
            "(sha256:75aa0c244c687f82a7b3f4583d0655a352a443f835ec75fc83fe4d5f44a206b8) acquired "
            "host-side through the audited HTTPS proxy and installed with --no-index, so the image "
            "BUILD performs zero network egress. Entrypoint is the sqlmap binary; no shell."
        ),
        kind="local-build",
        build_context="deploy/sqlmap-runner",
    ),
    "range-target": PinnedImage(
        key="range-target",
        repository="aegis-range-phase28",
        digest="",
        tool_version="aegis_range.shop (first-party) on CPython 3.12",
        provenance=(
            "Locally built (deploy/range/Dockerfile.phase-2-8) from python-base@"
            f"{_PY_BASE_DIGEST} plus a host-fetched cp312/manylinux wheelhouse "
            "(fastapi 0.116.1, uvicorn 0.35.0, pydantic 2.13.5 + transitive) installed with "
            "--no-index (zero build egress) and the first-party aegis_range source."
        ),
        kind="local-build",
        build_context="deploy/range/Dockerfile.phase-2-8",
    ),
    # Recon tool images pulled from Docker Hub and pinned by the RepoDigest resolved on 2026-09-25.
    # Only the tools whose image was actually acquirable are recorded; ffuf/dnsx/tlsx are NOT here
    # (ffuf publishes no Docker Hub image under the recorded reference, and dnsx/tlsx have no honest
    # DNS/TLS fixture in the synthetic range), so those capabilities stay NOT_EVALUATED.
    "httpx": PinnedImage(
        key="httpx",
        repository="projectdiscovery/httpx",
        digest="sha256:c8eaaf8be57df7e8c9dc573aeebe5a52192dbc822e3415d0c20f014f89957af5",
        tool_version="httpx v1.6.9",
        provenance=(
            "Official ProjectDiscovery image. Tag `v1.6.9` resolved to this immutable RepoDigest "
            "at pull time on 2026-09-25 (linux/amd64); referenced only by digest."
        ),
        kind="registry",
    ),
    "katana": PinnedImage(
        key="katana",
        repository="projectdiscovery/katana",
        digest="sha256:a045fd0428e64456ee299cab48d0a3db48c7c4d481fb21f74bc672839a9fc9e3",
        tool_version="katana v1.1.2",
        provenance=(
            "Official ProjectDiscovery image. Tag `v1.1.2` resolved to this immutable RepoDigest "
            "at pull time on 2026-09-25 (linux/amd64); referenced only by digest."
        ),
        kind="registry",
    ),
}


def resolve_local_build(image: PinnedImage, image_id: str) -> PinnedImage:
    """Return a copy of a local-build image with its immutable content-addressed id filled in.

    ``image_id`` is a ``sha256:<64hex>`` from ``docker image inspect --format {{.Id}}`` on the
    operator's daemon; it is validated as an immutable pin before being recorded."""

    if image.kind != "local-build":
        raise UnpinnedImageError(f"NOT_A_LOCAL_BUILD:{image.key}")
    return replace(image, digest=require_pinned(image_id))
