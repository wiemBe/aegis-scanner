"""Deterministic TEST_FIXTURE for the prior-evidence SHA256 manifest byte-identity contract.

The production check (``test_prior_evidence_manifest_is_byte_identical``) validates that the real,
gitignored Phase 0.7 / Phase 0.8 evidence files still match their recorded ``*.sha256`` manifests.
That manifest and its referenced files live only in a developer's private ``artifacts/`` directory,
so in a fresh checkout there is nothing to validate.

This module provides a tiny, committed, synthetic manifest + evidence files so the *byte-identity
contract itself* is exercised in every checkout. The files are unmistakably ``TEST_FIXTURE`` and are
never treated as real acceptance evidence. The generator is deterministic, so
``tests/test_portable_fixtures.py`` can assert it reproduces the committed bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

FIXTURE_RELDIR = "tests/fixtures/prior_evidence"

# Fixed synthetic evidence contents. The leading marker makes their nature unmistakable.
_FILES: dict[str, str] = {
    "evidence-alpha.txt": "TEST_FIXTURE prior-evidence alpha\nsynthetic, never live evidence\n",
    "evidence-beta.txt": "TEST_FIXTURE prior-evidence beta\ndeterministic byte-identity sample\n",
}
MANIFEST_NAME = "manifest.sha256"


@dataclass(frozen=True)
class ManifestFixture:
    directory: Path
    manifest: Path


def write_fixture(repo_root: Path) -> ManifestFixture:
    """Write the synthetic evidence files and their manifest; return the manifest path."""

    dest = repo_root / FIXTURE_RELDIR
    dest.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for name in sorted(_FILES):
        (dest / name).write_text(_FILES[name], encoding="utf-8")
        digest = hashlib.sha256((dest / name).read_bytes()).hexdigest()
        # Manifest paths are repository-root relative, exactly like the production manifests.
        lines.append(f"{digest}  {FIXTURE_RELDIR}/{name}")
    manifest = dest / MANIFEST_NAME
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ManifestFixture(directory=dest, manifest=manifest)


def ensure_fixture(repo_root: Path) -> ManifestFixture:
    """Resolve the committed fixture, regenerating deterministically only if a file is missing."""

    dest = repo_root / FIXTURE_RELDIR
    manifest = dest / MANIFEST_NAME
    if manifest.is_file() and all((dest / name).is_file() for name in _FILES):
        return ManifestFixture(directory=dest, manifest=manifest)
    return write_fixture(repo_root)
