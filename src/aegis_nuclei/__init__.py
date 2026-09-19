"""Shared, dependency-light Nuclei integration core for Aegis Phase 1.2.

This package is imported by BOTH sides of the controller/runner boundary:

- the control plane (``aegis``) uses it to construct and validate typed runner RPC requests and to
  re-validate the runner's typed responses;
- the isolated ``nuclei_runner`` service uses it to verify the pinned template manifest, admit
  templates, build the fixed Nuclei argv and parse Nuclei JSONL output.

It deliberately depends only on the standard library, pydantic and PyYAML so the runner image can
carry it without the rest of the Aegis control plane (no settings, no synthetic credentials, no LLM
provider code).
"""

from aegis_nuclei.manifest import (
    MANIFEST_PATH,
    TemplateEntry,
    TemplateManifest,
    load_manifest,
    manifest_digest,
)

__all__ = [
    "MANIFEST_PATH",
    "TemplateEntry",
    "TemplateManifest",
    "load_manifest",
    "manifest_digest",
]
