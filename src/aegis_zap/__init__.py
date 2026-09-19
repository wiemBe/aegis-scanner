"""Shared, dependency-light ZAP integration core for Aegis Phase 1.3.

Imported by BOTH sides of the controller/runner boundary:

- the control plane (``aegis``) uses it to project the controller-owned OpenAPI inventory, build
  and validate the typed runner RPC and re-validate the runner's typed responses;
- the isolated ``zap_runner`` uses it to verify the pinned image/add-on inventory, re-derive the
  projection from its own copy of the inventory, generate the fixed Automation Framework plan and
  argv, extract bounded facts from ZAP output and parse the ZAP report.

It depends only on the standard library and pydantic and stays compatible with the Python 3.11
interpreter shipped inside the pinned ZAP image. It has no settings, credentials or LLM code.
"""

from aegis_zap.manifest import MANIFEST_PATH, ZapManifest, load_manifest, manifest_digest

__all__ = ["MANIFEST_PATH", "ZapManifest", "load_manifest", "manifest_digest"]
