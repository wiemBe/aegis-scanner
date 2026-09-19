"""The fixed synthetic-lab target inventory for Nuclei.

Both the controller and the runner resolve a target REFERENCE through this inventory; neither ever
accepts a URL from the AI, the operator request body or the RPC caller. The runner re-resolves the
reference itself and refuses a request whose controller-resolved origin disagrees (defense in
depth), so a compromised or mis-wired control plane still cannot point Nuclei elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

LAB_ORIGIN = "http://lab-api:8001"


@dataclass(frozen=True)
class NucleiTarget:
    target_ref: str
    origin: str
    base_path: str
    variant: Literal["vulnerable", "patched"]
    operation_id: str

    @property
    def target_url(self) -> str:
        return f"{self.origin}{self.base_path}"


NUCLEI_TARGETS: dict[str, NucleiTarget] = {
    "synthetic-scm-vulnerable": NucleiTarget(
        target_ref="synthetic-scm-vulnerable",
        origin=LAB_ORIGIN,
        base_path="/lab/nuclei/vulnerable",
        variant="vulnerable",
        operation_id="labScmMetadataVulnerable",
    ),
    "synthetic-scm-patched": NucleiTarget(
        target_ref="synthetic-scm-patched",
        origin=LAB_ORIGIN,
        base_path="/lab/nuclei/patched",
        variant="patched",
        operation_id="labScmMetadataPatched",
    ),
}


def target_for_variant(variant: Literal["vulnerable", "patched"]) -> NucleiTarget:
    return NUCLEI_TARGETS[f"synthetic-scm-{variant}"]


def origin_parts(origin: str) -> tuple[str, str, int]:
    """(scheme, host, port) of an inventory origin. Raises on anything but plain http(s)://host:port."""

    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("origin must be a bare scheme://host[:port]")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, parsed.hostname.lower(), port
