"""The fixed, controller-owned synthetic-lab inventory for the ZAP active reflected-XSS profile.

Every active execution is derived from an entry here: an approved origin, a checked-in source
OpenAPI document, the exact GET operation id that may be projected, and the single bounded query
parameter that ZAP may mutate. Nothing here is supplied by the model, the operator request body or
the RPC caller; both the controller and the isolated runner import this module and resolve a target
REFERENCE themselves.

``ACCEPTANCE`` entries carry the vulnerable/patched scenario. ``NEGATIVE_CONTROL`` entries exist
only to prove the projection fails closed; they can never produce a PASS.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

LAB_ORIGIN = "http://lab-api:8001"
SOURCES_DIR = Path(__file__).with_name("sources")
MAIN_SOURCE = "synthetic-active-openapi.json"
QUERY_PARAM = "q"

Purpose = Literal["ACCEPTANCE", "NEGATIVE_CONTROL"]
Variant = Literal["vulnerable", "patched", "negative"]


@dataclass(frozen=True)
class ZapActiveTarget:
    target_ref: str
    origin: str
    variant: Variant
    source: str
    operation_id: str
    query_param: str
    purpose: Purpose
    title: str
    negative_class: str | None = None

    @property
    def base_path(self) -> str:
        segment = self.variant if self.purpose == "ACCEPTANCE" else "negative"
        return f"/lab/zap-active/{segment}"

    @property
    def search_path(self) -> str:
        return f"/lab/zap-active/{self.variant}/search"


def _acceptance(variant: Literal["vulnerable", "patched"]) -> ZapActiveTarget:
    op = "labZapActiveVulnerableSearch" if variant == "vulnerable" else "labZapActivePatchedSearch"
    return ZapActiveTarget(
        target_ref=f"synthetic-zap-active-{variant}",
        origin=LAB_ORIGIN,
        variant=variant,
        source=MAIN_SOURCE,
        operation_id=op,
        query_param=QUERY_PARAM,
        purpose="ACCEPTANCE",
        title=f"Synthetic ZAP active reflected-XSS scenario ({variant})",
    )


def _negative(ref: str, source: str, op: str, negative_class: str) -> ZapActiveTarget:
    return ZapActiveTarget(
        target_ref=f"synthetic-zap-active-negative-{ref}",
        origin=LAB_ORIGIN,
        variant="negative",
        source=source,
        operation_id=op,
        query_param=QUERY_PARAM,
        purpose="NEGATIVE_CONTROL",
        title=f"Negative control: {negative_class.lower().replace('_', ' ')}",
        negative_class=negative_class,
    )


ZAP_ACTIVE_TARGETS: dict[str, ZapActiveTarget] = {
    target.target_ref: target
    for target in (
        _acceptance("vulnerable"),
        _acceptance("patched"),
        _negative(
            "state-changing",
            MAIN_SOURCE,
            "labZapActiveAdminPurge",
            "STATE_CHANGING_OPERATION",
        ),
        _negative(
            "alternate-server",
            "negative-active-alternate-server.json",
            "labZapActiveVulnerableSearch",
            "ALTERNATE_SERVER",
        ),
        _negative(
            "external-ref",
            "negative-active-external-ref.json",
            "labZapActiveVulnerableSearch",
            "EXTERNAL_REFERENCE",
        ),
    )
}


def target_for_variant(variant: Literal["vulnerable", "patched"]) -> ZapActiveTarget:
    return ZAP_ACTIVE_TARGETS[f"synthetic-zap-active-{variant}"]


def source_bytes(target: ZapActiveTarget, sources_dir: Path = SOURCES_DIR) -> bytes:
    name = Path(target.source).name
    if name != target.source or not name.endswith(".json"):
        raise ValueError("inventory source must be a plain file name")
    return (sources_dir / name).read_bytes()


def source_sha256(target: ZapActiveTarget, sources_dir: Path = SOURCES_DIR) -> str:
    return hashlib.sha256(source_bytes(target, sources_dir)).hexdigest()
