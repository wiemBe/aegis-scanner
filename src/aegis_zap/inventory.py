"""The fixed, controller-owned synthetic-lab inventory for the ZAP passive profile.

Every ZAP execution is derived from an entry here: an approved origin, a checked-in source OpenAPI
document, the exact operation ids that may be projected, and the bounded non-secret values for
their path parameters. Nothing here is supplied by the model, the operator request body or the RPC
caller; both the controller and the isolated runner import this module and resolve a target
REFERENCE themselves, so a mis-wired control plane cannot point ZAP anywhere else.

``ACCEPTANCE`` entries carry the vulnerable/patched scenario. ``NEGATIVE_CONTROL`` entries exist
only to prove that the projection and the runtime guard fail closed; they are clearly labelled and
can never produce a PASS.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

LAB_ORIGIN = "http://lab-api:8001"
SOURCES_DIR = Path(__file__).with_name("sources")
MAIN_SOURCE = "synthetic-lab-openapi.json"
CATALOG_ID = "synthetic-catalog-1"

Purpose = Literal["ACCEPTANCE", "NEGATIVE_CONTROL"]
Variant = Literal["vulnerable", "patched", "negative"]


@dataclass(frozen=True)
class ZapTarget:
    target_ref: str
    origin: str
    variant: Variant
    source: str
    operation_ids: tuple[str, ...]
    path_values: tuple[tuple[str, str], ...]
    purpose: Purpose
    title: str
    scenario_operation_id: str | None = None
    control_operation_id: str | None = None
    negative_class: str | None = None

    @property
    def expected_requests(self) -> int:
        """One request per approved operation: the importer sends nothing else."""

        return len(self.operation_ids)

    @property
    def base_path(self) -> str:
        segment = self.variant if self.purpose == "ACCEPTANCE" else "negative"
        return f"/lab/zap/{segment}"

    def path_value(self, name: str) -> str | None:
        return dict(self.path_values).get(name)


def _acceptance(variant: Literal["vulnerable", "patched"]) -> ZapTarget:
    prefix = "labZapVulnerable" if variant == "vulnerable" else "labZapPatched"
    return ZapTarget(
        target_ref=f"synthetic-zap-{variant}",
        origin=LAB_ORIGIN,
        variant=variant,
        source=MAIN_SOURCE,
        operation_ids=(f"{prefix}Status", f"{prefix}Catalog"),
        path_values=(("catalog_id", CATALOG_ID),),
        purpose="ACCEPTANCE",
        title=f"Synthetic ZAP passive header scenario ({variant})",
        scenario_operation_id=f"{prefix}Catalog",
        control_operation_id=f"{prefix}Status",
    )


def _negative(ref: str, source: str, ops: tuple[str, ...], negative_class: str) -> ZapTarget:
    return ZapTarget(
        target_ref=f"synthetic-zap-negative-{ref}",
        origin=LAB_ORIGIN,
        variant="negative",
        source=source,
        operation_ids=ops,
        path_values=(("catalog_id", CATALOG_ID),),
        purpose="NEGATIVE_CONTROL",
        title=f"Negative control: {negative_class.lower().replace('_', ' ')}",
        negative_class=negative_class,
    )


ZAP_TARGETS: dict[str, ZapTarget] = {
    target.target_ref: target
    for target in (
        _acceptance("vulnerable"),
        _acceptance("patched"),
        # Projection-time negative controls: rejected before any runner call or target traffic.
        _negative(
            "state-changing",
            MAIN_SOURCE,
            ("labZapVulnerableStatus", "labZapAdminPurge"),
            "STATE_CHANGING_OPERATION",
        ),
        _negative(
            "alternate-server",
            "negative-alternate-server.json",
            ("labZapVulnerableStatus",),
            "ALTERNATE_SERVER",
        ),
        _negative(
            "external-ref",
            "negative-external-ref.json",
            ("labZapVulnerableStatus",),
            "EXTERNAL_REFERENCE",
        ),
        # Runtime negative controls: valid projections whose synthetic routes misbehave. The
        # scope guard and the runner must fail these closed; they can never PASS.
        _negative("redirect", MAIN_SOURCE, ("labZapRedirectStatus",), "UNEXPECTED_REDIRECT"),
        _negative("unstable", MAIN_SOURCE, ("labZapUnstableStatus",), "UNEXPECTED_EXTRA_REQUEST"),
        _negative("slow", MAIN_SOURCE, ("labZapSlowStatus",), "TARGET_TIMEOUT"),
    )
}


def target_for_variant(variant: Literal["vulnerable", "patched"]) -> ZapTarget:
    return ZAP_TARGETS[f"synthetic-zap-{variant}"]


def source_bytes(target: ZapTarget, sources_dir: Path = SOURCES_DIR) -> bytes:
    """The exact checked-in source document bytes for a target (controller-owned)."""

    name = Path(target.source).name
    if name != target.source or not name.endswith(".json"):
        raise ValueError("inventory source must be a plain file name")
    return (sources_dir / name).read_bytes()


def source_sha256(target: ZapTarget, sources_dir: Path = SOURCES_DIR) -> str:
    return hashlib.sha256(source_bytes(target, sources_dir)).hexdigest()
