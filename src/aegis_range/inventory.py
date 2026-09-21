"""Controller-owned Phase 1.6 target inventory; never built from planner input."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Environment = Literal["SYNTHETIC_RANGE"]


@dataclass(frozen=True)
class RangeTarget:
    target_ref: str
    application_id: str
    name: str
    origin: str
    management_origin: str
    openapi_path: str
    environment: Environment = "SYNTHETIC_RANGE"
    synthetic_data_only: bool = True
    reset_available: bool = True

    def scanner_projection(self) -> dict[str, object]:
        """The safe inventory projection: no mode, answer key, probes or management origin."""

        return {
            "target_ref": self.target_ref,
            "application_id": self.application_id,
            "name": self.name,
            "origin": self.origin,
            "openapi_url": self.origin + self.openapi_path,
            "environment": self.environment,
            "synthetic_data_only": self.synthetic_data_only,
        }


RANGE_TARGETS: dict[str, RangeTarget] = {
    item.application_id: item
    for item in (
        RangeTarget(
            target_ref="range-bank",
            application_id="aegis-bank",
            name="Aegis Bank",
            origin="http://aegis-bank:8101",
            management_origin="http://aegis-bank-control:8101",
            openapi_path="/openapi.json",
        ),
        RangeTarget(
            target_ref="range-shop",
            application_id="aegis-shop",
            name="Aegis Shop",
            origin="http://aegis-shop:8102",
            management_origin="http://aegis-shop-control:8102",
            openapi_path="/openapi.json",
        ),
        RangeTarget(
            target_ref="range-ops",
            application_id="aegis-ops",
            name="Aegis Ops",
            origin="http://aegis-ops:8103",
            management_origin="http://aegis-ops-control:8103",
            openapi_path="/openapi.json",
        ),
        RangeTarget(
            target_ref="range-cloud",
            application_id="aegis-cloud",
            name="Aegis Cloud",
            origin="http://aegis-cloud:8104",
            management_origin="http://aegis-cloud-control:8104",
            openapi_path="/openapi.json",
        ),
    )
}


def scanner_inventory() -> list[dict[str, object]]:
    return [RANGE_TARGETS[key].scanner_projection() for key in sorted(RANGE_TARGETS)]
