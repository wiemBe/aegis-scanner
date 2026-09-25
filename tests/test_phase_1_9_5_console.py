"""Phase 1.9.5 operator-console productization: authorized target inventory and plain-language
assessment-profile projections, plus their read-only controller endpoints."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from aegis import main as main_module
from aegis.console_catalog import (
    _project_capability,
    profile_directory,
    profile_display_name,
    target_directory,
)
from aegis.target_inventory import TargetInventoryStore


def _use_temp_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> TargetInventoryStore:
    """Point the app's controller-owned inventory at a writable temp database. The module-level
    store defaults to the production mount, which the offline suite cannot open."""

    store = TargetInventoryStore(str(tmp_path / "targets.db"))
    store.initialize()
    monkeypatch.setattr(main_module, "target_store", store)
    return store

# The four operator-facing catalog profiles, in display order.
OPERATOR_PROFILE_IDS = [
    "aegis-native-bola-synthetic",
    "NUCLEI_LAB_SAFE_HTTP_V1",
    "ZAP_LAB_PASSIVE_OPENAPI_V1",
    "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
]


def test_target_directory_is_authorized_inventory_only() -> None:
    items = target_directory()
    refs = {item["target_ref"] for item in items}
    # The default native target plus the range inventory.
    assert "synthetic-bank-api" in refs
    assert {"range-bank", "range-shop", "range-ops", "range-cloud"} <= refs
    required = {
        "target_ref",
        "name",
        "type",
        "target_type",
        "environment",
        "description",
        "supported_profile_ids",
    }
    for item in items:
        # The onboarding projection carries scope/lifecycle metadata, but never management
        # origins, credential *values*, modes or answer-key material.
        assert required <= set(item)
        assert item["synthetic"] is True
        assert item["credential_reference"] is None
        assert "management" not in str(item).lower()


def test_profile_directory_reflects_availability_and_reasons() -> None:
    availability = {
        "aegis-native-bola-synthetic": {"available": True, "reason": ""},
        "NUCLEI_LAB_SAFE_HTTP_V1": {"available": False, "reason": "Nuclei disabled."},
        "ZAP_LAB_PASSIVE_OPENAPI_V1": {"available": False, "reason": "ZAP disabled."},
        "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1": {"available": False, "reason": "Lease required."},
    }
    profiles = profile_directory(availability)
    assert [p["profile_id"] for p in profiles] == OPERATOR_PROFILE_IDS
    native = profiles[0]
    assert native["available"] is True
    assert native["unavailable_reason"] == ""
    assert native["display_name"] == "Web & API Authorization"
    # Every profile carries operator copy and real capability budgets.
    for profile in profiles:
        assert profile["operator_summary"]
        assert profile["how_it_runs"]
        assert profile["capabilities"]
        for cap in profile["capabilities"]:
            assert cap["request_budget"] >= 0
            assert "time_budget_ms" in cap
    nuclei = next(p for p in profiles if p["profile_id"] == "NUCLEI_LAB_SAFE_HTTP_V1")
    assert nuclei["available"] is False
    assert nuclei["unavailable_reason"] == "Nuclei disabled."


def test_profile_directory_defaults_unmapped_to_unavailable() -> None:
    # A profile with no availability entry is never advertised as a clickable option.
    profiles = profile_directory({})
    assert all(p["available"] is False for p in profiles)
    assert all(p["unavailable_reason"] for p in profiles)


def test_profile_display_name_falls_back_to_id() -> None:
    assert profile_display_name("aegis-native-bola-synthetic") == "Web & API Authorization"
    assert profile_display_name("does-not-exist") == "does-not-exist"


def test_project_capability_unknown_id_falls_back_to_safe_defaults() -> None:
    # An unknown capability id must never crash projection or fabricate a severity/budget; it
    # projects as UNKNOWN activity/severity with a zero request budget and no approvals.
    projected = _project_capability("capability-that-does-not-exist")
    assert projected["capability_id"] == "capability-that-does-not-exist"
    assert projected["title"] == "capability-that-does-not-exist"
    assert projected["activity"] == "UNKNOWN"
    assert projected["verified_severity"] == "UNKNOWN"
    assert projected["request_budget"] == 0
    assert projected["required_approvals"] == []


async def test_targets_endpoint_returns_authorized_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/api/console/targets")
    assert response.status_code == 200
    body = response.json()
    # Operators now onboard company targets through the typed endpoint, not free-text scan input.
    assert body["custom_target_entry"] is True
    refs = {item["target_ref"] for item in body["items"]}
    assert "synthetic-bank-api" in refs


async def test_profiles_endpoint_only_native_available_by_default() -> None:
    # Default deployment settings leave the Nuclei/ZAP adapters and the ZAP Active lease disabled,
    # so only the in-process native assessment is executable; the rest are honestly unavailable.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/api/console/profiles")
    assert response.status_code == 200
    profiles = {p["profile_id"]: p for p in response.json()["items"]}
    assert profiles["aegis-native-bola-synthetic"]["available"] is True
    for disabled_id in OPERATOR_PROFILE_IDS[1:]:
        assert profiles[disabled_id]["available"] is False
        assert profiles[disabled_id]["unavailable_reason"]


async def test_console_projections_leak_no_management_or_credential_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        targets = (await client.get("/api/console/targets")).text
        profiles = (await client.get("/api/console/profiles")).text
    # Sensitive material only. "Authorization" appears legitimately as the OWASP class name.
    for banned in ("management_origin", "answer_key", "-control:", "Bearer ", "openapi_url"):
        assert banned not in targets
        assert banned not in profiles


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
