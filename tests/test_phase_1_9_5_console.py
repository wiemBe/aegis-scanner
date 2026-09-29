"""Phase 1.9.5 operator-console productization: authorized target inventory and plain-language
assessment-profile projections, plus their read-only controller endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from aegis import main as main_module
from aegis.beast.contracts import BeastRun, RunState
from aegis.beast.store import BeastStore
from aegis.console_catalog import (
    _project_capability,
    profile_directory,
    profile_display_name,
    target_directory,
)
from aegis.planner import GatewayPlanner
from aegis.settings import Settings
from aegis.storage import ScanStore
from aegis.target_inventory import TargetInventoryStore


def _use_temp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TargetInventoryStore:
    """Point the app's controller-owned inventory at a writable temp database. The module-level
    store defaults to the production mount, which the offline suite cannot open."""

    store = TargetInventoryStore(str(tmp_path / "targets.db"))
    store.initialize()
    monkeypatch.setattr(main_module, "target_store", store)
    return store


# Operator-facing catalog and capability-pack profiles, in display order.
OPERATOR_PROFILE_IDS = [
    "aegis-native-bola-synthetic",
    "NUCLEI_LAB_SAFE_HTTP_V1",
    "ZAP_LAB_PASSIVE_OPENAPI_V1",
    "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
    "OUTSIDE_IN_WEB_DISCOVERY_V1",
    "TOOLBOX_INFORMATION_EXPOSURE_V1",
    "TOOLBOX_BOLA_READONLY_V1",
    "SQLMAP_AUTHORIZED_WEB_V1",
    "IP_NETWORK_ASSESSMENT_V1",
]


def test_target_directory_is_authorized_inventory_only() -> None:
    items = target_directory()
    refs = {item["target_ref"] for item in items}
    # The default native target plus the range inventory.
    assert "synthetic-bank-api" in refs
    assert {"range-bank", "range-shop", "range-ops", "range-cloud"} <= refs
    assert {"beast-synthetic-vulnerable", "beast-synthetic-patched"} <= refs
    toolbox_target = next(
        item for item in items if item["target_ref"] == "beast-synthetic-vulnerable"
    )
    assert toolbox_target["supported_profile_ids"] == [
        "OUTSIDE_IN_WEB_DISCOVERY_V1",
        "TOOLBOX_INFORMATION_EXPOSURE_V1",
        "TOOLBOX_BOLA_READONLY_V1",
        "SQLMAP_AUTHORIZED_WEB_V1",
    ]
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
    web = next(p for p in profiles if p["profile_id"] == "OUTSIDE_IN_WEB_DISCOVERY_V1")
    assert web["execution_mode"] == "STANDARD"
    assert web["engine"] == "TOOLBOX"
    assert web["tools"] == ["ffuf", "gobuster"]
    sqlmap = next(p for p in profiles if p["profile_id"] == "SQLMAP_AUTHORIZED_WEB_V1")
    assert sqlmap["execution_mode"] == "STANDARD"
    assert sqlmap["engine"] == "TOOLBOX"
    assert sqlmap["tools"] == ["sqlmap"]
    exposure = next(
        p for p in profiles if p["profile_id"] == "TOOLBOX_INFORMATION_EXPOSURE_V1"
    )
    assert exposure["engine"] == "TOOLBOX"
    assert exposure["tools"] == ["curl", "nuclei"]
    bola = next(p for p in profiles if p["profile_id"] == "TOOLBOX_BOLA_READONLY_V1")
    assert bola["engine"] == "TOOLBOX"
    assert bola["tools"] == ["curl", "httpie"]
    network = next(p for p in profiles if p["profile_id"] == "IP_NETWORK_ASSESSMENT_V1")
    assert network["execution_mode"] == "NETWORK_RUNNER"
    assert network["tools"] == ["nmap"]


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


async def test_toolbox_health_endpoint_returns_every_tool_with_an_honest_state() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/api/console/toolbox/health")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] in {"READY", "DEGRADED", "UNAVAILABLE"}
    assert {item["name"] for item in body["tools"]} >= {"ffuf", "gobuster", "sqlmap"}
    assert all(
        item["status"] in {"READY", "MISSING", "ERROR", "UNAVAILABLE"} for item in body["tools"]
    )


async def test_ai_dropdown_selection_and_ephemeral_test_are_controller_gated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_settings = Settings(
        ai_provider="ollama",
        ai_model="qwen3:4b",
        ai_allowed_models="qwen3:4b,qwen3:8b",
    )
    runtime_planner = GatewayPlanner(runtime_settings)
    monkeypatch.setattr(main_module, "settings", runtime_settings)
    monkeypatch.setattr(main_module, "planner", runtime_planner)
    monkeypatch.setattr(main_module, "_ai_change_blocker", lambda: None)

    async def gateway_control(
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, object]:
        del method, timeout_seconds
        if path == "/v1/models/select":
            selected = str((payload or {})["model"])
            return {
                "provider": "ollama",
                "current_model": selected,
                "models": ["qwen3:4b", "qwen3:8b"],
                "runtime_switching": True,
            }
        if path == "/v1/synthetic-test":
            return {
                "test_id": "ai-test-aaaaaaaaaaaa",
                "status": "PASS",
                "code": "SYNTHETIC_AI_TEST_PASSED",
                "provider": "ollama",
                "model": runtime_planner.model,
                "decision_type": "stop",
                "usage": {"input_tokens": 20, "output_tokens": 5, "total_tokens": 25},
                "fixture_state": "DESTROYED",
                "cleanup_verified": True,
                "docker_resources_created": 0,
                "started_at": "2026-09-29T10:00:00Z",
                "completed_at": "2026-09-29T10:00:01Z",
            }
        if path == "/v1/billing/balance":
            return {
                "provider": "deepseek",
                "state": "AVAILABLE",
                "available": True,
                "balances": [{"currency": "USD", "remaining": "12.50"}],
                "checked_at": "2026-09-29T10:00:00Z",
            }
        return {
            "provider": "ollama",
            "current_model": runtime_planner.model,
            "models": ["qwen3:4b", "qwen3:8b"],
            "runtime_switching": True,
        }

    monkeypatch.setattr(main_module, "_gateway_control_request", gateway_control)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        catalog = await client.get("/api/console/ai/models")
        balance = await client.get("/api/console/ai/balance")
        selected = await client.post("/api/console/ai/select", json={"model": "qwen3:8b"})
        tested = await client.post("/api/console/ai/test", json={})

    assert catalog.status_code == 200
    assert balance.json()["balances"] == [{"currency": "USD", "remaining": "12.50"}]
    assert selected.status_code == 200
    assert runtime_planner.model == "qwen3:8b"
    assert runtime_settings.ai_model == "qwen3:8b"
    assert tested.status_code == 200
    assert tested.json()["fixture_state"] == "DESTROYED"
    assert tested.json()["cleanup_verified"] is True
    assert tested.json()["docker_resources_created"] == 0


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


async def test_toolbox_runs_surface_in_the_normal_runs_list_and_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disposable-toolbox run is projected into the same Runs list/detail the operator uses for
    every other assessment: no scan-store finding is fabricated; the verifier conclusion stays in
    the toolbox run record and its own audit event stream."""

    _use_temp_store(tmp_path, monkeypatch)
    scan_store = ScanStore(str(tmp_path / "scans.db"))
    scan_store.initialize()
    monkeypatch.setattr(main_module, "store", scan_store)
    store = BeastStore(str(tmp_path / "beast.db"))
    store.initialize()
    monkeypatch.setattr(main_module, "beast_store", store)
    run = BeastRun(
        run_id="beast-run-toolbox000001",
        lease_id="beast-lease-toolbox",
        target_ref="beast-synthetic-vulnerable",
        scenario_id="endpoint_discovery",
        state=RunState.VERIFIED,
        model="qwen3:8b",
        operator_profile_id="OUTSIDE_IN_WEB_DISCOVERY_V1",
        created_at=datetime.now(UTC),
        verifier_conclusion={"status": "CONFIRMED", "authority": "DETERMINISTIC_VERIFIER"},
    )
    store.save_run(run)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        listed = (await client.get("/api/console/runs")).json()
        detail_response = await client.get(f"/api/console/runs/{run.run_id}")

    item = next(entry for entry in listed["items"] if entry["id"] == run.run_id)
    assert item["engine"] == "TOOLBOX"
    # VERIFIED maps to the console FAIL state: the verifier confirmed a vulnerability.
    assert item["status"] == "FAIL"
    assert item["variant"] == "OUTSIDE_IN_WEB_DISCOVERY_V1"
    assert item["model"] == "qwen3:8b"
    assert item["verifier_confirmed_count"] == 1
    assert item["finding_ids"] == []

    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["run"]["id"] == run.run_id
    assert detail["toolbox"]["run"]["run_id"] == run.run_id
    assert detail["toolbox"]["run"]["operator_profile_id"] == "OUTSIDE_IN_WEB_DISCOVERY_V1"
    assert isinstance(detail["toolbox"]["events"], list)

    # An uninitialized toolbox store projects as no runs, never a 5xx on the shared endpoint.
    monkeypatch.setattr(main_module, "beast_store", BeastStore(str(tmp_path / "missing.db")))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        empty = await client.get("/api/console/runs")
        missing_detail = await client.get(f"/api/console/runs/{run.run_id}")
    assert empty.status_code == 200
    assert all(entry["id"] != run.run_id for entry in empty.json()["items"])
    assert missing_detail.status_code == 404


async def test_toolbox_profile_cannot_start_through_the_plain_assessment_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TOOLBOX profiles start from the wizard's toolbox step (preflight + typed phrase + lease);
    the plain assessment endpoint fails closed instead of guessing an executor."""

    _use_temp_store(tmp_path, monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/console/assessments",
            json={
                "target_id": "beast-synthetic-vulnerable",
                "profile_id": "OUTSIDE_IN_WEB_DISCOVERY_V1",
            },
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "TOOLBOX_PROFILE_STARTS_FROM_TOOLBOX_STEP"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
