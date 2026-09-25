"""Phase 1.6 range foundation and initial four-application vertical slices."""

from __future__ import annotations

import inspect
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

from aegis.engine.contracts import EngineEnvironment
from aegis.range_inventory import RANGE_TARGETS, scanner_inventory
from aegis_range import bank, canary, cloud, cloud_admin, ops, ops_worker, shop, shop_canary
from aegis_range.chain_acceptance import exercise_chain
from aegis_range.controller import RangeController
from aegis_range.ground_truth import CHAIN_GROUND_TRUTH, GROUND_TRUTH
from aegis_range.ingress import create_app
from aegis_range.runtime import Mode, ModeSelection
from aegis_range.verifier import RangeVerifier, VerificationStatus

ROOT = Path(__file__).resolve().parents[1]
APP_MODULES = {
    "aegis-bank": bank,
    "aegis-shop": shop,
    "aegis-ops": ops,
    "aegis-cloud": cloud,
}
SCENARIOS = {
    "aegis-bank": (
        "bank-object-access-v1",
        "bank-operation-access-v1",
        "bank-session-validation-v1",
        "bank-profile-update-v1",
        "bank-recovery-response-v1",
    ),
    "aegis-shop": (
        "shop-catalog-query-v1",
        "shop-promotion-preview-v1",
        "shop-review-content-v1",
        "shop-preference-request-v1",
        "shop-attachment-policy-v1",
    ),
    "aegis-ops": (
        "ops-report-selection-v1",
        "ops-diagnostic-input-v1",
        "ops-report-preview-v1",
        "ops-support-status-v1",
    ),
    "aegis-cloud": (
        "cloud-integration-fetch-v1",
        "cloud-xml-import-v1",
        "cloud-workspace-sharing-v1",
        "cloud-metadata-response-v1",
        "cloud-service-access-v1",
    ),
}
FORBIDDEN_PUBLIC_TERMS = ("vulnerable", "patched", "idor", "sqli", "xss", "ssrf", "answer")


class BrowserRequest(BaseModel):
    url: str


fake_browser = FastAPI()


@fake_browser.post("/v1/view")
async def fake_view(payload: BrowserRequest) -> dict[str, str]:
    assert payload.url == "http://aegis-shop-view:8102/internal/reviews/view"
    async with httpx.AsyncClient(
        base_url="http://shop", transport=httpx.ASGITransport(app=shop.app)
    ) as client:
        page = await client.get("/internal/reviews/view")
    match = re.search(
        rb"<script>new Image\(\)\.src='http://shop-effect-canary:8800/effect/([a-f0-9]+)'",
        page.content,
    )
    if match:
        async with httpx.AsyncClient(
            base_url="http://canary", transport=httpx.ASGITransport(app=shop_canary.app)
        ) as client:
            await client.get(f"/effect/{match.group(1).decode()}")
    return {"status": "viewed"}


@pytest.fixture(autouse=True)
def reset_range() -> None:
    for module in APP_MODULES.values():
        module.runtime.reset()
    cloud.app.state.canary_transport = httpx.ASGITransport(app=canary.app)
    cloud.app.state.admin_transport = httpx.ASGITransport(app=cloud_admin.app)
    ops.app.state.worker_transport = httpx.ASGITransport(app=ops_worker.app)
    ops_worker.reset()
    shop_canary.reset()


def transports() -> dict[str, httpx.AsyncBaseTransport]:
    return {
        application_id: httpx.ASGITransport(app=module.app)
        for application_id, module in APP_MODULES.items()
    }


def service_transports() -> dict[str, httpx.AsyncBaseTransport]:
    return {
        "ops-worker": httpx.ASGITransport(app=ops_worker.app),
        "shop-canary": httpx.ASGITransport(app=shop_canary.app),
        "shop-browser": httpx.ASGITransport(app=fake_browser),
    }


def test_four_targets_are_registered_as_synthetic_range() -> None:
    assert sorted(RANGE_TARGETS) == ["aegis-bank", "aegis-cloud", "aegis-ops", "aegis-shop"]
    assert EngineEnvironment.SYNTHETIC_RANGE.value == "SYNTHETIC_RANGE"
    for target in RANGE_TARGETS.values():
        assert target.environment == "SYNTHETIC_RANGE"
        assert target.origin.startswith(f"http://{target.application_id}:")
        assert target.synthetic_data_only and target.reset_available


def test_scanner_inventory_excludes_management_mode_and_answers() -> None:
    encoded = json.dumps(scanner_inventory(), sort_keys=True).lower()
    assert "management" not in encoded
    assert "ground_truth" not in encoded
    assert "evidence_requirements" not in encoded
    assert '"mode"' not in encoded
    for truth in GROUND_TRUTH:
        assert truth.scenario_id.lower() not in encoded
        assert truth.vulnerability_class_id.lower() not in encoded
        assert truth.ground_truth_id.lower() not in encoded
        assert truth.title.lower() not in encoded
    assert len(scanner_inventory()) == 4


@pytest.mark.parametrize("application_id", sorted(APP_MODULES))
def test_checked_in_openapi_is_truthful_and_has_ordinary_names(application_id: str) -> None:
    module = APP_MODULES[application_id]
    client = TestClient(module.app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    document = response.json()
    assert document["openapi"] == "3.1.0"
    assert document["servers"] == [{"url": RANGE_TARGETS[application_id].origin}]
    operation_ids: list[str] = []
    app_routes = {(route.path, method) for route in module.app.routes for method in route.methods}
    for path, path_item in document["paths"].items():
        for method, operation in path_item.items():
            assert (path, method.upper()) in app_routes
            operation_ids.append(operation["operationId"])
    assert len(operation_ids) == len(set(operation_ids))
    public_text = json.dumps(document).lower()
    assert not any(term in public_text for term in FORBIDDEN_PUBLIC_TERMS)
    assert "/__control" not in public_text


@pytest.mark.asyncio
async def test_bank_owner_controls_cross_owner_probes_and_verifier() -> None:
    verifier = RangeVerifier(transports(), service_transports(), use_management_origins=True)
    headers = {"Authorization": "Bearer range-user-alex"}  # noqa: S105
    async with httpx.AsyncClient(
        base_url="http://test", transport=httpx.ASGITransport(app=bank.app)
    ) as client:
        owner = await client.get("/api/accounts/ACC-100", headers=headers)
        cross = await client.get("/api/accounts/ACC-200", headers=headers)
        listed = await client.get("/api/accounts", headers=headers)
    assert owner.status_code == 200 and cross.status_code == 403
    assert [row["account_id"] for row in listed.json()["accounts"]] == ["ACC-100"]
    patched = await verifier.verify("aegis-bank", "bank-object-access-v1")
    assert patched.status is VerificationStatus.PASS and patched.complete
    bank.runtime.select("bank-object-access-v1", Mode.VULNERABLE)
    vulnerable = await verifier.verify("aegis-bank", "bank-object-access-v1")
    assert vulnerable.status is VerificationStatus.CONFIRMED and vulnerable.complete
    assert vulnerable.facts["cross_owner_identity_proved"] is True


@pytest.mark.asyncio
async def test_shop_query_control_probe_and_patched_rejection() -> None:
    verifier = RangeVerifier(transports(), service_transports(), use_management_origins=True)
    patched = await verifier.verify("aegis-shop", "shop-catalog-query-v1")
    assert patched.status is VerificationStatus.PASS
    shop.runtime.select("shop-catalog-query-v1", Mode.VULNERABLE)
    vulnerable = await verifier.verify("aegis-shop", "shop-catalog-query-v1")
    assert vulnerable.status is VerificationStatus.CONFIRMED
    assert vulnerable.facts["control_result_count"] == 1
    assert vulnerable.facts["probe_result_count"] == 3


@pytest.mark.asyncio
async def test_shop_preview_uses_contextual_encoding_in_patched_mode() -> None:
    verifier = RangeVerifier(transports(), service_transports(), use_management_origins=True)
    patched = await verifier.verify("aegis-shop", "shop-promotion-preview-v1")
    assert patched.status is VerificationStatus.PASS
    assert patched.facts["contextually_encoded"] is True
    shop.runtime.select("shop-promotion-preview-v1", Mode.VULNERABLE)
    vulnerable = await verifier.verify("aegis-shop", "shop-promotion-preview-v1")
    assert vulnerable.status is VerificationStatus.CONFIRMED
    assert vulnerable.facts["raw_html_context"] is True


@pytest.mark.asyncio
async def test_ops_traversal_is_confirmed_patched_and_fixture_contained() -> None:
    verifier = RangeVerifier(transports(), service_transports(), use_management_origins=True)
    patched = await verifier.verify("aegis-ops", "ops-report-selection-v1")
    assert patched.status is VerificationStatus.PASS
    ops.runtime.select("ops-report-selection-v1", Mode.VULNERABLE)
    vulnerable = await verifier.verify("aegis-ops", "ops-report-selection-v1")
    assert vulnerable.status is VerificationStatus.CONFIRMED
    async with httpx.AsyncClient(
        base_url="http://test", transport=httpx.ASGITransport(app=ops.app)
    ) as client:
        escaped = await client.get(
            "/api/reports/download", params={"file": "../../../../etc/passwd"}
        )
    assert escaped.status_code == 404


@pytest.mark.asyncio
async def test_cloud_reaches_only_exact_synthetic_canary_destination() -> None:
    verifier = RangeVerifier(transports(), service_transports(), use_management_origins=True)
    patched = await verifier.verify("aegis-cloud", "cloud-integration-fetch-v1")
    assert patched.status is VerificationStatus.PASS
    cloud.runtime.select("cloud-integration-fetch-v1", Mode.VULNERABLE)
    vulnerable = await verifier.verify("aegis-cloud", "cloud-integration-fetch-v1")
    assert vulnerable.status is VerificationStatus.CONFIRMED
    async with httpx.AsyncClient(
        base_url="http://test", transport=httpx.ASGITransport(app=cloud.app)
    ) as client:
        for destination in (
            "http://169.254.169.254/latest/meta-data",
            "https://example.com/callback",
            "http://range-canary:8500/other",
            "http://range-canary:8501/status/instance",
        ):
            response = await client.post("/api/integrations/check", json={"url": destination})
            assert response.status_code == 400


@pytest.mark.asyncio
async def test_controller_resets_deterministically_and_links_runs() -> None:
    controller = RangeController(transports(), service_transports())
    await controller.select_mode("aegis-shop", "shop-catalog-query-v1", Mode.VULNERABLE)
    first = await controller.reset_application("aegis-shop")
    second = await controller.reset_application("aegis-shop")
    assert first.healthy and second.healthy
    assert first.reset_generation is not None and second.reset_generation is not None
    assert second.reset_generation == first.reset_generation + 1
    result = await controller.verify("aegis-shop", "shop-catalog-query-v1")
    assert result.status is VerificationStatus.PASS and result.complete
    link = controller.link_run("run-range-001", "aegis-shop", "shop-catalog-query-v1")
    assert controller.run_link(link.run_id) == link
    with pytest.raises(ValueError, match="RUN_ALREADY_LINKED"):
        controller.link_run("run-range-001", "aegis-shop", "shop-catalog-query-v1")


def test_modes_are_strict_and_resets_default_to_patched() -> None:
    with pytest.raises(ValidationError):
        ModeSelection.model_validate({"mode": "unknown"})
    with pytest.raises(ValidationError):
        ModeSelection.model_validate({"mode": "patched", "answer": True})
    for module in APP_MODULES.values():
        state = module.runtime.reset()
        assert set(state["scenarios"].values()) == {"patched"}  # type: ignore[union-attr]


def test_ground_truth_is_controller_owned_and_not_imported_by_apps() -> None:
    assert len(GROUND_TRUTH) == 21
    assert len({item.ground_truth_id for item in GROUND_TRUTH}) == 21
    assert len(CHAIN_GROUND_TRUTH) == 3
    for item in GROUND_TRUTH:
        assert item.evidence_requirements and item.severity_rationale and item.verifier_id
        assert item.compatible_engines
        assert item.supported_modes == ("vulnerable", "patched")
    for module in APP_MODULES.values():
        source = inspect.getsource(module)
        assert "ground_truth" not in source
        assert "vulnerability_class_id" not in source


def test_ingress_blocks_management_before_backend_traffic() -> None:
    ingress = create_app("http://unreachable.invalid")
    with TestClient(ingress) as client:
        response = client.get("/__control/health")
    assert response.status_code == 404


def test_ingress_enforces_a_hard_request_budget() -> None:
    ingress = create_app("http://unreachable.invalid", request_budget=0)
    with TestClient(ingress) as client:
        response = client.get("/health")
    assert response.status_code == 429


def test_compose_topology_is_internal_hardened_and_has_no_host_mounts() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.range.yml").read_text())
    services: dict[str, dict[str, Any]] = compose["services"]
    assert all(network["internal"] is True for network in compose["networks"].values())
    for service in services.values():
        assert "ports" not in service and service.get("network_mode") != "host"
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
        assert service["user"] == "65532:65532"
        assert service["pids_limit"] <= 128 and service["mem_limit"] in {
            "128m",
            "192m",
            "512m",
        }
        assert "volumes" not in service
        assert "no-new-privileges:true" in service["security_opt"]
        assert "/var/run/docker.sock" not in json.dumps(service)
    assert services["range-canary"]["networks"] == ["cloud-fixtures"]
    assert services["cloud-admin"]["networks"] == ["cloud-internal"]
    assert set(services["ops-worker"]["networks"]) == {"ops-worker-control"}
    assert set(services["shop-browser"]["networks"]) == {
        "shop-viewer",
        "shop-browser-control",
    }
    assert "shop-viewer" not in services["range-ingress"]["networks"]
    assert "ops-worker-control" not in services["range-ingress"]["networks"]
    assert "cloud-internal" not in services["range-ingress"]["networks"]
    assert "cloud-fixtures" in services["aegis-cloud-core"]["networks"]
    assert "cloud-fixtures" not in services["range-ingress"]["networks"]
    assert services["range-probe"]["networks"] == ["range-access"]
    assert "range-access" not in services["range-controller"]["networks"]
    for name in ("aegis-bank-core", "aegis-shop-core", "aegis-ops-core", "aegis-cloud-core"):
        assert "RANGE_CONTROLLER_TOKEN" not in services[name].get("environment", {})


def test_range_dockerfile_runs_non_root() -> None:
    dockerfile = (ROOT / "deploy/range/Dockerfile").read_text()
    assert "USER 65532:65532" in dockerfile
    assert "Docker.sock" not in dockerfile
    browser_dockerfile = (ROOT / "deploy/range-browser/Dockerfile").read_text()
    assert "USER 65532:65532" in browser_dockerfile
    assert "chromium" in browser_dockerfile


@pytest.mark.asyncio
async def test_every_scenario_has_vulnerable_and_patched_complete_evidence() -> None:
    controller = RangeController(transports(), service_transports())
    results = 0
    for application_id, scenario_ids in SCENARIOS.items():
        for scenario_id in scenario_ids:
            await controller.select_mode(application_id, scenario_id, Mode.VULNERABLE)
            vulnerable = await controller.verify(application_id, scenario_id)
            await controller.select_mode(application_id, scenario_id, Mode.PATCHED)
            patched = await controller.verify(application_id, scenario_id)
            assert vulnerable.status is VerificationStatus.CONFIRMED and vulnerable.complete
            assert patched.status is VerificationStatus.PASS and patched.complete
            assert vulnerable.evidence_sha256 != patched.evidence_sha256
            results += 2
    assert results == 38


@pytest.mark.asyncio
async def test_all_attack_chains_confirm_and_reject_patched_paths() -> None:
    controller = RangeController(transports(), service_transports())
    for chain in CHAIN_GROUND_TRUTH:
        await controller.reset_application(chain.application_id)
        vulnerable = await exercise_chain(controller, chain.chain_id, Mode.VULNERABLE)
        await controller.reset_application(chain.application_id)
        patched = await exercise_chain(controller, chain.chain_id, Mode.PATCHED)
        assert vulnerable.status == "CONFIRMED" and vulnerable.complete
        assert patched.status == "PASS" and patched.complete


@pytest.mark.asyncio
async def test_reset_invalidates_bank_recovery_references_and_cloud_credentials() -> None:
    controller = RangeController(transports(), service_transports())
    await controller.select_mode("aegis-bank", "bank-object-access-v1", Mode.VULNERABLE)
    async with httpx.AsyncClient(
        base_url="http://bank", transport=httpx.ASGITransport(app=bank.app)
    ) as client:
        account = await client.get(
            "/api/accounts/ACC-200", headers={"Authorization": "Bearer range-user-alex"}
        )
        stale_reference = account.json()["recovery_reference"]
    await controller.reset_application("aegis-bank")
    async with httpx.AsyncClient(
        base_url="http://bank", transport=httpx.ASGITransport(app=bank.app)
    ) as client:
        stale = await client.post(
            "/api/access/complete",
            json={"reference": stale_reference, "new_passcode": "fresh-synthetic-pass"},
        )
    assert stale.status_code == 400

    cloud.runtime.select("cloud-integration-fetch-v1", Mode.VULNERABLE)
    cloud.runtime.select("cloud-metadata-response-v1", Mode.VULNERABLE)
    async with httpx.AsyncClient(
        base_url="http://cloud", transport=httpx.ASGITransport(app=cloud.app)
    ) as client:
        metadata = await client.post(
            "/api/integrations/check",
            json={"url": "http://range-canary:8500/status/instance"},
        )
        stale_token = metadata.json()["result"]["access_token"]
    await controller.reset_application("aegis-cloud")
    async with httpx.AsyncClient(
        base_url="http://admin", transport=httpx.ASGITransport(app=cloud_admin.app)
    ) as client:
        stale = await client.get(
            "/v1/summary",
            headers={
                "Authorization": f"Bearer {stale_token}",
                "X-Range-Generation": str(cloud.runtime.generation),
                "X-Validation-Mode": "strict",
            },
        )
    assert stale.status_code == 403


@pytest.mark.asyncio
async def test_incomplete_evidence_never_becomes_pass_for_any_scenario() -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"status": "unavailable"}, request=request)

    failed = httpx.MockTransport(unavailable)
    verifier = RangeVerifier(
        {application_id: failed for application_id in APP_MODULES},
        {"ops-worker": failed, "shop-canary": failed, "shop-browser": failed},
        use_management_origins=True,
    )
    for truth in GROUND_TRUTH:
        # The Phase 2.2 detection-control-bypass scenario is adjudicated from worker-produced
        # evidence (RangeVerifier.adjudicate_detection_control_bypass), not through the generic
        # single-request verify() path, so the verifier never generates substitute bypass traffic.
        # Its incomplete/reset behaviour is covered in tests/test_phase_2_2.py.
        if truth.scenario_id == "ops-detection-control-bypass-v1":
            continue
        result = await verifier.verify(truth.application_id, truth.scenario_id)
        assert result.status is VerificationStatus.INCOMPLETE
        assert not result.complete


@pytest.mark.asyncio
async def test_reset_replay_restores_every_scenario_to_a_fresh_vulnerable_result() -> None:
    controller = RangeController(transports(), service_transports())
    for truth in GROUND_TRUTH:
        # See the note above: the Phase 2.2 detection-control-bypass scenario is adjudicated from
        # worker evidence, not the generic verify() path (covered in tests/test_phase_2_2.py).
        if truth.scenario_id == "ops-detection-control-bypass-v1":
            continue
        await controller.select_mode(truth.application_id, truth.scenario_id, Mode.VULNERABLE)
        first = await controller.verify(truth.application_id, truth.scenario_id)
        reset = await controller.reset_application(truth.application_id)
        await controller.select_mode(truth.application_id, truth.scenario_id, Mode.VULNERABLE)
        replay = await controller.verify(truth.application_id, truth.scenario_id)
        assert reset.healthy
        assert first.status is replay.status is VerificationStatus.CONFIRMED
        assert first.facts["verification_reference"] != replay.facts["verification_reference"]
