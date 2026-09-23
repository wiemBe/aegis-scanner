"""Phase 1.9.5 correction: company target onboarding. The controller — never the browser —
normalizes, validates, authorizes, persists and scope-enforces every operator-added target.

These tests exercise the deterministic offline path only: no DNS resolution, no network egress, no
model calls and no real company scan. They prove inventory persistence, scope normalization and
enforcement, and typed assessment creation against a stable inventory target id.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from aegis import main as main_module
from aegis.target_inventory import (
    ScopeViolation,
    TargetCreate,
    TargetInventoryStore,
    TargetValidationError,
    authorize_url_against_target,
    normalize_address,
    normalize_origin,
    scope_preview,
)


def _website(**overrides: object) -> TargetCreate:
    base: dict[str, object] = {
        "target_type": "WEBSITE",
        "display_name": "Company Marketing Site",
        "environment": "PRODUCTION",
        "authorization_reference": "CHG-1029",
        "authorization_attested": True,
        "origins": ["example.company.com"],
    }
    base.update(overrides)
    return TargetCreate.model_validate(base)


def _store(tmp_path: Path) -> TargetInventoryStore:
    store = TargetInventoryStore(str(tmp_path / "targets.db"))
    store.initialize()
    return store


# --- normalization --------------------------------------------------------------------------------


def test_add_company_fqdn_normalizes_to_https_origin() -> None:
    assert normalize_origin("example.company.com") == "https://example.company.com"
    assert normalize_origin("https://Example.Company.com/") == "https://example.company.com"


def test_https_origin_with_custom_port_is_preserved() -> None:
    assert normalize_origin("https://api.company.com:8443") == "https://api.company.com:8443"
    # A default port is normalized away so equivalent origins compare equal.
    assert normalize_origin("https://api.company.com:443") == "https://api.company.com"


def test_multiple_api_base_urls_are_all_authorized() -> None:
    request = TargetCreate.model_validate(
        {
            "target_type": "API",
            "display_name": "Payments API",
            "environment": "STAGING",
            "authorization_reference": "JIRA-88",
            "authorization_attested": True,
            "origins": [
                "https://api.company.com",
                "https://api.company.com:8443",
                "https://eu.api.company.com",
            ],
        }
    )
    preview = scope_preview(request)
    assert preview["authorized_scope"] == [
        "https://api.company.com",
        "https://api.company.com:8443",
        "https://eu.api.company.com",
    ]


def test_optional_openapi_url_must_be_inside_authorized_scope() -> None:
    ok = _website(
        target_type="API",
        origins=["https://api.company.com"],
        openapi_url="https://api.company.com/openapi.json",
    )
    assert scope_preview(ok)["openapi_url"] == "https://api.company.com/openapi.json"

    with pytest.raises(TargetValidationError) as exc:
        scope_preview(_website(target_type="API", openapi_url="https://cdn.other.com/openapi.json"))
    assert exc.value.code == "OPENAPI_URL_OUTSIDE_SCOPE"


def test_authorized_internal_private_target_is_allowed() -> None:
    assert normalize_address("10.4.1.20") == "10.4.1.20"
    request = TargetCreate.model_validate(
        {
            "target_type": "IP_CIDR",
            "display_name": "Internal Admin Host",
            "environment": "INTERNAL",
            "authorization_reference": "CHG-2001",
            "authorization_attested": True,
            "addresses": ["10.4.1.20"],
        }
    )
    assert scope_preview(request)["authorized_scope"] == ["10.4.1.20"]


def test_duplicate_origin_detection() -> None:
    with pytest.raises(TargetValidationError) as exc:
        scope_preview(_website(origins=["example.company.com", "https://example.company.com"]))
    assert exc.value.code == "DUPLICATE_ORIGIN"


def test_embedded_url_credentials_are_rejected() -> None:
    with pytest.raises(TargetValidationError) as exc:
        normalize_origin("https://admin:hunter2@example.company.com")
    assert exc.value.code == "EMBEDDED_CREDENTIALS_FORBIDDEN"


def test_metadata_host_is_never_authorized() -> None:
    with pytest.raises(TargetValidationError):
        normalize_origin("http://169.254.169.254")
    with pytest.raises(TargetValidationError):
        normalize_address("169.254.169.254")


def test_wildcard_requires_explicit_authorization() -> None:
    with pytest.raises(TargetValidationError) as exc:
        scope_preview(_website(wildcard_subdomains=["*.company.com"]))
    assert exc.value.code == "WILDCARD_REQUIRES_EXPLICIT_AUTHORIZATION"
    ok = scope_preview(
        _website(wildcard_subdomains=["*.company.com"], wildcard_authorized=True)
    )
    assert "*.company.com" in ok["authorized_scope"]


def test_cidr_requires_explicit_authorization() -> None:
    payload = {
        "target_type": "IP_CIDR",
        "display_name": "Range",
        "environment": "INTERNAL",
        "authorization_reference": "CHG-9",
        "authorization_attested": True,
        "addresses": ["10.4.0.0/24"],
    }
    with pytest.raises(TargetValidationError) as exc:
        scope_preview(TargetCreate.model_validate(payload))
    assert exc.value.code == "CIDR_REQUIRES_EXPLICIT_AUTHORIZATION"
    ok = scope_preview(TargetCreate.model_validate({**payload, "cidr_authorized": True}))
    assert ok["authorized_scope"] == ["10.4.0.0/24"]


def test_attestation_is_mandatory() -> None:
    with pytest.raises(TargetValidationError) as exc:
        scope_preview(_website(authorization_attested=False))
    assert exc.value.code == "AUTHORIZATION_ATTESTATION_REQUIRED"


# --- scope enforcement (fail closed) --------------------------------------------------------------


def test_redirect_target_escape_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = store.create(_website(origins=["https://example.company.com"]))
    # An in-scope URL resolves; a redirect to another host fails closed with an auditable reason.
    assert authorize_url_against_target(record, "https://example.company.com/login") == (
        "https://example.company.com"
    )
    with pytest.raises(ScopeViolation) as exc:
        authorize_url_against_target(record, "https://evil.attacker.com/steal")
    assert exc.value.code == "TARGET_ESCAPE_OUTSIDE_AUTHORIZED_SCOPE"


def test_company_com_is_not_silently_broadened_to_wildcard(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = store.create(_website(origins=["https://example.company.com"]))
    with pytest.raises(ScopeViolation):
        authorize_url_against_target(record, "https://other.company.com/")


def test_excluded_path_prefix_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = store.create(
        _website(origins=["https://example.company.com"], excluded_path_prefixes=["/admin"])
    )
    with pytest.raises(ScopeViolation) as exc:
        authorize_url_against_target(record, "https://example.company.com/admin/users")
    assert exc.value.code == "PATH_EXCLUDED_FROM_SCOPE"


# --- persistence ----------------------------------------------------------------------------------


def test_persistence_survives_store_reopen(tmp_path: Path) -> None:
    db = str(tmp_path / "targets.db")
    first = TargetInventoryStore(db)
    first.initialize()
    created = first.create(_website(), operator_id="local-operator")
    # A fresh store object over the same file — i.e. a page reload / process restart.
    reopened = TargetInventoryStore(db)
    records = reopened.list()
    assert [r.id for r in records] == [created.id]
    assert reopened.get(created.id) is not None
    assert records[0].attested_by == "local-operator"


def test_duplicate_scope_across_targets_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create(_website(display_name="First", origins=["https://example.company.com"]))
    with pytest.raises(TargetValidationError) as exc:
        store.create(_website(display_name="Second", origins=["https://example.company.com"]))
    assert exc.value.code == "DUPLICATE_ORIGIN"


def test_disabled_target_preserves_record_and_frees_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    record = store.create(_website())
    disabled = store.set_enabled(record.id, False)
    assert disabled is not None and disabled.status == "DISABLED"
    # The record is preserved (not deleted) and its scope no longer blocks a re-add.
    assert store.get(record.id) is not None


# --- endpoints ------------------------------------------------------------------------------------


def _use_temp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TargetInventoryStore:
    store = _store(tmp_path)
    monkeypatch.setattr(main_module, "target_store", store)
    return store


async def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    )


async def test_create_target_endpoint_persists_and_returns_stable_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        response = await client.post(
            "/api/console/targets", json=_website().model_dump(mode="json")
        )
    assert response.status_code == 201
    body = response.json()
    assert body["target_ref"].startswith("tgt-")
    assert body["synthetic"] is False
    assert body["authorized_scope"] == ["https://example.company.com"]
    # A real controller-owned record now exists, not browser state.
    assert store.get(body["target_ref"]) is not None


async def test_create_target_rejects_embedded_credentials_with_bounded_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        response = await client.post(
            "/api/console/targets",
            json=_website(origins=["https://admin:pw@example.company.com"]).model_dump(mode="json"),
        )
    assert response.status_code == 422
    assert response.json()["detail"] == "EMBEDDED_CREDENTIALS_FORBIDDEN"


async def test_onboarded_target_appears_in_new_assessment_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        created = (
            await client.post("/api/console/targets", json=_website().model_dump(mode="json"))
        ).json()
        listing = (await client.get("/api/console/targets")).json()
    refs = {item["target_ref"] for item in listing["items"]}
    # Both the synthetic seed and the new company target are selectable, and distinguishable.
    assert "synthetic-bank-api" in refs
    assert created["target_ref"] in refs
    company = next(i for i in listing["items"] if i["target_ref"] == created["target_ref"])
    synthetic = next(i for i in listing["items"] if i["target_ref"] == "synthetic-bank-api")
    assert company["synthetic"] is False and synthetic["synthetic"] is True


async def test_disabled_target_cannot_start_assessment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        created = (
            await client.post(
                "/api/console/targets",
                json=_website(target_type="WEBSITE").model_dump(mode="json"),
            )
        ).json()
        await client.post(f"/api/console/targets/{created['target_ref']}/disable")
        response = await client.post(
            "/api/console/assessments",
            json={"target_id": created["target_ref"], "profile_id": "NUCLEI_LAB_SAFE_HTTP_V1"},
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "TARGET_DISABLED"


async def test_assessment_uses_stable_target_id_and_native_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    # The native synthetic path runs a real deterministic in-process scan (no model calls), so point
    # its scan store at a writable temp database too.
    from aegis.storage import ScanStore

    scan_store = ScanStore(str(tmp_path / "scans.db"))
    scan_store.initialize()
    monkeypatch.setattr(main_module.service, "store", scan_store)
    async with await _client() as client:
        response = await client.post(
            "/api/console/assessments",
            json={
                "target_id": "synthetic-bank-api",
                "profile_id": "aegis-native-bola-synthetic",
            },
        )
    assert response.status_code == 202
    body = response.json()
    assert body["target_id"] == "synthetic-bank-api"
    assert body["run_id"]


async def test_company_target_engine_profile_is_unavailable_in_default_deployment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A company website's engine profiles need Nuclei/ZAP, which are disabled by default. The
    # controller fails closed rather than starting a real company scan.
    _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        created = (
            await client.post("/api/console/targets", json=_website().model_dump(mode="json"))
        ).json()
        response = await client.post(
            "/api/console/assessments",
            json={"target_id": created["target_ref"], "profile_id": "NUCLEI_LAB_SAFE_HTTP_V1"},
        )
    assert response.status_code == 409
    assert response.json()["detail"] == "PROFILE_UNAVAILABLE_FOR_DEPLOYMENT"


async def test_scope_preview_endpoint_shows_normalized_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    async with await _client() as client:
        response = await client.post(
            "/api/console/targets/preview",
            json=_website(origins=["Example.Company.com:443"]).model_dump(mode="json"),
        )
    assert response.status_code == 200
    assert response.json()["authorized_scope"] == ["https://example.company.com"]


async def test_target_data_never_exposes_secret_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_temp_store(tmp_path, monkeypatch)
    # A credential *reference* is accepted; a secret value is never stored or projected.
    payload = _website(
        target_type="API",
        origins=["https://api.company.com"],
        credential_reference="vault://payments-api/token",
    ).model_dump(mode="json")
    async with await _client() as client:
        created = (await client.post("/api/console/targets", json=payload)).json()
        listing = (await client.get("/api/console/targets")).text
    assert created["credential_reference"] == "vault://payments-api/token"
    for secret_marker in ("hunter2", "Bearer ", "password", "token=", "secret_value"):
        assert secret_marker not in listing


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
