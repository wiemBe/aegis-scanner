"""WP1 blocker G-READY-1: fail-closed control-plane readiness.

Covers the pure evaluator (positive + every fail-closed negative) and the `/ready` endpoint's
`200 READY / 503 NOT_READY` contract. The credential-isolation cases use an obvious placeholder
string, never a real secret, and assert that the placeholder never appears in the report.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import httpx
import pytest

import aegis.main as main_module
from aegis.readiness import (
    READINESS_CONTRACT_VERSION,
    CheckStatus,
    ReadinessReport,
    evaluate_readiness,
)
from aegis.settings import Settings
from aegis.storage import ScanStore

_PLACEHOLDER_CREDENTIAL = "placeholder-not-a-real-credential-000000"


def _check(report: ReadinessReport, name: str) -> CheckStatus:
    return next(check.status for check in report.checks if check.name == name)


# --- Positive ------------------------------------------------------------------------------------


def test_ready_when_store_initialized_and_no_credential(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(), store)

    assert report.ready is True
    assert report.contract_version == READINESS_CONTRACT_VERSION
    assert _check(report, "persistence") is CheckStatus.PASS
    assert _check(report, "credential_isolation") is CheckStatus.PASS


# --- Fail-closed negatives (persistence) ---------------------------------------------------------


def test_not_ready_when_store_uninitialized(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))  # never initialize(): file absent

    report = evaluate_readiness(Settings(), store)

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL


def test_not_ready_when_data_volume_missing(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "missing-volume" / "aegis.db"))  # parent dir does not exist

    report = evaluate_readiness(Settings(), store)

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL


def test_not_ready_when_schema_incomplete(tmp_path: Path) -> None:
    db_path = tmp_path / "aegis.db"
    connection = sqlite3.connect(str(db_path))
    connection.execute("CREATE TABLE unrelated (x INTEGER)")
    connection.commit()
    connection.close()

    report = evaluate_readiness(Settings(), ScanStore(str(db_path)))

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL


def test_unknown_persistence_fails_closed(tmp_path: Path) -> None:
    # database_path points at a directory: it exists, parent is writable, but opening it as a
    # SQLite database raises -> the check resolves to UNKNOWN and readiness fails closed.
    report = evaluate_readiness(Settings(), ScanStore(str(tmp_path)))

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.UNKNOWN


# --- Fail-closed negatives (credential isolation) ------------------------------------------------


def test_not_ready_when_auth_token_present(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(ai_auth_token=_PLACEHOLDER_CREDENTIAL), store)

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL


def test_not_ready_when_deepseek_key_present(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(deepseek_api_key=_PLACEHOLDER_CREDENTIAL), store)

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL


def test_report_never_contains_credential_value(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(ai_auth_token=_PLACEHOLDER_CREDENTIAL), store)

    assert _PLACEHOLDER_CREDENTIAL not in report.model_dump_json()


# --- Endpoint contract (200 READY / 503 NOT_READY) -----------------------------------------------


async def test_ready_endpoint_returns_200_when_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "ready.db"))
    store.initialize()
    monkeypatch.setattr(main_module, "store", store)
    monkeypatch.setattr(main_module, "settings", Settings())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["contract_version"] == READINESS_CONTRACT_VERSION


async def test_ready_endpoint_returns_503_when_persistence_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A store whose file was never created models a detached/absent persistence volume.
    monkeypatch.setattr(main_module, "store", ScanStore(str(tmp_path / "absent.db")))
    monkeypatch.setattr(main_module, "settings", Settings())

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert response.json()["ready"] is False


async def test_ready_endpoint_returns_503_when_credential_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "cred.db"))
    store.initialize()
    monkeypatch.setattr(main_module, "store", store)
    monkeypatch.setattr(main_module, "settings", Settings(ai_auth_token=_PLACEHOLDER_CREDENTIAL))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert _PLACEHOLDER_CREDENTIAL not in response.text
