"""WP1 blocker G-READY-1: fail-closed control-plane readiness.

Covers the pure evaluator (positive + every fail-closed negative) and the `/ready` endpoint's
`200 READY / 503 NOT_READY` contract. The credential-isolation cases use an obvious placeholder
string, never a real secret, and assert that the placeholder never appears in the report.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import aegis.main as main_module
import aegis.readiness as readiness_module
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


def test_existing_store_is_opened_read_write_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()
    real_connect = readiness_module.sqlite3.connect
    observed_uris: list[str] = []

    def observed_connect(database: str, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        observed_uris.append(database)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(readiness_module.sqlite3, "connect", observed_connect)

    report = evaluate_readiness(Settings(), store)

    assert report.ready is True
    assert len(observed_uris) == 1
    assert observed_uris[0].endswith("?mode=rw")


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


def test_non_regular_store_fails_closed(tmp_path: Path) -> None:
    report = evaluate_readiness(Settings(), ScanStore(str(tmp_path)))

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL
    assert report.checks[0].detail == "persistence store is not a regular file"


def test_zero_available_filesystem_capacity_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()
    monkeypatch.setattr(
        readiness_module.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_bavail=0, f_frsize=4096),
    )

    report = evaluate_readiness(Settings(), store)

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL
    assert report.checks[0].detail == "data volume has no available capacity"


def test_statvfs_failure_is_unknown_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    def unavailable(_path: Path) -> None:
        raise OSError("raw-sensitive-filesystem-diagnostic")

    monkeypatch.setattr(readiness_module.os, "statvfs", unavailable)

    report = evaluate_readiness(Settings(), store)

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.UNKNOWN
    assert "raw-sensitive" not in report.model_dump_json()


def test_sqlite_read_write_open_failure_is_unknown_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise sqlite3.OperationalError("raw-sensitive-sqlite-diagnostic")

    monkeypatch.setattr(readiness_module.sqlite3, "connect", unavailable)

    report = evaluate_readiness(Settings(), store)

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.UNKNOWN
    assert "raw-sensitive" not in report.model_dump_json()
    assert str(tmp_path) not in report.model_dump_json()


def test_required_table_with_malformed_columns_fails_closed(tmp_path: Path) -> None:
    db_path = tmp_path / "aegis.db"
    connection = sqlite3.connect(str(db_path))
    for table in ("scans", "audit_events", "audit_access_log"):
        connection.execute(f'CREATE TABLE "{table}" (wrong_column TEXT)')
    connection.commit()
    connection.close()

    report = evaluate_readiness(Settings(), ScanStore(str(db_path)))

    assert report.ready is False
    assert _check(report, "persistence") is CheckStatus.FAIL
    assert report.checks[0].detail == "persistence schema is incomplete"


# --- Fail-closed negatives (credential isolation) ------------------------------------------------


def test_not_ready_when_auth_token_present(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(ai_auth_token=_PLACEHOLDER_CREDENTIAL), store)

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL


def test_not_ready_when_auth_token_file_present(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(
        Settings(ai_auth_token_file="/run/secrets/provider"),  # noqa: S106 - path, not a secret
        store,
    )

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL
    assert "/run/secrets/provider" not in report.model_dump_json()


def test_not_ready_when_deepseek_key_present(tmp_path: Path) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(Settings(deepseek_api_key=_PLACEHOLDER_CREDENTIAL), store)

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL


@pytest.mark.parametrize(
    "settings",
    [
        Settings(openrouter_api_key=_PLACEHOLDER_CREDENTIAL),
        Settings(openrouter_api_key_file="/run/secrets/openrouter-api-key"),
    ],
)
def test_not_ready_when_openrouter_credential_present(tmp_path: Path, settings: Settings) -> None:
    store = ScanStore(str(tmp_path / "aegis.db"))
    store.initialize()

    report = evaluate_readiness(settings, store)

    assert report.ready is False
    assert _check(report, "credential_isolation") is CheckStatus.FAIL
    assert _PLACEHOLDER_CREDENTIAL not in report.model_dump_json()
    assert "/run/secrets/openrouter-api-key" not in report.model_dump_json()


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
