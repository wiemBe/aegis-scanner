"""Run ledger: per-run persisted CSV/JSONL record keyed by date + FQDN/API/IP."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from aegis import run_ledger


def _target(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "target_ref": "shop-web",
        "name": "Shop Web",
        "target_type": "WEBSITE",
        "environment": "PRODUCTION",
        "authorized_scope": ["https://shop.example.com"],
        "synthetic": False,
    }
    base.update(overrides)
    return base


def test_identifier_is_fqdn_for_website() -> None:
    assert run_ledger.target_identifier(_target()) == ("shop.example.com", "FQDN")


def test_identifier_is_api_host_for_api_target() -> None:
    target = _target(
        target_ref="pay-api",
        target_type="API",
        authorized_scope=["https://api.example.com:8443"],
    )
    assert run_ledger.target_identifier(target) == ("api.example.com", "API")


def test_identifier_keeps_cidr_for_ip_target() -> None:
    target = _target(target_ref="net", target_type="IP_CIDR", authorized_scope=["10.0.0.0/24"])
    assert run_ledger.target_identifier(target) == ("10.0.0.0/24", "IP")


def test_identifier_falls_back_to_ref_for_synthetic() -> None:
    target = _target(
        target_ref="synthetic-bank-api",
        target_type="SYNTHETIC",
        authorized_scope=[],
        synthetic=True,
    )
    assert run_ledger.target_identifier(target) == ("synthetic-bank-api", "SYNTHETIC")


def test_build_row_keys_by_date_and_identifier() -> None:
    run = {
        "id": "scan-abc",
        "status": "FAIL",
        "target_name": "Shop Web",
        "engine": "AEGIS_NATIVE",
        "finding_count": 2,
        "created_at": "2026-09-28T14:30:05Z",
    }
    row = run_ledger.build_row(run, _target(), "aegis-native-bola-synthetic")
    assert row["record_key"] == "2026-09-28-shop.example.com"
    assert row["date"] == "2026-09-28"
    assert row["identifier"] == "shop.example.com"
    assert row["identifier_kind"] == "FQDN"
    assert row["outcome"] == "FAIL"
    assert row["findings"] == "2"
    assert row["run_id"] == "scan-abc"
    assert row["profile_id"] == "aegis-native-bola-synthetic"


def test_append_then_read_roundtrips_csv_and_jsonl(tmp_path: Path) -> None:
    run = {"id": "scan-1", "status": "PASS", "finding_count": 0, "created_at": "2026-09-28T09:00Z"}
    assert run_ledger.append(tmp_path, run_ledger.build_row(run, _target(), "p1")) is True
    run2 = {
        "id": "scan-2",
        "status": "FAIL",
        "finding_count": 1,
        "created_at": "2026-09-28T10:00:00Z",
    }
    assert run_ledger.append(tmp_path, run_ledger.build_row(run2, _target(), "p1")) is True

    text = run_ledger.read_csv(tmp_path)
    rows = list(csv.DictReader(text.splitlines()))
    assert [r["run_id"] for r in rows] == ["scan-1", "scan-2"]
    assert rows[0]["record_key"] == "2026-09-28-shop.example.com"
    # Exactly one header row.
    assert text.splitlines()[0].startswith("record_key,")

    jsonl = (tmp_path / run_ledger.LEDGER_JSONL_NAME).read_text().splitlines()
    assert json.loads(jsonl[1])["run_id"] == "scan-2"


def test_read_csv_returns_header_only_when_empty(tmp_path: Path) -> None:
    text = run_ledger.read_csv(tmp_path)
    assert text.strip() == ",".join(run_ledger.LEDGER_COLUMNS)


def test_append_is_fail_soft_when_dir_is_a_file(tmp_path: Path) -> None:
    # A path whose parent is a regular file cannot be created; append must return False, not raise.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    assert run_ledger.append(blocker / "nested", {"record_key": "k"}) is False
