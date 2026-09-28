"""Append-only run ledger: one persisted record per completed assessment.

Each row is keyed by ``<date>-<identifier>`` where the identifier is the target's FQDN (website
targets), the API host (API targets), the IP/CIDR (address targets), or the synthetic target
reference. The ledger is written next to the SQLite database so it shares the same persistence, and
it is served verbatim by ``GET /api/console/runs.csv``.

Design constraints:
- **Fail-soft.** A ledger write must never break or fail a run. Every write is wrapped and returns
  a bool; callers ignore ``False`` (e.g. a read-only filesystem simply produces no ledger).
- **Redaction-safe.** Only fields already present in the console run/target projections are written:
  no response bodies, credentials, or scanner arguments.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LEDGER_CSV_NAME = "run-ledger.csv"
LEDGER_JSONL_NAME = "run-ledger.jsonl"

LEDGER_COLUMNS = [
    "record_key",
    "date",
    "time_utc",
    "run_id",
    "target",
    "identifier",
    "identifier_kind",
    "target_type",
    "environment",
    "profile_id",
    "engine",
    "outcome",
    "findings",
]

_IDENTIFIER_KIND = {
    "WEBSITE": "FQDN",
    "API": "API",
    "IP_CIDR": "IP",
    "SYNTHETIC": "SYNTHETIC",
}

_write_lock = threading.Lock()


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def target_identifier(target: dict[str, Any]) -> tuple[str, str]:
    """Return ``(identifier, kind)`` for the ledger key: FQDN / API host / IP / synthetic ref."""

    target_type = str(target.get("target_type") or "").upper()
    kind = _IDENTIFIER_KIND.get(target_type, "TARGET")
    for entry in target.get("authorized_scope") or []:
        raw = str(entry).split()[0] if entry else ""
        if not raw:
            continue
        # A bare IP or CIDR is kept verbatim (so the mask survives) rather than URL-parsed.
        if "://" not in raw and _looks_like_ip(raw):
            return raw, "IP" if kind == "TARGET" else kind
        host = urlsplit(raw if "://" in raw else f"//{raw}").hostname
        if host:
            return host, kind
    fallback = str(target.get("target_ref") or target.get("name") or "target")
    if kind == "TARGET" and target.get("synthetic"):
        kind = "SYNTHETIC"
    return fallback, kind


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_row(run: dict[str, Any], target: dict[str, Any], profile_id: str) -> dict[str, str]:
    """Build one ledger row from a console run projection + the resolved target projection."""

    created = str(run.get("created_at") or "")
    parsed = _parse_dt(created)
    date = parsed.date().isoformat() if parsed else created[:10]
    time_utc = parsed.time().isoformat(timespec="seconds") if parsed else ""
    identifier, kind = target_identifier(target)
    findings = run.get("finding_count")
    return {
        "record_key": f"{date}-{identifier}",
        "date": date,
        "time_utc": time_utc,
        "run_id": str(run.get("id") or ""),
        "target": str(target.get("name") or run.get("target_name") or ""),
        "identifier": identifier,
        "identifier_kind": kind,
        "target_type": str(target.get("target_type") or ""),
        "environment": str(target.get("environment") or ""),
        "profile_id": str(profile_id or ""),
        "engine": str(run.get("engine") or ""),
        "outcome": str(run.get("status") or ""),
        "findings": "" if findings is None else str(findings),
    }


def append(ledger_dir: Path | str, row: dict[str, str]) -> bool:
    """Append one row to the CSV and JSONL ledgers. Returns False on any I/O failure (fail-soft)."""

    try:
        directory = Path(ledger_dir)
        directory.mkdir(parents=True, exist_ok=True)
        csv_path = directory / LEDGER_CSV_NAME
        jsonl_path = directory / LEDGER_JSONL_NAME
        with _write_lock:
            write_header = not csv_path.exists()
            with csv_path.open("a", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=LEDGER_COLUMNS, extrasaction="ignore")
                if write_header:
                    writer.writeheader()
                writer.writerow({key: row.get(key, "") for key in LEDGER_COLUMNS})
            with jsonl_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
        return True
    except OSError:
        return False


def read_csv(ledger_dir: Path | str) -> str:
    """Return the persisted CSV text, or a header-only CSV when nothing has been recorded yet."""

    csv_path = Path(ledger_dir) / LEDGER_CSV_NAME
    try:
        if csv_path.exists():
            return csv_path.read_text(encoding="utf-8")
    except OSError:
        pass
    buffer = io.StringIO()
    csv.DictWriter(buffer, fieldnames=LEDGER_COLUMNS).writeheader()
    return buffer.getvalue()


def download_filename() -> str:
    return f"aegis-run-ledger-{datetime.now(UTC).date().isoformat()}.csv"
