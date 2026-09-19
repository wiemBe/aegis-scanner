"""Phase 0.9 host-side operator runner (synthetic lab only, docs/phase-0.9).

Drives exactly one live discovery + linked patched retest against the already-running Aegis control
plane (through the localhost-only dashboard ingress) and writes an auditable evidence package. It
uses only the Python standard library so it runs on a bare host with no project dependencies; all
validation and manifest logic lives in the strictly-typed, unit-tested ``aegis.demo`` module.

It never calls a model or a target directly, never injects a candidate, and never overwrites a
prior demo run: each run has a unique id and its own timestamped evidence paths. A single failed
invariant raises and exits non-zero before any manifest is written.

Environment:
    AEGIS_BASE_URL          dashboard ingress (default http://127.0.0.1:8000)
    DEMO_RUN_ID             unique run id (default demo-<UTC>-<rand>)
    DEMO_COMPOSE_PROJECT    compose project name, recorded in the manifest
    DEMO_TOPOLOGY_RESULT    topology test result string, recorded in the manifest
    SCAN_DEADLINE_SECONDS   per-scan poll deadline (default 600)
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from aegis import demo  # noqa: E402  (path set above)

BASE_URL = os.environ.get("AEGIS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
DEADLINE = float(os.environ.get("SCAN_DEADLINE_SECONDS", "600"))
ARTIFACTS = ROOT / "artifacts"


def _utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _get(path: str) -> dict[str, Any]:
    with urllib.request.urlopen(BASE_URL + path, timeout=30) as response:  # noqa: S310 (localhost)
        return json.loads(response.read())


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 (localhost ingress)
        BASE_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return json.loads(response.read())


def run_scan(payload: dict[str, Any]) -> dict[str, Any]:
    """Create one scan and poll until it reaches a terminal state, returning the full report."""

    scan_id = _post("/api/scans", payload)["id"]
    deadline = time.monotonic() + DEADLINE
    while time.monotonic() < deadline:
        report = _get(f"/api/scans/{scan_id}")
        if report["scan"]["status"] not in {"QUEUED", "RUNNING"}:
            return report
        time.sleep(0.5)
    raise SystemExit(f"DEMO_TIMEOUT: scan {scan_id} did not complete within {DEADLINE}s")


def write_with_checksum(path: Path, text: str) -> str:
    """Write a file and its .sha256 sidecar. Refuses to overwrite an existing evidence file."""

    if path.exists() or path.with_suffix(path.suffix + ".sha256").exists():
        raise SystemExit(f"DEMO_EVIDENCE_EXISTS: refusing to overwrite {path.name}")
    path.write_text(text)
    digest = sha256(text.encode()).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n")
    return digest


def main() -> int:
    run_id = os.environ.get("DEMO_RUN_ID") or f"demo-{_utc_stamp()}-{secrets.token_hex(3)}"
    timestamp = datetime.now(UTC).isoformat()
    compose_project = os.environ.get("DEMO_COMPOSE_PROJECT", "aegis-management-demo")
    dashboard_url = os.environ.get("DEMO_DASHBOARD_URL", "http://127.0.0.1:8000")

    print(f"[demo] run id: {run_id}")
    print(f"[demo] control plane: {BASE_URL}")

    health = _get("/health")
    if health.get("planner") != demo.EXPECTED_PLANNER:
        raise SystemExit(f"PLANNER_NOT_LOCAL_LLM: health={health}")

    print("[demo] running discovery (positive vulnerable BOLA)…")
    discovery = run_scan({"target": "synthetic-bank-api", "scenario": "positive_vulnerable"})
    d_scan = discovery["scan"]
    if not (d_scan.get("status") == "FAIL" and d_scan.get("findings")):
        raise SystemExit(f"DISCOVERY_NO_FINDING: status={d_scan.get('status')}")

    print("[demo] running linked patched retest…")
    retest = run_scan(
        {
            "target": "synthetic-bank-api",
            "variant": "patched",
            "scenario": "patched_negative",
            "retest_of": d_scan["id"],
        }
    )

    # Fail-closed validation. Any violated invariant raises before a manifest is written.
    print("[demo] validating invariants…")
    demo.validate_demo(health, discovery, retest)
    # No hidden reasoning may exist in either raw report.
    demo.assert_no_secrets(
        [demo.build_timeline(discovery), demo.build_timeline(retest)],
        code="TIMELINE_SECRET_LEAK",
    )

    environment: dict[str, Any] = {
        "prompt_version": os.environ.get("DEMO_PROMPT_VERSION", "phase-0.7-candidate-first-v3"),
        "compose_project": compose_project,
        "dashboard_url": dashboard_url,
        "topology_test_result": os.environ.get("DEMO_TOPOLOGY_RESULT", "PASS"),
        "max_requests_per_scan": 8,
        "max_iterations": 6,
        "max_model_calls": 6,
        "scan_timeout_seconds": 90,
    }
    manifest = demo.build_manifest(run_id, timestamp, health, discovery, retest, environment)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    json_path = ARTIFACTS / f"phase-0.9-demo-{run_id}.json"
    summary_path = ARTIFACTS / f"phase-0.9-demo-{run_id}.summary.md"

    summary_text = demo.build_summary_markdown(manifest)

    # A file cannot contain the SHA-256 of its own final bytes without a circular definition. The
    # manifest therefore records the summary digest and names both authoritative sidecars; the JSON
    # sidecar written below hashes the final manifest bytes (including this metadata).
    manifest["checksums"] = {
        summary_path.name: sha256(summary_text.encode()).hexdigest(),
    }
    manifest["checksum_sidecars"] = [
        json_path.name + ".sha256",
        summary_path.name + ".sha256",
    ]
    manifest_text = json.dumps(manifest, indent=2) + "\n"

    write_with_checksum(json_path, manifest_text)
    write_with_checksum(summary_path, summary_text)

    print(f"[demo] discovery {d_scan['id']} -> {manifest['discovery']['response_codes']}")
    print(f"[demo] retest    {retest['scan']['id']} -> {manifest['retest']['response_codes']}")
    print(f"[demo] finding   {manifest['finding']['id']} "
          f"({manifest['finding']['severity']}/{manifest['finding']['confidence']})")
    print(f"[demo] verdict   {manifest['final_status']['verdict']}")
    print(f"[demo] manifest  {json_path}")
    print(f"[demo] summary   {summary_path}")

    # Emit the two scan ids so the operator entry point can build the dashboard demo URL.
    print(f"DEMO_DISCOVERY_ID={d_scan['id']}")
    print(f"DEMO_RETEST_ID={retest['scan']['id']}")
    print(f"DEMO_RUN_ID={run_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:  # pragma: no cover - operator-facing connectivity error
        raise SystemExit(f"CONTROL_PLANE_UNREACHABLE: {exc}") from None
    except demo.DemoGuardError as exc:
        raise SystemExit(f"DEMO_GUARD_FAILED {exc}") from None
