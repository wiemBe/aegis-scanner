#!/usr/bin/env python3
"""Live Phase 1.2 acceptance against the real pinned Nuclei runner.

Run this inside the control-plane container so both internal endpoints are reachable:

    python scripts/phase_1_2_acceptance.py \
      --base-url http://10.213.47.10:8000 \
      --runner-url http://nuclei-runner:8090

The script uses only the public controller API for scans. Direct runner calls are limited to three
negative RPC admission controls; they carry no executable template selector and must not increment
the runner's execution counter.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CAPABILITY = "nuclei_scm_metadata_exposure_v1"
TERMINAL = {"PASS", "FAIL", "REVIEW", "INCOMPLETE", "CANCELLED"}


def request_json(
    url: str, payload: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 - CLI URL is limited to internal HTTP(S)
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - CLI URL
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {"error": "NON_JSON_ERROR"}
        return exc.code, body


def run_scan(base_url: str, payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    status, created = request_json(f"{base_url}/api/scans", payload)
    if status != 202:
        raise AssertionError(f"scan create returned {status}: {created}")
    scan_id = str(created["id"])
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        read_status, detail = request_json(f"{base_url}/api/scans/{scan_id}")
        if read_status != 200:
            raise AssertionError(f"scan read returned {read_status}")
        scan = detail["scan"]
        if scan["status"] in TERMINAL:
            return scan, [str(event["event"]) for event in detail["audit"]]
        time.sleep(0.2)
    raise AssertionError(f"scan {scan_id} did not complete")


def runner_attestation(runner_url: str) -> dict[str, Any]:
    status, body = request_json(f"{runner_url}/v1/attestation")
    if status != 200 or not body.get("ready"):
        raise AssertionError(f"runner is not READY: {status} {body.get('failure_codes')}")
    return body


def assert_vulnerable(scan: dict[str, Any], events: list[str]) -> None:
    required = {
        "NUCLEI_JOB_ADMITTED",
        "NUCLEI_EXECUTION_COMPLETED",
        "NUCLEI_FINDING_REPORTED",
        "NUCLEI_FINDING_CORRELATED",
        "NUCLEI_VERIFICATION_COMPLETED",
    }
    provenance = scan.get("nuclei_provenance") or {}
    assert scan["status"] == "FAIL"
    assert (scan.get("verification") or {}).get("status") == "CONFIRMED"
    assert len(scan.get("findings") or []) == 1
    assert provenance.get("coverage_complete") is True
    assert (provenance.get("counts") or {}).get("matched") == 1
    assert (provenance.get("counts") or {}).get("http_connections") == 1
    assert all(
        item.get("lifecycle_state") == "VERIFIED"
        for item in scan.get("normalized_findings") or []
    )
    assert required <= set(events)


def assert_patched(scan: dict[str, Any], events: list[str]) -> None:
    provenance = scan.get("nuclei_provenance") or {}
    assert scan["status"] == "PASS"
    assert scan.get("terminal_reason") == "COVERAGE_COMPLETE"
    assert (scan.get("verification") or {}).get("status") == "PASS"
    assert not scan.get("findings") and not scan.get("normalized_findings")
    assert provenance.get("coverage_complete") is True
    assert (provenance.get("counts") or {}).get("matched") == 0
    assert (provenance.get("counts") or {}).get("unmatched") == 1
    assert (provenance.get("counts") or {}).get("http_connections") == 1
    assert "NUCLEI_VERIFICATION_COMPLETED" in events


def rejected_controller_case(base_url: str, payload: dict[str, Any], code: str) -> str:
    scan, events = run_scan(base_url, payload)
    assert scan["status"] == "REVIEW"
    assert not scan.get("engine_executions")
    assert not scan.get("findings") and not scan.get("normalized_findings")
    assert "NUCLEI_JOB_REJECTED" in events and "NUCLEI_EXECUTION_STARTED" not in events
    assert code in str(scan.get("terminal_reason"))
    return str(scan["id"])


def rejected_runner_cases(runner_url: str, attestation: dict[str, Any]) -> list[int]:
    base: dict[str, Any] = {
        "schema_version": "aegis.nuclei.rpc/1",
        "engine_execution_id": "exec-000000000101",
        "job_id": "job-000000000101",
        "run_id": "scan-000000000101",
        "scan_id": "scan-000000000101",
        "target_ref": "synthetic-scm-vulnerable",
        "origin": "http://lab-api:8001",
        "profile_id": "NUCLEI_LAB_SAFE_HTTP_V1",
        "template_set_id": attestation["template_set_id"],
        "manifest_digest": attestation["manifest_digest"],
        "budgets": {
            "max_requests": 1,
            "max_results": 4,
            "time_budget_ms": 30000,
            "max_output_bytes": 65536,
        },
        "nonce": "00000000000000000000000000000101",
        "correlation_id": "corr-0000000000000101",
    }
    variants = [
        {**base, "template_set_id": "unknown-template-set"},
        {
            **base,
            "engine_execution_id": "exec-000000000102",
            "job_id": "job-000000000102",
            "run_id": "scan-000000000102",
            "scan_id": "scan-000000000102",
            "nonce": "00000000000000000000000000000102",
            "correlation_id": "corr-0000000000000102",
            "manifest_digest": "0" * 64,
        },
        {
            **base,
            "engine_execution_id": "exec-000000000103",
            "job_id": "job-000000000103",
            "run_id": "scan-000000000103",
            "scan_id": "scan-000000000103",
            "nonce": "00000000000000000000000000000103",
            "correlation_id": "corr-0000000000000103",
            "template_id": "git-config",
        },
    ]
    statuses: list[int] = []
    for payload in variants:
        status, response = request_json(f"{runner_url}/v1/run", payload)
        assert status in {200, 400}
        assert response.get("status") == "REJECTED"
        statuses.append(status)
    return statuses


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://10.213.47.10:8000")
    parser.add_argument("--runner-url", default="http://nuclei-runner:8090")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    runner_url = args.runner_url.rstrip("/")
    before = runner_attestation(runner_url)
    vulnerable: list[str] = []
    patched: list[str] = []
    for _ in range(args.trials):
        scan, events = run_scan(base_url, {"capability": CAPABILITY, "variant": "vulnerable"})
        assert_vulnerable(scan, events)
        vulnerable.append(str(scan["id"]))
    for _ in range(args.trials):
        scan, events = run_scan(base_url, {"capability": CAPABILITY, "variant": "patched"})
        assert_patched(scan, events)
        patched.append(str(scan["id"]))

    out_of_scope = [
        rejected_controller_case(
            base_url,
            {"capability": CAPABILITY, "target_ref": f"synthetic-unknown-{index}"},
            "OUT_OF_SCOPE_ORIGIN",
        )
        for index in range(3)
    ]
    denied = [
        rejected_controller_case(
            base_url,
            {"capability": capability},
            code,
        )
        for capability, code in (
            ("nuclei_http_state_changing_v0", "UNAPPROVED_STATE_CHANGE"),
            ("nuclei_network_protocol_v0", "UNSUPPORTED_PROTOCOL"),
            ("nuclei_passive_http_templates_v0", "UNKNOWN_CAPABILITY"),
        )
    ]
    runner_rejections = rejected_runner_cases(runner_url, before)
    after = runner_attestation(runner_url)
    execution_delta = int(after["executions_total"]) - int(before["executions_total"])
    assert execution_delta == args.trials * 2

    report = {
        "schema": "aegis.phase-1.2.live-acceptance/1",
        "generated_at": datetime.now(UTC).isoformat(),
        "verdict": "GO",
        "runner": {
            "version": after["runner_version"],
            "nuclei_version": after["engine"]["nuclei_version"],
            "binary_sha256": after["engine"]["binary_sha256"],
            "profile_id": after["profile_id"],
            "manifest_digest": after["manifest_digest"],
            "signature_probe": after["signature_probe"],
        },
        "vulnerable": {"passed": len(vulnerable), "total": args.trials, "scan_ids": vulnerable},
        "patched_negative": {"passed": len(patched), "total": args.trials, "scan_ids": patched},
        "out_of_scope": {"passed": len(out_of_scope), "total": 3, "scan_ids": out_of_scope},
        "state_changing_or_non_http": {"passed": len(denied), "total": 3, "scan_ids": denied},
        "unknown_or_mismatched_template_rpc": {
            "passed": len(runner_rejections),
            "total": 3,
            "http_statuses": runner_rejections,
        },
        "runner_execution_delta": execution_delta,
        "authorized_executions_expected": args.trials * 2,
        "unauthorized_executions": 0,
        "unauthorized_target_traffic": 0,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
