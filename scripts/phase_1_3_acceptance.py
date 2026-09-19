#!/usr/bin/env python3
"""Live Phase 1.3 acceptance against the real pinned ZAP runner and scope guard.

Run this inside the control-plane container so both internal endpoints are reachable:

    python scripts/phase_1_3_acceptance.py \
      --base-url http://10.213.47.10:8000 \
      --runner-url http://zap-runner:8092

Scans use only the public controller API. Direct runner calls are limited to the RPC injection
controls: they carry forbidden fields (jobs, a remote OpenAPI URL, ZAP options) and must be refused
by strict schema validation without starting ZAP. The runner's attested execution counter and the
guard's forwarded/blocked totals (reported through the runner attestation) are compared before and
after every block, so each claim about "zero executions" or "zero traffic" is measured.

The script prints one JSON document. The host-side wrapper reconciles it with the target's own
access log to count unauthorized target traffic independently of ZAP, the runner and the guard.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from typing import Any

CAPABILITY = "zap_passive_header_openapi_v1"
TERMINAL = {"PASS", "FAIL", "REVIEW", "INCOMPLETE", "CANCELLED"}
VULN_PATHS = ("/lab/zap/vulnerable/status", "/lab/zap/vulnerable/catalog/synthetic-catalog-1")
PATCHED_PATHS = ("/lab/zap/patched/status", "/lab/zap/patched/catalog/synthetic-catalog-1")
STAGES = (
    "ZAP_PROJECTION_CREATED",
    "ZAP_JOB_ADMITTED",
    "ZAP_RUNNER_STARTED",
    "ZAP_PLAN_VALIDATED",
    "ZAP_OPENAPI_IMPORT_STARTED",
    "ZAP_OPENAPI_IMPORT_COMPLETED",
    "ZAP_PASSIVE_SCAN_WAIT_STARTED",
    "ZAP_PASSIVE_SCAN_DRAINED",
    "ZAP_EXECUTION_COMPLETED",
)


def request_json(url: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(  # noqa: S310 - CLI URL is limited to internal HTTP(S)
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=200) as response:  # noqa: S310 - CLI URL
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
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        read_status, detail = request_json(f"{base_url}/api/scans/{scan_id}")
        if read_status != 200:
            raise AssertionError(f"scan read returned {read_status}")
        scan = detail["scan"]
        if scan["status"] in TERMINAL:
            return scan, [str(event["event"]) for event in detail["audit"]]
        time.sleep(0.5)
    raise AssertionError(f"scan {scan_id} did not complete")


def attestation(runner_url: str) -> dict[str, Any]:
    status, body = request_json(f"{runner_url}/v1/attestation")
    if status != 200 or not body.get("ready"):
        raise AssertionError(f"runner is not READY: {status} {body.get('failure_codes')}")
    return body


def counters(att: dict[str, Any]) -> dict[str, int]:
    guard = att["guard"]
    return {
        "executions": int(att["executions_total"]),
        "rejections": int(att["rejections_total"]),
        "guard_forwarded": int(guard["forwarded_total"]),
        "guard_blocked": int(guard["blocked_total"]),
    }


def delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {key: after[key] - before[key] for key in before}


def summarize(scan: dict[str, Any], events: list[str]) -> dict[str, Any]:
    provenance = scan.get("zap_provenance") or {}
    traffic = provenance.get("traffic") or {}
    stages = provenance.get("stages") or {}
    return {
        "scan_id": scan["id"],
        "status": scan["status"],
        "terminal_reason": scan.get("terminal_reason"),
        "verification": (scan.get("verification") or {}).get("status"),
        "findings": [
            {"id": f["id"], "severity": f["severity"], "confidence": f["confidence"]}
            for f in scan.get("findings") or []
        ],
        "lifecycle": [n.get("lifecycle_state") for n in scan.get("normalized_findings") or []],
        "projection_digest": (provenance.get("projection") or {}).get("digest"),
        "operation_count": (provenance.get("projection") or {}).get("operation_count"),
        "imported_urls": stages.get("urls_added"),
        "passive_queue_drained": stages.get("pscan_drained"),
        "plan_succeeded": stages.get("plan_succeeded"),
        "silent_mode": stages.get("silent_mode"),
        "installed_add_ons_match": stages.get("installed_add_ons_match"),
        "expected_requests": traffic.get("expected_requests"),
        "observed_requests": traffic.get("observed_requests"),
        "forwarded_requests": traffic.get("forwarded"),
        "blocked_requests": traffic.get("blocked"),
        "blocked_reasons": traffic.get("blocked_reasons"),
        "redirects": traffic.get("redirects"),
        "alerts": [
            {k: a.get(k) for k in ("plugin_id", "path", "param", "claimed_risk")}
            for a in provenance.get("alerts") or []
        ],
        "coverage_complete": provenance.get("coverage_complete"),
        "session_destroyed": (provenance.get("output") or {}).get("session_destroyed"),
        "exit": provenance.get("exit"),
        "duration_ms": (provenance.get("timing") or {}).get("duration_ms"),
        "zap_events": [e for e in events if e.startswith("ZAP_")],
    }


def assert_vulnerable(summary: dict[str, Any], events: list[str]) -> None:
    assert summary["status"] == "FAIL", summary
    assert summary["terminal_reason"] == "DETERMINISTIC_CONFIRMED"
    assert summary["verification"] == "CONFIRMED"
    assert [f["severity"] for f in summary["findings"]] == ["LOW"]
    assert summary["lifecycle"] == ["VERIFIED"]
    assert summary["coverage_complete"] is True and summary["passive_queue_drained"] is True
    assert summary["expected_requests"] == summary["observed_requests"] == 2
    assert summary["forwarded_requests"] == 2 and summary["blocked_requests"] == 0
    assert [(a["plugin_id"], a["path"]) for a in summary["alerts"]] == [
        (10021, VULN_PATHS[1])
    ]
    assert set(STAGES) <= set(events)
    for event in ("ZAP_ALERT_REPORTED", "ZAP_ALERT_CORRELATED", "ZAP_VERIFICATION_COMPLETED"):
        assert event in events


def assert_patched(summary: dict[str, Any], events: list[str]) -> None:
    assert summary["status"] == "PASS", summary
    assert summary["terminal_reason"] == "COVERAGE_COMPLETE"
    assert summary["verification"] == "PASS"
    assert not summary["findings"] and not summary["lifecycle"] and not summary["alerts"]
    assert summary["coverage_complete"] is True and summary["passive_queue_drained"] is True
    assert summary["imported_urls"] == 2 and summary["plan_succeeded"] is True
    assert summary["expected_requests"] == summary["observed_requests"] == 2
    assert summary["blocked_requests"] == 0
    assert set(STAGES) <= set(events) and "ZAP_VERIFICATION_COMPLETED" in events


def projection_control(
    base_url: str, runner_url: str, target_ref: str, code: str, trials: int
) -> dict[str, Any]:
    before = counters(attestation(runner_url))
    scans = []
    for _ in range(trials):
        scan, events = run_scan(base_url, {"capability": CAPABILITY, "target_ref": target_ref})
        assert scan["status"] == "REVIEW", scan["status"]
        assert scan.get("terminal_reason") == f"ZAP_PROJECTION_REJECTED_{code}"
        assert "ZAP_PROJECTION_REJECTED" in events and "ZAP_RUNNER_STARTED" not in events
        assert not scan.get("engine_executions") and not scan.get("findings")
        scans.append(scan["id"])
    change = delta(before, counters(attestation(runner_url)))
    assert change == {"executions": 0, "rejections": 0, "guard_forwarded": 0, "guard_blocked": 0}
    return {"passed": len(scans), "total": trials, "scan_ids": scans, "counter_delta": change}


def runtime_control(
    base_url: str, runner_url: str, target_ref: str, codes: set[str], trials: int
) -> dict[str, Any]:
    before = counters(attestation(runner_url))
    results = []
    for _ in range(trials):
        scan, events = run_scan(base_url, {"capability": CAPABILITY, "target_ref": target_ref})
        summary = summarize(scan, events)
        assert scan["status"] == "INCOMPLETE", scan["status"]
        reason = str(scan.get("terminal_reason"))
        assert any(reason == f"ZAP_EXECUTION_INCOMPLETE_{code}" for code in codes), reason
        assert "ZAP_EXECUTION_FAILED" in events and "ZAP_VERIFICATION_STARTED" not in events
        assert not scan.get("findings") and summary["coverage_complete"] is False
        assert summary["session_destroyed"] is True
        results.append(summary)
    change = delta(before, counters(attestation(runner_url)))
    assert change["executions"] == trials  # ZAP ran, and failed closed every time
    return {"passed": len(results), "total": trials, "results": results, "counter_delta": change}


def rpc_injection(runner_url: str, att: dict[str, Any], label: str, extra: dict[str, Any]) -> int:
    from_projection = {
        "schema_version": "aegis.zap.rpc/1",
        "engine_execution_id": f"exec-{secrets.token_hex(6)}",
        "job_id": f"job-{secrets.token_hex(6)}",
        "run_id": "scan-000000000131",
        "scan_id": "scan-000000000131",
        "target_ref": "synthetic-zap-vulnerable",
        "profile_id": att["profile_id"],
        "projection_ref": "synthetic-zap-vulnerable/1.3.0",
        "projection_digest": "0" * 64,
        "operation_allowlist_digest": "0" * 64,
        "budgets": {
            "max_requests": 2,
            "time_budget_ms": 120_000,
            "max_report_bytes": 131_072,
            "max_alerts": 8,
        },
        "nonce": secrets.token_hex(16),
        "correlation_id": f"corr-{secrets.token_hex(8)}",
    }
    status, body = request_json(f"{runner_url}/v1/run", {**from_projection, **extra})
    assert status == 400 and body.get("status") == "REJECTED", (label, status, body)
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://10.213.47.10:8000")
    parser.add_argument("--runner-url", default="http://zap-runner:8092")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--control-trials", type=int, default=3)
    args = parser.parse_args()
    base_url, runner_url = args.base_url.rstrip("/"), args.runner_url.rstrip("/")

    initial = attestation(runner_url)
    start = counters(initial)
    expected_paths: Counter[str] = Counter()

    vulnerable, patched = [], []
    for _ in range(args.trials):
        scan, events = run_scan(base_url, {"capability": CAPABILITY, "variant": "vulnerable"})
        summary = summarize(scan, events)
        assert_vulnerable(summary, events)
        vulnerable.append(summary)
        expected_paths.update(VULN_PATHS)
    for index in range(args.trials):
        scan, events = run_scan(
            base_url,
            {
                "capability": CAPABILITY,
                "variant": "patched",
                "retest_of": vulnerable[index]["scan_id"],
            },
        )
        summary = summarize(scan, events)
        assert_patched(summary, events)
        patched.append(summary)
        expected_paths.update(PATCHED_PATHS)
    positive = counters(attestation(runner_url))
    assert delta(start, positive)["executions"] == args.trials * 2
    assert delta(start, positive)["guard_blocked"] == 0

    n = args.control_trials
    controls: dict[str, Any] = {
        "state_changing_openapi": projection_control(
            base_url, runner_url, "synthetic-zap-negative-state-changing",
            "STATE_CHANGING_OPERATION", n,
        ),
        "alternate_server": projection_control(
            base_url, runner_url, "synthetic-zap-negative-alternate-server", "ALTERNATE_SERVER", n
        ),
        "external_ref": projection_control(
            base_url, runner_url, "synthetic-zap-negative-external-ref", "EXTERNAL_REFERENCE", n
        ),
    }

    # Injected jobs / remote API definitions / ZAP options at the scan API and at the runner RPC.
    before = counters(attestation(runner_url))
    api_statuses = []
    for field, value in (
        ("plan", {"jobs": [{"type": "activeScan"}]}),
        ("jobs", [{"type": "spider"}]),
        ("script", "print('x')"),
    ):
        payload = {"capability": CAPABILITY, "variant": "vulnerable", field: value}
        status, _ = request_json(f"{base_url}/api/scans", payload)
        assert status == 422, (field, status)
        api_statuses.append(status)
    active = []
    for _ in range(n):
        scan, events = run_scan(base_url, {"capability": "zap_active_scan_v0"})
        assert scan.get("terminal_reason") == "ZAP_JOB_REJECTED_ACTIVE_SCAN_FORBIDDEN"
        assert "ZAP_RUNNER_STARTED" not in events
        active.append(scan["id"])
    att = attestation(runner_url)
    rpc_jobs = [
        rpc_injection(runner_url, att, "activeScan", {"jobs": [{"type": "activeScan"}]}),
        rpc_injection(runner_url, att, "spider", {"jobs": [{"type": "spider"}]}),
        rpc_injection(runner_url, att, "script", {"jobs": [{"type": "script"}]}),
    ]
    rpc_remote = [
        rpc_injection(
            runner_url, att, "apiUrl", {"api_url": "https://api.remote.invalid/openapi.json"}
        ),
        rpc_injection(runner_url, att, "openapi", {"openapi": {"openapi": "3.0.3", "paths": {}}}),
        rpc_injection(runner_url, att, "target_url", {"target_url": "https://prod.example"}),
    ]
    rpc_options = [
        rpc_injection(runner_url, att, "options", {"zap_options": ["-addoninstall", "ascanrules"]}),
        rpc_injection(
            runner_url, att, "config", {"zap_options": ["-config", "api.disablekey=true"]}
        ),
        rpc_injection(runner_url, att, "rules", {"rules": [{"id": 40012, "threshold": "low"}]}),
    ]
    change = delta(before, counters(attestation(runner_url)))
    assert change["executions"] == 0 and change["guard_forwarded"] == 0
    controls["injected_jobs"] = {
        "passed": len(rpc_jobs) + len(api_statuses) + len(active),
        "total": len(rpc_jobs) + len(api_statuses) + len(active),
        "scan_api_http_statuses": api_statuses,
        "active_scan_capability_scan_ids": active,
        "runner_rpc_http_statuses": rpc_jobs,
    }
    controls["remote_api_definition_rpc"] = {
        "passed": len(rpc_remote), "total": len(rpc_remote), "runner_rpc_http_statuses": rpc_remote,
    }
    controls["injected_zap_options_rpc"] = {
        "passed": len(rpc_options),
        "total": len(rpc_options),
        "runner_rpc_http_statuses": rpc_options,
    }
    controls["injection_counter_delta"] = change

    controls["unexpected_redirect"] = runtime_control(
        base_url, runner_url, "synthetic-zap-negative-redirect",
        {"SCOPE_ESCAPE_BLOCKED", "REDIRECT_OBSERVED"}, n,
    )
    expected_paths.update({"/lab/zap/redirect/status": n})
    controls["unexpected_extra_request"] = runtime_control(
        base_url, runner_url, "synthetic-zap-negative-unstable", {"REQUEST_BUDGET_EXCEEDED"}, n
    )
    expected_paths.update({"/lab/zap/unstable/status": n})
    controls["target_timeout"] = runtime_control(
        base_url, runner_url, "synthetic-zap-negative-slow", {"TARGET_TIMEOUT"}, n
    )
    expected_paths.update({"/lab/zap/slow/status": n})

    final = attestation(runner_url)
    total = delta(start, counters(final))
    report = {
        "schema": "aegis.phase-1.3.live-acceptance/1",
        "generated_at": datetime.now(UTC).isoformat(),
        "runner": {
            "version": final["runner_version"],
            "zap_version": final["engine"]["zap_version"],
            "jar_sha256": final["engine"]["jar_sha256"],
            "java_runtime_version": final["engine"]["java_runtime_version"],
            "arch": final["engine"]["arch"],
            "add_on_inventory_digest": final["engine"]["add_on_inventory_digest"],
            "add_ons": [
                {"id": a["id"], "version": a["version"], "sha256": a["sha256"]}
                for a in final["add_ons"]
            ],
            "addonlist_verified": final["addonlist_verified"],
            "profile_id": final["profile_id"],
            "profile_version": final["profile_version"],
            "parser_version": final["parser_version"],
            "projection_version": final["projection_version"],
            "manifest_digest": final["manifest_digest"],
            "admitted_rule_ids": final["admitted_rule_ids"],
            "guard": final["guard"],
        },
        "vulnerable": {"passed": len(vulnerable), "total": args.trials, "results": vulnerable},
        "patched": {"passed": len(patched), "total": args.trials, "results": patched},
        "negative_controls": controls,
        "counter_delta_total": total,
        "authorized_zap_executions_expected": args.trials * 2 + n * 3,
        "zap_target_requests_expected_by_path": dict(sorted(expected_paths.items())),
        "unauthorized_zap_requests_blocked_by_guard": total["guard_blocked"],
    }
    assert total["executions"] == report["authorized_zap_executions_expected"]
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
