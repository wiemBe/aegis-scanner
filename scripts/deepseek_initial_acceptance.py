"""DeepSeek initial acceptance: ONE provider-only smoke + ONE full synthetic discovery.

Deliberately small first acceptance for the external DeepSeek OpenAI-compatible API (mode
INTERNAL_LLM), driven over the running control-plane. It never weakens a schema, allowlist,
verifier rule or budget: the model only proposes a bounded candidate; the deterministic controller
validates/admits it, compiles the typed read-only requests, and the deterministic verifier is the
sole finding/PASS authority. The linked patched retest is controller-constructed and needs no model
call.

The smoke result JSON (from scripts/deepseek_smoke.py) is read from SMOKE_RESULT_PATH and folded
into the evidence. This script performs no model call of its own and never holds or prints the
credential. Writes artifacts/deepseek-initial-acceptance.json (+ .sha256 written by the caller).
"""

import asyncio
import hashlib
import json
import os
import time
from typing import Any

import httpx

BASE_URL = os.environ.get("AEGIS_BASE_URL", "http://control-plane:8000")
EVIDENCE_PATH = os.environ.get("EVIDENCE_PATH", "artifacts/deepseek-initial-acceptance.json")
SMOKE_RESULT_PATH = os.environ.get("SMOKE_RESULT_PATH", "artifacts/deepseek-smoke.json")
EXPECTED_MODEL = os.environ.get("EXPECTED_MODEL", "deepseek-v4-pro")
EXPECTED_MODE = "INTERNAL_LLM"
API_HOST = os.environ.get("DEEPSEEK_API_HOST", "api.deepseek.com")
ADAPTER_VERSION = "deepseek-internal-openai-compatible-1"
SCAN_DEADLINE = float(os.environ.get("SCAN_DEADLINE_SECONDS", "180"))
# Hard caps for the deliberately small first acceptance.
MAX_TARGET_REQUESTS = int(os.environ.get("MAX_TARGET_REQUESTS", "8"))
# Genuine sensitive VALUES that must never appear in a scan report: the synthetic target
# credentials. The DeepSeek API key value itself is scanned authoritatively by the orchestrator
# (scripts/deepseek_acceptance.sh) against the real key. Generic HTTP vocabulary such as
# "Authorization"/"Bearer"/"sk-" is NOT secret and legitimately appears in the projected OpenAPI
# surface and model rationale, so it is deliberately not treated as a leak marker here.
SECRET_MARKERS = ("lab-token", "synthetic-password")


class AcceptanceError(AssertionError):
    """Fail-closed precondition violation; the message carries no secret."""


def _read_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)  # type: ignore[no-any-return]


def _write_json(path: str, payload: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


async def _run_scan(client: httpx.AsyncClient, payload: dict[str, str]) -> dict[str, Any]:
    response = await client.post("/api/scans", json=payload)
    response.raise_for_status()
    scan_id = response.json()["id"]
    deadline = time.monotonic() + SCAN_DEADLINE
    while time.monotonic() < deadline:
        report = (await client.get(f"/api/scans/{scan_id}")).json()
        if report["scan"]["status"] not in {"QUEUED", "RUNNING"}:
            return report
        await asyncio.sleep(0.5)
    raise AcceptanceError("Scan exceeded the acceptance deadline")


def _classify(scan: dict[str, Any]) -> str:
    findings = scan.get("findings", [])
    if scan["status"] == "FAIL" and findings:
        f = findings[0]
        return f"CONFIRMED_{f['severity']}_{f['confidence']}"
    return f"TERMINAL_{scan['status']}"


async def main() -> None:
    smoke = await asyncio.to_thread(_read_json, SMOKE_RESULT_PATH)
    if smoke.get("smoke") != "PASS":
        raise AcceptanceError("Smoke call did not pass; discovery is not attempted")

    async with httpx.AsyncClient(base_url=BASE_URL, trust_env=False, timeout=60) as client:
        health = (await client.get("/health")).json()
        if health.get("planner") != EXPECTED_MODE:
            raise AcceptanceError(
                f"Deployed planner is {health.get('planner')!r}, not {EXPECTED_MODE}"
            )

        # One full synthetic vulnerable discovery.
        discovery = await _run_scan(client, {"target": "synthetic-bank-api"})
        scan = discovery["scan"]
        if scan.get("model") != EXPECTED_MODEL:
            raise AcceptanceError(f"Discovery model is {scan.get('model')!r}, not {EXPECTED_MODEL}")
        usage = scan["usage"]
        if usage["requests"] > MAX_TARGET_REQUESTS:
            raise AcceptanceError(
                f"Target requests {usage['requests']} exceeded cap {MAX_TARGET_REQUESTS}"
            )

        findings = scan.get("findings", [])
        confirmed = (
            scan["status"] == "FAIL"
            and bool(findings)
            and (findings[0]["severity"], findings[0]["confidence"]) == ("HIGH", "CONFIRMED")
        )

        # Findings must be verifier-derived from real 200 cross-owner evidence, never model prose.
        evidence_by_name = {e["name"]: e for e in scan.get("evidence", [])}
        finding_from_evidence = True
        for finding in findings:
            for name in finding.get("evidence_names", []):
                item = evidence_by_name.get(name)
                if not item or item.get("status_code") != 200 or item.get("error"):
                    finding_from_evidence = False

        retest: dict[str, Any] | None = None
        retest_model_calls = None
        if confirmed:
            # Linked patched retest: controller-constructed, must require no model call.
            retest = await _run_scan(
                client,
                {"target": "synthetic-bank-api", "variant": "patched", "retest_of": scan["id"]},
            )
            retest_model_calls = retest["scan"]["usage"]["model_calls"]

        combined = json.dumps(discovery) + (json.dumps(retest) if retest else "")
        redaction_clean = not any(m in combined for m in SECRET_MARKERS)

        evidence: dict[str, Any] = {
            "acceptance": "deepseek-initial",
            "provider_mode": EXPECTED_MODE,
            "provider_name": "deepseek",
            "provider_type": "internal_openai_compatible",
            "model": scan.get("model"),
            "requested_model": os.environ.get("REQUESTED_MODEL", EXPECTED_MODEL),
            "api_host": API_HOST,
            "endpoint_path": "/chat/completions",
            "adapter_version": ADAPTER_VERSION,
            "planner_contract_version": scan.get("planner_contract_version"),
            "execution_policy_version": next(
                (
                    e["details"].get("execution_policy_version")
                    for e in discovery["audit"]
                    if e["event"] == "SCAN_CREATED"
                    and "execution_policy_version" in e.get("details", {})
                ),
                None,
            ),
            "provider_response_status": "OK",
            "smoke": smoke,
            "provider_usage": {
                "smoke": smoke.get("usage"),
                "discovery": usage,
            },
            "latency_ms": {"smoke": smoke.get("latency_ms")},
            "timeouts": {
                "scan_deadline_seconds": SCAN_DEADLINE,
                "model_timeout_seconds": os.environ.get("MODEL_TIMEOUT_SECONDS"),
            },
            "model_call_count": {
                "smoke": 1,
                "discovery": usage["model_calls"],
                "retest": retest_model_calls,
                "total": 1 + usage["model_calls"] + (retest_model_calls or 0),
            },
            "target_request_count": {
                "smoke": 0,
                "discovery": usage["requests"],
                "retest": (retest["scan"]["usage"]["requests"] if retest else None),
            },
            "decision_types": [d.get("decision_type") for d in scan.get("decisions", [])],
            "decision_type": _classify(scan),
            "validation_result": {
                "confirmed_direction": confirmed,
                "finding_only_from_deterministic_evidence": finding_from_evidence,
                "within_target_request_cap": usage["requests"] <= MAX_TARGET_REQUESTS,
            },
            "deterministic_verifier_result": {
                "status": scan["status"],
                "finding": (
                    {"severity": findings[0]["severity"], "confidence": findings[0]["confidence"]}
                    if findings
                    else None
                ),
            },
            "linked_retest_result": (
                {
                    "status": retest["scan"]["status"],
                    "codes": [e["status_code"] for e in retest["scan"]["evidence"]],
                    "model_calls": retest_model_calls,
                    "controller_constructed_no_model_call": retest_model_calls == 0,
                }
                if retest
                else None
            ),
            "rejection_reason": None if confirmed else _classify(scan),
            "redaction_status": "CLEAN" if redaction_clean else "LEAK_DETECTED",
            "provider_metadata": scan.get("provider_metadata"),
        }
        digest = hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode("utf-8")
        ).hexdigest()
        evidence["evidence_digest"] = digest

        verdict = (
            "GO"
            if (
                confirmed
                and finding_from_evidence
                and redaction_clean
                and usage["requests"] <= MAX_TARGET_REQUESTS
                and retest is not None
                and retest["scan"]["status"] == "PASS"
                and retest["scan"]["evidence"]
                and [e["status_code"] for e in retest["scan"]["evidence"]] == [200, 200, 403]
                and retest_model_calls == 0
            )
            else "NO-GO"
        )
        evidence["verdict"] = verdict

        await asyncio.to_thread(_write_json, EVIDENCE_PATH, evidence)
        # Print a secret-free summary for the operator.
        print(
            json.dumps(
                {k: v for k, v in evidence.items() if k not in {"smoke", "provider_metadata"}},
                indent=2,
            )
        )
        print(f"Evidence written to {EVIDENCE_PATH} (digest {digest})")


if __name__ == "__main__":
    asyncio.run(main())
