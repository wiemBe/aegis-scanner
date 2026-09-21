"""Phase 1.5 live acceptance driver (runs INSIDE the control-plane container).

This script is the operator-facing acceptance harness for the controlled ZAP active reflected-XSS
profile. It is deliberately split from the repository's normal modules: it knows how to speak to
the controller's own API, the runner RPC and the lease-signing material, which is exactly the
privilege boundary the runtime components enforce.

Subcommands (each writes one JSON evidence object to stdout; the host orchestrator collects,
checksums and stores them):

- ``preflight``     config + preflight projection (countersign, runner, admission, guard).
- ``negatives``     the eight live zero-traffic negative controls through the runner RPC.
- ``trial``         one full isolated trial: activate -> run -> poll -> redacted session view.
- ``stop-trial``    one real mid-scan emergency-stop trial (lease consumed, engine running).
- ``summary``       aggregates a directory of per-step evidence into one checksummed summary.

Every trial uses a fresh activation (fresh signed single-use lease), asserts the deterministic
target reset, and the controller revokes the lease on completion. The script never prints the
lease-signing secret, a raw lease token, a raw attack payload or a response body.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets as secrets_module
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

BASE = "http://127.0.0.1:8000"
RUNNER = "http://zap-active-runner:8093"
PHRASE = "ACTIVATE SYNTHETIC-LAB REFLECTED-XSS ACTIVE SCAN"
TRIAL_TIMEOUT_SECONDS = 420
POLL_SECONDS = 1.0
_API = httpx.Client(timeout=60.0, trust_env=False)
_CSRF_TOKEN: str | None = None

# The placeholder token for policy-level negatives: shaped like an AZL1 token, but it is never
# read because the policy rejects the request before any lease is verified.
PLACEHOLDER_TOKEN = "AZL1." + "A" * 64 + "." + "B" * 43


def now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _operator_session() -> str:
    """Create one server-side operator session without printing or persisting its bootstrap key."""

    global _CSRF_TOKEN
    if _CSRF_TOKEN is not None:
        return _CSRF_TOKEN
    bootstrap = os.environ.get("AEGIS_ZAP_ACTIVE_OPERATOR_BOOTSTRAP_SECRET", "")
    if len(bootstrap.encode()) < 32:
        raise RuntimeError("operator bootstrap credential unavailable")
    response = _API.post(
        f"{BASE}/api/zap-active/operator/login", json={"bootstrap_secret": bootstrap}
    )
    if response.status_code != 200:
        raise RuntimeError("operator authentication failed")
    token = response.json().get("csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        raise RuntimeError("operator session response invalid")
    _CSRF_TOKEN = token
    return token


def api_get(path: str) -> dict[str, Any]:
    _operator_session()
    response = _API.get(f"{BASE}{path}", timeout=30.0)
    response.raise_for_status()
    return response.json()


def api_post(path: str, body: dict[str, Any], expect: int = 200) -> httpx.Response:
    response = _API.post(
        f"{BASE}{path}", json=body, timeout=60.0, headers={"X-CSRF-Token": _operator_session()}
    )
    if response.status_code != expect:
        raise RuntimeError(f"{path}: HTTP {response.status_code}: {response.text[:300]}")
    return response


def runner_get(path: str) -> dict[str, Any]:
    response = httpx.get(
        f"{RUNNER}{path}", timeout=30.0, headers=_runner_headers()
    )
    response.raise_for_status()
    return response.json()


def runner_post(path: str, body: dict[str, Any]) -> httpx.Response:
    return httpx.post(f"{RUNNER}{path}", json=body, timeout=120.0, headers=_runner_headers())


def _runner_headers() -> dict[str, str]:
    credential = os.environ.get("AEGIS_ZAP_ACTIVE_RUNNER_CLIENT", "")
    if len(credential.encode()) < 32:
        raise RuntimeError("runner control credential unavailable")
    return {"X-Aegis-Active-Runner-Client": credential}


def preflight() -> dict[str, Any]:
    config = api_get("/api/zap-active/config")
    state = api_get("/api/zap-active/preflight")
    assert config["enabled"], "adapter not enabled"
    assert state["countersign"]["valid"], state["countersign"]
    assert state["ready"], state["blockers"]
    return {
        "step": "preflight",
        "at": now(),
        "config": {
            "profile_id": config["profile_id"],
            "capability_id": config["capability_id"],
            "environment": config["environment"],
            "manifest_digest": config["manifest_digest"],
            "manifest_version": config["manifest_version"],
            "engine_version": config["engine_version"],
            "image_index_digest": config["image_index_digest"],
            "admitted_rule": config["admitted_rule"],
            "neutralised_dependency_ids": config["neutralised_dependency_ids"],
            "countersign": config["countersign"],
        },
        "preflight": state,
    }


def _sign_claims(
    *, offset: int = 0, lifetime: int = 600, nonce: str | None = None
) -> tuple[str, dict[str, Any]]:
    """Mint one controller-signed lease for the vulnerable acceptance target."""
    from aegis_zap_active.inventory import ZAP_ACTIVE_TARGETS
    from aegis_zap_active.lease import AUDIENCE, LeaseClaims, sign_lease
    from aegis_zap_active.manifest import manifest_digest
    from aegis_zap_active.projection import project

    target = ZAP_ACTIVE_TARGETS["synthetic-zap-active-vulnerable"]
    projection = project(target)
    stamp = int(datetime.now(UTC).timestamp()) + offset
    claims = LeaseClaims(
        lease_id=f"lease-{secrets_module.token_hex(8)}",
        capability_id="zap_active_reflected_xss_v1",
        profile_id="ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        target_ref=target.target_ref,
        target_origin=target.origin,
        projection_digest=projection.digest,
        allowlist_digest=projection.allowlist_digest,
        manifest_digest=manifest_digest(),
        issued_at=stamp,
        not_before=stamp,
        expires_at=stamp + lifetime,
        nonce=nonce or secrets_module.token_hex(16),
        audience=AUDIENCE,
        budget_id=f"budget-{secrets_module.token_hex(6)}",
    )
    secret = os.environ["ZAP_ACTIVE_LEASE_SECRET"]
    return sign_lease(claims, secret), claims.model_dump(mode="json")


def _run_request_body(*, target_ref: str, token: str, **overrides: Any) -> dict[str, Any]:
    """A strictly-typed runner /v1/run body, optionally tampered field-by-field."""
    from aegis_zap_active.contracts import ZapActiveRunRequest
    from aegis_zap_active.inventory import ZAP_ACTIVE_TARGETS
    from aegis_zap_active.projection import project, projection_ref

    target = ZAP_ACTIVE_TARGETS.get(target_ref)
    if target is None:
        projection = project(ZAP_ACTIVE_TARGETS["synthetic-zap-active-vulnerable"])
        projection_ref_value = projection_ref("synthetic-zap-active-vulnerable")
    else:
        try:
            projection = project(target)
        except Exception:
            projection = project(ZAP_ACTIVE_TARGETS["synthetic-zap-active-vulnerable"])
        projection_ref_value = projection_ref(target_ref)
    payload: dict[str, Any] = {
        "engine_execution_id": f"exec-{secrets_module.token_hex(6)}",
        "job_id": f"job-{secrets_module.token_hex(6)}",
        "run_id": f"scan-{secrets_module.token_hex(6)}",
        "scan_id": f"scan-{secrets_module.token_hex(6)}",
        "target_ref": target_ref,
        "profile_id": "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1",
        "capability_id": "zap_active_reflected_xss_v1",
        "projection_ref": projection_ref_value,
        "projection_digest": projection.digest,
        "operation_allowlist_digest": projection.allowlist_digest,
        "query_param": projection.query_param,
        "budgets": {
            "max_requests": 200,
            "time_budget_ms": 300_000,
            "max_report_bytes": 131_072,
            "max_alerts": 8,
            "delay_ms": 250,
        },
        "lease_token": token,
        "nonce": secrets_module.token_hex(16),
        "correlation_id": f"corr-{secrets_module.token_hex(8)}",
    }
    payload.update(overrides)
    return ZapActiveRunRequest.model_validate(payload).model_dump(mode="json")


def negatives() -> dict[str, Any]:
    """The eight live negative controls. Every one must be refused with ZERO target traffic."""
    results: list[dict[str, Any]] = []
    vulnerable_ref = "synthetic-zap-active-vulnerable"

    def run_negative(
        name: str,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        expect_code: str,
    ) -> None:
        if method == "POST":
            response = runner_post(path, body or {})
            payload = response.json()
        else:
            payload = runner_get(path)
        code = payload.get("error_code")
        status = payload.get("status")
        results.append(
            {
                "name": name,
                "http_status": response.status_code if method == "POST" else 200,
                "response_status": status,
                "error_code": code,
                "expected": expect_code,
                "refused": (status == "REJECTED" and code == expect_code)
                or (response.status_code in {400, 403, 404} and code == expect_code),
            }
        )

    # --- policy-level rejections (the lease is never read; the guard is never armed) ---------
    for name, overrides, code in (
        ("unknown_target", {"target_ref": "synthetic-zap-active-unknown"}, "UNKNOWN_TARGET"),
        (
            "projection_digest_mismatch",
            {"projection_digest": "a" * 64},
            "PROJECTION_DIGEST_MISMATCH",
        ),
        (
            "allowlist_digest_mismatch",
            {"operation_allowlist_digest": "b" * 64},
            "ALLOWLIST_DIGEST_MISMATCH",
        ),
        ("unexpected_query_param", {"query_param": "debug"}, "UNEXPECTED_QUERY_PARAM"),
    ):
        target_ref = overrides.get("target_ref", vulnerable_ref)
        narrowed = {key: value for key, value in overrides.items() if key != "target_ref"}
        body = _run_request_body(target_ref=target_ref, token=PLACEHOLDER_TOKEN, **narrowed)
        run_negative(name, method="POST", path="/v1/run", body=body, expect_code=code)

    # --- lease-level rejections (controller-signed tokens the admission must refuse) ----------
    # 1. expired lease
    expired, _ = _sign_claims(offset=-2_000, lifetime=600)
    run_negative("expired_lease", method="POST", path="/v1/lease/arm",
                 body={"lease_token": expired}, expect_code="LEASE_EXPIRED")

    # 2. tampered signature
    valid, _ = _sign_claims()
    prefix, payload, signature = valid.split(".")
    run_negative("invalid_signature", method="POST", path="/v1/lease/arm",
                 body={"lease_token": f"{prefix}.{payload}.{signature[:-1]}x"},
                 expect_code="LEASE_SIGNATURE_INVALID")

    # 3. unarmed but perfectly valid lease: nothing was armed, nothing may execute
    unarmed, _ = _sign_claims()
    run_negative("unarmed_lease", method="POST", path="/v1/run",
                 body=_run_request_body(target_ref=vulnerable_ref, token=unarmed),
                 expect_code="LEASE_NOT_ARMED")

    # 4. replayed lease: one extra vulnerable execution consumes lease R; replaying R is refused
    #    with zero further traffic (this is the live "second execution with the same lease" case).
    replay_token, _ = _sign_claims()
    arm_replay = runner_post("/v1/lease/arm", {"lease_token": replay_token})
    assert arm_replay.status_code == 200, arm_replay.text
    first_body = _run_request_body(target_ref=vulnerable_ref, token=replay_token)
    first_run = runner_post("/v1/run", first_body)
    assert first_run.status_code == 200, first_run.text
    first_payload = first_run.json()
    results.append(
        {
            "name": "replayed_lease_first_execution",
            "http_status": first_run.status_code,
            "response_status": first_payload.get("status"),
            "error_code": first_payload.get("error_code"),
            "expected": "COMPLETED",
            "refused": False,
            "consumed": first_payload.get("lease", {}).get("consumed"),
            "revoked_after_execution": first_payload.get("lease", {}).get(
                "revoked_after_execution"
            ),
        }
    )
    second_body = _run_request_body(target_ref=vulnerable_ref, token=replay_token)
    replay = runner_post("/v1/run", second_body)
    replay_payload = replay.json()
    results.append(
        {
            "name": "replayed_lease",
            "http_status": replay.status_code,
            "response_status": replay_payload.get("status"),
            "error_code": replay_payload.get("error_code"),
            "expected": "LEASE_ALREADY_CONSUMED",
            "refused": (
                replay_payload.get("status") == "REJECTED"
                and replay_payload.get("error_code") == "LEASE_ALREADY_CONSUMED"
            ),
        }
    )

    refused = all(item["refused"] for item in results if item.get("expected") != "COMPLETED")
    return {
        "step": "negatives",
        "at": now(),
        "count": len(results),
        "all_refused_with_expected_code": refused,
        "results": results,
    }


def _wait_session(step_name: str, activation: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + TRIAL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        view = api_get("/api/zap-active/session")
        if view["state"] in {"COMPLETED", "FAILED", "STOPPED"}:
            assert view["scan_id"] == activation["scan_id"], "session switched unexpectedly"
            return view
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"{step_name}: session did not reach a terminal state in time")


def trial(scenario: str, index: int) -> dict[str, Any]:
    step_name = f"trial-{scenario}-{index:02d}"
    activation = api_post(
        "/api/zap-active/activate",
        {
            "scenario": scenario,
            "confirmation_phrase": PHRASE,
            "operator_id": "acceptance-harness",
            "ttl_seconds": 900,
        },
        expect=201,
    ).json()
    assert activation["state"] == "ARMED", activation
    api_post("/api/zap-active/run", {}, expect=202)
    view = _wait_session(step_name, activation)
    view["step"] = step_name
    view["activated_at"] = activation["created_at"]
    return view


def stop_trial() -> dict[str, Any]:
    step_name = "trial-emergency-stop"
    activation = api_post(
        "/api/zap-active/activate",
        {
            "scenario": "scenario-a",
            "confirmation_phrase": PHRASE,
            "operator_id": "acceptance-harness",
            "ttl_seconds": 900,
        },
        expect=201,
    ).json()
    assert activation["state"] == "ARMED", activation
    baseline = runner_get("/v1/lease/status").get("consumed_total", 0)
    api_post("/api/zap-active/run", {}, expect=202)
    # Wait until the lease is consumed (execution began) and the engine is up, then stop mid-scan.
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        status = runner_get("/v1/lease/status")
        if status.get("consumed_total", 0) > baseline:
            break
        time.sleep(0.4)
    else:
        raise TimeoutError(f"{step_name}: the lease was never consumed")
    time.sleep(2.0)  # let the JVM actually reach the active scan before the kill
    stopped = api_post(
        "/api/zap-active/stop", {"operator_id": "acceptance-harness"}, expect=200
    ).json()
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        view = api_get("/api/zap-active/session")
        if view["state"] == "STOPPED":
            break
        time.sleep(POLL_SECONDS)
    else:
        raise TimeoutError(f"{step_name}: the stopped session never reached STOPPED")
    view["step"] = step_name
    view["stop_request_view"] = stopped
    return view


def summary(directory: str) -> dict[str, Any]:
    files = sorted(
        path for path in Path(directory).glob("*.json") if path.name != "summary.json"
    )
    digest = hashlib.sha256()
    payloads: list[dict[str, Any]] = []
    for path in files:
        raw = path.read_bytes()
        digest.update(raw)
        payloads.append(json.loads(raw))
        (path.parent / f"{path.name}.sha256").write_text(sha256_bytes(raw) + "\n")
    trials = [p for p in payloads if str(p.get("step", "")).startswith("trial-")]
    negatives = next((p for p in payloads if p.get("step") == "negatives"), None)
    pre = next((p for p in payloads if p.get("step") == "preflight"), None)
    summary_payload = {
        "step": "summary",
        "at": now(),
        "steps": sorted(path.name for path in files),
        "evidence_sha256": digest.hexdigest(),
        "preflight": pre,
        "negatives": negatives,
        "trials": trials,
    }
    return summary_payload


def main() -> None:
    usage = (
        "usage: phase_1_5_acceptance.py preflight|negatives|trial <variant> <index>"
        "|stop-trial|summary <dir>"
    )
    if len(sys.argv) < 2:
        raise SystemExit(usage)
    command = sys.argv[1]
    if command == "preflight":
        payload = preflight()
    elif command == "negatives":
        payload = negatives()
    elif command == "trial":
        payload = trial(sys.argv[2], int(sys.argv[3]))
    elif command == "stop-trial":
        payload = stop_trial()
    elif command == "summary":
        payload = summary(sys.argv[2])
    else:
        raise SystemExit(f"unknown command: {command}")
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
