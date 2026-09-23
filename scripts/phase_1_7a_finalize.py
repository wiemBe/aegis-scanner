"""Finalize external acceptance gates and create checksums without handling a provider secret."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def main() -> None:
    root = Path(os.environ["ARTIFACT_DIR"])
    acceptance_path = root / "acceptance.json"
    payload = json.loads(acceptance_path.read_text(encoding="utf-8"))
    payload["external_secret_scan"] = os.environ["SECRET_SCAN_STATUS"]
    payload["teardown"] = os.environ["TEARDOWN_STATUS"]
    payload["quality_gates"] = os.environ.get("QUALITY_GATE_STATUS", "PENDING")
    cases = payload.get("cases", [])
    if (
        payload.get("failed_classification") == "PROVIDER_MODEL_MISMATCH"
        and len(cases) == 1
        and cases[0].get("case") == "single-agent-vulnerable"
    ):
        # The first single-agent provider call follows one documented-surface request. The gateway
        # rejected the provider model identifier before returning validated output, token usage, or
        # its safe request projection. Unknown values remain unknown rather than becoming zero.
        case = cases[0]
        case.update(
            {
                "architecture_path": (
                    "Operator -> controller -> single Authorization agent -> documented-surface "
                    "request -> model gateway -> FAILED_CLOSED before hypothesis/broker/verifier"
                ),
                "provider": payload.get("provider"),
                "requested_model": payload.get("requested_model"),
                "role_sequence_attempted": ["AUTHORIZATION_AGENT"],
                "task_sequence_attempted": ["SINGLE_AGENT_BOLA"],
                "validated_structured_outputs": [],
                "model_usage": {
                    "calls": case.get("model_call_attempts", 1),
                    "input_tokens": None,
                    "output_tokens": None,
                    "total_tokens": None,
                    "usage_status": "UNAVAILABLE_AFTER_GATEWAY_REJECTION",
                    "retry_count": 0,
                },
                "target_requests": 1,
                "commands_executed_by_agents": 0,
                "hypotheses_produced": 0,
                "broker_actions": {"admitted": 0, "rejected": 0},
                "verifier_owned_outcome": "NOT_RUN",
                "final_controller_outcome": "FAILED_CLOSED",
                "reset_cleanup": {
                    "succeeded": bool(case.get("cleanup", {}).get("healthy"))
                    and bool(case.get("health", {}).get("healthy")),
                    "final_generation": case.get("cleanup", {}).get("reset_generation"),
                },
                "gateway_request_proof": {
                    "captured_count": 0,
                    "required_projection_gate": "FAILED_NOT_RETURNED_ON_GATEWAY_REJECTION",
                },
                "secret_redaction": {
                    "structural_scan": payload["external_secret_scan"],
                    "provider_secret_value_scan": "NOT_PERFORMED_KEY_NOT_READ",
                },
            }
        )
        payload["global_usage"]["provider_tokens"] = None
        payload["global_usage"]["provider_token_usage_status"] = (
            "UNAVAILABLE_AFTER_GATEWAY_REJECTION"  # noqa: S105 - status, not a password
        )
        payload["global_usage"]["target_requests"] = 1
        payload["global_gates"]["combined_provider_tokens_at_most_60000"] = False
        payload["global_gates"]["gateway_request_projection_proof_complete"] = False
        payload["comparison"] = {"status": "NOT_AVAILABLE_MATRIX_STOPPED_AFTER_FIRST_FAILURE"}
    clean = (
        payload.get("preliminary_verdict") == "GO"
        and payload["external_secret_scan"] in {"CLEAN", "CLEAN_STRUCTURAL"}  # noqa: S105 - statuses, not passwords
        and payload["teardown"] == "VERIFIED"
        and payload["quality_gates"] == "PASS"
    )
    payload["final_verdict"] = "GO for live Phase 1.7-A BOLA smoke only" if clean else "NO-GO"
    for case in cases:
        if "secret_redaction" in case:
            case["secret_redaction"]["external_structural_scan"] = payload["external_secret_scan"]
    acceptance_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows: list[str] = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(json.dumps({"artifact_dir": str(root), "final_verdict": payload["final_verdict"]}))


if __name__ == "__main__":
    main()
