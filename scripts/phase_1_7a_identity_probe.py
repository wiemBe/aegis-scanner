"""Phase 1.7-A provider-only structured identity probe.

Runs the exact provider-binding health preflight, then performs ONE strict structured generation
through the isolated model gateway with zero target requests. It retains the sanitized pre-dispatch
request projection and captures the exact, non-secret provider-reported model identity. There is no
retry, no aliasing, no normalization and no offline fallback: any mismatch or omitted identity fails
closed before the synthetic range is touched.

Exit code 0 only when the provider reports exactly the canonical model. Any other identity, an
omitted identity, or a preflight failure exits non-zero so the caller must not run the BOLA matrix.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.contracts import AgentRole
from aegis.multi_agent.model import GatewayAgentModel
from aegis.multi_agent.provider_binding import (
    PHASE_1_7A_CANONICAL_MODEL,
    ProviderBindingFailure,
    provider_binding_preflight,
)
from aegis.settings import Settings

# A bounded, target-free discovery context: no origins, no credential values, no scenario mode,
# no answer key. It exists only to elicit one strict structured response for identity capture.
PROBE_ROLE = AgentRole.SURFACE_AGENT
PROBE_TASK = "OBSERVE_SURFACE"
PROBE_CONTEXT: dict[str, Any] = {
    "target_ref": "range-bank",
    "scenario_ref": "identity-probe",
    "allowed_operation_ids": ["getAccount"],
}


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


async def main() -> int:
    settings = Settings()
    evidence_dir = Path(os.environ["EVIDENCE_DIR"])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    base: dict[str, Any] = {
        "phase": "1.7-A",
        "probe": "provider-only-structured-identity",
        "canonical_model": PHASE_1_7A_CANONICAL_MODEL,
        "requested_model": settings.ai_model,
        "provider": settings.ai_provider,
        "target_requests": 0,
        "created_at": datetime.now(UTC).isoformat(),
    }

    if settings.ai_provider != "internal_openai_compatible":
        payload = {**base, "status": "FAILED_CLOSED", "gate": "PROVIDER_NOT_INTERNAL_OPENAI"}
        _write(evidence_dir / "identity-probe.json", payload)
        print(json.dumps({k: payload[k] for k in ("status", "gate")}, sort_keys=True))
        return 1

    # Step 2: exact provider-binding health preflight (config/allowlist/health identity).
    try:
        binding = await provider_binding_preflight(settings, PHASE_1_7A_CANONICAL_MODEL)
    except ProviderBindingFailure as exc:
        payload = {
            **base,
            "status": "FAILED_CLOSED",
            "gate": "PROVIDER_BINDING_PREFLIGHT",
            "classification": exc.code,
            "binding_projection": exc.projection,
            "provider_call_attempts": 0,
        }
        _write(evidence_dir / "identity-probe.json", payload)
        print(
            json.dumps(
                {
                    "status": "FAILED_CLOSED",
                    "gate": "PROVIDER_BINDING_PREFLIGHT",
                    "classification": exc.code,
                },
                sort_keys=True,
            )
        )
        return 1

    # Step 3: exactly one provider call through the gateway. No retry, no fallback.
    model = GatewayAgentModel(settings)
    probe_error: str | None = None
    try:
        await model.generate(PROBE_ROLE, PROBE_TASK, PROBE_CONTEXT, {})
    except Exception as exc:  # noqa: BLE001 - fail closed on any adapter/provider rejection
        probe_error = str(exc)[:200]

    reported = list(model.provider_reported_models)
    projections = [item.model_dump(mode="json") for item in model.failed_request_projections]
    success_projections = [
        item.request_projection.model_dump(mode="json") for item in model.call_records
    ]
    all_projections = success_projections + projections
    exact_identity = (
        len(reported) == 1 and reported[0] == PHASE_1_7A_CANONICAL_MODEL and probe_error is None
    )

    payload = {
        **base,
        "binding_preflight": {**binding.model_dump(mode="json"), "status": "PASS"},
        "provider_call_attempts": model.call_attempts,
        "provider_reported_models": reported,
        "provider_reported_identity": reported[0] if len(reported) == 1 else None,
        "identity_omitted": len(reported) == 0,
        "exact_canonical_identity": exact_identity,
        "failure_code": probe_error,
        "gateway_failure_codes": list(model.failure_codes),
        "retained_request_projections": all_projections,
        "sanitized_projection_retained": len(all_projections) >= 1,
        "status": "PASS" if exact_identity else "FAILED_CLOSED",
        "gate": "PROVIDER_IDENTITY_PROBE",
        "range_state": "NOT_TOUCHED",
    }
    _write(evidence_dir / "identity-probe.json", payload)

    summary = {
        "status": payload["status"],
        "gate": "PROVIDER_IDENTITY_PROBE",
        "provider_call_attempts": model.call_attempts,
        "provider_reported_identity": payload["provider_reported_identity"],
        "identity_omitted": payload["identity_omitted"],
        "exact_canonical_identity": exact_identity,
        "failure_code": probe_error,
        "sanitized_projection_retained": payload["sanitized_projection_retained"],
        "target_requests": 0,
    }
    blob = json.dumps(summary, sort_keys=True)
    for marker in ("Bearer ", "Authorization", "authorization", "AI_AUTH_TOKEN"):
        if marker in blob:
            print(json.dumps({"status": "FAILED_CLOSED", "gate": "OUTPUT_CREDENTIAL_MARKER"}))
            return 1
    print(blob)
    return 0 if exact_identity else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
