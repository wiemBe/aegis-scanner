"""DeepSeek provider-only smoke call (INTERNAL_LLM via the isolated llm-gateway).

Sends ONE harmless synthetic planner request straight to the gateway's /v1/plan endpoint. It does
NOT create a scan and never touches the lab/target network, so a successful smoke proves the
gateway reaches DeepSeek and returns a valid Contract V3 decision with ZERO target requests.

Fails closed unless the deployed planner reports mode INTERNAL_LLM and the exact expected model.
The credential lives only inside the gateway; this script neither holds nor prints it, and prints
no Authorization header. Run from a container attached to the planner-rpc network, e.g.
`GATEWAY_URL=http://llm-gateway:8080 EXPECTED_MODEL=deepseek-v4-pro \
 python scripts/deepseek_smoke.py`
"""

import json
import os
import sys
import time

import httpx

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://llm-gateway:8080")
EXPECTED_MODEL = os.environ.get("EXPECTED_MODEL", "deepseek-v4-pro")
EXPECTED_MODE = "INTERNAL_LLM"
# DeepSeek has no seed (non-deterministic) and can be verbose, so give the terminal-decision JSON
# the full bounded completion headroom rather than a tight cap that truncates it (fail-closed).
MAX_OUTPUT_TOKENS = int(os.environ.get("SMOKE_MAX_OUTPUT_TOKENS", "2048"))

# A harmless, target-free discovery context. With an empty surface the model can only return a
# non-executing terminal decision (stop/review/continue); no object references exist to probe.
SMOKE_CONTEXT = {
    "surface": {},
    "observations": [],
    "verification": {"status": "INSUFFICIENT"},
    "permitted_decision_types": ["stop", "review", "continue"],
    "stage": "discovery",
}


def _fail(message: str) -> None:
    print(json.dumps({"smoke": "FAIL", "reason": message}))
    sys.exit(1)


def main() -> None:
    with httpx.Client(base_url=GATEWAY_URL, trust_env=False, timeout=45) as client:
        health = client.get("/health").json()
        provider_type = health.get("provider")
        model = health.get("model")
        if provider_type != "internal_openai_compatible":
            _fail(f"gateway provider is {provider_type!r}, expected internal_openai_compatible")
        if model != EXPECTED_MODEL:
            _fail(f"gateway model is {model!r}, expected {EXPECTED_MODEL!r}")

        started = time.monotonic()
        response = client.post(
            "/v1/plan",
            json={"context": SMOKE_CONTEXT, "max_output_tokens": MAX_OUTPUT_TOKENS},
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        if response.status_code != 200:
            # Only the safe diagnostic code leaves the gateway; no body/secret is exposed.
            detail = response.json().get("detail", {}) if response.content else {}
            _fail(f"provider call failed: HTTP {response.status_code} code={detail.get('code')}")

        body = response.json()
        decision = body["decision"]
        usage = body["usage"]
        metadata = body["metadata"]
        if body["model"] != EXPECTED_MODEL or metadata["model"] != EXPECTED_MODEL:
            _fail(f"response model mismatch: {body['model']!r}")
        if metadata["provider_type"] != "internal_openai_compatible":
            _fail("response provider_type is not internal_openai_compatible")

        result = {
            "smoke": "PASS",
            "provider_mode": EXPECTED_MODE,
            "provider_type": metadata["provider_type"],
            "model": body["model"],
            "planner_contract_version": body.get("planner_contract_version"),
            "decision_type": decision.get("decision_type"),
            "stop_reason": metadata.get("stop_reason"),
            "temperature": metadata.get("temperature"),
            "seed": metadata.get("seed"),
            "usage": usage,
            "latency_ms": latency_ms,
        }
        # The response carries no credential; assert it defensively before printing.
        blob = json.dumps(result)
        for marker in ("Bearer ", "Authorization", "authorization"):
            if marker in blob:
                _fail("unexpected credential-like marker in response")
        print(blob)


if __name__ == "__main__":
    main()
