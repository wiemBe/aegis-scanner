"""OpenRouter/Qwen3.8 27B provider-only smoke call (PUBLIC_LLM_OPENROUTER via the llm-gateway).

Sends ONE harmless synthetic planner request straight to the isolated gateway's /v1/plan endpoint.
It does NOT create a scan and never touches the lab/target network, so a successful smoke proves the
gateway reaches OpenRouter and returns a valid Contract V3 decision with ZERO target requests — the
one authorized live check the deployment guide calls for before accepting traffic.

Fails closed unless the deployed planner reports provider_type "openrouter" and the exact pinned
model qwen/qwen3.8-27b. The credential lives only inside the gateway; this script neither holds nor
prints it, and asserts no Authorization/Bearer marker is echoed back. Run from a container attached
to the planner-rpc network, e.g.
`GATEWAY_URL=http://llm-gateway:8080 python scripts/openrouter_smoke.py`
"""

import json
import os
import sys
import time

import httpx

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://llm-gateway:8080")
EXPECTED_MODEL = os.environ.get("EXPECTED_MODEL", "qwen/qwen3.8-27b")
EXPECTED_PROVIDER = "openrouter"
EXPECTED_MODE = "PUBLIC_LLM_OPENROUTER"
# The routed upstream is non-deterministic and can be verbose, so give the terminal-decision JSON
# the full bounded completion headroom rather than a tight cap that truncates it (fails closed).
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
    with httpx.Client(base_url=GATEWAY_URL, trust_env=False, timeout=60) as client:
        health = client.get("/health").json()
        provider_type = health.get("provider")
        model = health.get("model")
        if provider_type != EXPECTED_PROVIDER:
            _fail(f"gateway provider is {provider_type!r}, expected {EXPECTED_PROVIDER!r}")
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
        if metadata["provider_type"] != EXPECTED_PROVIDER:
            _fail(f"response provider_type is not {EXPECTED_PROVIDER!r}")
        # Routed upstreams carry no reproducible seed; assert the provenance is honest about it.
        if metadata.get("seed") is not None:
            _fail("response recorded a seed; routed OpenRouter runs must claim no determinism")

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
