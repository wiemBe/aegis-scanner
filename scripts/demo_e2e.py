"""Run inside control-plane: python - < scripts/demo_e2e.py. Only synthetic lab targets."""

import asyncio
import json
import time
from typing import Any

import httpx


async def scan(client: httpx.AsyncClient, payload: dict[str, str]) -> dict[str, Any]:
    response = await client.post("/api/scans", json=payload)
    response.raise_for_status()
    scan_id = response.json()["id"]
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        response = await client.get(f"/api/scans/{scan_id}")
        response.raise_for_status()
        report: dict[str, Any] = response.json()
        if report["scan"]["status"] not in {"QUEUED", "RUNNING"}:
            return report
        await asyncio.sleep(0.1)
    raise TimeoutError("Synthetic scan exceeded smoke-test deadline")


async def main() -> None:
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000", trust_env=False) as client:
        page = await client.get("/")
        assert page.status_code == 200 and "DEMO_HEURISTIC" in page.text
        for asset in ("/static/app.js", "/static/style.css"):
            assert (await client.get(asset)).status_code == 200
        initial = await scan(client, {"target": "synthetic-bank-api"})
        assert initial["scan"]["status"] == "FAIL", initial
        assert initial["scan"]["findings"][0]["confidence"] == "CONFIRMED"
        fixed = await scan(
            client,
            {
                "target": "synthetic-bank-api",
                "variant": "patched",
                "retest_of": initial["scan"]["id"],
            },
        )
        assert fixed["scan"]["status"] == "PASS", fixed
        assert fixed["scan"]["verification"]["status"] == "PASS"
        assert [e["status_code"] for e in fixed["scan"]["evidence"]] == [200, 200, 403]
        for report in (initial, fixed):
            assert report["scan"]["usage"]["requests"] == 4
            assert report["scan"]["usage"]["model_calls"] == 0
            assert "lab-token" not in json.dumps(report)
        print(json.dumps({"initial": initial, "retest": fixed}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
