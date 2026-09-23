"""Offline, bounded Phase 1.7 vulnerable/patched and baseline comparison acceptance."""

from __future__ import annotations

import asyncio
import json

import httpx

from aegis.multi_agent.model import OfflineBankModel
from aegis.multi_agent.runtime import MultiAgentRuntime
from aegis_range import bank
from aegis_range.controller import RangeController
from aegis_range.runtime import Mode


async def main() -> None:
    bank.runtime.reset()
    transports: dict[str, httpx.AsyncBaseTransport] = {
        "aegis-bank": httpx.ASGITransport(app=bank.app)
    }
    controller = RangeController(transports)
    records: list[dict[str, object]] = []
    for mode in (Mode.VULNERABLE, Mode.PATCHED):
        for execution_mode in ("single_agent", "multi_agent"):
            result = await MultiAgentRuntime(OfflineBankModel(), controller, transports).execute(
                mode=mode, execution_mode=execution_mode
            )
            records.append(
                {
                    "scenario_mode": mode.value,
                    "execution_mode": execution_mode,
                    "verdict": result.run.verdict.value if result.run.verdict else None,
                    "metrics": result.metrics.model_dump(mode="json"),
                    "budget_limit": result.global_budget.limit.model_dump(mode="json"),
                    "cleanup_succeeded": result.run.cleanup_succeeded,
                    "model": "OFFLINE_STRUCTURED_FIXTURE",
                }
            )
    checks = {
        "vulnerable_confirmed": all(
            item["verdict"] == "CONFIRMED"
            for item in records
            if item["scenario_mode"] == "vulnerable"
        ),
        "patched_pass": all(
            item["verdict"] == "PASS" for item in records if item["scenario_mode"] == "patched"
        ),
        "equal_target_requests": len(
            {item["metrics"]["target_requests"] for item in records}  # type: ignore[index]
        )
        == 1,
        "equal_budget_limits": len(
            {json.dumps(item["budget_limit"], sort_keys=True) for item in records}
        )
        == 1,
        "cleanup_all": all(item["cleanup_succeeded"] is True for item in records),
    }
    print(
        json.dumps(
            {
                "phase": "1.7",
                "scope": "offline synthetic aegis-bank BOLA slice",
                "live_model_claim": False,
                "records": records,
                "checks": checks,
                "passed": all(checks.values()),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
