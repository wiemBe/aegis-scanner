"""Containerized vulnerable/patched verifier smoke for the initial Phase 1.6 slice."""

from __future__ import annotations

import asyncio
import json

from aegis_range.chain_acceptance import exercise_chain
from aegis_range.controller import RangeController
from aegis_range.ground_truth import CHAIN_GROUND_TRUTH, GROUND_TRUTH
from aegis_range.runtime import Mode
from aegis_range.verifier import VerificationStatus


async def main() -> None:
    controller = RangeController()
    first_reset = await controller.reset_all()
    second_reset = await controller.reset_all()
    if not all(item.healthy for item in first_reset + second_reset):
        raise SystemExit("range reset or health verification failed")
    if not all(
        second.reset_generation is not None
        and first.reset_generation is not None
        and second.reset_generation > first.reset_generation
        for first, second in zip(first_reset, second_reset, strict=True)
    ):
        raise SystemExit("range reset generation was not deterministic")

    rows: list[dict[str, object]] = []
    for truth in GROUND_TRUTH:
        await controller.select_mode(truth.application_id, truth.scenario_id, Mode.VULNERABLE)
        vulnerable = await controller.verify(truth.application_id, truth.scenario_id)
        await controller.select_mode(truth.application_id, truth.scenario_id, Mode.PATCHED)
        patched = await controller.verify(truth.application_id, truth.scenario_id)
        if vulnerable.status is not VerificationStatus.CONFIRMED or not vulnerable.complete:
            raise SystemExit(f"vulnerable verification failed: {truth.scenario_id}")
        if patched.status is not VerificationStatus.PASS or not patched.complete:
            raise SystemExit(f"patched verification failed: {truth.scenario_id}")
        rows.append(
            {
                "application_id": truth.application_id,
                "scenario_id": truth.scenario_id,
                "vulnerable": vulnerable.status.value,
                "patched": patched.status.value,
                "evidence": [vulnerable.evidence_sha256, patched.evidence_sha256],
            }
        )

    chain_rows: list[dict[str, object]] = []
    for chain in CHAIN_GROUND_TRUTH:
        await controller.reset_application(chain.application_id)
        vulnerable = await exercise_chain(controller, chain.chain_id, Mode.VULNERABLE)
        await controller.reset_application(chain.application_id)
        patched = await exercise_chain(controller, chain.chain_id, Mode.PATCHED)
        if vulnerable.status != "CONFIRMED" or not vulnerable.complete:
            raise SystemExit(f"vulnerable chain verification failed: {chain.chain_id}")
        if patched.status != "PASS" or not patched.complete:
            raise SystemExit(f"patched chain verification failed: {chain.chain_id}")
        chain_rows.append(
            {
                "application_id": chain.application_id,
                "chain_id": chain.chain_id,
                "vulnerable": vulnerable.status,
                "patched": patched.status,
            }
        )

    final_reset = await controller.reset_all()
    if not all(item.healthy for item in final_reset):
        raise SystemExit("final cleanup reset failed")
    print(
        json.dumps(
            {
                "status": "PASS",
                "scenario_count": len(rows),
                "smoke_count": len(rows) * 2,
                "chain_count": len(chain_rows),
                "chain_smoke_count": len(chain_rows) * 2,
                "reset_count": len(first_reset + second_reset + final_reset) + len(chain_rows) * 2,
                "results": rows,
                "chains": chain_rows,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
