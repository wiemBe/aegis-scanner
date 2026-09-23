"""Range-independent Phase 1.7-A model-binding preflight."""

from __future__ import annotations

import asyncio
import json

from aegis.multi_agent.provider_binding import (
    PHASE_1_7A_CANONICAL_MODEL,
    ProviderBindingFailure,
    provider_binding_preflight,
)
from aegis.settings import Settings


async def main() -> int:
    try:
        result = await provider_binding_preflight(Settings(), PHASE_1_7A_CANONICAL_MODEL)
    except ProviderBindingFailure as exc:
        print(
            json.dumps(
                {"status": "FAILED_CLOSED", "classification": exc.code, **exc.projection},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps({"status": "PASS", **result.model_dump(mode="json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
