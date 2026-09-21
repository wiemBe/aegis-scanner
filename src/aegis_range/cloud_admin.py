"""Private synthetic cloud administration service; never scanner-facing."""

from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, Header, HTTPException

from aegis_range.cloud_fixture import validate

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/summary")
def summary(
    authorization: Annotated[str, Header()],
    x_range_generation: Annotated[int, Header(ge=1)],
    x_validation_mode: Annotated[str, Header()],
) -> dict[str, str]:
    scheme, _, token = authorization.partition(" ")
    audience = None if x_validation_mode == "compatibility" else "admin-service"
    if scheme.lower() != "bearer" or not validate(token, x_range_generation, audience=audience):
        raise HTTPException(status_code=403, detail="Operation unavailable")
    return {"status": "ready", "effect": f"ADMIN-EFFECT-{x_range_generation}"}
