"""Dedicated synthetic SSRF canary, isolated from every service except Aegis Cloud."""

from typing import Annotated

from fastapi import FastAPI, Header, HTTPException

from aegis_range.cloud_fixture import credential

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/status/{resource}")
def status(resource: str, x_range_generation: Annotated[int, Header(ge=1)]) -> dict[str, str]:
    if resource != "instance":
        raise HTTPException(status_code=404, detail="Resource not found")
    return {
        "service": "integration-fixture",
        "instance": "canary-node-01",
        "proof": "AEGIS_RANGE_CANARY_2026_01",
        "access_token": credential(x_range_generation, "metadata-read"),
        "token_type": "synthetic",
        "generation": str(x_range_generation),
    }
