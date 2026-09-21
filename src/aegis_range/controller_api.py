"""Internal-only HTTP surface for the Phase 1.6 range controller."""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from aegis_range.controller import RangeController
from aegis_range.runtime import Mode

app = FastAPI(title="Aegis Range Controller", openapi_url=None, docs_url=None, redoc_url=None)
controller = RangeController()


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode


class LinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    application_id: str
    scenario_id: str


class ChainEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: dict[str, bool | int | str]


def _authorize(value: str | None) -> None:
    expected = os.environ.get("RANGE_CONTROLLER_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="Controller authorization is not configured")
    if value != expected:
        raise HTTPException(status_code=403, detail="Access denied")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "aegis-range-controller"}


@app.get("/v1/range/inventory")
def inventory(
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    return {"targets": controller.inventory()}


@app.get("/v1/range/scenarios")
def scenarios(
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    return {"scenarios": controller.scenarios()}


@app.get("/v1/range/chains")
def chains(
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    return {"chains": controller.chains()}


@app.put("/v1/range/applications/{application_id}/scenarios/{scenario_id}")
async def select_mode(
    application_id: str,
    scenario_id: str,
    selection: Selection,
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    try:
        return await controller.select_mode(application_id, scenario_id, selection.mode)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Range item not found") from exc


@app.post("/v1/range/applications/{application_id}/reset")
async def reset_application(
    application_id: str, x_range_controller_token: Annotated[str | None, Header()] = None
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    try:
        return (await controller.reset_application(application_id)).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Range item not found") from exc


@app.post("/v1/range/reset")
async def reset_all(
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    return {"applications": [row.model_dump(mode="json") for row in await controller.reset_all()]}


@app.post("/v1/range/runs")
def link_run(
    request: LinkRequest, x_range_controller_token: Annotated[str | None, Header()] = None
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    try:
        return controller.link_run(
            request.run_id, request.application_id, request.scenario_id
        ).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Run linkage rejected") from exc


@app.post("/v1/range/applications/{application_id}/scenarios/{scenario_id}/verify")
async def verify(
    application_id: str,
    scenario_id: str,
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    try:
        return (await controller.verify(application_id, scenario_id)).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Range item not found") from exc


@app.post("/v1/range/chains/{chain_id}/verify")
async def verify_chain(
    chain_id: str,
    evidence: ChainEvidence,
    x_range_controller_token: Annotated[str | None, Header()] = None,
) -> dict[str, object]:
    _authorize(x_range_controller_token)
    try:
        return (await controller.evaluate_chain(chain_id, evidence.observations)).model_dump(
            mode="json"
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Range item not found") from exc
