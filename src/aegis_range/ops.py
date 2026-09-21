"""Aegis Ops: deterministic operational report service with bounded fixture access."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from aegis_range.documents import openapi_document
from aegis_range.runtime import Mode, ScenarioRuntime, management_router

SERVICE = "aegis-ops"
SCENARIO = "ops-report-selection-v1"
COMMAND_SCENARIO = "ops-diagnostic-input-v1"
TEMPLATE_SCENARIO = "ops-report-preview-v1"
CONFIG_SCENARIO = "ops-support-status-v1"
runtime = ScenarioRuntime(SERVICE, (SCENARIO, COMMAND_SCENARIO, TEMPLATE_SCENARIO, CONFIG_SCENARIO))
app = FastAPI(title="Aegis Ops", version="1.0.0", openapi_url=None, docs_url=None, redoc_url=None)
app.state.worker_transport = None
app.state.worker_origin = "http://ops-worker:8600"
FIXTURE_ROOT = Path(__file__).with_name("fixtures") / "ops"
PUBLIC_ROOT = FIXTURE_ROOT / "reports"
SYNTHETIC_CONFIG_SECRET = ""


class DiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=160)
    reference: str = Field(pattern=r"^[a-z0-9-]{3,60}$")


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(max_length=500)


def _reset_state(generation: int) -> None:
    global SYNTHETIC_CONFIG_SECRET
    SYNTHETIC_CONFIG_SECRET = hashlib.sha256(f"ops-config-{generation}".encode()).hexdigest()[:28]


runtime.add_reset_hook(_reset_state)


def _selected_file(name: str) -> Path:
    root = FIXTURE_ROOT if runtime.mode(SCENARIO) is Mode.VULNERABLE else PUBLIC_ROOT
    candidate = (PUBLIC_ROOT / name).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Report not found") from exc
    if not candidate.is_file() or candidate.suffix != ".txt":
        raise HTTPException(status_code=404, detail="Report not found")
    return candidate


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE, "seed": "2026.1"}


@app.get("/openapi.json", include_in_schema=False)
def openapi() -> dict[str, object]:
    return openapi_document(SERVICE)


@app.get("/api/reports", operation_id="listReports")
def reports() -> dict[str, object]:
    return {"reports": ["daily-summary.txt", "service-health.txt"]}


@app.get("/api/reports/download", response_class=PlainTextResponse, operation_id="downloadReport")
def download(file: str = Query(max_length=160)) -> PlainTextResponse:
    return PlainTextResponse(_selected_file(file).read_text(encoding="utf-8"))


@app.get("/api/teams", operation_id="listTeams")
def teams() -> dict[str, object]:
    return {"teams": ["platform", "fulfillment", "support"]}


async def _worker(request: Request, path: str, payload: dict[str, object]) -> dict[str, Any]:
    transport: httpx.AsyncBaseTransport | None = request.app.state.worker_transport
    async with httpx.AsyncClient(
        base_url=request.app.state.worker_origin,
        timeout=4,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        response = await client.post(path, json=payload)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Operation could not be completed")
    body: object = response.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail="Operation could not be completed")
    return body


@app.post("/api/diagnostics/run", operation_id="runServiceDiagnostic")
async def diagnostic(payload: DiagnosticRequest, request: Request) -> dict[str, str]:
    body = await _worker(
        request,
        "/v1/diagnostics",
        {
            "target": payload.target,
            "reference": payload.reference,
            "execution": (
                "shell" if runtime.mode(COMMAND_SCENARIO) is Mode.VULNERABLE else "typed"
            ),
        },
    )
    return {"run_id": str(body["run_id"]), "status": "completed"}


@app.post("/api/reports/preview", operation_id="previewOperationalReport")
async def preview(payload: PreviewRequest, request: Request) -> dict[str, str]:
    body = await _worker(
        request,
        "/v1/templates",
        {
            "content": payload.content,
            "evaluation": (
                "template" if runtime.mode(TEMPLATE_SCENARIO) is Mode.VULNERABLE else "data"
            ),
        },
    )
    return {"preview": str(body["preview"])}


@app.get("/api/support/status", operation_id="getSupportStatus")
def support_status() -> dict[str, str]:
    response = {"service": "operations", "status": "ready", "region": "eu-central"}
    response["configuration_reference"] = (
        SYNTHETIC_CONFIG_SECRET if runtime.mode(CONFIG_SCENARIO) is Mode.VULNERABLE else "redacted"
    )
    return response


app.include_router(management_router(runtime))
