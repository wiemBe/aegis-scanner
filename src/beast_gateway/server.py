from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field


class ArmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    allowed_path_prefix: str = Field(pattern=r"^/lab/beast/(vulnerable|patched)$")
    allowed_methods: list[Literal["GET", "HEAD", "OPTIONS"]]
    max_connections: int = Field(ge=1, le=100)
    max_request_rate_per_second: int = Field(ge=1, le=10)
    max_concurrency: int = Field(ge=1, le=4)
    max_transmitted_bytes: int = Field(ge=1024, le=1_048_576)
    max_received_bytes: int = Field(ge=4096, le=4_194_304)


@dataclass
class GuardState:
    run_id: str | None = None
    prefix: str | None = None
    allowed_methods: frozenset[str] = frozenset()
    max_connections: int = 0
    max_rate: int = 0
    max_concurrency: int = 0
    max_tx: int = 0
    max_rx: int = 0
    connections: int = 0
    active: int = 0
    tx: int = 0
    rx: int = 0
    blocked: list[dict[str, Any]] = field(default_factory=list)
    request_times: deque[float] = field(default_factory=deque)


app = FastAPI(title="Aegis Beast Target Gateway", docs_url=None, redoc_url=None)
state = GuardState()
state_lock = asyncio.Lock()
TOKEN = os.environ.get("BEAST_BOUNDARY_TOKEN", "")
BACKEND = os.environ.get("BEAST_TARGET_BACKEND", "http://lab-api:8001").rstrip("/")


def _authorize(value: str | None) -> None:
    if not TOKEN or value != TOKEN:
        raise HTTPException(status_code=403, detail="BOUNDARY_AUTHORIZATION_REQUIRED")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/__aegis/arm")
async def arm(
    body: ArmRequest, x_beast_boundary_token: str | None = Header(default=None)
) -> dict[str, Any]:
    _authorize(x_beast_boundary_token)
    state.run_id = body.run_id
    state.prefix = body.allowed_path_prefix
    state.allowed_methods = frozenset(body.allowed_methods)
    state.max_connections = body.max_connections
    state.max_rate = body.max_request_rate_per_second
    state.max_concurrency = body.max_concurrency
    state.max_tx = body.max_transmitted_bytes
    state.max_rx = body.max_received_bytes
    state.connections = state.active = state.tx = state.rx = 0
    state.blocked.clear()
    state.request_times.clear()
    return {"armed": True, "run_id": state.run_id, "prefix": state.prefix}


@app.post("/__aegis/disarm")
async def disarm(x_beast_boundary_token: str | None = Header(default=None)) -> dict[str, Any]:
    _authorize(x_beast_boundary_token)
    snapshot = _snapshot()
    state.run_id = state.prefix = None
    state.allowed_methods = frozenset()
    return snapshot


@app.get("/__aegis/state")
async def guard_state(x_beast_boundary_token: str | None = Header(default=None)) -> dict[str, Any]:
    _authorize(x_beast_boundary_token)
    return _snapshot()


def _snapshot() -> dict[str, Any]:
    return {
        "run_id": state.run_id,
        "allowed_path_prefix": state.prefix,
        "allowed_methods": sorted(state.allowed_methods),
        "connections": state.connections,
        "active_connections": state.active,
        "max_request_rate_per_second": state.max_rate,
        "max_concurrency": state.max_concurrency,
        "transmitted_bytes": state.tx,
        "received_bytes": state.rx,
        "blocked": list(state.blocked),
    }


def _block(request: Request, reason: str) -> JSONResponse:
    state.blocked.append(
        {"method": request.method, "path": request.url.path[:240], "reason": reason}
    )
    return JSONResponse(status_code=403, content={"detail": reason})


@app.api_route("/{path:path}", methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request) -> Response:
    route = "/" + path
    if route.startswith("/__aegis/"):
        return _block(request, "BOUNDARY_CONTROL_UNREACHABLE")
    if state.run_id is None or state.prefix is None:
        return _block(request, "TARGET_GATEWAY_NOT_ARMED")
    if request.method not in state.allowed_methods:
        return _block(request, "METHOD_OUTSIDE_TARGET_SCOPE")
    if not (route == state.prefix or route.startswith(state.prefix + "/")):
        return _block(request, "PATH_OUTSIDE_EXACT_TARGET_SCOPE")
    body = await request.body()
    async with state_lock:
        now = time.monotonic()
        while state.request_times and now - state.request_times[0] >= 1:
            state.request_times.popleft()
        projected_tx = state.tx + len(body) + len(route.encode()) + len(request.url.query.encode())
        if state.connections >= state.max_connections:
            return _block(request, "TARGET_CONNECTION_BUDGET_EXHAUSTED")
        if len(state.request_times) >= state.max_rate:
            return _block(request, "TARGET_REQUEST_RATE_EXHAUSTED")
        if state.active >= state.max_concurrency:
            return _block(request, "TARGET_CONCURRENCY_EXHAUSTED")
        if projected_tx > state.max_tx:
            return _block(request, "TRANSMITTED_BYTE_BUDGET_EXHAUSTED")
        state.connections += 1
        state.active += 1
        state.tx = projected_tx
        state.request_times.append(now)
    url = BACKEND + route
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() in {"accept", "content-type", "authorization", "user-agent"}
    }
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
            response = await client.request(
                request.method, url, params=request.url.query, content=body, headers=headers
            )
    except httpx.HTTPError:
        return Response(status_code=502, content=b"bounded target unavailable")
    finally:
        async with state_lock:
            state.active = max(0, state.active - 1)
    async with state_lock:
        bounded = response.content[: min(262_144, max(0, state.max_rx - state.rx))]
        state.rx += len(bounded)
    if len(response.content) != len(bounded):
        state.blocked.append(
            {"method": request.method, "path": route, "reason": "RECEIVED_BYTE_BUDGET_EXHAUSTED"}
        )
    response_headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() in {"content-type", "x-content-type-options"}
    }
    response_headers["X-Aegis-Beast-Run"] = state.run_id
    return Response(
        status_code=response.status_code,
        content=bounded,
        headers=response_headers,
        media_type=response.headers.get("content-type"),
    )
