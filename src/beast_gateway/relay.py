from __future__ import annotations

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI(title="Aegis Beast One-Way RPC Relay", docs_url=None, redoc_url=None)
UPSTREAM = "http://beast-sandbox:8094"


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/{path:path}")
async def relay(path: str, request: Request) -> Response:
    # Only supervisor RPC is forwarded. No route from this process reaches the control plane.
    if not (
        path == "sessions"
        or path == "commands"
        or (path.startswith("runs/") and path.endswith(("/stop", "/destroy")))
    ):
        return JSONResponse(status_code=404, content={"detail": "RPC_ROUTE_NOT_ADMITTED"})
    body = await request.body()
    if len(body) > 262_144:
        return JSONResponse(status_code=413, content={"detail": "RPC_BODY_LIMIT"})
    headers: dict[str, str] = {"Content-Type": "application/json"}
    token = request.headers.get("x-beast-supervisor-token")
    if token:
        headers["X-Beast-Supervisor-Token"] = token
    try:
        async with httpx.AsyncClient(timeout=75, follow_redirects=False, trust_env=False) as client:
            response = await client.post(f"{UPSTREAM}/v1/{path}", content=body, headers=headers)
    except httpx.HTTPError:
        return JSONResponse(status_code=502, content={"detail": "SANDBOX_SUPERVISOR_UNAVAILABLE"})
    return Response(
        status_code=response.status_code,
        content=response.content[:262_144],
        media_type="application/json",
    )
