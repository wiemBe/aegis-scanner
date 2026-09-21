"""Aegis-controlled range ingress with fixed service-to-backend mappings."""

from __future__ import annotations

import asyncio
import multiprocessing
import signal
import time
from collections.abc import Callable

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

BACKENDS = {
    8101: "http://aegis-bank-core:8101",
    8102: "http://aegis-shop-core:8102",
    8103: "http://aegis-ops-core:8103",
    8104: "http://aegis-cloud-core:8104",
}
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})
REQUEST_WINDOW_SECONDS = 60
REQUESTS_PER_WINDOW = 600
MAX_CONCURRENT_REQUESTS = 8
HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)


class RequestBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._window_started = time.monotonic()
        self._count = 0
        self._lock = asyncio.Lock()

    async def admit(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            if now - self._window_started >= REQUEST_WINDOW_SECONDS:
                self._window_started = now
                self._count = 0
            if self._count >= self.limit:
                return False
            self._count += 1
            return True


def create_app(backend: str, request_budget: int = REQUESTS_PER_WINDOW) -> FastAPI:
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    budget = RequestBudget(request_budget)
    concurrency = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    @app.api_route("/{path:path}", methods=sorted(ALLOWED_METHODS))
    async def proxy(path: str, request: Request) -> Response:
        normalized_path = "/" + path
        if normalized_path.startswith("/__control"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if request.method not in ALLOWED_METHODS:
            return JSONResponse(status_code=405, content={"detail": "Method not allowed"})
        if not await budget.admit():
            return JSONResponse(status_code=429, content={"detail": "Request budget exhausted"})
        body = await request.body()
        if len(body) > 1_048_576:
            return JSONResponse(status_code=413, content={"detail": "Request too large"})
        headers = {
            key: value for key, value in request.headers.items() if key.lower() not in HOP_HEADERS
        }
        url = backend + normalized_path
        try:
            async with concurrency:
                async with httpx.AsyncClient(
                    timeout=5, follow_redirects=False, trust_env=False
                ) as client:
                    upstream = await client.request(
                        request.method,
                        url,
                        params=request.query_params,
                        headers=headers,
                        content=body,
                    )
        except httpx.HTTPError:
            return JSONResponse(status_code=502, content={"detail": "Service unavailable"})
        content = upstream.content[:1_048_576]
        response_headers = {
            key: value for key, value in upstream.headers.items() if key.lower() not in HOP_HEADERS
        }
        return Response(content, status_code=upstream.status_code, headers=response_headers)

    return app


def _serve(port: int, backend: str) -> None:
    uvicorn.run(create_app(backend), host="0.0.0.0", port=port, log_level="warning")  # noqa: S104


def main() -> None:
    processes = [
        multiprocessing.Process(target=_serve, args=(port, backend), daemon=False)
        for port, backend in sorted(BACKENDS.items())
    ]
    for process in processes:
        process.start()

    def stop(_signum: int, _frame: object) -> None:
        for child in processes:
            child.terminate()

    handlers: tuple[tuple[int, Callable[[int, object], None]], ...] = (
        (signal.SIGTERM, stop),
        (signal.SIGINT, stop),
    )
    for signum, handler in handlers:
        signal.signal(signum, handler)
    for process in processes:
        process.join()
    if any(process.exitcode not in {0, -signal.SIGTERM} for process in processes):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
