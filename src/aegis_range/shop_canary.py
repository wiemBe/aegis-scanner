"""Fresh-effect canary reachable only by the isolated shop browser worker."""

from __future__ import annotations

from threading import RLock

from fastapi import FastAPI

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
_EFFECTS: set[str] = set()
_LOCK = RLock()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/effect/{nonce}")
def effect(nonce: str) -> dict[str, str]:
    if 8 <= len(nonce) <= 64 and nonce.replace("-", "").isalnum():
        with _LOCK:
            _EFFECTS.add(nonce)
    return {"status": "recorded"}


@app.get("/__control/effects/{nonce}")
def observed(nonce: str) -> dict[str, bool]:
    with _LOCK:
        return {"observed": nonce in _EFFECTS}


@app.post("/__control/reset")
def reset() -> dict[str, str]:
    with _LOCK:
        _EFFECTS.clear()
    return {"status": "reset"}
