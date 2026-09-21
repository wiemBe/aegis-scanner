"""Isolated fresh Chromium process used only for privileged synthetic review viewing."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


class ViewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/view")
def view(request: ViewRequest) -> dict[str, str]:
    if request.url != "http://aegis-shop-view:8102/internal/reviews/view":
        raise HTTPException(status_code=400, detail="View target unavailable")
    with tempfile.TemporaryDirectory(prefix="range-browser-", dir="/tmp") as profile:
        process: subprocess.Popen[bytes] | None = None
        argv = [
            "/usr/bin/chromium",
            "--headless",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-sync",
            "--metrics-recording-only",
            f"--user-data-dir={profile}",
            "--virtual-time-budget=2500",
            "--dump-dom",
            request.url,
        ]
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed Chromium argv and fixed internal URL
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={"PATH": "/usr/bin:/bin", "HOME": profile, "LANG": "C.UTF-8"},
                start_new_session=True,
            )
            output, _ = process.communicate(timeout=8)
            return_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            if process is not None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            raise HTTPException(status_code=408, detail="View timed out") from exc
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
    if return_code != 0 or len(output) > 1_048_576:
        raise HTTPException(status_code=502, detail="View failed")
    return {"status": "viewed"}
