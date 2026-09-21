"""Coordinator for fresh, bounded task processes inside the isolated ops worker."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from threading import RLock

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
_EFFECTS: set[str] = set()
_LOCK = RLock()


class DiagnosticJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(max_length=160)
    reference: str = Field(pattern=r"^[a-z0-9-]{3,60}$")
    execution: str


class TemplateJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(max_length=500)
    evaluation: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _task(payload: dict[str, str], workspace: Path) -> dict[str, str]:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed interpreter/module in isolated container
            [sys.executable, "-m", "aegis_range.ops_worker_task"],
            cwd=workspace,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            },
            input=json.dumps(payload, separators=(",", ":")).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=408, detail="Operation timed out") from exc
    if completed.returncode != 0 or len(completed.stdout) > 4096:
        raise HTTPException(status_code=400, detail="Operation could not be completed")
    try:
        result: object = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=502, detail="Operation could not be completed") from exc
    if not isinstance(result, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in result.items()
    ):
        raise HTTPException(status_code=502, detail="Operation could not be completed")
    return result


@app.post("/v1/diagnostics")
def diagnostic(job: DiagnosticJob) -> dict[str, str]:
    if job.execution not in {"shell", "typed"}:
        raise HTTPException(status_code=400, detail="Invalid execution request")
    with tempfile.TemporaryDirectory(prefix="range-ops-", dir="/tmp") as directory:
        workspace = Path(directory)
        result = _task({"kind": "diagnostic", **job.model_dump()}, workspace)
        if (workspace / f"canary-{job.reference}").exists():
            with _LOCK:
                _EFFECTS.add(job.reference)
    return result


@app.post("/v1/templates")
def template(job: TemplateJob) -> dict[str, str]:
    if job.evaluation not in {"template", "data"}:
        raise HTTPException(status_code=400, detail="Invalid preview request")
    with tempfile.TemporaryDirectory(prefix="range-template-", dir="/tmp") as directory:
        return _task({"kind": "template", **job.model_dump()}, Path(directory))


@app.get("/__control/effects/{reference}")
def effect(reference: str) -> dict[str, bool]:
    with _LOCK:
        return {"observed": reference in _EFFECTS}


@app.post("/__control/reset")
def reset() -> dict[str, str]:
    with _LOCK:
        _EFFECTS.clear()
    return {"status": "reset"}
