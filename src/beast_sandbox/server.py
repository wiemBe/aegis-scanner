from __future__ import annotations

import asyncio
import ctypes
import hashlib
import os
import resource
import shutil
import signal
import stat
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI, Header, HTTPException

from aegis.beast.contracts import (
    CommandResult,
    CommandTransport,
    SandboxDestroyResult,
    SandboxSession,
    SandboxSessionRequest,
)

app = FastAPI(title="Aegis Beast Sandbox Supervisor", docs_url=None, redoc_url=None)
AUTH = os.environ.get("BEAST_SUPERVISOR_TOKEN", "")
BOUNDARY_TOKEN = os.environ.get("BEAST_BOUNDARY_TOKEN", "")
GATEWAY = os.environ.get("BEAST_TARGET_GATEWAY", "http://beast-target:8080").rstrip("/")
WORKSPACE_ROOT = Path(os.environ.get("BEAST_WORKSPACE_ROOT", "/workspace"))
COMMAND_UID = int(os.environ.get("BEAST_COMMAND_UID", "65532"))
COMMAND_GID = int(os.environ.get("BEAST_COMMAND_GID", "65532"))
ARTIFACT_PREVIEW_BYTES = 8192

# Reparent orphaned command descendants to the supervisor so a shell cannot escape cleanup by
# double-forking or creating a new session. This is namespace-local and grants no new capability.
_libc = ctypes.CDLL(None)
_libc.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER


class Supervisor:
    def __init__(self) -> None:
        self.session: SandboxSessionRequest | None = None
        self.instance_id: str | None = None
        self.process: asyncio.subprocess.Process | None = None
        self.lock = asyncio.Lock()

    def workspace(self, run_id: str) -> Path:
        return WORKSPACE_ROOT / run_id

    async def create(self, body: SandboxSessionRequest) -> SandboxSession:
        if self.session is not None:
            raise HTTPException(status_code=409, detail="SANDBOX_SESSION_ALREADY_ACTIVE")
        async with self.lock:
            if self.process is not None:
                raise HTTPException(status_code=409, detail="COMMAND_STILL_RUNNING")
            workspace = self.workspace(body.run_id)
            if workspace.exists():
                shutil.rmtree(workspace)
            # Root-owned supervisor directory, writable only by the command's dedicated group.
            # This lets the unprivileged shell create files while the capability-minimal root
            # supervisor can still enumerate, hash and destroy them without DAC_OVERRIDE.
            workspace.mkdir(parents=True, mode=0o770)
            os.chown(workspace, 0, COMMAND_GID)
            os.chmod(workspace, 0o770)  # noqa: S103 - only root and dedicated command gid
            self.session = body
            self.instance_id = f"sandbox-{uuid4().hex[:16]}"
            await self._gateway(
                "/__aegis/arm",
                {
                    "run_id": body.run_id,
                    "allowed_path_prefix": body.allowed_path_prefix,
                    "allowed_methods": body.allowed_methods,
                    "max_connections": body.resources.max_target_connections,
                    "max_request_rate_per_second": body.resources.max_request_rate_per_second,
                    "max_concurrency": body.resources.max_concurrency,
                    "max_transmitted_bytes": body.resources.max_transmitted_bytes,
                    "max_received_bytes": body.resources.max_received_bytes,
                },
            )
            return SandboxSession(
                run_id=body.run_id,
                sandbox_instance_id=self.instance_id,
                workspace_reference=f"workspace:{body.run_id}",
                ready=True,
            )

    async def _gateway(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=4, trust_env=False) as client:
            response = await client.request(
                "POST" if body is not None else "GET",
                GATEWAY + path,
                json=body,
                headers={"X-Beast-Boundary-Token": BOUNDARY_TOKEN},
            )
            response.raise_for_status()
            value = response.json()
            return value if isinstance(value, dict) else {}

    def _limits(self, transport: CommandTransport) -> Any:
        assert self.session is not None
        envelope = self.session.resources

        def apply() -> None:
            os.setsid()
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_NOFILE, (envelope.max_open_files,) * 2)
            resource.setrlimit(resource.RLIMIT_NPROC, (envelope.max_processes,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (envelope.writable_disk_bytes,) * 2)
            resource.setrlimit(
                resource.RLIMIT_CPU,
                (max(1, transport.timeout_seconds), max(1, transport.timeout_seconds + 1)),
            )
            os.setgroups([])
            os.setgid(COMMAND_GID)
            os.setuid(COMMAND_UID)

        return apply

    async def execute(self, command: CommandTransport) -> CommandResult:
        async with self.lock:
            if self.session is None or self.session.run_id != command.run_id:
                raise HTTPException(status_code=409, detail="NO_MATCHING_SANDBOX_SESSION")
            if self.process is not None:
                raise HTTPException(status_code=409, detail="COMMAND_STILL_RUNNING")
            workspace = self.workspace(command.run_id)
            started = time.monotonic()
            gateway_before = await self._gateway("/__aegis/state")
            self.process = await asyncio.create_subprocess_exec(
                command.shell,
                "-c",
                command.command_text,
                cwd=workspace,
                env={
                    "HOME": str(workspace),
                    "TMPDIR": str(workspace),
                    "XDG_CACHE_HOME": str(workspace / ".cache"),
                    "XDG_CONFIG_HOME": str(workspace / ".config"),
                    "XDG_DATA_HOME": str(workspace / ".local" / "share"),
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "BEAST_TARGET": "http://beast-target:8080",
                    "BEAST_TARGET_BASE_PATH": self.session.allowed_path_prefix,
                },
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=self._limits(command),
            )
            process = self.process
        timed_out = False
        terminated = False
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=command.timeout_seconds
            )
        except TimeoutError:
            timed_out = terminated = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = await process.communicate()
        exit_code = process.returncode
        terminated = terminated or bool(exit_code is not None and exit_code < 0)
        self._kill_command_identity()
        async with self.lock:
            self.process = None
        limit = command.output_limit_bytes
        combined = stdout + stderr
        truncated = len(combined) > limit
        stdout_cap = stdout[:limit]
        stderr_cap = stderr[: max(0, limit - len(stdout_cap))]
        artifacts = self._artifacts(workspace, command.artifact_limit_bytes)
        artifact_previews: dict[str, str] = {}
        preview_remaining = ARTIFACT_PREVIEW_BYTES
        for item in artifacts:
            if item["disposition"] != "ADMITTED" or preview_remaining <= 0:
                continue
            path = workspace / str(item["reference"]).removeprefix("artifact:")
            preview = path.read_bytes()[:preview_remaining]
            artifact_previews[str(item["reference"])] = preview.decode("utf-8", "replace")
            preview_remaining -= len(preview)
        gateway = await self._gateway("/__aegis/state")
        command_connections = max(
            0,
            int(gateway.get("connections", 0))
            - int(gateway_before.get("connections", 0)),
        )
        return CommandResult(
            command_id=command.command_id,
            exit_code=exit_code,
            timed_out=timed_out,
            terminated=terminated,
            duration_ms=round((time.monotonic() - started) * 1000),
            stdout=stdout_cap.decode("utf-8", "replace"),
            stderr=stderr_cap.decode("utf-8", "replace"),
            output_truncated=truncated,
            artifact_references=[
                item["reference"] for item in artifacts if item["disposition"] == "ADMITTED"
            ],
            artifact_previews=artifact_previews,
            resource_usage={
                "output_bytes": len(stdout_cap) + len(stderr_cap),
                "artifact_bytes": sum(
                    int(item["size"])
                    for item in artifacts
                    if item["disposition"] == "ADMITTED"
                ),
                "target_connections": int(gateway.get("connections", 0)),
                "command_target_connections": command_connections,
                "transmitted_bytes": int(gateway.get("transmitted_bytes", 0)),
                "received_bytes": int(gateway.get("received_bytes", 0)),
            },
            network_destinations=["beast-target:8080"]
            if command_connections
            else [],
        )

    def _artifacts(self, workspace: Path, limit: int) -> list[dict[str, Any]]:
        evaluated: list[dict[str, Any]] = []
        total = 0
        for path in sorted(workspace.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            data = path.read_bytes()
            total += len(data)
            item = {
                "reference": f"artifact:{path.relative_to(workspace)}",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            if total > limit:
                evaluated.append({**item, "disposition": "REJECTED", "reason": "ARTIFACT_LIMIT"})
            elif stat.S_IMODE(path.stat().st_mode) & 0o111:
                evaluated.append({**item, "disposition": "REJECTED", "reason": "EXECUTABLE"})
            elif b"PRIVATE KEY" in data or b"Authorization:" in data:
                evaluated.append({**item, "disposition": "REJECTED", "reason": "SECRET_PATTERN"})
            else:
                evaluated.append({**item, "disposition": "ADMITTED"})
        return evaluated

    def _kill_command_identity(self) -> None:
        """Kill all namespace-local processes owned by the dedicated command identity."""
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text()
                uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
                real_uid = int(uid_line.split()[1])
                if real_uid == COMMAND_UID:
                    os.kill(int(entry.name), signal.SIGKILL)
            except (
                FileNotFoundError,
                ProcessLookupError,
                PermissionError,
                StopIteration,
                ValueError,
            ):
                continue

    async def stop(self, run_id: str) -> dict[str, Any]:
        killed = False
        process = self.process
        if self.session and self.session.run_id == run_id and process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
            killed = True
        self._kill_command_identity()
        return {"run_id": run_id, "process_tree_killed": killed}

    async def destroy(self, run_id: str) -> SandboxDestroyResult:
        # Caller holds no lock when entering through the API. Stop first, then serialize cleanup.
        await self.stop(run_id)
        async with self.lock:
            if self.session is None or self.session.run_id != run_id:
                return SandboxDestroyResult(run_id=run_id, destroyed=True)
            workspace = self.workspace(run_id)
            artifacts = self._artifacts(workspace, self.session.resources.artifact_bytes)
            gateway = await self._gateway("/__aegis/disarm", {})
            if workspace.exists():
                shutil.rmtree(workspace)
            self.session = None
            self.instance_id = None
            return SandboxDestroyResult(
                run_id=run_id,
                destroyed=not workspace.exists(),
                artifacts=[*artifacts, {"network_boundary": gateway}],
            )


supervisor = Supervisor()


def authorize(value: str | None) -> None:
    if not AUTH or value != AUTH:
        raise HTTPException(status_code=403, detail="SUPERVISOR_AUTHORIZATION_REQUIRED")


@app.get("/health")
async def health() -> dict[str, Any]:
    tools = {
        name: shutil.which(name) is not None
        for name in (
            "bash",
            "python3",
            "curl",
            "http",
            "jq",
            "openssl",
            "nmap",
            "ffuf",
            "sqlmap",
            "nuclei",
        )
    }
    return {
        "status": "ok",
        "profile_id": "BEAST_ADVERSARY_SANDBOX_V1",
        "unprivileged_uid": COMMAND_UID,
        "tools": tools,
    }


@app.post("/v1/sessions", response_model=SandboxSession)
async def create_session(
    body: SandboxSessionRequest, x_beast_supervisor_token: str | None = Header(default=None)
) -> SandboxSession:
    authorize(x_beast_supervisor_token)
    return await supervisor.create(body)


@app.post("/v1/commands", response_model=CommandResult)
async def execute_command(
    body: CommandTransport, x_beast_supervisor_token: str | None = Header(default=None)
) -> CommandResult:
    authorize(x_beast_supervisor_token)
    return await supervisor.execute(body)


@app.post("/v1/runs/{run_id}/stop")
async def stop_run(
    run_id: str, x_beast_supervisor_token: str | None = Header(default=None)
) -> dict[str, Any]:
    authorize(x_beast_supervisor_token)
    return await supervisor.stop(run_id)


@app.post("/v1/runs/{run_id}/destroy", response_model=SandboxDestroyResult)
async def destroy_run(
    run_id: str, x_beast_supervisor_token: str | None = Header(default=None)
) -> SandboxDestroyResult:
    authorize(x_beast_supervisor_token)
    return await supervisor.destroy(run_id)
