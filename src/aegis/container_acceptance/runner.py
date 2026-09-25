"""Run one controller-rendered tool argv in a bounded, hardened container and capture its output.

The rendered argv's first token is the tool name; every pinned tool image sets that tool as its
ENTRYPOINT, so the runner passes only the arguments after it (the image supplies argv[0]). Output is
bounded and only a redacted digest + byte count is retained — never the raw response bodies.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from time import monotonic

from aegis.container_acceptance.contracts import ContainerRunResult
from aegis.container_acceptance.docker_cli import docker
from aegis.container_acceptance.images import require_pinned

# Hardening for every tool container: unprivileged, read-only root fs, bounded writable tmpfs, all
# capabilities dropped, no new privileges, bounded pids/memory. The network is always the caller's
# internal, no-egress range network.
_HARDENING = (
    "--user", "65532:65532", "--read-only",
    "--tmpfs", "/tmp:size=64m",  # noqa: S108 - docker tmpfs mount spec, not a host temp path
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--pids-limit", "128", "--memory", "512m", "-e", "HOME=/tmp",
)


@dataclass(frozen=True)
class RawRun:
    """Transient full run capture. The raw text is parsed in-memory and never stored downstream."""

    result: ContainerRunResult
    stdout: str
    stderr: str


def run_tool(
    *,
    image_reference: str,
    argv: tuple[str, ...],
    network: str,
    label: str,
    output_limit_bytes: int,
    timeout_seconds: int,
    volumes: tuple[tuple[str, str], ...] = (),
) -> RawRun:
    """Run ``argv`` (tool name stripped) in a hardened container on ``network``; capture output.

    ``volumes`` mounts controller-owned named volumes as ``(name, container_path)`` pairs — used to
    persist a tool's own traffic/evidence file past the ``--rm`` container for normalization."""

    image = require_pinned(image_reference)
    tool_args = list(argv[1:])  # the image entrypoint supplies argv[0]
    mount_args: list[str] = []
    for name, path in volumes:
        mount_args += ["-v", f"{name}:{path}"]
    started = monotonic()
    result = docker(
        "run", "--rm", "--network", network, "--label", label, *_HARDENING, *mount_args,
        image, *tool_args, timeout=float(timeout_seconds),
    )
    duration_ms = round((monotonic() - started) * 1000)
    combined = (result.stdout + result.stderr).encode("utf-8", "replace")
    truncated = len(combined) > output_limit_bytes
    stdout_digest = hashlib.sha256((result.stdout or "").encode("utf-8", "replace")).hexdigest()
    argv_sha256 = hashlib.sha256("\x00".join(argv).encode()).hexdigest()
    run = ContainerRunResult(
        image_reference=image,
        argv_sha256=argv_sha256,
        exit_code=124 if result.timed_out else result.returncode,
        timed_out=result.timed_out,
        duration_ms=duration_ms,
        stdout_digest=stdout_digest,
        output_bytes=len(combined),
        output_truncated=truncated,
    )
    return RawRun(result=run, stdout=result.stdout, stderr=result.stderr)
