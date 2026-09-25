"""A thin, fail-closed wrapper over the ``docker`` CLI.

Every call is a fixed argv list dispatched without a shell, so no container command is ever built by
string interpolation. The wrapper resolves the absolute ``docker`` path once and raises
:class:`DockerUnavailable` if the daemon or binary is missing, letting the harness degrade to a
skipped/NOT_EVALUATED state rather than crashing.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from aegis.container_acceptance.contracts import ContainerAcceptanceError


class DockerUnavailable(ContainerAcceptanceError):
    """Raised when the docker binary or daemon is not usable in this environment."""


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _binary() -> str:
    found = shutil.which("docker")
    if not found:
        raise DockerUnavailable("DOCKER_BINARY_NOT_FOUND")
    return found


def docker(*args: str, timeout: float = 60.0, check: bool = False) -> DockerResult:
    """Run ``docker <args>`` with a fixed argv and no shell."""

    argv = [_binary(), *args]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, absolute binary, never a shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        return DockerResult(
            returncode=124,
            stdout=out if isinstance(out, str) else out.decode("utf-8", "replace"),
            stderr=err if isinstance(err, str) else err.decode("utf-8", "replace"),
            timed_out=True,
        )
    result = DockerResult(completed.returncode, completed.stdout, completed.stderr)
    if check and result.returncode != 0:
        raise ContainerAcceptanceError(
            f"DOCKER_COMMAND_FAILED:{args[0] if args else ''}:{result.stderr.strip()[:160]}"
        )
    return result


def daemon_available() -> bool:
    """True iff the docker binary exists and the daemon answers ``docker info``."""

    try:
        return docker("info", "--format", "{{.ServerVersion}}", timeout=20).returncode == 0
    except DockerUnavailable:
        return False


def image_id(tag: str) -> str | None:
    """Resolve the content-addressed image id (``sha256:...``) for a local tag, or None."""

    result = docker("image", "inspect", tag, "--format", "{{.Id}}", timeout=30)
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def count_by_label(kind: str, label: str) -> int:
    """Count docker objects (``container``/``network``/``volume``) carrying ``label``."""

    sub = {
        "container": ["ps", "-aq"],
        "network": ["network", "ls", "-q"],
        "volume": ["volume", "ls", "-q"],
    }[kind]
    result = docker(*sub, "--filter", f"label={label}", timeout=30)
    if result.returncode != 0:
        return 0
    return len([line for line in result.stdout.splitlines() if line.strip()])
