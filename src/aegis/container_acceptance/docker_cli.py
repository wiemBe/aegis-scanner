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


class DockerQueryError(ContainerAcceptanceError):
    """Raised when a docker listing/inspection command itself fails or times out.

    A failed query establishes NOTHING about the world: it must never be read as "zero resources"
    or "resource absent". Callers catch this and fail closed (leftover state UNKNOWN), never treat
    it as a clean result.
    """


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


_LIST_ARGS = {
    "container": ["ps", "-aq"],
    "network": ["network", "ls", "-q"],
    "volume": ["volume", "ls", "-q"],
}


def count_by_label(kind: str, label: str) -> int:
    """Count docker objects (``container``/``network``/``volume``) carrying ``label``.

    Fail closed: a non-zero return code OR a timeout raises :class:`DockerQueryError`. A failed
    listing is never silently converted into a zero count — that would let a range whose teardown
    could not even be observed report itself as clean.
    """

    result = docker(*_LIST_ARGS[kind], "--filter", f"label={label}", timeout=30)
    if result.timed_out or result.returncode != 0:
        raise DockerQueryError(
            f"DOCKER_QUERY_FAILED:{kind}:label:rc={result.returncode}:"
            f"timeout={result.timed_out}:{result.stderr.strip()[:120]}"
        )
    return len([line for line in result.stdout.splitlines() if line.strip()])


def name_present(kind: str, name: str) -> bool:
    """Strictly test whether a ``container``/``network``/``volume`` with the exact ``name`` exists.

    Used to prove idempotent teardown: an already-removed resource may be accepted as gone ONLY when
    a successful query returns it absent. Fail closed: if the listing command itself fails or times
    out, raise :class:`DockerQueryError` so absence is NEVER inferred from a failed query. The
    ``^name$`` anchors make docker's regex name filter an exact match.
    """

    result = docker(*_LIST_ARGS[kind], "--filter", f"name=^{name}$", timeout=30)
    if result.timed_out or result.returncode != 0:
        raise DockerQueryError(
            f"DOCKER_QUERY_FAILED:{kind}:name:rc={result.returncode}:"
            f"timeout={result.timed_out}:{result.stderr.strip()[:120]}"
        )
    return any(line.strip() for line in result.stdout.splitlines())
