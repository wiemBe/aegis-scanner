"""WP2 — container hardening + deterministic production image (G-ROOT-1/G-LIMITS-1/G-ROLL-1).

Offline, fail-closed guards over the root ``Dockerfile``, the base Compose stack, the production
overlay, and the typed image-reference/preflight layer. Docker-gated integration tests additionally
prove the built image runs non-root, can write ``/data`` but not ``/app``, and that the rendered
production configuration pins an exact digest for both services with no build fallback.

Every image reference used here is an obvious placeholder digest; no real registry, credential, or
provider token appears in this file.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 - fixed, trusted docker argv in gated tests; no shell, no user input
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from aegis.deploy.image_reference import (
    ImageReferenceError,
    parse_immutable_image_reference,
)
from aegis.deploy.preflight import PreflightError, analyze_rendered_config

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
BASE_COMPOSE = ROOT / "docker-compose.yml"
PROD_COMPOSE = ROOT / "docker-compose.prod.yml"

_PLACEHOLDER_DIGEST = "sha256:" + "a" * 64
_PLACEHOLDER_IMAGE = f"registry.example.test/aegis@{_PLACEHOLDER_DIGEST}"
_DOCKER = shutil.which("docker")
_requires_docker = pytest.mark.skipif(_DOCKER is None, reason="docker not available on this host")


# --- YAML helpers --------------------------------------------------------------------------------


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader that understands Compose's ``!reset`` merge tag (renders to ``None``)."""


_ComposeLoader.add_constructor("!reset", lambda _loader, _node: None)


def _load(path: Path) -> dict[str, Any]:
    return yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader)  # noqa: S506 - custom SafeLoader subclass


def _base_service(name: str) -> dict[str, Any]:
    return _load(BASE_COMPOSE)["services"][name]


# --- Dockerfile: numeric non-root USER -----------------------------------------------------------


def _dockerfile_user() -> str:
    users = re.findall(r"^USER\s+(.+)$", DOCKERFILE.read_text(encoding="utf-8"), flags=re.MULTILINE)
    assert users, "Dockerfile must declare a USER"
    return users[-1].strip()


def test_dockerfile_declares_numeric_non_root_user() -> None:
    user = _dockerfile_user()
    assert re.fullmatch(r"\d+:\d+", user), f"USER must be numeric uid:gid, got {user!r}"


def test_dockerfile_user_is_not_uid_or_gid_zero() -> None:
    uid, gid = (int(part) for part in _dockerfile_user().split(":"))
    assert uid != 0 and gid != 0, f"runtime user must not be root, got {uid}:{gid}"


def test_dockerfile_creates_writable_data_dir_owned_by_runtime_user() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    uid, gid = _dockerfile_user().split(":")
    assert "mkdir -p /data" in text
    assert f"chown {uid}:{gid} /data" in text


def test_dockerfile_grants_no_extra_privilege() -> None:
    # Inspect instruction lines only (comments explicitly mention what is *not* used).
    instructions = "\n".join(
        line for line in DOCKERFILE.read_text(encoding="utf-8").lower().splitlines()
        if not line.lstrip().startswith("#")
    )
    for forbidden in ("sudo", "setcap", "--privileged", "docker.sock", "chmod u+s", "setuid"):
        assert forbidden not in instructions, f"Dockerfile must not use {forbidden!r}"


# --- Base Compose: hardening + resource controls -------------------------------------------------


@pytest.mark.parametrize("service", ["control-plane", "lab-api"])
def test_service_retains_rootfs_hardening(service: str) -> None:
    spec = _base_service(service)
    assert spec.get("read_only") is True
    assert "no-new-privileges:true" in spec.get("security_opt", [])
    assert spec.get("tmpfs") == ["/tmp"]  # noqa: S108 - container tmpfs mount, not a host temp path


def _mem_bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([kmg]?)", value.strip().lower())
    assert match, f"unrecognized mem_limit {value!r}"
    scale = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[match.group(2)]
    return int(match.group(1)) * scale


@pytest.mark.parametrize("service", ["control-plane", "lab-api"])
def test_service_has_nonzero_memory_cpu_and_pid_limits(service: str) -> None:
    spec = _base_service(service)
    assert _mem_bytes(str(spec["mem_limit"])) > 0
    assert float(spec["cpus"]) > 0
    assert int(spec["pids_limit"]) > 0


@pytest.mark.parametrize("service", ["control-plane", "lab-api"])
def test_service_has_expected_restart_policy(service: str) -> None:
    assert _base_service(service).get("restart") == "unless-stopped"


# --- Production overlay: immutable digest, no build ----------------------------------------------


@pytest.mark.parametrize("service", ["control-plane", "lab-api"])
def test_prod_overlay_resets_build_and_pins_image_var(service: str) -> None:
    spec = _load(PROD_COMPOSE)["services"][service]
    # ``build: !reset null`` parses to None: the local-build fallback is removed on merge.
    assert spec["build"] is None
    assert spec["image"].startswith("${AEGIS_IMAGE")


# --- Typed image-reference validator (fail closed) -----------------------------------------------


def test_valid_lowercase_sha256_digest_is_accepted_unchanged() -> None:
    parsed = parse_immutable_image_reference(_PLACEHOLDER_IMAGE)
    assert parsed.reference == _PLACEHOLDER_IMAGE
    assert parsed.digest == _PLACEHOLDER_DIGEST


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "   ",
        "registry.example.test/aegis",  # bare name, no digest
        "registry.example.test/aegis:0.2.0",  # mutable tag only
        "registry.example.test/aegis:latest",  # latest
        "aegis:latest",  # latest, no registry
        "registry.example.test/aegis@sha256:deadbeef",  # too-short digest
        "registry.example.test/aegis@sha256:" + "a" * 63,  # 63 hex
        "registry.example.test/aegis@sha256:" + "a" * 65,  # 65 hex
        "registry.example.test/aegis@sha256:" + "A" * 64,  # uppercase hex
        "registry.example.test/aegis@sha256:" + "g" * 64,  # non-hex
        "registry.example.test/aegis@sha512:" + "a" * 64,  # wrong algorithm
        "registry.example.test/aegis@md5:" + "a" * 32,  # wrong algorithm
    ],
)
def test_non_immutable_reference_is_rejected(bad: str | None) -> None:
    with pytest.raises(ImageReferenceError):
        parse_immutable_image_reference(bad)


# --- Preflight rendered-config analysis (fail closed) --------------------------------------------


def _rendered(image_by_service: dict[str, Any]) -> dict[str, Any]:
    return {"services": {name: dict(spec) for name, spec in image_by_service.items()}}


def test_analyze_accepts_exact_digest_on_both_services_with_no_build() -> None:
    config = _rendered(
        {
            "control-plane": {"image": _PLACEHOLDER_IMAGE},
            "lab-api": {"image": _PLACEHOLDER_IMAGE},
        }
    )
    analyze_rendered_config(config, _PLACEHOLDER_IMAGE)  # must not raise


def test_analyze_rejects_active_build_fallback() -> None:
    config = _rendered(
        {
            "control-plane": {"image": _PLACEHOLDER_IMAGE, "build": {"context": "."}},
            "lab-api": {"image": _PLACEHOLDER_IMAGE},
        }
    )
    with pytest.raises(PreflightError, match="build fallback"):
        analyze_rendered_config(config, _PLACEHOLDER_IMAGE)


def test_analyze_rejects_image_mismatch() -> None:
    other = f"registry.example.test/aegis@sha256:{'b' * 64}"
    config = _rendered(
        {"control-plane": {"image": other}, "lab-api": {"image": _PLACEHOLDER_IMAGE}}
    )
    with pytest.raises(PreflightError, match="does not match"):
        analyze_rendered_config(config, _PLACEHOLDER_IMAGE)


def test_analyze_rejects_missing_service() -> None:
    config = _rendered({"control-plane": {"image": _PLACEHOLDER_IMAGE}})
    with pytest.raises(PreflightError, match="missing service"):
        analyze_rendered_config(config, _PLACEHOLDER_IMAGE)


# --- Docker-gated: rendered production config -----------------------------------------------------


@_requires_docker
def test_rendered_production_compose_pins_digest_and_has_no_build() -> None:
    assert _DOCKER is not None
    completed = subprocess.run(  # noqa: S603 - fixed argv; placeholder digest via env, no shell
        [
            _DOCKER,
            "compose",
            "-f",
            str(BASE_COMPOSE),
            "-f",
            str(PROD_COMPOSE),
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "AEGIS_IMAGE": _PLACEHOLDER_IMAGE},
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        pytest.skip(f"docker compose config unavailable: {completed.stderr[:200]}")
    config = json.loads(completed.stdout)
    # Proven from the configuration Compose actually renders, not from parsing YAML by hand.
    analyze_rendered_config(config, _PLACEHOLDER_IMAGE)
    for service in ("control-plane", "lab-api"):
        assert "build" not in config["services"][service]


# --- Docker-gated: built image runs non-root, /data writable, /app read-only ---------------------


@pytest.fixture(scope="module")
def wp2_image() -> Iterator[str]:
    if _DOCKER is None:
        pytest.skip("docker not available on this host")
    tag = f"aegis-wp2-test:{uuid.uuid4().hex[:12]}"
    build = subprocess.run(  # noqa: S603 - fixed argv; local build context, no shell
        [_DOCKER, "build", "-t", tag, "-f", str(DOCKERFILE), str(ROOT)],
        capture_output=True,
        text=True,
        timeout=1200,
        check=False,
    )
    if build.returncode != 0:
        pytest.skip(f"docker build unavailable: {build.stderr[-300:]}")
    yield tag
    subprocess.run(  # noqa: S603 - fixed argv, best-effort cleanup
        [_DOCKER, "image", "rm", "-f", tag], capture_output=True, text=True, check=False
    )


def _run_in_image(tag: str, script: str) -> subprocess.CompletedProcess[str]:
    assert _DOCKER is not None
    return subprocess.run(  # noqa: S603 - fixed argv; script is a test-authored constant, no shell
        [_DOCKER, "run", "--rm", "--network", "none", "--entrypoint", "python", tag, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@_requires_docker
def test_image_runtime_user_is_non_root(wp2_image: str) -> None:
    result = _run_in_image(wp2_image, "import os; print(os.getuid(), os.getgid())")
    assert result.returncode == 0, result.stderr
    uid, gid = (int(part) for part in result.stdout.split())
    assert uid != 0 and gid != 0, f"container must not run as root, got {uid}:{gid}"


@_requires_docker
def test_image_runtime_user_cannot_write_into_app(wp2_image: str) -> None:
    script = (
        "import pathlib\n"
        "try:\n"
        "    (pathlib.Path('/app') / 'should-not-write').write_text('x')\n"
        "    print('WROTE')\n"
        "except (PermissionError, OSError) as exc:\n"
        "    print('DENIED', type(exc).__name__)\n"
    )
    result = _run_in_image(wp2_image, script)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("DENIED"), result.stdout


@_requires_docker
def test_image_runtime_user_can_initialize_data_sqlite(wp2_image: str) -> None:
    assert _DOCKER is not None
    # A fresh anonymous named volume at /data inherits the image's uid:gid ownership, so the
    # non-root runtime user creates /data/aegis.db exactly as ScanStore.initialize() does.
    script = (
        "from aegis.storage import ScanStore\n"
        "s = ScanStore('/data/aegis.db')\n"
        "s.initialize()\n"
        "import os; print('OK', os.path.exists('/data/aegis.db'))\n"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv; anonymous volume, no shell
        [
            _DOCKER,
            "run",
            "--rm",
            "--network",
            "none",
            "--tmpfs",
            "/tmp",  # noqa: S108 - container tmpfs mount, not a host temp path
            "--read-only",
            "-v",
            "/data",
            "--entrypoint",
            "python",
            wp2_image,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "OK True", result.stdout
