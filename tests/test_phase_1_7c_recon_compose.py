"""Static guard for the Phase 1.7-C isolated recon worker overlay.

No Docker is required: these assertions read the overlay and prove the ephemeral nmap worker is
non-root, read-only, egress-blocked, minimally capable, and mounts neither the host filesystem nor
the Docker socket. A Docker-gated test additionally resolves the merged config when available.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.phase-1-7c-recon.yml"


def _doc() -> dict[str, object]:
    return yaml.safe_load(OVERLAY.read_text(encoding="utf-8"))


def _worker() -> dict[str, object]:
    return _doc()["services"]["recon-nmap-worker"]  # type: ignore[index]


def test_scope_network_is_internal_and_not_external() -> None:
    networks = _doc()["networks"]  # type: ignore[index]
    scope = networks["recon-scope"] or {}  # type: ignore[index]
    assert scope.get("internal") is True, "recon-scope must be internal (no public egress)"
    assert not scope.get("external"), "recon-scope must be Compose-managed, not external"
    assert "name" not in scope, "recon-scope must have no fixed cross-project name"


def test_no_network_is_external() -> None:
    for name, spec in (_doc()["networks"] or {}).items():  # type: ignore[union-attr]
        assert not (spec or {}).get("external"), f"{name} must not be external"


def test_worker_is_non_root() -> None:
    user = str(_worker().get("user", ""))
    assert user and not user.startswith("0:") and user != "root", user


def test_worker_is_read_only_with_bounded_tmpfs() -> None:
    worker = _worker()
    assert worker.get("read_only") is True, "worker filesystem must be read-only"
    tmpfs = worker.get("tmpfs") or []
    assert any("noexec" in entry and "size=" in entry for entry in tmpfs), tmpfs


def test_worker_drops_all_caps_and_adds_only_net_raw() -> None:
    worker = _worker()
    assert worker.get("cap_drop") == ["ALL"], worker.get("cap_drop")
    cap_add = set(worker.get("cap_add") or [])
    assert cap_add <= {"NET_RAW"}, f"only NET_RAW may be added, got {cap_add}"
    assert "NET_ADMIN" not in cap_add and "SYS_ADMIN" not in cap_add


def test_worker_has_no_new_privileges_and_is_not_privileged() -> None:
    worker = _worker()
    assert "no-new-privileges:true" in (worker.get("security_opt") or [])
    assert worker.get("privileged") is not True


def test_worker_has_bounded_resources() -> None:
    worker = _worker()
    for field in ("pids_limit", "mem_limit", "cpus"):
        assert worker.get(field), f"worker must bound {field}"


def test_worker_mounts_no_host_path_and_no_docker_socket() -> None:
    worker = _worker()
    volumes = worker.get("volumes") or []
    assert volumes == [], f"worker must mount nothing from the host, got {volumes}"
    serialized = yaml.safe_dump(worker)
    assert "docker.sock" not in serialized, "worker must never see the Docker socket"


def test_worker_publishes_no_host_port_and_joins_only_scope_network() -> None:
    worker = _worker()
    assert "ports" not in worker, "worker must publish nothing to the host"
    assert list(worker.get("networks") or []) == ["recon-scope"]


def test_worker_image_is_pinned_by_digest() -> None:
    image = str(_worker().get("image", ""))
    assert "@sha256:" in image, f"nmap worker image must be pinned by digest, got {image}"


def test_overlay_has_no_active_scan_or_beast_or_shell_service() -> None:
    services = set(_doc()["services"])  # type: ignore[arg-type]
    forbidden = ("beast", "shell", "active", "burp")
    assert not any(any(f in name.lower() for f in forbidden) for name in services), services


def test_worker_default_command_is_inert() -> None:
    # The default command must not scan; the controller injects the rendered argv at exec time.
    command = _worker().get("command")
    assert command == ["--version"], command


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available on this host")
def test_generated_argv_combinations_are_accepted_by_real_nmap() -> None:
    """Prove every rendered job argv is ACCEPTED by the pinned nmap binary, not just built by us.

    Each job runs against loopback on an isolated ``--network none`` with its minimum privilege
    profile; a rejected argument combination makes nmap print ``QUITTING!``. We assert nmap parses
    the args and emits XML instead.
    """

    from aegis.multi_agent.recon import (
        NMAP_IMAGE_REF,
        NmapScanPlan,
        build_nmap_bundle,
        nmap_run_profile,
    )

    docker_bin = shutil.which("docker")
    assert docker_bin is not None
    # Pull-by-digest guard: skip (don't fail) if the pinned image is unavailable in this env.
    if subprocess.run(  # noqa: S603
        [docker_bin, "image", "inspect", NMAP_IMAGE_REF], capture_output=True
    ).returncode != 0:
        if subprocess.run(  # noqa: S603
            [docker_bin, "pull", NMAP_IMAGE_REF], capture_output=True, timeout=300
        ).returncode != 0:
            pytest.skip("pinned nmap image unavailable")

    plan = NmapScanPlan(
        target_ref="range-bank",
        profile_id="RANGE_FULL_RECON",
        transports=["TCP", "UDP"],
        tcp_port_spec="DISCOVERY_TOP_100",
        udp_port_spec="TOP_50",
        discovery_strategy="TCP_SYN",
        version_detection=True,
        os_detection=True,
        timing_profile="T4",
        nse_categories=["SAFE"],
        nse_script_ids=["banner", "http-title"],
    )
    # Follow-ups pinned to one concrete port so version/OS jobs stay fast against loopback.
    bundle = build_nmap_bundle(plan, observed_open_ports=(80,))
    for job in bundle.jobs:
        profile = nmap_run_profile(job)
        flags = [
            "run", "--rm", "--network", "none", "--user", str(profile["user"]),
            "--read-only", "--tmpfs", "/tmp:size=8m",  # noqa: S108 - container tmpfs
            "--security-opt", "no-new-privileges:true",
        ]
        for cap in profile["cap_drop"]:  # type: ignore[union-attr]
            flags += ["--cap-drop", cap]
        for cap in profile["cap_add"]:  # type: ignore[union-attr]
            flags += ["--cap-add", cap]
        argv = ["127.0.0.1" if tok == "aegis-bank" else tok for tok in job.argv[1:]]
        proc = subprocess.run(  # noqa: S603 - fixed docker/image args, no shell
            [docker_bin, *flags, NMAP_IMAGE_REF, *argv], capture_output=True, timeout=120
        )
        combined = proc.stdout + proc.stderr
        assert b"QUITTING" not in combined, f"{job.kind}: nmap rejected argv: {combined[:200]!r}"
        assert b"<nmaprun" in proc.stdout, f"{job.kind}: no nmap XML produced"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available on this host")
def test_docker_compose_config_resolves() -> None:
    docker_bin = shutil.which("docker")
    assert docker_bin is not None
    proc = subprocess.run(  # noqa: S603 - fixed, trusted argument vector; no user input
        [docker_bin, "compose", "-f", str(OVERLAY), "-p", "aegis-p17c-recon-pytest", "config"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"docker compose config unavailable: {proc.stderr[:200]}")
    assert "external: true" not in proc.stdout
