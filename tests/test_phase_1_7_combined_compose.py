"""Regression: the Phase 1.7 combined live stack must be self-contained.

The combined runner failed for an operator with:

    network aegis-range_bank-backend declared as external, but could not be found

These tests prove the fix statically (no Docker, and specifically on a host where the
`aegis-range_bank-backend` network does NOT exist): the runner's merged Compose file set declares
no external network and owns its own internal `bank-runtime`. A Docker-gated test additionally
resolves the merged config when Docker is available.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "phase_1_7_combined_live.sh"
COMBINED_OVERLAY = ROOT / "docker-compose.phase-1-7-combined.yml"
EXPECTED_FILES = (
    "docker-compose.yml",
    "docker-compose.deepseek.yml",
    "docker-compose.phase-1-7-combined.yml",
)


def _runner_stack_files() -> list[str]:
    text = RUNNER.read_text(encoding="utf-8")
    match = re.search(r"^STACK=\((.*?)\)", text, re.MULTILINE)
    assert match, "runner must define a STACK=(...) compose file list"
    return re.findall(r"-f\s+(\S+)", match.group(1))


def test_runner_uses_self_contained_overlay_not_the_attach_overlay() -> None:
    files = _runner_stack_files()
    assert files == list(EXPECTED_FILES), files
    # The attach-mode overlay (external aegis-range network) must not be in the combined run.
    assert "docker-compose.phase-1-7a.yml" not in files


def test_runner_guards_against_external_networks_before_up() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "external:[[:space:]]*true" in text, "runner must fail closed on any external network"
    # The guard must run before the first `up`.
    guard_at = text.index("external:[[:space:]]*true")
    up_at = text.index("up -d")
    assert guard_at < up_at, "external-network guard must precede `up`"


def test_no_stack_file_declares_an_external_network() -> None:
    for name in EXPECTED_FILES:
        document = yaml.safe_load((ROOT / name).read_text(encoding="utf-8")) or {}
        networks = document.get("networks", {}) or {}
        for net_name, spec in networks.items():
            spec = spec or {}
            assert not spec.get("external"), (
                f"{name}:{net_name} is declared external; the combined run must be self-contained"
            )
            # A fixed cross-project name is what coupled this to aegis-range; forbid it here.
            assert "aegis-range_bank-backend" != spec.get("name"), name


def test_bank_runtime_is_project_owned_internal() -> None:
    document = yaml.safe_load(COMBINED_OVERLAY.read_text(encoding="utf-8"))
    bank = document["networks"]["bank-runtime"] or {}
    assert bank.get("internal") is True, "bank-runtime must stay internal: true"
    assert not bank.get("external"), "bank-runtime must be Compose-managed, not external"
    assert "name" not in bank, "bank-runtime must have no fixed name (project-scoped)"


def test_bank_service_publishes_no_host_port_and_only_bank_net() -> None:
    document = yaml.safe_load(COMBINED_OVERLAY.read_text(encoding="utf-8"))
    bank = document["services"]["aegis-bank-live"]
    assert "ports" not in bank, "the Bank service must not be published to the host"
    assert list(bank["networks"].keys()) == ["bank-runtime"]
    # Only the runner (controller/client) also joins bank-runtime.
    runner_nets = document["services"]["phase-1-7a-runner"]["networks"]
    assert "bank-runtime" in runner_nets


def test_no_scanner_or_beast_or_zap_services_in_overlay() -> None:
    document = yaml.safe_load(COMBINED_OVERLAY.read_text(encoding="utf-8"))
    services = set(document.get("services", {}))
    forbidden = {"beast", "zap", "nuclei", "scanner"}
    assert not any(any(f in name for f in forbidden) for name in services), services


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available on this host")
def test_docker_compose_config_resolves_with_no_external_networks() -> None:
    # Runs on a host where aegis-range_bank-backend does not exist; `config` must resolve and show
    # no external network. (`config` never creates networks, so this is safe and side-effect free.)
    docker_bin = shutil.which("docker")
    assert docker_bin is not None  # guarded by skipif
    files: list[str] = []
    for name in EXPECTED_FILES:
        files += ["-f", name]
    proc = subprocess.run(  # noqa: S603 - fixed, trusted argument vector; no user input
        [docker_bin, "compose", *files, "-p", "aegis-p17c-pytest", "config"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"docker compose config unavailable: {proc.stderr[:200]}")
    in_networks = False
    for line in proc.stdout.splitlines():
        if line.startswith("networks:"):
            in_networks = True
            continue
        if line and line[0].isalpha():
            in_networks = False
        if in_networks:
            assert "external: true" not in line, line
