"""Phase 1.7-C Gate 1 — reused Nuclei/ZAP passive runners executed THROUGH the recon dispatch.

This harness proves that the Phase 1.7-C controlled Recon Agent capability dispatch path reaches the
*existing*, attested Phase 1.2 nuclei-runner and Phase 1.3 zap-runner containers and executes real
scans — not merely their standalone historical harnesses, and not a fixture. It reuses the existing
``build_reviewed_exposure_job`` / ``build_passive_openapi_job`` controller builders and the existing
``NucleiAdapter`` / ``ZapAdapter`` RPC clients (their runner protocol, response validation and
parser). Nothing here duplicates a runner, parser, manifest or verification rule.

Two modes:

* ``--in-container --engine {nuclei,zap}`` runs INSIDE a control-plane container joined to the
  runner's internal RPC network. It drives the recon dispatch (capability selection -> reused
  controller builder -> reused adapter -> attested runner container) for the vulnerable and clean
  target variants, plus a forced runner-unavailable case, and prints one JSON object to stdout. It
  writes no file (the container mounts nothing).

* the default host mode brings up the reused Phase 1.2 / 1.3 stack per engine, runs the in-container
  pass via ``docker compose run``, inspects runner network isolation and published ports from the
  host, tears the stack down, and writes fresh timestamped evidence under ``artifacts/``.

Matrix per engine: candidate target (vulnerable), clean target (patched), forced-incomplete. It
never runs ZAP Active. Recon never confirms, PASSes or sets severity; the deterministic verifier
remains the sole confirming authority and the Recon Agent has no path to it.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
BASE_COMPOSE = "docker-compose.yml"
OVERLAYS = {"nuclei": "docker-compose.nuclei.yml", "zap": "docker-compose.zap.yml"}
RUNNER_SERVICE = {"nuclei": "nuclei-runner", "zap": "zap-runner"}
INTERNAL_NETWORKS = {
    "nuclei": {"engine-rpc", "nuclei-target"},
    "zap": {"zap-rpc", "zap-egress"},
}


# --------------------------------------------------------------------------- #
# In-container: drive the recon dispatch against the attested runner.
# --------------------------------------------------------------------------- #


def _gate_summary(result: Any) -> dict[str, Any]:
    return {
        "outcome": str(result.outcome),
        "confirmed_by_recon": result.confirmed_by_recon,
        "observation_counts": result.observation_counts,
        "commands": result.commands,
        "target_requests": result.target_requests,
        "facts": result.facts,
        "evidence_sha256": result.evidence_sha256,
    }


def _structural_invariants() -> dict[str, bool]:
    from aegis.multi_agent.recon import NormalizedReconReport, ReconBroker

    no_verify = not any(
        hasattr(ReconBroker, m) for m in ("verify", "confirm", "promote", "conclude")
    )
    report = NormalizedReconReport("nuclei-probe")
    no_verdict = not any(
        hasattr(report, a) for a in ("verdict", "pass_", "severity", "confirmed", "status")
    )
    return {"broker_has_no_verify": no_verify, "report_has_no_verdict": no_verdict}


async def _run_matrix(engine: str) -> dict[str, Any]:
    from aegis.multi_agent.model import OfflineReconModel
    from aegis.multi_agent.recon import (
        ReconExecutionOutcome,
        nuclei_execution_outcome,
        zap_execution_outcome,
    )
    from aegis.multi_agent.recon_runtime import ReconAcceptanceRuntime
    from aegis_range.controller import RangeController

    # The controller is unused by the reuse gates (they perform no range reset); an empty one is
    # sufficient and keeps this harness free of any range dependency.
    runtime = ReconAcceptanceRuntime(OfflineReconModel(), RangeController({}, {}))
    out: dict[str, Any] = {"engine": engine}

    if engine == "nuclei":
        from aegis.engine.nuclei import NucleiAdapter

        adapter = NucleiAdapter("http://nuclei-runner:8090", enabled=True, timeout_seconds=90.0)
        attestation = await adapter.attest()
        out["attestation_ready"] = bool(attestation and attestation.ready)
        out["runner_reachable"] = adapter.last_reachable is True

        async def execute(job: object) -> ReconExecutionOutcome:
            result = await adapter.run(
                job,  # type: ignore[arg-type]
                f"scan-{secrets.token_hex(6)}",
                execution_id=f"exec-{secrets.token_hex(6)}",
            )
            return nuclei_execution_outcome(result)

        for variant in ("vulnerable", "patched"):
            res = await runtime.reviewed_exposure_gate(target_variant=variant, executor=execute)  # type: ignore[arg-type]
            out[variant] = _gate_summary(res)

        # Forced-incomplete: a genuinely unreachable runner endpoint -> adapter FAILED ->
        # INCOMPLETE_TOOL_ERROR (never a clean pass or a candidate).
        dead = NucleiAdapter("http://nuclei-runner:9", enabled=True, timeout_seconds=5.0)

        async def execute_dead(job: object) -> ReconExecutionOutcome:
            result = await dead.run(
                job,  # type: ignore[arg-type]
                f"scan-{secrets.token_hex(6)}",
                execution_id=f"exec-{secrets.token_hex(6)}",
            )
            return nuclei_execution_outcome(result)

        res = await runtime.reviewed_exposure_gate(
            target_variant="vulnerable", executor=execute_dead  # type: ignore[arg-type]
        )
        out["incomplete"] = _gate_summary(res)
    else:
        from aegis.engine.zap import ZapAdapter

        adapter_z = ZapAdapter("http://zap-runner:8092", enabled=True, timeout_seconds=150.0)
        attestation_z = await adapter_z.attest()
        out["attestation_ready"] = bool(attestation_z and attestation_z.ready)
        out["runner_reachable"] = adapter_z.last_reachable is True

        async def execute_z(job: object) -> ReconExecutionOutcome:
            result = await adapter_z.run(
                job,  # type: ignore[arg-type]
                f"scan-{secrets.token_hex(6)}",
                execution_id=f"exec-{secrets.token_hex(6)}",
            )
            return zap_execution_outcome(result)

        for variant in ("vulnerable", "patched"):
            res = await runtime.passive_openapi_gate(target_variant=variant, executor=execute_z)  # type: ignore[arg-type]
            out[variant] = _gate_summary(res)

        dead_z = ZapAdapter("http://zap-runner:9", enabled=True, timeout_seconds=5.0)

        async def execute_dead_z(job: object) -> ReconExecutionOutcome:
            result = await dead_z.run(
                job,  # type: ignore[arg-type]
                f"scan-{secrets.token_hex(6)}",
                execution_id=f"exec-{secrets.token_hex(6)}",
            )
            return zap_execution_outcome(result)

        res = await runtime.passive_openapi_gate(
            target_variant="vulnerable", executor=execute_dead_z  # type: ignore[arg-type]
        )
        out["incomplete"] = _gate_summary(res)

    out["recon_cannot_confirm"] = _structural_invariants()
    return out


# --------------------------------------------------------------------------- #
# Host: bring up the reused stack, run the in-container pass, inspect isolation, tear down.
# --------------------------------------------------------------------------- #


def _dc(engine: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    project = f"aegis-p17c-gate1-{engine}"
    cmd = [
        DOCKER, "compose", "-p", project,
        "-f", BASE_COMPOSE, "-f", OVERLAYS[engine], *args,
    ]
    return subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        cmd, capture_output=True, text=True, timeout=timeout
    )


def _runner_isolation(engine: str) -> dict[str, Any]:
    ps = _dc(engine, "ps", "-q", RUNNER_SERVICE[engine], timeout=60)
    cid = ps.stdout.strip().splitlines()[0] if ps.stdout.strip() else ""
    if not cid:
        return {"container_found": False}
    inspect = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        [DOCKER, "inspect", cid, "--format", "{{json .NetworkSettings}}"],
        capture_output=True, text=True, timeout=60,
    )
    net = json.loads(inspect.stdout) if inspect.stdout.strip() else {}
    networks = sorted((net.get("Networks") or {}).keys())
    # Compose prefixes networks with the project name; strip it for comparison.
    bare = {n.split("_", 1)[-1] for n in networks}
    ports = net.get("Ports") or {}
    published = {k: v for k, v in ports.items() if v}
    return {
        "container_found": True,
        "networks": networks,
        "no_published_port": not published,
        "only_internal_networks": bare == INTERNAL_NETWORKS[engine],
    }


def _network_internal(engine: str) -> dict[str, bool]:
    project = f"aegis-p17c-gate1-{engine}"
    result: dict[str, bool] = {}
    for net in INTERNAL_NETWORKS[engine]:
        name = f"{project}_{net}"
        inspect = subprocess.run(  # noqa: S603 - fixed docker binary, list argv
            [DOCKER, "network", "inspect", name, "--format", "{{.Internal}}"],
            capture_output=True, text=True, timeout=30,
        )
        result[net] = inspect.stdout.strip() == "true"
    return result


def _cleanup_verified(engine: str) -> dict[str, Any]:
    down = _dc(engine, "down", "-v", "--remove-orphans", timeout=180)
    project = f"aegis-p17c-gate1-{engine}"
    leftovers = subprocess.run(  # noqa: S603 - fixed docker binary, list argv
        [DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={project}",
         "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    names = [n for n in leftovers.stdout.splitlines() if n.strip()]
    return {"down_rc": down.returncode, "container_leftovers": names, "ok": not names}


def _run_engine(engine: str) -> dict[str, Any]:
    record: dict[str, Any] = {"engine": engine}
    build = _dc(engine, "build", "control-plane", timeout=1200)
    record["build_rc"] = build.returncode
    if build.returncode != 0:
        record["build_stderr_tail"] = build.stderr[-800:]
        return record
    try:
        run = _dc(
            engine, "run", "--rm", "-T", "control-plane",
            "python", "scripts/phase_1_7c_recon_adapter.py", "--in-container", "--engine", engine,
            timeout=900,
        )
        record["run_rc"] = run.returncode
        stdout = run.stdout.strip()
        # The harness prints exactly one JSON object as its last stdout line.
        json_line = stdout.splitlines()[-1] if stdout else ""
        try:
            record["matrix"] = json.loads(json_line)
        except json.JSONDecodeError:
            record["matrix"] = None
            record["run_stdout_tail"] = stdout[-2000:]
            record["run_stderr_tail"] = run.stderr[-2000:]
        record["runner_isolation"] = _runner_isolation(engine)
        record["network_internal"] = _network_internal(engine)
    finally:
        record["cleanup"] = _cleanup_verified(engine)
    return record


def _engine_verdict(record: dict[str, Any]) -> dict[str, Any]:
    matrix = record.get("matrix") or {}
    vuln = matrix.get("vulnerable") or {}
    clean = matrix.get("patched") or {}
    incomplete = matrix.get("incomplete") or {}
    iso = record.get("runner_isolation") or {}
    checks = {
        "attested_runner_reached": bool(matrix.get("attestation_ready")),
        "vulnerable_is_candidate": vuln.get("outcome") == "OBSERVED"
        and int((vuln.get("facts") or {}).get("candidates", 0)) >= 1
        and vuln.get("confirmed_by_recon") is False,
        "clean_is_no_finding": clean.get("outcome") == "OBSERVED"
        and bool((clean.get("facts") or {}).get("no_finding"))
        and int((clean.get("facts") or {}).get("candidates", 1)) == 0,
        "incomplete_is_incomplete": incomplete.get("outcome") == "INCONCLUSIVE"
        and bool((incomplete.get("facts") or {}).get("incomplete")),
        "nothing_confirmed_by_recon": all(
            (matrix.get(v) or {}).get("confirmed_by_recon") is False
            for v in ("vulnerable", "patched", "incomplete")
        ),
        "recon_cannot_confirm": all(
            (matrix.get("recon_cannot_confirm") or {}).values()
        ),
        "runner_no_published_port": bool(iso.get("no_published_port")),
        "runner_only_internal_networks": bool(iso.get("only_internal_networks")),
        "networks_internal": all((record.get("network_internal") or {}).values()),
        "cleanup_ok": bool((record.get("cleanup") or {}).get("ok")),
    }
    return {"checks": checks, "passed": all(checks.values())}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-container", action="store_true")
    parser.add_argument("--engine", choices=["nuclei", "zap"], default=None)
    parser.add_argument("--engines", default="nuclei,zap")
    args = parser.parse_args()

    if args.in_container:
        if args.engine is None:
            print(json.dumps({"error": "engine required"}))
            return 2
        matrix = asyncio.run(_run_matrix(args.engine))
        print(json.dumps(matrix))
        return 0

    if shutil.which("docker") is None:
        print("FAIL_CLOSED: docker not available", file=sys.stderr)
        return 2

    started = datetime.now(UTC)
    engines = [e for e in args.engines.split(",") if e in OVERLAYS]
    records = {engine: _run_engine(engine) for engine in engines}
    verdicts = {engine: _engine_verdict(records[engine]) for engine in engines}
    all_pass = all(v["passed"] for v in verdicts.values())
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path("artifacts") / f"phase-1.7c-recon-adapter-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    acceptance: dict[str, Any] = {
        "phase": "1.7-C",
        "gate": "gate1_recon_adapter_integration",
        "scope": (
            "Reused Phase 1.2 nuclei-runner and Phase 1.3 zap-runner executed THROUGH the recon "
            "capability dispatch path (build_reviewed_exposure_job / build_passive_openapi_job + "
            "the existing NucleiAdapter / ZapAdapter). No runner/parser/manifest duplicated. No "
            "ZAP Active. No live provider."
        ),
        "provider_calls": 0,
        "live_provider_run": False,
        "engines": engines,
        "records": records,
        "verdicts": verdicts,
        "elapsed_seconds": round(elapsed_s, 2),
        "verdict": (
            "CONTAINERIZED PASS for the reused Nuclei/ZAP passive recon integration"
            if all_pass
            else "PARTIAL"
        ),
    }
    files = {"acceptance.json": acceptance}
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    sha_lines = [
        f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in sorted(files)
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
    print(json.dumps({**acceptance, "evidence_dir": str(out_dir)}, indent=2, sort_keys=True))
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
