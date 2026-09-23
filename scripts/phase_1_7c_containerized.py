"""Phase 1.7-C REAL containerized acceptance for the controlled Recon Agent's Nmap capability.

This harness executes the pinned nmap worker in Docker against ONLY the synthetic Bank and Shop
range on an isolated, internal (egress-blocked) network, and experimentally verifies the isolation
and safety properties — it is not a fixture and not static Compose validation. It performs **no**
DeepSeek/provider calls: the recon plan comes from the deterministic offline fixture.

What it does, per target (range-bank, range-shop):
  1. supply-chain preflight: resolve the image RepoDigest live and assert it equals the recorded
     pin (fail closed on mismatch); assert the nmap version;
  2. build the typed job bundle (TCP discovery, service/version+NSE, OS detection; UDP for Shop);
  3. run each job in its own ephemeral, non-root/read-only/cap-dropped container with the minimum
     privilege for the scan type, capturing real XML;
  4. parse + normalize + deduplicate into typed observations; refine the follow-up against observed
     open ports;
  5. run negative controls experimentally (egress, host FS, docker socket, scope escape, published
     ports, container removal, malformed XML, candidate/verdict invariants).

Evidence (real digests, exact argv, container ids, network attachments, raw-output digests,
normalized observations, budgets, negative-control results, cleanup proof, SHA256SUMS) is written to
``artifacts/phase-1.7c-containerized-<UTC>/``. Prior offline evidence is never touched.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.recon import (
    NMAP_IMAGE_REF,
    NMAP_TOOL_DIGEST,
    NMAP_TOOL_VERSION,
    NmapJobKind,
    NmapReconJob,
    NmapScanPlan,
    ReconRejection,
    build_nmap_bundle,
    deduplicate,
    nmap_run_profile,
    normalize_service_discovery,
    parse_nmap_xml,
)

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
RANGE_IMAGE = "aegis-range:1.6.0-dev"
RUN_ID = f"aegis-p17c-{int(time.time())}-{os.getpid()}"
SCOPE_NET = f"{RUN_ID}-scope"
TARGETS = {
    "range-bank": {"container": f"{RUN_ID}-bank", "alias": "aegis-bank", "port": 8101,
                   "module": "aegis_range.bank:app"},
    "range-shop": {"container": f"{RUN_ID}-shop", "alias": "aegis-shop", "port": 8102,
                   "module": "aegis_range.shop:app"},
}
# Bounded per-job wall-clock for the harness (the argv also carries --host-timeout/--max-rate).
JOB_TIMEOUT_S = 180


def docker(*args: str, timeout: int = 60, stdin: bytes | None = None) -> tuple[int, bytes, str]:
    proc = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        [DOCKER, *args], capture_output=True, timeout=timeout, input=stdin
    )
    return proc.returncode, proc.stdout, proc.stderr.decode("utf-8", "replace")


def _fail(msg: str) -> None:
    print(f"FAIL_CLOSED: {msg}", file=sys.stderr)


def preflight() -> dict[str, Any]:
    """Resolve the real image digest and version; fail closed if the pin does not match."""

    rc, out, err = docker(
        "image", "inspect", NMAP_IMAGE_REF, "--format", "{{json .RepoDigests}}|{{.Architecture}}"
    )
    if rc != 0:
        # Not present locally by digest; try to pull the pinned digest.
        prc, _, perr = docker("pull", NMAP_IMAGE_REF, timeout=300)
        if prc != 0:
            raise SystemExit(f"cannot obtain pinned nmap image {NMAP_IMAGE_REF}: {perr[:200]}")
        rc, out, err = docker(
            "image", "inspect", NMAP_IMAGE_REF, "--format",
            "{{json .RepoDigests}}|{{.Architecture}}",
        )
    repo_digests_raw, _, arch = out.decode().strip().partition("|")
    repo_digests = json.loads(repo_digests_raw)
    if not any(NMAP_TOOL_DIGEST in d for d in repo_digests):
        raise SystemExit(f"digest pin mismatch: {repo_digests} != {NMAP_TOOL_DIGEST}")
    vrc, vout, _ = docker("run", "--rm", NMAP_IMAGE_REF, "--version", timeout=60)
    version_line = vout.decode().splitlines()[0] if vout else ""
    if NMAP_TOOL_VERSION not in version_line:
        raise SystemExit(f"nmap version mismatch: {version_line!r} lacks {NMAP_TOOL_VERSION}")
    return {
        "image_ref": NMAP_IMAGE_REF,
        "repo_digests": repo_digests,
        "architecture": arch.strip(),
        "version_line": version_line,
        "digest_pin_verified": True,
    }


def cleanup() -> dict[str, Any]:
    removed = []
    for spec in TARGETS.values():
        docker("rm", "-f", spec["container"], timeout=30)
        removed.append(spec["container"])
    docker("network", "rm", SCOPE_NET, timeout=30)
    # Confirm removal.
    rc, out, _ = docker("ps", "-a", "--filter", f"name={RUN_ID}", "--format", "{{.Names}}")
    leftovers = [ln for ln in out.decode().splitlines() if ln.strip()]
    nrc, nout, _ = docker("network", "ls", "--filter", f"name={SCOPE_NET}", "--format", "{{.Name}}")
    net_leftover = [ln for ln in nout.decode().splitlines() if ln.strip()]
    return {"removed": removed, "container_leftovers": leftovers, "network_leftovers": net_leftover}


def bring_up_range() -> dict[str, Any]:
    rc, _, err = docker("network", "create", "--internal", SCOPE_NET, timeout=30)
    if rc != 0:
        raise SystemExit(f"cannot create internal scope network: {err[:200]}")
    up: dict[str, Any] = {"network": SCOPE_NET, "internal": True, "containers": {}}
    for target_ref, spec in TARGETS.items():
        rc, out, err = docker(
            "run", "-d", "--name", spec["container"],
            "--network", SCOPE_NET, "--network-alias", spec["alias"],
            "--user", "65532:65532", "--read-only",
            "--tmpfs", "/tmp:size=16m",  # noqa: S108 - container tmpfs, not a host temp path
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--pids-limit", "64", "--memory", "192m",
            # No -p / --publish: nothing is published to the host.
            RANGE_IMAGE,
            "uvicorn", spec["module"], "--host", "0.0.0.0", "--port", str(spec["port"]),  # noqa: S104
            timeout=60,
        )
        if rc != 0:
            raise SystemExit(f"cannot start {target_ref}: {err[:200]}")
        up["containers"][target_ref] = out.decode().strip()[:12]
    # Wait for readiness by execing a request from inside one container's network namespace is
    # awkward; instead poll each app's /health via a throwaway curl-less python in the range image.
    for target_ref, spec in TARGETS.items():
        ready = False
        for _ in range(40):
            rc, _, _ = docker(
                "run", "--rm", "--network", SCOPE_NET, "--entrypoint", "python", RANGE_IMAGE,
                "-c",
                f"import urllib.request,sys;"
                f"sys.exit(0 if urllib.request.urlopen('http://{spec['alias']}:{spec['port']}"
                f"/health',timeout=2).status==200 else 1)",
                timeout=15,
            )
            if rc == 0:
                ready = True
                break
            time.sleep(0.5)
        up["containers"].setdefault("_ready", {})
        up["containers"]["_ready"][target_ref] = ready
        if not ready:
            raise SystemExit(f"{target_ref} did not become healthy on the scope network")
    return up


def run_job(job: NmapReconJob) -> dict[str, Any]:
    """Run one nmap job in an ephemeral container with its minimum privilege profile."""

    profile = nmap_run_profile(job)
    flags = [
        "run", "--rm", "--name", f"{RUN_ID}-nmap-{job.kind.value.lower()}-{job.host}",
        "--network", SCOPE_NET,
        "--user", str(profile["user"]),
        "--read-only", "--tmpfs", "/tmp:size=16m",  # noqa: S108 - container tmpfs
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", "128", "--memory", "256m",
    ]
    for cap in profile["cap_drop"]:  # type: ignore[union-attr]
        flags += ["--cap-drop", cap]
    for cap in profile["cap_add"]:  # type: ignore[union-attr]
        flags += ["--cap-add", cap]
    # argv[0] is "nmap"; the image entrypoint already IS /usr/bin/nmap, so pass argv[1:].
    started = time.monotonic()
    rc, out, err = docker(*flags, NMAP_IMAGE_REF, *job.argv[1:], timeout=JOB_TIMEOUT_S)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    services, open_ports, ok = parse_nmap_xml(out, job.target_ref)
    return {
        "kind": job.kind.value,
        "privilege": job.privilege.value,
        "run_user": profile["user"],
        "cap_add": profile["cap_add"],
        "argv": list(job.argv),
        "exit_code": rc,
        "elapsed_ms": elapsed_ms,
        "raw_xml_sha256": hashlib.sha256(out).hexdigest(),
        "raw_xml_bytes": len(out),
        "parse_ok": ok,
        "services": services,
        "open_tcp_ports": open_ports,
        "stderr_head": err[:300],
    }


def scan_target(target_ref: str) -> dict[str, Any]:
    plan = NmapScanPlan(
        target_ref=target_ref,
        profile_id="RANGE_FULL_RECON",
        transports=["TCP", "UDP"] if target_ref == "range-shop" else ["TCP"],
        # Full TCP: the synthetic apps listen on 8101/8102, which are NOT in nmap's top-1000, so a
        # full-port scan is required to actually discover them.
        tcp_port_spec="FULL_65535",
        udp_port_spec="TOP_50" if target_ref == "range-shop" else "NONE",
        discovery_strategy="TCP_SYN",
        version_detection=True,
        version_intensity=5,
        os_detection=True,
        timing_profile="T4",
        nse_categories=["DISCOVERY", "SAFE", "VERSION", "VULN"],
        nse_script_ids=["banner", "http-title", "http-headers", "http-methods"],
    )
    bundle = build_nmap_bundle(plan)
    results: list[dict[str, Any]] = []
    observed_tcp: tuple[int, ...] = ()
    # Run discovery first to learn open ports, then refine the follow-ups against them.
    tcp = bundle.by_kind(NmapJobKind.TCP_DISCOVERY)
    if tcp is not None:
        r = run_job(tcp)
        results.append(r)
        observed_tcp = tuple(int(p) for p in r["open_tcp_ports"])
    udp = bundle.by_kind(NmapJobKind.UDP_DISCOVERY)
    if udp is not None:
        results.append(run_job(udp))
    refined = build_nmap_bundle(plan, observed_open_ports=observed_tcp)
    for kind in (NmapJobKind.SERVICE_VERSION_NSE, NmapJobKind.OS_DETECTION):
        job = refined.by_kind(kind)
        if job is not None:
            results.append(run_job(job))

    # Normalize every service across jobs into typed, deduplicated observations. A parse failure on
    # a discovery job is surfaced as INCOMPLETE; a completed scan with services yields typed
    # DiscoveredService records. Only when NOTHING parsed do we report INCOMPLETE.
    any_incomplete = any(not r["parse_ok"] for r in results)
    # Order service/version results first so the richer service name/product (e.g. http / Uvicorn)
    # survives deduplication over a discovery scan's bare port-number guess (e.g. ldoms-migr).
    version_services = [
        s for r in results if r["kind"] == "SERVICE_VERSION_NSE" for s in r["services"]
    ]
    other_services = [
        s for r in results if r["kind"] != "SERVICE_VERSION_NSE" for s in r["services"]
    ]
    raw_services = version_services + other_services
    observations = deduplicate(
        normalize_service_discovery(target_ref, raw_services if raw_services else None)
    )
    os_job = next((r for r in results if r["kind"] == "OS_DETECTION"), None)
    os_status = "not_run"
    if os_job is not None:
        os_status = (
            "executed" if os_job["parse_ok"] and os_job["exit_code"] == 0 else "inconclusive"
        )
    return {
        "target_ref": target_ref,
        "jobs": results,
        "observed_open_tcp_ports": list(observed_tcp),
        "normalized_observations": [o.model_dump(mode="json") for o in observations],
        "observation_kinds": sorted({o.kind for o in observations}),
        "any_incomplete": any_incomplete,
        "os_detection_status": os_status,
        "command_budget_used": len(results),
    }


def negative_controls() -> dict[str, Any]:
    controls: dict[str, Any] = {}

    # (1) No public egress: from the internal scope network, a scan of a public IP must NOT find an
    # open port (the network has no route off-host). Runs with the raw-socket profile.
    rc, out, _ = docker(
        "run", "--rm", "--network", SCOPE_NET, "--user", "0:0",
        "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--read-only",
        "--tmpfs", "/tmp:size=8m",  # noqa: S108 - container tmpfs
        "--security-opt", "no-new-privileges:true", NMAP_IMAGE_REF,
        "-p", "443", "-n", "-Pn", "--host-timeout", "10s", "-oX", "-", "1.1.1.1",
        timeout=40,
    )
    svc, _, _ = parse_nmap_xml(out, "range-egress-probe")
    egress_open = [s for s in svc if s["state"] == "open"]
    controls["no_public_egress"] = {
        "open_services_to_1.1.1.1": egress_open,
        "blocked": not egress_open,
    }

    # (2) No host filesystem / no docker socket in the worker (it mounts nothing).
    rc, out, _ = docker(
        "run", "--rm", "--network", "none", "--user", "65534:65534", "--entrypoint", "sh",
        NMAP_IMAGE_REF, "-c",
        "test -S /var/run/docker.sock && echo SOCKET_PRESENT || echo NO_SOCKET; "
        "test -e /host && echo HOST_MOUNT || echo NO_HOST_MOUNT",
        timeout=30,
    )
    fs = out.decode().split()
    controls["no_host_fs_or_docker_socket"] = {
        "checks": fs,
        "ok": "NO_SOCKET" in fs and "NO_HOST_MOUNT" in fs,
    }

    # (3) Scope escape rejected BEFORE execution (controller-side; zero docker runs).
    escape = {}
    for name, plan in {
        "out_of_inventory_target": NmapScanPlan(
            target_ref="range-attacker", profile_id="RANGE_FULL_RECON", transports=["TCP"]
        ),
        "evasion_smuggled": NmapScanPlan(
            target_ref="range-bank", profile_id="RANGE_FULL_RECON", transports=["TCP"],
            evasion_experiments=["idle-scan decoys"],
        ),
        "credentialed_smuggled": NmapScanPlan(
            target_ref="range-bank", profile_id="RANGE_FULL_RECON", transports=["TCP"],
            credentialed_scripts=["http-brute"],
        ),
    }.items():
        try:
            build_nmap_bundle(plan)
            escape[name] = "NOT_REJECTED"
        except ReconRejection as exc:
            escape[name] = str(exc)
    controls["scope_escape_rejected_pre_execution"] = {
        "results": escape,
        "ok": all(v not in ("NOT_REJECTED",) for v in escape.values()),
    }

    # (4) No published host port on any target container.
    ports = {}
    for target_ref, spec in TARGETS.items():
        rc, out, _ = docker(
            "inspect", spec["container"], "--format", "{{json .NetworkSettings.Ports}}"
        )
        ports[target_ref] = out.decode().strip()
    controls["no_published_host_port"] = {
        "ports": ports,
        "ok": all(p in ("{}", "null") for p in ports.values()),
    }

    # (5) Malformed/truncated XML → INCOMPLETE (never a clean PASS).
    obs = normalize_service_discovery("range-bank", None)
    truncated_ok = parse_nmap_xml(b"<nmaprun><host><ports><port", "range-bank")[2] is False
    controls["malformed_xml_is_incomplete"] = {
        "none_result_is_incomplete": obs[0].kind == "INCOMPLETE_TOOL_ERROR",
        "truncated_parse_ok_false": truncated_ok,
        "ok": obs[0].kind == "INCOMPLETE_TOOL_ERROR" and truncated_ok,
    }

    # (6) Recon cannot confirm / call a verifier / create a final finding (structural).
    from aegis.multi_agent.recon import NormalizedReconReport, ReconBroker

    controls["recon_cannot_confirm"] = {
        "broker_has_no_verify": not any(
            hasattr(ReconBroker, m) for m in ("verify", "confirm", "promote")
        ),
        "report_has_no_verdict_field": not any(
            hasattr(NormalizedReconReport("range-bank"), a)
            for a in ("verdict", "pass_", "severity", "confirmed")
        ),
        "ok": True,
    }
    controls["recon_cannot_confirm"]["ok"] = (
        controls["recon_cannot_confirm"]["broker_has_no_verify"]
        and controls["recon_cannot_confirm"]["report_has_no_verdict_field"]
    )
    return controls


def main() -> int:
    if shutil.which("docker") is None:
        _fail("docker not available on this host")
        return 2
    started = datetime.now(UTC)
    supply_chain = preflight()
    topology = bring_up_range()
    try:
        scans = {ref: scan_target(ref) for ref in TARGETS}
        controls = negative_controls()
    finally:
        cleanup_result = cleanup()

    # Verdict: each expected TCP service must be discovered; controls must pass; cleanup clean.
    expected_ports = {"range-bank": 8101, "range-shop": 8102}
    services_found = {
        ref: any(
            o.get("kind") == "DISCOVERED_SERVICE" and int(o.get("port", 0)) == expected_ports[ref]
            for o in scans[ref]["normalized_observations"]
        )
        for ref in TARGETS
    }
    controls_ok = all(c.get("ok") or c.get("blocked") for c in controls.values())
    cleanup_ok = (
        not cleanup_result["container_leftovers"]
        and not cleanup_result["network_leftovers"]
    )
    os_status = {ref: scans[ref]["os_detection_status"] for ref in TARGETS}

    checks = {
        "supply_chain_digest_verified": supply_chain["digest_pin_verified"],
        "bank_service_discovered": services_found["range-bank"],
        "shop_service_discovered": services_found["range-shop"],
        "negative_controls_pass": controls_ok,
        "cleanup_verified": cleanup_ok,
    }
    nmap_pass = all(checks.values())
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    if nmap_pass:
        verdict = "CONTAINERIZED PASS for the exact synthetic Recon capabilities executed (Nmap)"
    else:
        verdict = "PARTIAL"

    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path("artifacts") / f"phase-1.7c-containerized-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    acceptance: dict[str, Any] = {
        "phase": "1.7-C",
        "scope": "REAL containerized Nmap recon acceptance (Bank + Shop synthetic range only)",
        "provider_calls": 0,
        "live_provider_run": False,
        "run_id": RUN_ID,
        "supply_chain": supply_chain,
        "topology": topology,
        "scans": scans,
        "negative_controls": controls,
        "cleanup": cleanup_result,
        "os_detection_status": os_status,
        "checks": checks,
        "elapsed_seconds": round(elapsed_s, 2),
        "nuclei_zap_runner_execution": (
            "NOT executed in this harness; the reused Phase 1.2 nuclei-runner and Phase 1.3 "
            "zap-runner have their own attested acceptance (scripts/phase_1_2_acceptance.py, "
            "phase_1_3_acceptance.py). 1.7-C reuses their controller build path, exercised in the "
            "offline suite. Recorded as inconclusive-in-this-harness, not claimed."
        ),
        "verdict": verdict,
    }
    files = {"acceptance.json": acceptance}
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    sha_lines = [
        f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in sorted(files)
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
    print(json.dumps({**acceptance, "evidence_dir": str(out_dir)}, indent=2, sort_keys=True))
    return 0 if nmap_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
