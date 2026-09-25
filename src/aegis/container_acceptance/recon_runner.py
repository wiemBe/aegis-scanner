"""Containerized recon smoke runner for Phase 2.8.

Runs one controller-rendered recon discovery job (from the preserved Phase 2.8-A ``build_discovery_
job``) in a bounded, pinned tool container against the internal range, and classifies the outcome
honestly. A tool that runs and emits parseable output is ``CONTAINERIZED_SYNTHETIC_PASS``; a
rendered argv the pinned binary rejects, a timeout, or a tool error is ``NOT_EVALUATED`` with a
precise
reason. Capabilities with no honest fixture (DNS/TLS) or no acquirable pinned image are never run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.runner import run_tool
from aegis.multi_agent.recon_capabilities import ReconDiscoveryJob


@dataclass(frozen=True)
class ReconSmokeOutcome:
    executed: bool
    ran_ok: bool
    reason: str
    detail: str
    observation_count: int
    exit_code: int
    argv_sha256: str
    image_reference: str


def _count_json_lines(text: str) -> int:
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            n += 1
    return n


def run_recon_smoke(
    job: ReconDiscoveryJob, range_: InternalRange, *, timeout_seconds: int = 90
) -> ReconSmokeOutcome:
    """Execute one bounded recon job in its pinned container; classify the honest outcome."""

    raw = run_tool(
        image_reference=job.image_ref,
        argv=job.argv,
        network=range_.network,
        label=range_.label,
        output_limit_bytes=job.max_output_bytes,
        timeout_seconds=timeout_seconds,
    )
    result = raw.result
    combined_lower = (raw.stdout + "\n" + raw.stderr).lower()
    observations = _count_json_lines(raw.stdout)
    if result.timed_out:
        return ReconSmokeOutcome(
            True, False, "CONTAINER_TIMEOUT", f"exceeded {timeout_seconds}s", 0,
            result.exit_code, result.argv_sha256, result.image_reference,
        )
    if "flag provided but not defined" in combined_lower or "unknown flag" in combined_lower:
        bad = ""
        for line in raw.stderr.splitlines():
            if "flag provided but not defined" in line.lower() or "unknown flag" in line.lower():
                bad = line.strip()[:120]
                break
        return ReconSmokeOutcome(
            True, False, "CONTAINER_ARGV_INCOMPATIBLE", bad, observations,
            result.exit_code, result.argv_sha256, result.image_reference,
        )
    if result.exit_code != 0 and observations == 0:
        return ReconSmokeOutcome(
            True, False, "TOOL_ERROR", f"exit={result.exit_code}", observations,
            result.exit_code, result.argv_sha256, result.image_reference,
        )
    return ReconSmokeOutcome(
        True, True, "RAN_OK", f"exit={result.exit_code}; observations={observations}",
        observations, result.exit_code, result.argv_sha256, result.image_reference,
    )
