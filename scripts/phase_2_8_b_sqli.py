"""Phase 2.8-B — OFFLINE bounded synthetic SQLi scenario (no container, no live SQLMap).

Drives the full chain the capability is built for, entirely offline:

    RECON_AGENT candidate discovery (2.8-A recon pack)
      -> persisted Recon->Injection delegation (real DelegationQueue)
      -> real INJECTION_AGENT job pickup (resolve delegation by address)
      -> controller-rendered SQLMap execution (deterministic argv; offline worker DOUBLE issues the
         boolean-based differential probes SQLMap would drive, against the in-process shop app)
      -> normalized worker evidence (never SQLMap's own verdict)
      -> independent verifier adjudicates worker evidence + controller ground truth (no injection
         traffic of its own): vulnerable -> CONFIRMED, patched -> PASS
      -> cleanup (range reset) + artifact manifest.

The container/live SQLMap binary is NOT run here (container_sqlmap_status / live_sqlmap_status
= NOT_EVALUATED); the offline worker double reproduces the exact result-set differential a boolean
-based SQLMap run surfaces, so the *verifier* logic is exercised on real HTTP evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any

import httpx

from aegis.multi_agent.delegation import DelegationQueue, EnqueuedDelegation
from aegis.multi_agent.recon_capabilities import (
    NormalizedReconObservation,
    ReconObservationKind,
    build_recon_to_injection_delegation,
)
from aegis.multi_agent.sqlmap_capability import (
    SQLMAP_CAPABILITY_ID,
    SqlmapInjectionJob,
    SqlmapPlan,
    SqlmapResultSlot,
    SqlmapWorkerEvidence,
    build_manifest,
    build_sqlmap_job,
)
from aegis_range import shop
from aegis_range.runtime import Mode
from aegis_range.verifier import RangeVerifier

SEEDED_TOTAL = 3
CONTROL_SELECTIVE_COUNT = 1
_TRUE_PAYLOAD = "%' OR 1=1 --"
_FALSE_PAYLOAD = "%' AND 1=2 --"


async def _count(client: httpx.AsyncClient, q: str) -> tuple[int, int]:
    response = await client.get("/api/products", params={"q": q})
    try:
        rows = response.json()["products"]
    except (ValueError, KeyError, TypeError):
        rows = []
    return response.status_code, len(rows)


class OfflineSqlmapWorker:
    """The controller-owned worker DOUBLE for the offline pass.

    It does NOT run the SQLMap binary; it issues the same benign control query and boolean-TRUE /
    boolean-FALSE probes a boolean-based SQLMap run would drive, against the in-process app, and
    returns normalized evidence. SQLMap's own "injectable" claim is recorded but is not a verdict.
    """

    def __init__(self, app: Any) -> None:
        self._app = app

    async def run(self, job: SqlmapInjectionJob, *, mode: Mode) -> SqlmapWorkerEvidence:
        # Controller-owned range mutation: select the scenario mode on the management plane.
        shop.runtime.select(shop.SQL_SCENARIO, mode)
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(
            base_url=job.authorized_origin, transport=transport, timeout=3
        ) as client:
            control_status, control_count = await _count(client, "Notebook")
            true_status, true_count = await _count(client, _TRUE_PAYLOAD)
            false_status, false_count = await _count(client, _FALSE_PAYLOAD)
        return SqlmapWorkerEvidence(
            job_id=job.job_id,
            parameter=job.parameter,
            control=SqlmapResultSlot(status_code=control_status, result_count=control_count),
            boolean_true=SqlmapResultSlot(status_code=true_status, result_count=true_count),
            boolean_false=SqlmapResultSlot(status_code=false_status, result_count=false_count),
            # What SQLMap itself would infer — recorded for audit, NOT a verdict input.
            tool_reported_injectable=true_count != false_count,
            sanitized_note="boolean-based differential probe (offline worker double)",
        )


async def run_scenario(mode: Mode) -> dict[str, Any]:
    """Run the full recon->injection->SQLMap->verifier->cleanup chain for one range mode."""

    with tempfile.TemporaryDirectory() as scratch:
        queue = DelegationQueue(str(Path(scratch) / "delg.db"))
        queue.initialize()

        # 1) RECON candidate discovery -> persisted Recon->Injection delegation (SQLMap target).
        candidate = NormalizedReconObservation(
            kind=ReconObservationKind.PARAMETER_CANDIDATE,
            route="/api/products", parameter="q", injectable_candidate=True,
        )
        delegation: EnqueuedDelegation = build_recon_to_injection_delegation(
            target_ref="range-shop",
            candidate=candidate,
            source_evidence_sha256="c" * 64,
            injection_capability_id=SQLMAP_CAPABILITY_ID,
            delegation_id="delg-" + "5" * 16,
        )
        address = queue.enqueue(delegation)

        # 2) INJECTION_AGENT job pickup: resolve the delegation by address; the controller then
        #    the bounded SQLMap job from the (target, route, parameter) references it carries.
        resolved = queue.resolve(address)
        assert resolved is not None
        plan = SqlmapPlan(
            capability_id=SQLMAP_CAPABILITY_ID,
            profile_id="sqlmap_sqli_detect_v1",
            target_ref=resolved.target_ref,
            route=resolved.route,
            parameter=resolved.parameter,
        )
        job = build_sqlmap_job(plan)

        # 3) Controller-rendered SQLMap execution (offline worker double) -> normalized evidence.
        worker = OfflineSqlmapWorker(shop.app)
        evidence = await worker.run(job, mode=mode)

        # 4) Independent verifier: adjudicate WORKER evidence + controller ground truth; no traffic.
        verifier = RangeVerifier()
        result = verifier.adjudicate_sqli_offline(
            job.application_id,
            evidence.as_verifier_input(),
            seeded_total=SEEDED_TOTAL,
            control_selective_count=CONTROL_SELECTIVE_COUNT,
        )

        # 5) Cleanup + manifest.
        shop.runtime.reset()
        manifest = build_manifest(
            job, output_bytes=len(result.evidence_sha256), output_truncated=False,
            canary_read_performed=False, cleanup_complete=True,
        )

    return {
        "mode": mode.value,
        "delegation_address": address,
        "injection_job_id": job.job_id,
        "argv_shell_free": all(
            tok not in {";", "|", "&", "`", ">", "<"} for tok in "".join(job.argv)
        ),
        "verifier_status": result.status.value,
        "verifier_generated_injection_traffic": bool(
            result.facts.get("verifier_generated_injection_traffic", True)
        ),
        "tool_reported_injectable": evidence.tool_reported_injectable,
        "container_status": manifest.container_status,
        "cleanup_complete": manifest.cleanup_complete,
        "digest_pinned": manifest.digest_pinned,
        "manifest_argv_digest": manifest.argv_digest,
    }


def run_offline() -> dict[str, Any]:
    vulnerable = asyncio.run(run_scenario(Mode.VULNERABLE))
    patched = asyncio.run(run_scenario(Mode.PATCHED))
    checks: dict[str, bool] = {
        "recon_to_injection_delegation_persisted": vulnerable["delegation_address"].startswith(
            "agentqueue://INJECTION_AGENT/"
        ),
        "injection_job_rendered_shell_free": vulnerable["argv_shell_free"]
        and patched["argv_shell_free"],
        "vulnerable_confirmed": vulnerable["verifier_status"] == "CONFIRMED",
        "patched_pass": patched["verifier_status"] == "PASS",
        "verifier_sent_no_injection_traffic": (
            not vulnerable["verifier_generated_injection_traffic"]
            and not patched["verifier_generated_injection_traffic"]
        ),
        "cleanup_complete": vulnerable["cleanup_complete"] and patched["cleanup_complete"],
        "provenance_recorded_container_unpinned": vulnerable["digest_pinned"] is False,
    }
    passed = all(checks.values())
    verdict = {
        "phase": "2.8-B",
        "sqlmap_capability_status": "OFFLINE_PASS" if passed else "OFFLINE_FAIL",
        "container_sqlmap_status": "NOT_EVALUATED",
        "live_sqlmap_status": "NOT_EVALUATED",
        "evidence_type": "OFFLINE_SCENARIO",
        "checks": checks,
        "vulnerable": vulnerable,
        "patched": patched,
        "passed": passed,
    }
    return {"verdict": verdict}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_offline()
    print(json.dumps(result if args.json else result["verdict"], indent=2, sort_keys=True))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
