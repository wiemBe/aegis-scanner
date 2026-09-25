"""Phase 2.8 containerized synthetic capability acceptance controller.

Stands up ONE internal, no-egress synthetic range and drives, against it:

* the SQLMap vulnerable/patched pair — a real containerized, controller-rendered, digest-pinned
  SQLMap run per arm, normalized worker evidence, and the independent verifier's adjudication
  against controller ground truth (no substitute injection traffic);
* one bounded controller-rendered smoke per recon capability that has a suitable fixture and an
  acquirable, digest-pinned tool image; every other recon capability stays NOT_EVALUATED.

It then tears the range down and proves zero stack/volume/network leftovers. It calls no AI
provider, loads no gateway secret, and never widens the offline authority model: a tool's own claim
is audit-only; only the verifier promotes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from aegis.container_acceptance.contracts import (
    ContainerAcceptanceError,
    EvidenceCategory,
    GroundTruth,
    SqlmapArmResult,
    ToolAcceptanceRecord,
    ToolAcceptanceStatus,
    assert_arms_fresh,
)
from aegis.container_acceptance.docker_cli import daemon_available, docker, image_id
from aegis.container_acceptance.images import PINNED_IMAGES, PinnedImage, resolve_local_build
from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.recon_runner import run_recon_smoke
from aegis.container_acceptance.sqlmap_worker import SQLMAP_SEED_VALUE, SqlmapContainerWorker
from aegis.multi_agent.recon_capabilities import (
    ReconDiscoveryPlan,
    ToolProvenance,
    build_discovery_job,
)
from aegis.multi_agent.sqlmap_capability import (
    SQLMAP_CAPABILITY_ID,
    SqlmapPlan,
    SqlmapToolImage,
    assert_container_pinned,
    build_sqlmap_job,
)
from aegis_range.verifier import RangeVerifier

# The shop's fixed synthetic ground truth (controller-owned, not read back from the tool).
SEEDED_TOTAL = 3
CONTROL_SELECTIVE_COUNT = 1

RANGE_TAG = "aegis-range-phase28:2.8.0"
SQLMAP_TAG = "aegis-sqlmap-runner:2.8.0"

# Recon capabilities and whether the synthetic range offers an honest fixture for each. DNS/TLS have
# no honest fixture (the shop is plain HTTP with no DNS zone), so they are never run.
_RECON_PLAN = [
    ("aegis.recon.http_probe", "http_probe_discovery_v1", "httpx", "httpx", True),
    ("aegis.recon.web_crawl", "web_crawl_bounded_v1", "katana", "katana", True),
    ("aegis.recon.api_http_probe", "api_http_probe_v1", "httpx", "httpx", True),
    ("aegis.recon.content_discovery", "content_discovery_bounded_v1", "ffuf", "", False),
    ("aegis.recon.dns_discovery", "dns_discovery_bounded_v1", "dnsx", "", False),
    ("aegis.recon.tls_inspect", "tls_inspect_v1", "tlsx", "", False),
]
_NO_FIXTURE_REASON = {
    "aegis.recon.content_discovery": "IMAGE_NOT_ACQUIRABLE:no ffuf image on the registry",
    "aegis.recon.dns_discovery": "NO_DNS_FIXTURE:synthetic range has no DNS zone",
    "aegis.recon.tls_inspect": "NO_TLS_FIXTURE:shop serves plain HTTP, no TLS endpoint",
}


@dataclass
class Phase28Controller:
    build_missing: bool = True
    _sqlmap_image: SqlmapToolImage | None = field(default=None, init=False)
    _range_ref: str = field(default="", init=False)
    _recon_images: dict[str, ToolProvenance] = field(default_factory=dict, init=False)

    # ---- image supply chain -------------------------------------------------------------------- #

    def _ensure_local_image(self, tag: str, dockerfile: str, context: str) -> str:
        current = image_id(tag)
        if current is None and self.build_missing:
            build = docker("build", "-t", tag, "-f", dockerfile, context, timeout=600)
            if build.returncode != 0:
                raise ContainerAcceptanceError(f"IMAGE_BUILD_FAILED:{tag}:{build.stderr[-160:]}")
            current = image_id(tag)
        if current is None:
            raise ContainerAcceptanceError(f"IMAGE_NOT_AVAILABLE:{tag}")
        return current

    def ensure_images(self) -> None:
        # Range target (local build, egress-free) pinned by its resolved content id.
        range_id = self._ensure_local_image(
            RANGE_TAG, "deploy/range/Dockerfile.phase-2-8", "."
        )
        self._range_ref = resolve_local_build(
            PINNED_IMAGES["range-target"], range_id
        ).run_reference()

        # SQLMap worker (local build) pinned by its resolved content id, wrapped as an operator-
        # reviewed SqlmapToolImage so build_sqlmap_job admits an actual container run.
        sqlmap_id = self._ensure_local_image(
            SQLMAP_TAG, "deploy/sqlmap-runner/Dockerfile", "deploy/sqlmap-runner"
        )
        sqlmap_pin = resolve_local_build(PINNED_IMAGES["sqlmap-runner"], sqlmap_id)
        self._sqlmap_image = SqlmapToolImage(
            tool="sqlmap",
            image=sqlmap_pin.repository,
            tag="2.8.0",
            version="1.10.9",
            image_digest=sqlmap_pin.digest,
            digest_pinned=True,
        )
        assert_container_pinned(self._sqlmap_image)

        # Recon tool images: registry-pinned RepoDigests, only for the ones actually acquired.
        for key in ("httpx", "katana"):
            pinned: PinnedImage = PINNED_IMAGES[key]
            if image_id(f"{pinned.repository}@{pinned.digest}") is None:
                continue  # not present locally -> capability stays NOT_EVALUATED
            self._recon_images[pinned.repository] = ToolProvenance(
                tool=key,
                image=pinned.repository,
                tag=pinned.tool_version.split()[-1],
                version=pinned.tool_version,
                image_digest=pinned.digest,
                digest_pinned=True,
            )

    # ---- SQLMap vulnerable/patched pair -------------------------------------------------------- #

    def _run_arm(self, range_: InternalRange, arm: str) -> SqlmapArmResult:
        assert self._sqlmap_image is not None
        generation = range_.set_arm(arm)
        ground_truth = GroundTruth(
            scenario_id="shop-catalog-query-v1",
            arm=arm,
            control_generation=generation,
            seeded_total=SEEDED_TOTAL,
            control_selective_count=CONTROL_SELECTIVE_COUNT,
            expected_injectable=(arm == "vulnerable"),
        )
        plan = SqlmapPlan(
            capability_id=SQLMAP_CAPABILITY_ID,
            profile_id="sqlmap_sqli_detect_boolean_v1",
            target_ref="range-shop",
            route="/api/products",
            parameter="q",
        )
        job = build_sqlmap_job(
            plan, image=self._sqlmap_image, seed_value=SQLMAP_SEED_VALUE, capture_dir="/out"
        )
        worker = SqlmapContainerWorker(job, range_)
        output = worker.run()
        evidence = output.traffic_evidence

        verifier = RangeVerifier()
        # Functional verdict: adjudicate SQLMap-ORIGINATED differential + controller ground truth.
        functional = verifier.adjudicate_sqli_from_sqlmap_traffic(
            job.application_id,
            evidence.as_verifier_input(),
            seeded_total=ground_truth.seeded_total,
            control_selective_count=ground_truth.control_selective_count,
        )
        # Separate scenario control: the OR-style probe just corroborates the fixture's own state.
        control = verifier.adjudicate_sqli_offline(
            job.application_id,
            {
                "control": {
                    "status_code": output.control_counts["control"][0],
                    "result_count": output.control_counts["control"][1],
                },
                "boolean_true": {
                    "status_code": output.control_counts["boolean_true"][0],
                    "result_count": output.control_counts["boolean_true"][1],
                },
                "boolean_false": {
                    "status_code": output.control_counts["boolean_false"][0],
                    "result_count": output.control_counts["boolean_false"][1],
                },
            },
            seeded_total=ground_truth.seeded_total,
            control_selective_count=ground_truth.control_selective_count,
        )
        verifier_sent = bool(
            functional.facts.get("verifier_generated_injection_traffic", True)
        ) or bool(control.facts.get("verifier_generated_injection_traffic", True))
        normalized_sha = hashlib.sha256(
            json.dumps(evidence.model_dump(), sort_keys=True).encode()
        ).hexdigest()
        return SqlmapArmResult(
            arm=arm,
            run_label=range_.label,
            job_id=job.job_id,
            process_exec_id=evidence.process_exec_id,
            argv_sha256=output.run_result.argv_sha256,
            image_reference=output.run_result.image_reference,
            image_id=job.image_digest,
            digest_pinned=job.digest_pinned,
            sqlmap_run=output.run_result,
            tool_reported_injectable=output.tool_reported_injectable,
            sqlmap_requests_observed=evidence.request_count,
            control_row_count=evidence.control_row_count,
            injected_max_row_count=evidence.injected_max_row_count,
            injected_min_row_count=evidence.injected_min_row_count,
            verifier_status=functional.status.value,
            verifier_sent_injection_traffic=verifier_sent,
            verifier_used_sqlmap_worker_evidence=True,
            normalized_evidence_sha256=normalized_sha,
            control_scenario_status=control.status.value,
            control_probe_is_separate=True,
        )

    # ---- recon smokes -------------------------------------------------------------------------- #

    def _run_recon(self, range_: InternalRange) -> list[ToolAcceptanceRecord]:
        records: list[ToolAcceptanceRecord] = []
        for capability_id, profile_id, tool, repo_key, has_fixture in _RECON_PLAN:
            if not has_fixture:
                records.append(
                    ToolAcceptanceRecord(
                        capability_id=capability_id, tool=tool,
                        status=ToolAcceptanceStatus.NOT_EVALUATED,
                        evidence_category=EvidenceCategory.NOT_EVALUATED,
                        reason=_NO_FIXTURE_REASON[capability_id],
                    )
                )
                continue
            repo = "projectdiscovery/" + repo_key if repo_key in {"httpx", "katana"} else repo_key
            image = self._recon_images.get(repo)
            if image is None:
                records.append(
                    ToolAcceptanceRecord(
                        capability_id=capability_id, tool=tool,
                        status=ToolAcceptanceStatus.NOT_EVALUATED,
                        evidence_category=EvidenceCategory.NOT_EVALUATED,
                        reason="IMAGE_NOT_PRESENT:pinned tool image not pulled",
                    )
                )
                continue
            plan = ReconDiscoveryPlan(
                capability_id=capability_id, profile_id=profile_id, target_ref="range-shop"  # type: ignore[arg-type]
            )
            job = build_discovery_job(plan, image=image)
            outcome = run_recon_smoke(job, range_)
            if outcome.ran_ok:
                records.append(
                    ToolAcceptanceRecord(
                        capability_id=capability_id, tool=tool,
                        status=ToolAcceptanceStatus.CONTAINERIZED_SYNTHETIC_PASS,
                        evidence_category=EvidenceCategory.CONTAINERIZED_SYNTHETIC_PASS,
                        image_reference=outcome.image_reference, digest_pinned=True,
                        reason=outcome.reason, detail=outcome.detail,
                    )
                )
            else:
                records.append(
                    ToolAcceptanceRecord(
                        capability_id=capability_id, tool=tool,
                        status=ToolAcceptanceStatus.NOT_EVALUATED,
                        evidence_category=EvidenceCategory.NOT_EVALUATED,
                        image_reference=outcome.image_reference, digest_pinned=True,
                        reason=outcome.reason, detail=outcome.detail,
                    )
                )
        return records

    # ---- top-level run ------------------------------------------------------------------------- #

    def run(self) -> dict[str, Any]:
        if not daemon_available():
            raise ContainerAcceptanceError("DOCKER_DAEMON_UNAVAILABLE")
        self.ensure_images()
        range_ = InternalRange(range_image_ref=self._range_ref)
        arms: list[SqlmapArmResult] = []
        recon: list[ToolAcceptanceRecord] = []
        egress_proof = ""
        was_internal = False
        try:
            range_.create()
            was_internal = range_.network_is_internal()
            egress_proof = range_.egress_blocked_proof()
            if not range_.benign_health():
                raise ContainerAcceptanceError("TARGET_BENIGN_HEALTH_FAILED")
            for arm in ("vulnerable", "patched"):
                arms.append(self._run_arm(range_, arm))
            recon = self._run_recon(range_)
        finally:
            range_.cleanup()
        cleanup = range_.leftover_proof(was_internal=was_internal, egress_proof=egress_proof)
        return self._assemble(arms, recon, cleanup, range_.label)

    def _assemble(
        self,
        arms: list[SqlmapArmResult],
        recon: list[ToolAcceptanceRecord],
        cleanup: Any,
        label: str,
    ) -> dict[str, Any]:
        # Freshness: every arm's evidence must be bound to this run's nonce (no stale reuse).
        assert_arms_fresh([a.run_label for a in arms], label)
        by_arm = {a.arm: a for a in arms}
        vuln = by_arm.get("vulnerable")
        patched = by_arm.get("patched")
        checks = self._sqlmap_checks(vuln, patched)
        # Functional detection is proven only from SQLMap-originated evidence on both arms.
        functional_proven = (
            checks["vulnerable_sqlmap_functional_detection_proven"]
            and checks["patched_sqlmap_false_positive_absent"]
            and checks["sqlmap_process_executed"]
            and checks["sqlmap_requests_observed"]
            and checks["sqlmap_request_evidence_correlated"]
            and checks["controller_controls_separate_from_sqlmap_evidence"]
            and checks["verifier_used_sqlmap_worker_evidence"]
            and checks["verifier_sent_no_injection_traffic"]
            and bool(vuln and patched and vuln.digest_pinned and patched.digest_pinned)
        )
        if functional_proven:
            status = ToolAcceptanceStatus.CONTAINERIZED_SYNTHETIC_PASS
            category = EvidenceCategory.CONTAINERIZED_SYNTHETIC_PASS
            reason = "SQLMap-originated differential: vulnerable CONFIRMED / patched none"
        elif checks["sqlmap_process_executed"]:
            status = ToolAcceptanceStatus.CONTAINER_EXECUTED_INCONCLUSIVE
            category = EvidenceCategory.NOT_EVALUATED
            reason = "SQLMap executed but functional SQLMap-originated detection not proven"
        else:
            status = ToolAcceptanceStatus.NOT_EVALUATED
            category = EvidenceCategory.NOT_EVALUATED
            reason = "SQLMap did not execute"
        sqlmap_record = ToolAcceptanceRecord(
            capability_id=SQLMAP_CAPABILITY_ID,
            tool="sqlmap",
            status=status,
            evidence_category=category,
            image_reference=vuln.image_reference if vuln else "",
            digest_pinned=bool(vuln and vuln.digest_pinned),
            reason=reason,
        )
        tools = [sqlmap_record, *recon]
        return {
            "phase": "2.8",
            "evidence_type": "CONTAINERIZED_SYNTHETIC",
            "run_label": label,
            "cleanup_clean": cleanup.clean,
            "cleanup": cleanup.model_dump(),
            "sqlmap": {
                "status": status.value,
                "synthetic_sqli_scenario_confirmed": checks["synthetic_sqli_scenario_confirmed"],
                "sqlmap_functional_detection_proven": functional_proven,
                "checks": checks,
                "image_id": vuln.image_id if vuln else "",
                "vulnerable": vuln.model_dump() if vuln else None,
                "patched": patched.model_dump() if patched else None,
            },
            "tools": [t.model_dump() for t in tools],
            "live_provider_status": EvidenceCategory.NOT_EVALUATED.value,
            "not_evaluated": [
                t.capability_id
                for t in tools
                if t.status is ToolAcceptanceStatus.NOT_EVALUATED
            ],
        }

    @staticmethod
    def _sqlmap_checks(
        vuln: SqlmapArmResult | None, patched: SqlmapArmResult | None
    ) -> dict[str, bool]:
        both = [a for a in (vuln, patched) if a is not None]
        executed = len(both) == 2 and all(a.sqlmap_run.exit_code is not None for a in both)
        requests_observed = bool(both) and all(a.sqlmap_requests_observed > 0 for a in both)
        correlated = bool(both) and all(
            a.process_exec_id
            and a.image_id.startswith("sha256:")
            and a.normalized_evidence_sha256
            for a in both
        )
        controls_separate = bool(both) and all(a.control_probe_is_separate for a in both)
        used_sqlmap_evidence = bool(both) and all(
            a.verifier_used_sqlmap_worker_evidence for a in both
        )
        no_injection_traffic = bool(both) and all(
            not a.verifier_sent_injection_traffic for a in both
        )
        # The scenario itself (via the SEPARATE OR-style control probe) is genuinely vuln/patched.
        scenario_confirmed = (
            vuln is not None
            and patched is not None
            and vuln.control_scenario_status == "CONFIRMED"
            and patched.control_scenario_status == "PASS"
        )
        return {
            "sqlmap_process_executed": executed,
            "sqlmap_requests_observed": requests_observed,
            "sqlmap_request_evidence_correlated": correlated,
            "controller_controls_separate_from_sqlmap_evidence": controls_separate,
            "verifier_used_sqlmap_worker_evidence": used_sqlmap_evidence,
            "verifier_sent_no_injection_traffic": no_injection_traffic,
            "vulnerable_sqlmap_functional_detection_proven": vuln is not None
            and vuln.verifier_status == "CONFIRMED",
            "patched_sqlmap_false_positive_absent": patched is not None
            and patched.verifier_status != "CONFIRMED",
            "synthetic_sqli_scenario_confirmed": scenario_confirmed,
        }
