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
from aegis.container_acceptance.sqlmap_worker import SqlmapContainerWorker
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
            profile_id="sqlmap_sqli_confirm_bounded_v1",
            target_ref="range-shop",
            route="/api/products",
            parameter="q",
        )
        job = build_sqlmap_job(plan, image=self._sqlmap_image)
        worker = SqlmapContainerWorker(job, range_)
        evidence, run_result, _types = worker.run()

        # Independent verifier: normalized worker evidence + controller ground truth, zero SQLi.
        verifier = RangeVerifier()
        conclusion = verifier.adjudicate_sqli_offline(
            job.application_id,
            evidence.as_verifier_input(),
            seeded_total=ground_truth.seeded_total,
            control_selective_count=ground_truth.control_selective_count,
        )
        verifier_sent = bool(conclusion.facts.get("verifier_generated_injection_traffic", True))
        normalized_sha = hashlib.sha256(
            json.dumps(evidence.model_dump(), sort_keys=True).encode()
        ).hexdigest()
        return SqlmapArmResult(
            arm=arm,
            run_label=range_.label,
            job_id=job.job_id,
            argv_sha256=run_result.argv_sha256,
            image_reference=run_result.image_reference,
            digest_pinned=job.digest_pinned,
            sqlmap_run=run_result,
            total_http_requests=0
            if not evidence.sanitized_note
            else _requests_from_note(evidence.sanitized_note),
            tool_reported_injectable=evidence.tool_reported_injectable,
            control_count=evidence.control.result_count,
            boolean_true_count=evidence.boolean_true.result_count,
            boolean_false_count=evidence.boolean_false.result_count,
            verifier_status=conclusion.status.value,
            verifier_sent_injection_traffic=verifier_sent,
            normalized_evidence_sha256=normalized_sha,
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
        sqlmap_pass = (
            vuln is not None
            and patched is not None
            and vuln.verifier_status == "CONFIRMED"
            and patched.verifier_status == "PASS"
            and not vuln.verifier_sent_injection_traffic
            and not patched.verifier_sent_injection_traffic
            and vuln.digest_pinned
            and patched.digest_pinned
        )
        sqlmap_record = ToolAcceptanceRecord(
            capability_id=SQLMAP_CAPABILITY_ID,
            tool="sqlmap",
            status=ToolAcceptanceStatus.CONTAINERIZED_SYNTHETIC_PASS
            if sqlmap_pass
            else ToolAcceptanceStatus.NOT_EVALUATED,
            evidence_category=EvidenceCategory.CONTAINERIZED_SYNTHETIC_PASS
            if sqlmap_pass
            else EvidenceCategory.NOT_EVALUATED,
            image_reference=vuln.image_reference if vuln else "",
            digest_pinned=bool(vuln and vuln.digest_pinned),
            reason="vulnerable=CONFIRMED patched=PASS"
            if sqlmap_pass
            else "arm verdicts incomplete",
        )
        tools = [sqlmap_record, *recon]
        return {
            "phase": "2.8",
            "evidence_type": "CONTAINERIZED_SYNTHETIC",
            "run_label": label,
            "cleanup_clean": cleanup.clean,
            "cleanup": cleanup.model_dump(),
            "sqlmap_pair": {
                "vulnerable": vuln.model_dump() if vuln else None,
                "patched": patched.model_dump() if patched else None,
                "containerized_synthetic_pass": sqlmap_pass,
            },
            "tools": [t.model_dump() for t in tools],
            "live_provider_status": EvidenceCategory.NOT_EVALUATED.value,
            "not_evaluated": [
                t.capability_id
                for t in tools
                if t.status is ToolAcceptanceStatus.NOT_EVALUATED
            ],
        }


def _requests_from_note(note: str) -> int:
    marker = "requests="
    if marker not in note:
        return 0
    tail = note.split(marker, 1)[1]
    digits = ""
    for ch in tail:
        if ch.isdigit():
            digits += ch
        else:
            break
    return int(digits) if digits else 0
