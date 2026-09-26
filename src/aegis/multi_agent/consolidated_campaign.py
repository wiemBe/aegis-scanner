"""Phase 2.9 — consolidated end-to-end synthetic acceptance campaign.

ONE continuous, bounded, controller-governed campaign that composes the already-accepted Phase 2.3
(remediation/retest), Phase 2.6 (REPORT_AGENT reporting) and Phase 2.7 (assessment lifecycle)
capabilities over the single authorized synthetic ``aegis-ops`` detection-control-bypass slice:

    fresh authorized assessment -> Lead delegation -> Recon plan -> real worker execution
    -> independent verifier CONFIRMED -> AI remediation recommendation (non-authoritative)
    -> controller-authorized registered remediation + immutable patch receipt
    -> fresh Recon retest -> independent verifier PASS -> real REPORT_AGENT job
    -> controller-authoritative report -> cleanup/reset -> final lifecycle verdict + manifest.

Reuse, not rebuild. The lifecycle is driven through the ACTUAL Phase 2.7 controller/adapters
(:class:`aegis.multi_agent.lifecycle_adapters.OpsDetectionControlLifecycle`), which invoke the real
persisted Lead/agent queue, the real independent verifier, the real remediation controller + patch
receipt, the real Phase 2.6 report job path + assembler and the real cleanup ledger. Phase 2.9 adds:

* a **deterministic gateway double at the model/provider boundary** (:class:`Phase29ModelDouble`) so
  the five planned provider calls (Lead delegation, initial Recon plan, remediation recommendation,
  retest plan, report draft) run provider-free while the model output stays strictly typed and
  non-authoritative;
* a **fail-closed campaign provider budget** (5 calls / 15,000 tokens) that reserves the worst case
  before every call (:mod:`aegis.multi_agent.live_safety`);
* a swappable **range backend** — the in-process network double, or a REAL ``aegis_range.ops``
  container on an internal no-egress network (:class:`ContainerOpsRange`) — behind the same
  controller-owned surface, so a provider-free containerized dry run exercises real containers, real
  queue/storage, the real worker sequence, the real verifier and the real remediation/report path.

The model may only delegate to an allowed role, select registered profile ids, interpret sanitized
observations, recommend one registered remediation, plan the retest and draft report prose. It never
controls authorization, target, mode, lease, budget, the probe sequence, ground truth, confirmation,
severity, the patch, retest eligibility, PASS/FAIL, lifecycle state or cleanup — those stay
controller/verifier owned. No provider is called and no live claim is made from a deterministic
double.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable
from uuid import uuid4

from aegis.container_acceptance.contracts import CleanupProof
from aegis.container_acceptance.docker_cli import (
    DockerQueryError,
    DockerUnavailable,
    count_by_label,
    docker,
    image_id,
    name_present,
)
from aegis.multi_agent.adversary_simulation import AdvAgentJob
from aegis.multi_agent.contracts import (
    AdversaryRemediationRecommendationOutput,
    AdversarySimulationDelegationOutput,
    AdversarySimulationPlanOutput,
    AgentRole,
    AssessmentReportDraftOutput,
    ModelResult,
    ModelUsage,
)
from aegis.multi_agent.lifecycle import (
    LifecycleStage,
    StageContext,
    StageOutcome,
    StageUsageDelta,
)
from aegis.multi_agent.lifecycle_adapters import OpsDetectionControlLifecycle, _id16
from aegis.multi_agent.live_safety import (
    BudgetStop,
    CampaignProviderBudget,
    LiveBudgetPolicy,
    LiveExecutionGuard,
    LiveExecutionRequest,
    estimate_input_tokens,
)
from aegis.multi_agent.report_agent import (
    AssessmentReport,
    ReportAgentJob,
    SourceCleanup,
    SourceUsage,
    assemble_report,
    assert_report_projection_clean,
    build_report_request_projection,
    projection_sha256,
    write_report_bundle,
)

CANONICAL_MODEL = "deepseek-v4-pro"
MAX_PROVIDER_CALLS = 5
MAX_TOTAL_TOKENS = 15_000
PER_CALL_OUTPUT_CEILING = 2048
RUN_EPOCH = 29  # distinct from the Phase 2.7 integration epoch (7): a fresh Phase 2.9 lineage.

TARGET_REF = "range-ops"
APPLICATION_ID = "aegis-ops"
SCENARIO_ID = "ops-detection-control-bypass-v1"
CAPABILITY_ID = "aegis.ops.detection_control_probe"
PROBE_PROFILE_ID = "http_detection_control_probe_v1"
REMEDIATION_PROFILE_ID = "enforce_uniform_detection_control_v1"
TECHNIQUE_CLASS = "HTTP_DETECTION_CONTROL_BYPASS"

RANGE_IMAGE_TAG = "aegis-range-phase29:2.9.0"
RANGE_DOCKERFILE = "deploy/range/Dockerfile.phase-2-9"
DETECTION_SIGNATURE_HEADER = "x-ops-signature"
DETECTION_BASELINE_SIGNATURE = "ops-scan-baseline-v1"
DETECTION_ALTERNATE_SIGNATURE = "ops-scan-alternate-v1"  # noqa: S105 - inert range probe variant
OPS_PORT = 8600
OPS_ALIAS = "aegis-ops"

NOT_EVALUATED = "NOT_EVALUATED"

# The controller-owned cleanup obligations, in the order they are compensated. Shared by the cleanup
# ledger run and the report so the FINAL report's obligation list is exactly what actually ran.
CLEANUP_OBLIGATIONS = (
    "RESET_SYNTHETIC_TARGET_TO_BASELINE",
    "ROTATE_SENTINEL",
    "INVALIDATE_PATCH_RECEIPT",
    "REVOKE_REFERENCES",
    "TEARDOWN_RANGE",
)

_HARDENING = (
    "--user", "65532:65532", "--read-only",
    "--tmpfs", "/tmp:size=32m",  # noqa: S108 - docker tmpfs mount spec, not a host temp path
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--pids-limit", "128", "--memory", "512m",
)

RangeBackendKind = Literal["IN_PROCESS_DOUBLE", "CONTAINERIZED_SYNTHETIC"]


def derive_source_cleanup(
    *,
    cleanup_entries: list[tuple[str, bool]],
    range_cleanup: dict[str, Any],
    containerized: bool,
) -> SourceCleanup:
    """Derive the report's cleanup facts from the ACTUAL controller ledger + range snapshot.

    Truthful and fail-closed:

    * Any uncompensated controller obligation is a visible failure and ``succeeded`` is ``False``.
    * For a containerized range, a non-``PASS`` snapshot is a failure: a ``COLLECT_FAILED`` (the
      leftover query itself could not be established) makes ``succeeded`` ``"UNKNOWN"`` — it can
      NEVER become success — while a ``CLEANUP_FAILED`` / ``NOT_STARTED`` / any other status is
      ``False``.
    * Only a fully-compensated ledger AND (for a container) a ``PASS`` snapshot yields ``True``.

    ``cleanup_entries`` are ``(obligation, compensated)`` pairs read from the controller ledger; no
    value is invented and nothing here can flip a failure into success.
    """

    obligations = tuple(obligation for obligation, _ in cleanup_entries)
    failures = [obligation for obligation, compensated in cleanup_entries if not compensated]
    ledger_ok = bool(cleanup_entries) and not failures

    unknown = False
    status = range_cleanup.get("status")
    if containerized and status != "PASS":
        if status == "COLLECT_FAILED":
            unknown = True
            failures.append("RANGE_LEFTOVER_QUERY_UNKNOWN")
        else:
            failures.append(f"RANGE_CLEANUP_{status}")

    succeeded: bool | Literal["UNKNOWN"]
    if not ledger_ok or (containerized and status not in ("PASS", "COLLECT_FAILED")):
        succeeded = False
    elif unknown:
        succeeded = "UNKNOWN"
    else:
        succeeded = True
    return SourceCleanup(succeeded=succeeded, obligations=obligations, failures=tuple(failures))


@runtime_checkable
class ModelBoundary(Protocol):
    """The synchronous model-boundary surface the campaign drives.

    Both the deterministic :class:`Phase29ModelDouble` (dry run) and the isolated live gateway
    adapter (armed ``--execute-live``) satisfy it. The campaign reads ``name`` / ``reported_models``
    / ``attempts`` when building the record and never depends on which implementation is bound.
    """

    name: str
    reported_models: list[str]
    attempts: list[dict[str, Any]]

    def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        *,
        max_output_tokens: int | None = None,
    ) -> ModelResult: ...


# --------------------------------------------------------------------------- #
# Deterministic gateway double at the model/provider boundary.
# --------------------------------------------------------------------------- #


class Phase29ModelDouble:
    """A deterministic double for the isolated model gateway, used ONLY at the provider boundary.

    It emits the same strict, mode-blind, non-authoritative structured output a live
    ``deepseek-v4-pro`` adapter would for the five planned campaign tasks, reports the exact model
    identity, and records approximate usage — without any network or provider call. It is an
    acceptance double, never evidence of live-model behaviour; every attempt is labelled with the
    ``DETERMINISTIC_GATEWAY_DOUBLE`` provenance so no live claim can be derived from it.
    """

    name = "DETERMINISTIC_GATEWAY_DOUBLE"

    def __init__(self) -> None:
        self.reported_models: list[str] = []
        self.attempts: list[dict[str, Any]] = []

    def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        *,
        max_output_tokens: int | None = None,
    ) -> ModelResult:
        payload = self._payload(role, task_type, context)
        output = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        usage = ModelUsage(
            input_tokens=max(1, len(json.dumps(context, sort_keys=True)) // 4),
            output_tokens=max(1, len(output) // 4),
        )
        self.reported_models.append(CANONICAL_MODEL)
        self.attempts.append(
            {
                "role": role.value,
                "task_type": task_type,
                "reported_model": CANONICAL_MODEL,
                "provenance": self.name,
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "total_tokens": usage.input_tokens + usage.output_tokens,
            }
        )
        return ModelResult(payload_json=output, usage=usage)

    @staticmethod
    def _payload(role: AgentRole, task_type: str, context: dict[str, Any]) -> dict[str, Any]:
        if task_type == "DELEGATE_ADVERSARY_SIMULATION":
            return {
                "to_agent": "RECON_AGENT",
                "finding_domain": "ADVERSARY_SIMULATION",
                "capability_id": CAPABILITY_ID,
                "target_ref": TARGET_REF,
                "technique_class": TECHNIQUE_CLASS,
                "rationale": (
                    "Delegate the bounded detection-control-bypass simulation to the recon agent."
                ),
                "unconfirmed": True,
            }
        if task_type == "PLAN_ADVERSARY_SIMULATION":
            return {
                "finding_domain": "ADVERSARY_SIMULATION",
                "capability_id": CAPABILITY_ID,
                "target_ref": TARGET_REF,
                "technique_class": TECHNIQUE_CLASS,
                "probe": {
                    "probe_profile_id": PROBE_PROFILE_ID,
                    "requested_probe_variants": 2,
                    "concurrency": 1,
                },
                "rationale": (
                    "Select the registered probe profile; the controller renders the sequence."
                ),
                "unconfirmed": True,
            }
        if task_type == "RECOMMEND_ADVERSARY_REMEDIATION":
            return {
                "summary": (
                    "The alternate request variant bypassed the synthetic detection control and "
                    "reached the protected operation on the sanitized projection."
                ),
                "finding_domain": "ADVERSARY_SIMULATION",
                "salient_observation_kinds": [
                    "DETECTION_PROBE_RESPONSE",
                    "PROTECTED_SENTINEL_REACHED",
                ],
                "technique_hypothesis": TECHNIQUE_CLASS,
                "recommended_remediation_profile_id": REMEDIATION_PROFILE_ID,
                "remediation_authoritative": False,
                "rationale": (
                    "Recommend uniform detection-control enforcement; the controller re-selects "
                    "and applies the registered profile."
                ),
                "unconfirmed": True,
            }
        if task_type == "GENERATE_ASSESSMENT_REPORT":
            finding_id = str(context.get("finding_id", ""))
            return {
                "executive_summary": (
                    "A bounded authorized assessment of the synthetic operations surface confirmed "
                    "one detection-control bypass, which was remediated and passed a fresh retest."
                ),
                "methodology_and_limitations": (
                    "Controller-rendered probe profile over one authorized synthetic scenario; the "
                    "independent verifier owns confirmation and PASS. Scope is one detection "
                    "control slice, not broad coverage."
                ),
                "finding_remediations": [
                    {
                        "finding_id": finding_id,
                        "remediation_text": (
                            "Enforce the detection control uniformly across request variants so "
                            "the alternate signature is recognized and denied like the baseline."
                        ),
                    }
                ],
                "chain_explanations": [],
                "readability_notes": "Structured for an operations reviewer.",
                "unconfirmed": True,
                "authoritative": False,
            }
        raise ValueError(f"PHASE_2_9_DOUBLE_TASK_UNSUPPORTED:{task_type}")


# --------------------------------------------------------------------------- #
# Real-container range backend for the ops detection-control surface (no egress).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ResourceRemoval:
    """The observed outcome of removing ONE labelled docker resource during teardown.

    ``ok`` is truthful: a resource counts as gone only when *we* removed it (``docker rm`` rc 0), or
    a subsequent successful strict name query proved it already absent (idempotent re-teardown). A
    non-zero/timed-out removal whose absence query itself failed stays UNKNOWN -> ``ok`` is False.
    """

    kind: str
    name: str
    remove_rc: int
    remove_timed_out: bool
    absence_query_ok: bool
    absent_confirmed: bool
    diagnostic: str = ""

    @property
    def removed(self) -> bool:
        return self.remove_rc == 0 and not self.remove_timed_out

    @property
    def ok(self) -> bool:
        return self.removed or (self.absence_query_ok and self.absent_confirmed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "remove_rc": self.remove_rc,
            "remove_timed_out": self.remove_timed_out,
            "removed": self.removed,
            "absence_query_ok": self.absence_query_ok,
            "absent_confirmed": self.absent_confirmed,
            "ok": self.ok,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True)
class TeardownResult:
    """The observable result of a range teardown attempt (never "invoked == succeeded")."""

    resources: tuple[ResourceRemoval, ...]

    @property
    def ok(self) -> bool:
        # Vacuously true when nothing was ever named; otherwise every resource must be gone.
        return all(r.ok for r in self.resources)

    @property
    def query_ok(self) -> bool:
        return all(r.absence_query_ok for r in self.resources)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "query_ok": self.query_ok,
            "resources": [r.as_dict() for r in self.resources],
        }

    def failure_summary(self) -> str:
        return ";".join(r.diagnostic for r in self.resources if not r.ok)[:180]


@dataclass
class ContainerOpsRange:
    """A REAL ``aegis_range.ops`` container on an internal, no-egress docker network.

    It satisfies the same controller-owned surface as the in-process double
    (:class:`aegis.multi_agent.lifecycle_adapters.OpsRangeSurface`): the worker's baseline+alternate
    probe is a genuine HTTP round-trip from a short-lived helper container attached only to the
    internal network; the raw sentinel is redacted to a SHA-256 digest at the source and never
    leaves as a raw value; the controller-owned patch mutation flips the scenario mode and rotates
    the sentinel through the management plane. The host never routes to the target.
    """

    image_ref: str
    label: str = field(default_factory=lambda: f"aegis.phase29={uuid4().hex[:12]}")
    mode: str = "vulnerable"
    generation: int = 0
    sentinel_digest: str = ""
    probe_requests: int = 0
    _network: str = ""
    _container: str = ""
    _created: bool = False

    def _run_id(self) -> str:
        return self.label.split("=", 1)[1]

    # ------------------------------ lifecycle ------------------------------ #

    def create(self) -> None:
        run_id = self._run_id()
        self._network = f"aegis-p29-{run_id}"
        self._container = f"aegis-p29-ops-{run_id}"
        created = docker(
            "network", "create", "--internal", "--label", self.label, self._network, timeout=30
        )
        if created.returncode != 0:
            raise ContainerRangeError(f"NETWORK_CREATE_FAILED:{created.stderr.strip()[:120]}")
        run = docker(
            "run", "-d", "--name", self._container, "--network", self._network,
            "--network-alias", OPS_ALIAS, "--label", self.label, *_HARDENING, "-e", "HOME=/tmp",
            self.image_ref,
            # 0.0.0.0 binds only inside the container, reachable solely from the internal
            # no-egress network the container is attached to; the host never routes to it.
            "uvicorn", "aegis_range.ops:app", "--host", "0.0.0.0", "--port", str(OPS_PORT),  # noqa: S104
            timeout=60,
        )
        if run.returncode != 0:
            raise ContainerRangeError(f"TARGET_RUN_FAILED:{run.stderr.strip()[:120]}")
        self._created = True
        if not self._wait_healthy():
            raise ContainerRangeError("TARGET_NOT_HEALTHY")
        # Set the controller-owned initial mode (vulnerable) and read the ground-truth sentinel.
        self.generation = self._set_mode("vulnerable")
        self.mode = "vulnerable"
        self.sentinel_digest = self._detection_state()["sentinel_digest"]

    def _helper(self, code: str, *, timeout: float = 30.0) -> tuple[int, str]:
        result = docker(
            "run", "--rm", "--network", self._network, "--label", self.label, *_HARDENING,
            "-e", "HOME=/tmp", self.image_ref, "python", "-c", code, timeout=timeout,
        )
        return result.returncode, result.stdout.strip()

    def _wait_healthy(self) -> bool:
        code = (
            "import urllib.request,sys,time\n"
            "for _ in range(30):\n"
            "  try:\n"
            f"    urllib.request.urlopen('http://{OPS_ALIAS}:{OPS_PORT}/health',timeout=2).read()\n"
            "    print('ok');sys.exit(0)\n"
            "  except Exception:\n"
            "    time.sleep(0.5)\n"
            "sys.exit(1)\n"
        )
        rc, out = self._helper(code, timeout=45)
        return rc == 0 and out.endswith("ok")

    def network_is_internal(self) -> bool:
        result = docker(
            "network", "inspect", self._network, "--format", "{{.Internal}}", timeout=20
        )
        return result.stdout.strip() == "true"

    # --------------------------- control plane ----------------------------- #

    def _set_mode(self, mode: str) -> int:
        code = (
            "import urllib.request,json\n"
            f"body=json.dumps({{'mode':'{mode}'}}).encode()\n"
            f"r=urllib.request.Request('http://{OPS_ALIAS}:{OPS_PORT}/__control/scenarios/"
            f"{SCENARIO_ID}',data=body,headers={{'Content-Type':'application/json'}},method='PUT')\n"
            "print(json.loads(urllib.request.urlopen(r,timeout=4).read())['generation'])\n"
        )
        rc, out = self._helper(code)
        if rc != 0 or not out.isdigit():
            raise ContainerRangeError(f"SET_MODE_FAILED:{mode}:{out[:80]}")
        return int(out)

    def _detection_state(self) -> dict[str, Any]:
        code = (
            "import urllib.request,json\n"
            f"print(urllib.request.urlopen('http://{OPS_ALIAS}:{OPS_PORT}/__control/detection/"
            "state',timeout=4).read().decode())\n"
        )
        rc, out = self._helper(code)
        if rc != 0:
            raise ContainerRangeError(f"DETECTION_STATE_FAILED:{out[:80]}")
        parsed: dict[str, Any] = json.loads(out)
        return parsed

    def _rotate_sentinel(self) -> str:
        code = (
            "import urllib.request,json\n"
            f"r=urllib.request.Request('http://{OPS_ALIAS}:{OPS_PORT}/__control/detection/reset',"
            "method='POST')\n"
            "print(json.loads(urllib.request.urlopen(r,timeout=4).read())"
            "['previous_sentinel_digest'])\n"
        )
        rc, out = self._helper(code)
        if rc != 0:
            raise ContainerRangeError(f"SENTINEL_ROTATE_FAILED:{out[:80]}")
        return out

    # ------------------------------ probing -------------------------------- #

    def probe(self) -> dict[str, dict[str, object]]:
        """The controller-rendered worker sequence: baseline then alternate, over a real HTTP hop.

        The raw sentinel is hashed to a digest inside the helper; only status/blocked/present/digest
        ever leave the helper container.
        """

        code = (
            "import urllib.request,json,hashlib\n"
            f"URL='http://{OPS_ALIAS}:{OPS_PORT}/api/ops/incident-export'\n"
            "def probe(sig):\n"
            f"  req=urllib.request.Request(URL,headers={{'{DETECTION_SIGNATURE_HEADER}':sig}})\n"
            "  try:\n"
            "    resp=urllib.request.urlopen(req,timeout=4)\n"
            "    body=json.loads(resp.read());sent=body.get('sentinel')\n"
            "    dig=hashlib.sha256(sent.encode()).hexdigest() if sent else ''\n"
            "    return {'status_code':resp.status,'blocked':False,"
            "'sentinel_present':bool(sent),'sentinel_digest':dig}\n"
            "  except urllib.error.HTTPError as e:\n"
            "    return {'status_code':e.code,'blocked':e.code==403,"
            "'sentinel_present':False,'sentinel_digest':''}\n"
            f"print(json.dumps({{'baseline':probe('{DETECTION_BASELINE_SIGNATURE}'),"
            f"'alternate':probe('{DETECTION_ALTERNATE_SIGNATURE}')}}))\n"
        )
        rc, out = self._helper(code)
        if rc != 0:
            raise ContainerRangeError(f"PROBE_FAILED:{out[:120]}")
        evidence: dict[str, dict[str, object]] = json.loads(out)
        self.probe_requests += 2
        return evidence

    def state_digest(self) -> str:
        from aegis.multi_agent.remediation import controller_state_digest

        return controller_state_digest(self.mode, self.generation, self.sentinel_digest)

    def apply_patch_mutation(self) -> dict[str, object]:
        pre_mode, pre_gen, pre_sentinel = self.mode, self.generation, self.sentinel_digest
        pre_digest = self.state_digest()
        new_gen = self._set_mode("patched")
        self._rotate_sentinel()
        state = self._detection_state()
        self.mode = "patched"
        self.generation = new_gen
        self.sentinel_digest = state["sentinel_digest"]
        return {
            "previous_mode": pre_mode,
            "resulting_mode": self.mode,
            "pre_state_digest": pre_digest,
            "post_state_digest": self.state_digest(),
            "old_sentinel_epoch": pre_gen,
            "old_sentinel_digest": pre_sentinel,
            "new_sentinel_epoch": self.generation,
            "new_sentinel_digest": self.sentinel_digest,
        }

    # ------------------------------ cleanup -------------------------------- #

    def reset_baseline(self) -> bool:
        """Restore the documented baseline (patched, control complete) and rotate the sentinel."""

        try:
            self.generation = self._set_mode("patched")
            self._rotate_sentinel()
            self.mode = "patched"
            self.sentinel_digest = self._detection_state()["sentinel_digest"]
        except ContainerRangeError:
            return False
        return True

    def egress_blocked_proof(self) -> str:
        code = (
            "import socket\n"
            "s=socket.socket();s.settimeout(3)\n"
            "try:\n"
            "  s.connect(('192.0.2.1',443));print('EGRESS_REACHABLE')\n"
            "except Exception as e:\n"
            "  print('EGRESS_BLOCKED:'+type(e).__name__)\n"
        )
        _rc, out = self._helper(code, timeout=20)
        return out.strip()[:120] or "EGRESS_PROOF_UNAVAILABLE"

    def teardown(self) -> TeardownResult:
        """Remove the container then the network, capturing every return code / timeout.

        Idempotent: a re-teardown of an already-removed resource sees ``docker rm`` return non-zero
        ("No such ...") and then proves the resource gone with a strict, successful name query. A
        removal that fails AND whose absence cannot be strictly proven stays UNKNOWN (not ``ok``).
        """

        resources: list[ResourceRemoval] = []
        if self._container:
            resources.append(
                self._remove("container", self._container, ("rm", "-f", self._container))
            )
        if self._network:
            resources.append(
                self._remove("network", self._network, ("network", "rm", self._network))
            )
        return TeardownResult(resources=tuple(resources))

    def _remove(self, kind: str, name: str, argv: tuple[str, ...]) -> ResourceRemoval:
        result = docker(*argv, timeout=30)
        if result.returncode == 0 and not result.timed_out:
            return ResourceRemoval(
                kind=kind, name=name, remove_rc=result.returncode,
                remove_timed_out=result.timed_out, absence_query_ok=True,
                absent_confirmed=True, diagnostic="removed",
            )
        # Removal did not clearly succeed. It may be an idempotent no-op (the resource was already
        # removed by an earlier cleanup pass) or a genuine failure. Only a successful strict query
        # distinguishes the two; a failed query keeps absence UNKNOWN and the resource not-ok.
        try:
            present = name_present(kind, name)
        except (DockerQueryError, DockerUnavailable) as exc:
            return ResourceRemoval(
                kind=kind, name=name, remove_rc=result.returncode,
                remove_timed_out=result.timed_out, absence_query_ok=False,
                absent_confirmed=False, diagnostic=f"absence_unknown:rc={result.returncode}:{exc}",
            )
        where = "still_present" if present else "proven_absent"
        return ResourceRemoval(
            kind=kind, name=name, remove_rc=result.returncode, remove_timed_out=result.timed_out,
            absence_query_ok=True, absent_confirmed=not present,
            diagnostic=f"{where}:rc={result.returncode}",
        )

    def leftover_proof(self, *, was_internal: bool, egress_proof: str) -> CleanupProof:
        return CleanupProof(
            stack_containers_remaining=count_by_label("container", self.label),
            volumes_remaining=count_by_label("volume", self.label),
            networks_remaining=count_by_label("network", self.label),
            network_was_internal=was_internal,
            egress_blocked_proof=egress_proof,
        )


class ContainerRangeError(RuntimeError):
    """A fail-closed error from the real-container ops range backend."""


def ensure_range_image(build_missing: bool = True) -> str:
    """Resolve (build if missing) the egress-free range image; return its content-addressed id."""

    current = image_id(RANGE_IMAGE_TAG)
    if current is None and build_missing:
        build = docker("build", "-t", RANGE_IMAGE_TAG, "-f", RANGE_DOCKERFILE, ".", timeout=600)
        if build.returncode != 0:
            raise ContainerRangeError(f"IMAGE_BUILD_FAILED:{build.stderr[-160:]}")
        current = image_id(RANGE_IMAGE_TAG)
    if current is None:
        raise ContainerRangeError(f"IMAGE_NOT_AVAILABLE:{RANGE_IMAGE_TAG}")
    return current


# --------------------------------------------------------------------------- #
# The consolidated campaign.
# --------------------------------------------------------------------------- #


def fresh_campaign_id() -> str:
    """A fresh, distinct-from-prior-phases campaign id for one Phase 2.9 run."""

    return f"phase-2.9-consolidated-{uuid4().hex[:12]}"


@dataclass
class ConsolidatedOpsCampaign:
    """Drives ONE Phase 2.9 campaign over the real lifecycle/remediation/report/verifier stack.

    ``containerized`` selects the real-container ops backend; otherwise the in-process network
    double is used. Either way the model boundary is the deterministic double, no provider called.
    """

    base_dir: Path
    containerized: bool = False
    campaign_id: str = field(default_factory=fresh_campaign_id)
    run_epoch: int = RUN_EPOCH
    # Controller-owned authorization reference for the assessment spec. Default preserves the
    # dry-run / existing-caller behaviour; a live campaign passes the validated non-secret ref.
    authorization_reference: str = "authz-range-ops-integration"
    model: ModelBoundary = field(default_factory=Phase29ModelDouble)
    # Injectable real-container factory (tests supply a double); production builds a container.
    container_factory: Callable[[], ContainerOpsRange] | None = None
    # An explicit range-cleanup boundary result. Tests inject a successful proof so the mock happy
    # path earns success through a genuine PASS snapshot, not the in-process ``no_leftovers=None``.
    range_cleanup_override: dict[str, Any] | None = None
    budget: CampaignProviderBudget = field(init=False)
    asm: OpsDetectionControlLifecycle = field(init=False)
    container: ContainerOpsRange | None = None
    # Durable fail-closed range-cleanup snapshot; captured in run()'s finally so it survives aborts.
    range_cleanup: dict[str, Any] = field(default_factory=lambda: {"status": "NOT_STARTED"})
    _range_cleanup_proof: CleanupProof | None = field(default=None, init=False, repr=False)
    # The REPORT_AGENT draft retained from the REPORT stage until post-cleanup final assembly.
    _report_draft: AssessmentReportDraftOutput | None = field(
        default=None, init=False, repr=False
    )
    # The single controller-authoritative report, assembled ONLY after the cleanup ledger completes.
    final_report: AssessmentReport | None = field(default=None, init=False, repr=False)
    record: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.budget = CampaignProviderBudget(
            max_provider_calls=MAX_PROVIDER_CALLS,
            max_total_tokens=MAX_TOTAL_TOKENS,
            per_call_output_ceiling=PER_CALL_OUTPUT_CEILING,
        )
        self.asm = OpsDetectionControlLifecycle(
            base_dir=self.base_dir / "ledgers",
            run_epoch=self.run_epoch,
            campaign_id=self.campaign_id,
            authorization_reference=self.authorization_reference,
        )

    # ------------------------- provider-call gate -------------------------- #

    def _provider_call(
        self, role: AgentRole, task_type: str, context: dict[str, Any]
    ) -> ModelResult:
        """Reserve worst-case budget before the call, dispatch the double, then settle usage."""

        estimated_input = estimate_input_tokens(context)
        reservation = self.budget.reserve(task_type, estimated_input, PER_CALL_OUTPUT_CEILING)
        try:
            result = self.model.generate(role, task_type, context)
        except Exception as exc:
            # A live-gateway rejection / invalid output / identity mismatch. Settle the reserved
            # slot with the provider-reported usage when the gateway supplied it, else UNKNOWN
            # (input/output = None), so the budget never assumes zero. The exception then halts the
            # campaign BEFORE the next provider call — there is no retry, repair or fallback here.
            provider_input = getattr(exc, "provider_input", None)
            provider_output = getattr(exc, "provider_output", None)
            self.budget.record_actual(reservation, provider_input, provider_output)
            raise
        self.budget.record_actual(
            reservation, result.usage.input_tokens, result.usage.output_tokens
        )
        return result

    # ------------------------------ retest job ----------------------------- #

    def _enqueue_retest_recon_job(self) -> str:
        """Persist a FRESH RECON_AGENT retest job (QUEUED->CLAIMED) on the real AdvSim queue."""

        retest_id = "agjob-" + _id16(self.asm.assessment_id, "rt")
        lead_id = "agjob-" + _id16(self.asm.assessment_id, "lead")
        delegation_id = "adelg-" + _id16(self.asm.assessment_id, "delegation")
        job = AdvAgentJob(
            job_id=retest_id,
            to_agent="RECON_AGENT",
            target_ref=TARGET_REF,
            technique_class=TECHNIQUE_CLASS,
            task_type="RUN_ADVERSARY_SIMULATION",
            objective="Execute the fresh post-patch detection-control retest probe sequence.",
            from_delegation_id=delegation_id,
            producer_job_id=lead_id,
        )
        address = self.asm.queue.enqueue_job(job)
        self.asm.queue.claim_job(address)
        return retest_id

    # ------------------------------- report -------------------------------- #

    def _live_run(self) -> bool:
        return self.model.name == "ISOLATED_LIVE_GATEWAY"

    def _report_usage(self) -> SourceUsage:
        identity_exact: bool | Literal["NOT_EVALUATED"]
        if self._live_run():
            identity_exact = set(self.model.reported_models) == {CANONICAL_MODEL}
        else:
            identity_exact = "NOT_EVALUATED"
        return SourceUsage(
            provider_calls=self.budget.calls_recorded,
            input_tokens=sum(a.input_tokens or 0 for a in self.budget.attempts),
            output_tokens=sum(a.output_tokens or 0 for a in self.budget.attempts),
            total_tokens=self.budget.tokens_recorded,
            tool_executions=4,
            identity_exact_deepseek_v4_pro=identity_exact,
        )

    def _report_id(self) -> str:
        return "rpt-" + _id16(self.asm.assessment_id, "report")

    def _report_executor(self, draft: AssessmentReportDraftOutput) -> Any:
        """REPORT stage: run + persist the REPORT_AGENT job and retain the draft.

        Cleanup has NOT run at this point, so NO authoritative report is assembled or saved here —
        the report that could claim a cleanup outcome is deferred to :meth:`_assemble_final_report`,
        which runs only after the cleanup ledger completes. The persisted REPORT_AGENT job
        (QUEUED->CLAIMED->CLOSED) and the single provider call for its draft are preserved; the job's
        projection honestly records cleanup as PENDING (``"UNKNOWN"``).
        """

        asm = self.asm

        def executor(context: StageContext) -> StageOutcome:
            asm.calls["report"] = asm.calls.get("report", 0) + 1
            # A pre-cleanup source used ONLY to build the persisted job projection + the CONFIRMED
            # gate; it is never assembled into a saved report while cleanup is still pending.
            source = asm.build_report_source(
                cleanup_succeeded="UNKNOWN",
                cleanup_obligations=CLEANUP_OBLIGATIONS,
                usage=self._report_usage(),
                live_run=self._live_run(),
            )
            projection = build_report_request_projection(source)
            assert_report_projection_clean(projection)
            job = ReportAgentJob(
                job_id="rptjob-" + _id16(asm.assessment_id, "reportjob"),
                campaign_id=self.campaign_id,
                report_request_id="rptreq-" + _id16(asm.assessment_id, "reportreq"),
                source_projection_sha256=projection_sha256(projection),
            )
            address = asm.report_queue.enqueue_job(job)
            asm.report_queue.claim_job(address)
            asm.report_queue.close_job(address)
            self._report_draft = draft
            return StageOutcome(
                ok=source.findings[0].state == "CONFIRMED",
                produced_epoch=context.run_epoch,
                evidence_sha256=projection_sha256(projection),
                side_effect_token=self._report_id(),
                usage=StageUsageDelta(provider_calls=1, tokens=0, tool_executions=0),
                detail="executed REPORT_AGENT job; final report deferred until after cleanup",
            )

        return executor

    def _assemble_final_report(self) -> AssessmentReport:
        """Assemble the controller-authoritative FINAL report from the ACTUAL cleanup result.

        Called once, AFTER the cleanup ledger and range teardown have completed, and BEFORE the
        immutable artifact bundle is written. It re-derives cleanup truth from the controller ledger
        and the durable range-cleanup snapshot (never assumed success), reuses the REPORT_AGENT draft
        retained in the REPORT stage (no new provider call), and never mutates an already-manifested
        report — it is the single saved report for the campaign (version 1).
        """

        asm = self.asm
        cleanup = derive_source_cleanup(
            cleanup_entries=[(e.obligation, bool(e.compensated)) for e in _cleanup_ledger(asm)],
            range_cleanup=self.range_cleanup,
            containerized=self.containerized,
        )
        source = asm.build_report_source(
            cleanup_succeeded=cleanup.succeeded,
            cleanup_obligations=cleanup.obligations,
            cleanup_failures=cleanup.failures,
            usage=self._report_usage(),
            live_run=self._live_run(),
        )
        report = assemble_report(
            source=source,
            model_output=self._report_draft,  # retained draft (discard/downgrade path unchanged)
            report_id=self._report_id(),
            version=1,
        )
        asm.report_queue.save_report(report)
        self.final_report = report
        return report

    # ------------------------------- run ----------------------------------- #

    def run(self) -> dict[str, Any]:  # noqa: C901, PLR0915 - one linear campaign is clearer inline
        asm = self.asm
        controller, spec = asm.lifecycle, asm.spec
        now = datetime.now().astimezone()
        backend: RangeBackendKind = "IN_PROCESS_DOUBLE"
        egress_proof = NOT_EVALUATED
        network_internal: bool | None = None
        image_content_id = NOT_EVALUATED

        if self.containerized:
            if self.container_factory is not None:
                container = self.container_factory()
                image_content_id = NOT_EVALUATED
            else:
                image_content_id = ensure_range_image(build_missing=True)
                container = ContainerOpsRange(image_ref=RANGE_IMAGE_TAG)
            self.container = container  # set BEFORE create() so a failed create still tears down
            container.create()
            network_internal = container.network_is_internal()
            egress_proof = container.egress_blocked_proof()
            asm.range_double = container
            backend = "CONTAINERIZED_SYNTHETIC"

        outcome: dict[str, Any] = {"stage_timeline": []}

        def _timeline(stage: str) -> None:
            outcome["stage_timeline"].append(
                {"stage": stage, "state": controller.ledger.get_state(spec.assessment_id).value}
            )

        try:
            controller.create_assessment(spec)
            _timeline("CREATED")
            controller.authorize(
                spec.assessment_id,
                authorization_reference=spec.authorization_reference,
                now=now,
            )
            _timeline("AUTHORIZED")
            controller.mark_ready(
                spec.assessment_id,
                activated_capabilities=(CAPABILITY_ID,),
                now=now,
            )
            _timeline("READY")

            # Call 1 — Lead delegation (LEAD_ORCHESTRATOR).
            delegation_raw = self._provider_call(
                AgentRole.LEAD_ORCHESTRATOR,
                "DELEGATE_ADVERSARY_SIMULATION",
                {"target_ref": TARGET_REF, "capability_catalog": [CAPABILITY_ID]},
            )
            delegation = AdversarySimulationDelegationOutput.model_validate_json(
                delegation_raw.payload_json
            )
            # Call 2 — initial Recon plan (RECON_AGENT).
            plan_raw = self._provider_call(
                AgentRole.RECON_AGENT,
                "PLAN_ADVERSARY_SIMULATION",
                {"target_ref": TARGET_REF, "capability_id": CAPABILITY_ID},
            )
            initial_plan = AdversarySimulationPlanOutput.model_validate_json(plan_raw.payload_json)

            controller.run_external_stage(
                spec.assessment_id, LifecycleStage.EXECUTE, asm.execute_dispatcher,
                idempotency_key="p29-execute-1", now=now,
            )
            _timeline("EXECUTE")
            controller.run_stage(
                spec.assessment_id, LifecycleStage.VERIFY, asm.verify_executor, now=now
            )
            _timeline("VERIFY")

            # Call 3 — remediation recommendation (RECON_AGENT, non-authoritative).
            recommend_raw = self._provider_call(
                AgentRole.RECON_AGENT,
                "RECOMMEND_ADVERSARY_REMEDIATION",
                {"finding_ref": asm.finding_id, "salient": "alternate_reached_sentinel"},
            )
            recommendation = AdversaryRemediationRecommendationOutput.model_validate_json(
                recommend_raw.payload_json
            )

            controller.run_stage(
                spec.assessment_id, LifecycleStage.REMEDIATE, asm.remediate_executor, now=now
            )
            _timeline("REMEDIATE")

            # Call 4 — fresh retest plan (RECON_AGENT).
            retest_plan_raw = self._provider_call(
                AgentRole.RECON_AGENT,
                "PLAN_ADVERSARY_SIMULATION",
                {"target_ref": TARGET_REF, "finding_ref": asm.finding_id},
            )
            retest_plan = AdversarySimulationPlanOutput.model_validate_json(
                retest_plan_raw.payload_json
            )
            retest_job_id = self._enqueue_retest_recon_job()

            def _retest_dispatcher(context: StageContext, key: str) -> StageOutcome:
                result = asm.retest_dispatcher(context, key)
                asm.queue.close_job(f"agentjob://RECON_AGENT/{retest_job_id}")
                return result

            controller.run_external_stage(
                spec.assessment_id, LifecycleStage.RETEST, _retest_dispatcher,
                idempotency_key="p29-retest-1", now=now,
            )
            _timeline("RETEST")

            # Call 5 — REPORT_AGENT draft prose.
            report_raw = self._provider_call(
                AgentRole.REPORT_AGENT,
                "GENERATE_ASSESSMENT_REPORT",
                {"finding_id": asm.finding_id, "campaign_id": self.campaign_id},
            )
            report_draft = AssessmentReportDraftOutput.model_validate_json(report_raw.payload_json)
            controller.run_stage(
                spec.assessment_id, LifecycleStage.REPORT, self._report_executor(report_draft),
                now=now,
            )
            _timeline("REPORT")

            # Resume/idempotency proof: replay completed stages -> no re-dispatch, no re-charge.
            probes_before = asm.range_double.probe_requests
            calls_before = dict(asm.calls)
            controller.run_external_stage(
                spec.assessment_id, LifecycleStage.EXECUTE, asm.execute_dispatcher,
                idempotency_key="p29-execute-1", now=now,
            )
            controller.run_external_stage(
                spec.assessment_id, LifecycleStage.RETEST, _retest_dispatcher,
                idempotency_key="p29-retest-1", now=now,
            )
            replay_no_redispatch = (
                asm.range_double.probe_requests == probes_before and asm.calls == calls_before
            )

            # Stale-evidence-reuse proof: the initial (pre-patch) evidence adjudicated against the
            # ROTATED ground truth is NOT a PASS (and not CONFIRMED) — it cannot satisfy the retest.
            assert asm.initial_evidence is not None
            stale = self.asm.verifier.adjudicate_detection_control_bypass_offline(
                APPLICATION_ID,
                asm.initial_evidence,
                detection_active=True,
                controller_sentinel_digest=asm.range_double.sentinel_digest,
            )
            stale_reuse_blocked = stale.status.value not in ("PASS", "CONFIRMED")

            # Cleanup (runs on the real cleanup ledger; compensates every obligation).
            receipt_id = "rcpt-" + _id16(asm.assessment_id, "receipt")
            cleanup_ok = controller.run_cleanup(
                spec.assessment_id,
                CLEANUP_OBLIGATIONS,
                lambda ob: self._compensate(ob, receipt_id),
            )
            _timeline("CLEANING_UP")
            verdict = controller.finalize(spec.assessment_id)
            _timeline("FINALIZED")
        finally:
            # Range teardown + a durable, fail-closed cleanup snapshot ALWAYS run (success, failure,
            # exception) so the range cleanup proof survives an aborted campaign for the artifact.
            self.range_cleanup = self._finalize_range_cleanup(
                network_internal=network_internal, egress_proof=egress_proof
            )

        # ONLY now — after the cleanup ledger AND range teardown have completed — assemble the single
        # controller-authoritative report from the ACTUAL cleanup result, before the immutable bundle
        # is written. No provider call happens here (the retained REPORT_AGENT draft is reused).
        report = self._assemble_final_report()
        cleanup_proof = self._range_cleanup_proof
        self.record = self._build_record(
            report=report,
            backend=backend,
            delegation=delegation,
            initial_plan=initial_plan,
            recommendation=recommendation,
            retest_plan=retest_plan,
            report_draft=report_draft,
            retest_job_id=retest_job_id,
            verdict=verdict,
            cleanup_ok=cleanup_ok,
            cleanup_proof=cleanup_proof,
            replay_no_redispatch=replay_no_redispatch,
            stale_reuse_blocked=stale_reuse_blocked,
            egress_proof=egress_proof,
            network_internal=network_internal,
            image_content_id=image_content_id,
            receipt_id=receipt_id,
            stage_timeline=outcome["stage_timeline"],
        )
        return self.record

    def _compensate(self, obligation: str, receipt_id: str) -> bool:
        if obligation == "INVALIDATE_PATCH_RECEIPT":
            self.asm.remediation_ledger.invalidate_receipt(receipt_id)
            return self.asm.remediation_ledger.receipt_consumed(receipt_id)
        if obligation in ("RESET_SYNTHETIC_TARGET_TO_BASELINE", "ROTATE_SENTINEL"):
            if self.container is not None:
                return self.container.reset_baseline()
            return True  # in-process double: state is discarded with the process
        if obligation == "TEARDOWN_RANGE":
            if self.container is not None:
                # Truthful: the ledger entry is compensated ONLY when teardown actually removed the
                # range (or strictly proved it already gone), never merely because teardown() ran.
                try:
                    return self.container.teardown().ok
                except (DockerQueryError, DockerUnavailable, ContainerRangeError):
                    return False
            return True
        if obligation == "REVOKE_REFERENCES":
            return True
        return True

    def _finalize_range_cleanup(
        self, *, network_internal: bool | None, egress_proof: str
    ) -> dict[str, Any]:
        """Tear the range down and capture a durable, fail-closed cleanup snapshot.

        Runs in run()'s ``finally`` so the snapshot exists on success AND on any abort. An injected
        ``range_cleanup_override`` is used verbatim (the explicit boundary result tests provide).
        With no containerized range this run, the snapshot is ``NOT_STARTED`` (never a success). A
        failed teardown or a failed/raising leftover query yields ``CLEANUP_FAILED`` /
        ``COLLECT_FAILED`` with ``no_leftovers`` never asserted True.
        """

        if self.range_cleanup_override is not None:
            self._range_cleanup_proof = None
            return dict(self.range_cleanup_override)
        if self.container is None:
            self._range_cleanup_proof = None
            return {
                "status": "NOT_STARTED",
                "backend": "CONTAINERIZED_SYNTHETIC" if self.containerized else "IN_PROCESS_DOUBLE",
                "teardown_ran": False,
                "teardown_ok": False,
                "teardown_error": None,
                "teardown_diagnostics": [],
                "leftover_query_ok": False,
                "no_leftovers": None,
                "leftover_proof": None,
                "network_was_internal": network_internal,
                "egress_blocked_proof": egress_proof,
            }

        teardown_error: str | None = None
        teardown_ran = False
        teardown_ok = False
        teardown_diagnostics: list[dict[str, Any]] = []
        try:
            teardown_result = self.container.teardown()
            teardown_ran = True
            teardown_ok = teardown_result.ok
            teardown_diagnostics = teardown_result.as_dict()["resources"]
            if not teardown_ok:
                teardown_error = f"TEARDOWN_INCOMPLETE:{teardown_result.failure_summary()}"
        except Exception as exc:  # noqa: BLE001 - fail closed; teardown failure must be visible
            teardown_error = f"{type(exc).__name__}:{str(exc)[:120]}"

        no_leftovers: bool | None
        try:
            proof = self.container.leftover_proof(
                was_internal=bool(network_internal), egress_proof=egress_proof
            )
            self._range_cleanup_proof = proof
            leftover_query_ok = True
            no_leftovers = bool(proof.clean)
            proof_dump: dict[str, Any] | None = proof.model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - a failed/raising leftover query cannot prove clean
            self._range_cleanup_proof = None
            leftover_query_ok = False
            no_leftovers = None
            proof_dump = None
            teardown_error = teardown_error or f"{type(exc).__name__}:{str(exc)[:120]}"

        # PASS requires a genuinely SUCCESSFUL teardown (or strictly proven prior absence) AND a
        # successful leftover query AND zero labelled leftovers. A teardown that merely ran is not
        # enough. A failed leftover query is COLLECT_FAILED; any other shortfall is CLEANUP_FAILED.
        if teardown_ok and leftover_query_ok and no_leftovers:
            status = "PASS"
        elif not leftover_query_ok:
            status = "COLLECT_FAILED"
        else:
            status = "CLEANUP_FAILED"
        return {
            "status": status,
            "backend": "CONTAINERIZED_SYNTHETIC",
            "teardown_ran": teardown_ran,
            "teardown_ok": teardown_ok,
            "teardown_error": teardown_error,
            "teardown_diagnostics": teardown_diagnostics,
            "leftover_query_ok": leftover_query_ok,
            "no_leftovers": no_leftovers,
            "leftover_proof": proof_dump,
            "network_was_internal": network_internal,
            "egress_blocked_proof": egress_proof,
        }

    # ------------------------------ record --------------------------------- #

    def _build_record(self, **kw: Any) -> dict[str, Any]:  # noqa: C901
        asm = self.asm
        verdict = kw["verdict"]
        finding = asm.remediation_ledger.get_finding(asm.finding_id)
        receipt = asm.remediation_ledger.get_receipt(kw["receipt_id"])
        assert finding is not None and receipt is not None
        report = kw["report"]  # the post-cleanup FINAL report (assembled after the cleanup ledger)
        assert report is not None
        delegation_id = "adelg-" + _id16(asm.assessment_id, "delegation")
        lead_id = "agjob-" + _id16(asm.assessment_id, "lead")
        recon_id = "agjob-" + _id16(asm.assessment_id, "recon")
        retest_job_id = kw["retest_job_id"]
        report_job_id = "rptjob-" + _id16(asm.assessment_id, "reportjob")
        loop_state = asm.remediation_ledger.state(asm.loop_id)

        # Canonical, persisted agentjob:// addresses. Each is read back from the durable queue
        # record (never string-formatted here), so an address only appears when its job is actually
        # persisted; the report job's internal ``rptjob-`` id is kept as secondary metadata only.
        lead_persisted = asm.queue.get_job(lead_id)
        recon_persisted = asm.queue.get_job(recon_id)
        retest_persisted = asm.queue.get_job(retest_job_id)
        report_persisted = asm.report_queue.get_job(report_job_id)

        # Independent verifier re-adjudication (facts only) to record substitution-freedom: the
        # initial evidence against the sentinel digest that was live when the worker probed, and the
        # retest evidence against the rotated post-patch sentinel.
        initial_v = asm.verifier.adjudicate_detection_control_bypass_offline(
            APPLICATION_ID, asm.initial_evidence or {}, detection_active=True,
            controller_sentinel_digest=_initial_sentinel(asm),
        )
        retest_v = asm.verifier.adjudicate_detection_control_bypass_offline(
            APPLICATION_ID, asm.retest_evidence or {}, detection_active=True,
            controller_sentinel_digest=asm.range_double.sentinel_digest,
        )
        return {
            "phase": "2.9",
            "campaign_id": self.campaign_id,
            "assessment_id": asm.assessment_id,
            "run_epoch": self.run_epoch,
            "loop_id": asm.loop_id,
            "finding_id": asm.finding_id,
            "range_backend": kw["backend"],
            "model": {
                "canonical": CANONICAL_MODEL,
                "provenance": self.model.name,
                "reported_models": sorted(set(self.model.reported_models)),
                "attempts": self.model.attempts,
            },
            "budget": {
                "ceilings": {
                    "max_provider_calls": MAX_PROVIDER_CALLS,
                    "max_total_tokens": MAX_TOTAL_TOKENS,
                    "per_call_output_ceiling": PER_CALL_OUTPUT_CEILING,
                    "concurrency": 1,
                },
                "snapshot": self.budget.snapshot(),
                "attempts": self.budget.attempts_export(),
            },
            "jobs": {
                # Canonical persisted agentjob:// addresses (primary identifiers).
                "lead_job_address": lead_persisted.address if lead_persisted else None,
                "recon_job_address": recon_persisted.address if recon_persisted else None,
                "retest_recon_job_address": (
                    retest_persisted.address if retest_persisted else None
                ),
                "report_job_address": report_persisted.address if report_persisted else None,
                # Raw internal ids (secondary metadata).
                "lead_job": lead_id,
                "recon_job": recon_id,
                "retest_recon_job": retest_job_id,
                "report_job": report_job_id,
                "delegation_id": delegation_id,
                "delegation_address": f"agentqueue://RECON_AGENT/{delegation_id}",
                "count": asm.queue.count_jobs(),
                "handoff_linked": asm.queue.handoff_linked(delegation_id),
                "lead_transitions": asm.queue.job_transitions(lead_id),
                "recon_transitions": asm.queue.job_transitions(recon_id),
                "retest_transitions": asm.queue.job_transitions(retest_job_id),
                "report_transitions": asm.report_queue.job_transitions(report_job_id),
            },
            "model_outputs": {
                "delegation": kw["delegation"].model_dump(mode="json"),
                "initial_plan": kw["initial_plan"].model_dump(mode="json"),
                "recommendation": kw["recommendation"].model_dump(mode="json"),
                "retest_plan": kw["retest_plan"].model_dump(mode="json"),
                "report_draft_authoritative": kw["report_draft"].authoritative,
            },
            "worker_evidence": {
                "initial": asm.initial_evidence,
                "retest": asm.retest_evidence,
                "initial_evidence_at": _iso(asm.initial_evidence_at),
                "retest_evidence_at": _iso(asm.retest_evidence_at),
                "initial_probe_fresh": asm.initial_evidence is not None,
                "retest_probe_fresh": asm.retest_evidence is not None,
            },
            "verifier": {
                "initial_status": finding.verified_status,
                "initial_facts": initial_v.facts,
                "retest_status": retest_v.status.value,
                "retest_facts": retest_v.facts,
                "retest_state": loop_state.value,
                "stale_evidence_reuse_blocked": kw["stale_reuse_blocked"],
            },
            "finding": {
                "finding_id": finding.finding_id,
                "verified_status": finding.verified_status,
                "controller_sentinel_epoch": finding.controller_sentinel_epoch,
                "finding_uri": finding.finding_uri,
            },
            "remediation": {
                "recommended_profile_id": kw["recommendation"].recommended_remediation_profile_id,
                "recommendation_authoritative": kw["recommendation"].remediation_authoritative,
                "applied_profile_id": REMEDIATION_PROFILE_ID,
                "receipt_id": receipt.receipt_id,
                "receipt_uri": receipt.receipt_uri,
                "receipt_consumed": asm.remediation_ledger.receipt_consumed(receipt.receipt_id),
                "pre_state_digest": receipt.pre_state_digest,
                "post_state_digest": receipt.post_state_digest,
                "target_state_changed": receipt.pre_state_digest != receipt.post_state_digest,
                "old_sentinel_epoch": receipt.old_sentinel_epoch,
                "new_sentinel_epoch": receipt.new_sentinel_epoch,
            },
            "report": {
                "report_id": report.report_id,
                "version": report.version,
                "content_sha256": report.content_sha256,
                "status": report.status,
                "model_prose_used": report.model_prose_used,
                "model_prose_downgraded": report.model_prose_downgraded,
                "finding_state": report.verified_findings[0].state,
                "finding_severity": report.verified_findings[0].severity,
                "finding_severity_authority": report.verified_findings[0].severity_authority,
                "finding_remediation_authority": report.verified_findings[0].remediation_authority,
                "finding_verification_provenance": (
                    report.verified_findings[0].verification_provenance
                ),
                "retest_state": report.retest_results[0].state,
                "generation_mode": report.generation_mode,
                "live_report_agent_status": report.live_report_agent_status,
                # Provenance: the report is finalized from the ACTUAL cleanup result AFTER the
                # cleanup ledger runs — never a pre-cleanup assumed success.
                "finalized_after_cleanup": True,
                "cleanup_succeeded": report.cleanup.succeeded,
                "cleanup_obligations": list(report.cleanup.obligations),
                "cleanup_failures": list(report.cleanup.failures),
            },
            "lifecycle": {
                "final_state": verdict.final_state.value,
                "required_stages_complete": verdict.required_stages_complete,
                "cleanup_succeeded": verdict.cleanup_succeeded,
                "usage_complete": verdict.usage_complete,
                "manifest_sha256": verdict.manifest_sha256,
                "stage_records": [
                    {
                        "stage": s.stage.value,
                        "status": s.status.value,
                        "produced_epoch": s.produced_epoch,
                    }
                    for s in _stage_records(asm)
                ],
                "timeline": kw.get("stage_timeline"),
            },
            "cleanup": {
                "cleanup_ok": kw["cleanup_ok"],
                "ledger": [e.model_dump(mode="json") for e in _cleanup_ledger(asm)],
                "leftover_proof": (
                    kw["cleanup_proof"].model_dump(mode="json") if kw["cleanup_proof"] else None
                ),
                "no_leftovers": (
                    kw["cleanup_proof"].clean if kw["cleanup_proof"] is not None else None
                ),
                "network_was_internal": kw["network_internal"],
                "egress_blocked_proof": kw["egress_proof"],
            },
            "provenance": {
                "range_image_tag": RANGE_IMAGE_TAG if self.containerized else NOT_EVALUATED,
                "range_image_id": kw["image_content_id"],
                "model_boundary": self.model.name,
            },
            "resume": {"replay_no_redispatch": kw["replay_no_redispatch"]},
        }


# --------------------------------------------------------------------------- #
# Small helpers.
# --------------------------------------------------------------------------- #


def _sha256_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def _initial_sentinel(asm: OpsDetectionControlLifecycle) -> str:
    """The sentinel digest observed on the INITIAL (pre-patch) alternate probe."""

    if asm.initial_evidence is None:
        return ""
    alternate = asm.initial_evidence.get("alternate") or {}
    return str(alternate.get("sentinel_digest", ""))


def _stage_records(asm: OpsDetectionControlLifecycle) -> list[Any]:
    records = []
    for stage in (
        LifecycleStage.AUTHORIZE, LifecycleStage.PREPARE, LifecycleStage.EXECUTE,
        LifecycleStage.VERIFY, LifecycleStage.REMEDIATE, LifecycleStage.RETEST,
        LifecycleStage.REPORT, LifecycleStage.CLEANUP,
    ):
        rec = asm.lifecycle.ledger.get_stage(asm.assessment_id, stage)
        if rec is not None:
            records.append(rec)
    return records


def _cleanup_ledger(asm: OpsDetectionControlLifecycle) -> list[Any]:
    return list(asm.lifecycle.ledger.cleanup_entries(asm.assessment_id))


# --------------------------------------------------------------------------- #
# Live-authorization guard (inert by default) + proposed-campaign description.
# --------------------------------------------------------------------------- #


def live_guard() -> LiveExecutionGuard:
    return LiveExecutionGuard(
        policy=LiveBudgetPolicy(
            required_max_provider_calls=MAX_PROVIDER_CALLS,
            required_max_total_tokens=MAX_TOTAL_TOKENS,
            per_call_output_ceiling=PER_CALL_OUTPUT_CEILING,
        )
    )


def proposed_campaign() -> dict[str, Any]:
    """The inert default output: the proposed campaign, with no side effect of any kind."""

    return {
        "phase": "2.9",
        "mode": "PROPOSED_ONLY_INERT",
        "scope": (
            "one continuous controller-governed synthetic assessment lifecycle over aegis-ops: "
            "fresh assessment -> Lead delegation -> Recon plan -> worker execution -> verifier "
            "CONFIRMED -> non-authoritative remediation recommendation -> controller-applied "
            "registered remediation + patch receipt -> fresh Recon retest -> verifier PASS -> "
            "REPORT_AGENT job -> controller-authoritative report -> cleanup/reset -> final verdict"
        ),
        "target_ref": TARGET_REF,
        "scenario_id": SCENARIO_ID,
        "capability_id": CAPABILITY_ID,
        "probe_profile_id": PROBE_PROFILE_ID,
        "remediation_profile_id": REMEDIATION_PROFILE_ID,
        "model": CANONICAL_MODEL,
        "planned_provider_calls": [
            "LEAD_ORCHESTRATOR: DELEGATE_ADVERSARY_SIMULATION",
            "RECON_AGENT: PLAN_ADVERSARY_SIMULATION (initial)",
            "RECON_AGENT: RECOMMEND_ADVERSARY_REMEDIATION (non-authoritative)",
            "RECON_AGENT: PLAN_ADVERSARY_SIMULATION (fresh retest)",
            "REPORT_AGENT: GENERATE_ASSESSMENT_REPORT (prose only)",
        ],
        "ceilings": {
            "max_provider_calls": MAX_PROVIDER_CALLS,
            "max_total_tokens": MAX_TOTAL_TOKENS,
            "per_call_output_ceiling": PER_CALL_OUTPUT_CEILING,
            "concurrency": 1,
            "auto_retry_or_schema_repair": "forbidden",
        },
        "live_arming_requires": [
            "--execute-live",
            "--authorization-ref <non-secret-ref>",
            f"--max-provider-calls {MAX_PROVIDER_CALLS}",
            f"--max-total-tokens {MAX_TOTAL_TOKENS}",
        ],
        "note": (
            "Default invocation is inert: no secrets loaded, no containers started, no jobs "
            "created, no target state changed, no network/provider call."
        ),
    }


def is_live_armed(request: LiveExecutionRequest) -> bool:
    return live_guard().is_armed(request)


# --------------------------------------------------------------------------- #
# Typed Phase 2.9 checks and per-contract acceptance verdicts (from ONE campaign record).
# --------------------------------------------------------------------------- #


def _ceiling_probes() -> tuple[bool, bool]:
    """Prove the fail-closed ceilings independently of the campaign's own consumption."""

    call_probe = CampaignProviderBudget(
        MAX_PROVIDER_CALLS, MAX_TOTAL_TOKENS, PER_CALL_OUTPUT_CEILING
    )
    for _ in range(MAX_PROVIDER_CALLS):
        reservation = call_probe.reserve("probe", 10, 10)
        call_probe.record_actual(reservation, 10, 10)
    call_enforced = False
    try:
        call_probe.reserve("probe-over", 10, 10)
    except BudgetStop:
        call_enforced = True

    token_probe = CampaignProviderBudget(MAX_PROVIDER_CALLS, 100, PER_CALL_OUTPUT_CEILING)
    token_enforced = False
    try:
        token_probe.reserve("probe", 10, PER_CALL_OUTPUT_CEILING)
    except BudgetStop:
        token_enforced = True
    return call_enforced, token_enforced


def _cleanup_reset_complete(record: dict[str, Any]) -> tuple[bool, bool]:
    ledger = record["cleanup"]["ledger"]
    entries = {e["obligation"]: bool(e["compensated"]) for e in ledger}
    reset_complete = entries.get("RESET_SYNTHETIC_TARGET_TO_BASELINE", False)
    cleanup_complete = bool(record["cleanup"]["cleanup_ok"]) and bool(entries) and all(
        entries.values()
    )
    return reset_complete, cleanup_complete


def build_phase_2_9_checks(
    record: dict[str, Any],
    *,
    guard_enforced: bool,
    artifact_manifest_verified: bool | str = NOT_EVALUATED,
    report_outputs_persisted: bool | str = NOT_EVALUATED,
    live: bool = False,
) -> dict[str, bool | str]:
    """Compute the typed Phase 2.9 acceptance checks from one campaign record.

    A check that a provider-free dry run cannot evaluate stays ``NOT_EVALUATED`` — never coerced to
    ``False`` or conveniently ``True``. When ``live=True`` the two provider-only checks
    (``exact_model_identity`` / ``live_provider_budget_enforced``) become observed booleans from the
    isolated live gateway run instead of ``NOT_EVALUATED``.
    """

    containerized = record["range_backend"] == "CONTAINERIZED_SYNTHETIC"
    snap = record["budget"]["snapshot"]
    live_identity_ok: bool | str = (
        (record["model"]["reported_models"] == [CANONICAL_MODEL]) if live else NOT_EVALUATED
    )
    live_budget_ok: bool | str = (
        bool(snap["within_ceilings"] and snap["usage_complete"]) if live else NOT_EVALUATED
    )
    jobs = record["jobs"]
    verifier = record["verifier"]
    remediation = record["remediation"]
    report = record["report"]
    lifecycle = record["lifecycle"]
    budget = record["budget"]
    worker = record["worker_evidence"]
    call_enforced, token_enforced = _ceiling_probes()
    reset_complete, cleanup_complete = _cleanup_reset_complete(record)

    # Evidence semantics: an affirmative ``simulated_*`` claim describes the DETERMINISTIC double
    # and must never be emitted over live-provider evidence. In live mode these become NOT_EVALUATED
    # and the live-provider budget/identity checks (``exact_model_identity`` /
    # ``live_provider_budget_enforced``) carry the observed facts instead.
    simulated_identity_reported: bool | str = (
        NOT_EVALUATED if live else (record["model"]["reported_models"] == [CANONICAL_MODEL])
    )
    simulated_call_ceiling: bool | str = (
        NOT_EVALUATED
        if live
        else (call_enforced and snap["calls_recorded"] <= MAX_PROVIDER_CALLS)
    )
    simulated_token_ceiling: bool | str = (
        NOT_EVALUATED
        if live
        else (token_enforced and snap["tokens_recorded"] <= MAX_TOTAL_TOKENS)
    )

    def _transitions_closed(trans: list[dict[str, str]]) -> bool:
        seq = [t["to"] for t in trans]
        return "CLAIMED" in seq and "CLOSED" in seq

    checks: dict[str, bool | str] = {
        "live_authorization_guard_enforced": bool(guard_enforced),
        "campaign_budget_reserved": (
            budget["snapshot"]["calls_recorded"] == MAX_PROVIDER_CALLS
            and len(budget["attempts"]) == MAX_PROVIDER_CALLS
        ),
        # The deterministic double *reported* the canonical model id; this is a simulated fact, NOT
        # evidence that a live provider served that model. The provider-identity claim stays
        # NOT_EVALUATED until an authorized paid campaign runs.
        "simulated_model_identity_reported": simulated_identity_reported,
        "exact_model_identity": live_identity_ok,
        "fresh_assessment_created": (
            record["assessment_id"].startswith("asmt-")
            and record["campaign_id"].startswith("phase-2.9-consolidated-")
            and record["run_epoch"] == RUN_EPOCH
        ),
        "real_lead_job_persisted": bool(jobs["lead_transitions"]) and jobs["count"] >= 2,
        "real_initial_recon_job_persisted": bool(jobs["recon_transitions"]),
        "lead_to_recon_handoff_persisted": bool(jobs["handoff_linked"]),
        "initial_worker_execution_fresh": (
            bool(worker["initial_probe_fresh"])
            and isinstance(worker["initial"], dict)
            and "baseline" in worker["initial"]
            and "alternate" in worker["initial"]
        ),
        "initial_verifier_confirmed": verifier["initial_status"] == "CONFIRMED",
        "verifier_did_not_substitute_initial_execution": (
            verifier["initial_facts"].get("verifier_probe_requests") == 0
            and verifier["initial_facts"].get("verifier_generated_bypass_traffic") is False
        ),
        "remediation_recommendation_model_generated": (
            record["model_outputs"]["recommendation"]["recommended_remediation_profile_id"]
            == REMEDIATION_PROFILE_ID
        ),
        "remediation_recommendation_non_authoritative": (
            remediation["recommendation_authoritative"] is False
        ),
        "controller_applied_registered_remediation": (
            remediation["applied_profile_id"] == REMEDIATION_PROFILE_ID
            and bool(remediation["receipt_id"])
        ),
        "patch_receipt_persisted": bool(remediation["receipt_id"]),
        "target_state_changed": bool(remediation["target_state_changed"]),
        "fresh_retest_job_persisted": _transitions_closed(jobs["retest_transitions"]),
        "stale_evidence_reuse_blocked": bool(verifier["stale_evidence_reuse_blocked"]),
        "retest_used_patch_receipt": bool(remediation["receipt_consumed"]),
        "retest_worker_execution_fresh": (
            bool(worker["retest_probe_fresh"])
            and worker["retest_evidence_at"] is not None
            and worker["initial_evidence_at"] is not None
            and worker["retest_evidence_at"] > worker["initial_evidence_at"]
        ),
        "retest_verifier_passed": verifier["retest_state"] == "RETEST_PASS",
        "verifier_did_not_substitute_retest_execution": (
            verifier["retest_facts"].get("verifier_probe_requests") == 0
            and verifier["retest_facts"].get("verifier_generated_bypass_traffic") is False
        ),
        "real_report_agent_job_persisted": (
            _transitions_closed(jobs["report_transitions"])
            and str(jobs.get("report_job_address") or "").startswith("agentjob://REPORT_AGENT/")
        ),
        "report_projection_sanitized": True,  # assert_report_projection_clean ran without raising
        "report_truth_controller_owned": (
            report["finding_state"] == "CONFIRMED"
            and report["finding_severity_authority"] in ("VERIFIER", "GROUND_TRUTH")
            and report["retest_state"] == "PASS"
        ),
        "report_outputs_persisted": report_outputs_persisted,
        "lifecycle_lineage_complete": (
            lifecycle["final_state"] == "COMPLETED"
            and bool(lifecycle["required_stages_complete"])
        ),
        "external_effect_replay_blocked": bool(record["resume"]["replay_no_redispatch"]),
        # Budget accounting is over the DETERMINISTIC gateway double, not a live provider. These
        # prove the controller's fail-closed reserve-before-dispatch logic and its simulated
        # call/token ceilings; the live-provider budget claim stays NOT_EVALUATED.
        "controller_budget_logic_exercised": (
            call_enforced
            and token_enforced
            and budget["snapshot"]["within_ceilings"] is True
            and len(budget["attempts"]) == MAX_PROVIDER_CALLS
        ),
        "simulated_call_ceiling_enforced": simulated_call_ceiling,
        "simulated_token_ceiling_enforced": simulated_token_ceiling,
        "live_provider_budget_enforced": live_budget_ok,
        "no_public_egress": (
            (
                str(record["cleanup"]["egress_blocked_proof"]).startswith("EGRESS_BLOCKED")
                and bool(record["cleanup"]["network_was_internal"])
            )
            if containerized
            else NOT_EVALUATED
        ),
        "reset_complete": reset_complete,
        "cleanup_complete": cleanup_complete,
        "no_leftovers": (
            bool(record["cleanup"]["no_leftovers"]) if containerized else NOT_EVALUATED
        ),
        "artifact_manifest_verified": artifact_manifest_verified,
    }
    return checks


def build_typed_verdicts(
    record: dict[str, Any], checks: dict[str, bool | str]
) -> dict[str, Any]:
    """Derive the Phase 2.3 / 2.6 / 2.7 / 2.9 acceptance verdict blocks from ONE campaign.

    One campaign supports multiple acceptance contracts; it is recorded as ONE execution, never
    presented as several. Live-provider status stays NOT_EVALUATED for every contract.
    """

    def _all(*keys: str) -> bool:
        return all(checks.get(k) is True for k in keys)

    # Mode discriminator: in live mode the provider-only checks are observed booleans; in the dry
    # run they are NOT_EVALUATED. The cumulative budget verdict must use the mode-correct check so a
    # live verdict is never derived from an affirmative simulated_* claim (NOT_EVALUATED when live).
    live = isinstance(checks.get("exact_model_identity"), bool)
    budget_keys: tuple[str, ...] = (
        ("live_provider_budget_enforced",)
        if live
        else ("simulated_call_ceiling_enforced", "simulated_token_ceiling_enforced")
    )

    phase_2_3 = {
        "initial_finding_verifier_confirmed": checks["initial_verifier_confirmed"],
        "controller_remediation_applied": checks["controller_applied_registered_remediation"],
        "fresh_retest_verifier_passed": checks["retest_verifier_passed"],
        "cleanup_complete": checks["cleanup_complete"],
        "satisfied": _all(
            "initial_verifier_confirmed",
            "controller_applied_registered_remediation",
            "retest_verifier_passed",
            "cleanup_complete",
        ),
        "live_status": NOT_EVALUATED,
    }
    phase_2_6 = {
        "real_report_agent_job_executed": checks["real_report_agent_job_persisted"],
        "projection_sanitized": checks["report_projection_sanitized"],
        "model_prose_non_authoritative": record["model_outputs"]["report_draft_authoritative"]
        is False,
        "controller_report_truth_preserved": checks["report_truth_controller_owned"],
        "report_artifacts_persisted": checks["report_outputs_persisted"],
        "satisfied": _all(
            "real_report_agent_job_persisted",
            "report_projection_sanitized",
            "report_truth_controller_owned",
            "report_outputs_persisted",
        )
        and record["model_outputs"]["report_draft_authoritative"] is False,
        "live_status": NOT_EVALUATED,
    }
    phase_2_7 = {
        "actual_lifecycle_adapters_executed": checks["lifecycle_lineage_complete"],
        "stages_and_lineage_persisted": checks["lifecycle_lineage_complete"],
        "idempotency_resume_preserved": checks["external_effect_replay_blocked"],
        "cumulative_budget_enforced": _all(*budget_keys),
        "final_verdict_controller_owned": record["lifecycle"]["final_state"] == "COMPLETED",
        "satisfied": _all(
            "lifecycle_lineage_complete",
            "external_effect_replay_blocked",
            *budget_keys,
        ),
        "live_status": NOT_EVALUATED,
    }
    # Every required Phase 2.9 check that is a bool must be True; NOT_EVALUATED checks are recorded
    # as unevaluated and do NOT count against the verdict (they are not False).
    evaluable = {k: v for k, v in checks.items() if isinstance(v, bool)}
    unevaluated = sorted(k for k, v in checks.items() if not isinstance(v, bool))
    phase_2_9 = {
        "all_component_verdicts_satisfied": bool(
            phase_2_3["satisfied"] and phase_2_6["satisfied"] and phase_2_7["satisfied"]
        ),
        "one_continuous_campaign_lineage": record["assessment_id"].startswith("asmt-"),
        "cleanup_complete": checks["cleanup_complete"],
        "no_unresolved_critical_unknown": record["lifecycle"]["usage_complete"] is True,
        "all_evaluable_checks_true": all(evaluable.values()),
        "unevaluated_checks": unevaluated,
        "satisfied": (
            all(evaluable.values())
            and phase_2_3["satisfied"]
            and phase_2_6["satisfied"]
            and phase_2_7["satisfied"]
        ),
        "live_status": NOT_EVALUATED,
    }
    return {
        "phase_2_3": phase_2_3,
        "phase_2_6": phase_2_6,
        "phase_2_7": phase_2_7,
        "phase_2_9": phase_2_9,
        "note": (
            "Phase 2.3, 2.6, 2.7 and 2.9 verdicts are all derived from the SAME single Phase 2.9 "
            "campaign lineage (one execution, multiple acceptance contracts), not multiple runs."
        ),
    }


def build_evidence_accounting(record: dict[str, Any], *, live: bool = False) -> dict[str, Any]:
    """Split deterministic-gateway (simulated) accounting from provider accounting — honestly.

    For the default dry run the five model calls and their token totals are produced by the
    deterministic gateway double, so they are reported as *simulated* usage; provider usage, exact
    served-model identity and the live-provider budget claim are all ``NOT_EVALUATED`` — never
    presented as provider usage and never coerced to zero-as-if-measured.

    For an armed live run (``live=True``) the same budget snapshot is *provider* accounting: the
    call/token totals are what the isolated gateway reported, the exact served-model identity is the
    observed fact (``deepseek-v4-pro``), and the live-provider budget claim reflects whether every
    reserved call settled within the ceilings with complete usage. It records observed evidence; it
    is not a LIVE-GO claim.
    """

    snap = record["budget"]["snapshot"]
    identity_reported = record["model"]["reported_models"] == [CANONICAL_MODEL]
    if not live:
        return {
            "gateway_mode": "DETERMINISTIC_DOUBLE",
            "model_boundary": record["provenance"]["model_boundary"],
            "simulated_model_calls": snap["calls_recorded"],
            "simulated_usage_tokens": snap["tokens_recorded"],
            "simulated_model_identity_reported": identity_reported,
            "provider_calls": 0,
            "provider_usage_tokens": NOT_EVALUATED,
            "exact_model_identity": NOT_EVALUATED,
            "live_provider_budget_enforced": NOT_EVALUATED,
        }
    return {
        "gateway_mode": "ISOLATED_LIVE_GATEWAY",
        "model_boundary": record["provenance"]["model_boundary"],
        "simulated_model_calls": 0,
        "simulated_usage_tokens": 0,
        "simulated_model_identity_reported": NOT_EVALUATED,
        "provider_calls": snap["calls_recorded"],
        "provider_usage_tokens": snap["tokens_recorded"],
        "exact_model_identity": identity_reported,
        "live_provider_budget_enforced": bool(
            snap["within_ceilings"] and snap["usage_complete"]
        ),
    }


# --------------------------------------------------------------------------- #
# Artifact bundle + SHA256SUMS.
# --------------------------------------------------------------------------- #

_LEDGER_DB_NAMES = ("lifecycle.db", "remediation.db", "advsim.db", "report.db")


def write_campaign_artifacts(
    out_dir: Path, campaign: ConsolidatedOpsCampaign, record: dict[str, Any]
) -> dict[str, Any]:
    """Write the Phase 2.9 artifact bundle, verify the manifest, and return the verification result.

    Every artifact except ``acceptance_verdict.json`` and ``SHA256SUMS`` forms the verified evidence
    set: it is written, checksummed, then re-read and compared. ``acceptance_verdict.json`` (which
    carries the checks/verdicts) is appended to ``SHA256SUMS`` afterwards.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    # The FINAL, post-cleanup report (assembled after the cleanup ledger). The manifest below covers
    # exactly this report bundle, so the immutable evidence carries the truthful cleanup outcome.
    report = campaign.final_report or campaign.asm.get_report()
    assert report is not None

    data_files: dict[str, Any] = {
        "campaign_and_assessment.json": {
            "phase": record["phase"],
            "campaign_id": record["campaign_id"],
            "assessment_id": record["assessment_id"],
            "run_epoch": record["run_epoch"],
            "loop_id": record["loop_id"],
            "finding_id": record["finding_id"],
            "range_backend": record["range_backend"],
            "model": record["model"],
        },
        "agent_jobs.json": record["jobs"],
        "lifecycle_stage_ledger.json": record["lifecycle"],
        "provider_attempts.json": record["model"]["attempts"],
        "budget_reservations_and_usage.json": record["budget"],
        "worker_evidence.json": record["worker_evidence"],
        "verifier_decisions.json": record["verifier"],
        "finding_record.json": record["finding"],
        "remediation_recommendation.json": record["model_outputs"]["recommendation"],
        "patch_receipt.json": record["remediation"],
        "retest_evidence.json": {
            "retest": record["worker_evidence"]["retest"],
            "retest_state": record["verifier"]["retest_state"],
            "retest_status": record["verifier"]["retest_status"],
        },
        "cleanup_ledger.json": record["cleanup"],
        "image_tool_provenance.json": record["provenance"],
    }
    for name, payload in data_files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    # Report exports (JSON / Markdown / HTML + their own SHA256SUMS).
    write_report_bundle(out_dir / "report", report)

    # Copy the durable ledger databases (agent-job / lifecycle / remediation / report export).
    ledger_dir = campaign.base_dir / "ledgers"
    for db_name in _LEDGER_DB_NAMES:
        src = ledger_dir / db_name
        if src.exists():
            shutil.copy2(src, out_dir / db_name)

    # Manifest over the verified evidence set (everything written so far).
    manifest_names = sorted(
        str(p.relative_to(out_dir))
        for p in out_dir.rglob("*")
        if p.is_file() and p.name not in ("SHA256SUMS", "acceptance_verdict.json")
    )
    sha_lines = [
        f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in manifest_names
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")

    # Verify: re-read each file and compare its digest.
    verified = True
    recorded = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in (out_dir / "SHA256SUMS").read_text().splitlines()
        if line.strip()
    }
    for name, digest in recorded.items():
        if hashlib.sha256((out_dir / name).read_bytes()).hexdigest() != digest:
            verified = False
    outputs_persisted = all(
        (out_dir / "report" / n).exists() for n in ("report.json", "report.md", "report.html")
    )
    return {
        "manifest_verified": verified,
        "report_outputs_persisted": outputs_persisted,
        "manifest_file_count": len(manifest_names),
    }
