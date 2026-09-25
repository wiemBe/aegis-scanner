"""Phase 2.2 bounded Adversary-Simulation slice: capability + controller-owned probe-profile
registry, a shell-free Tool Broker, source-side response sanitization/normalization, a bounded
disposable HTTP detection-control probe worker, and a real persisted, addressable
LEAD_ORCHESTRATOR -> RECON_AGENT job/delegation queue.

This is the control-plane half of the single synthetic HTTP detection-control-bypass vertical slice.
It mirrors the accepted Phase 2.1 authentication design point-for-point, adapted to a *bounded
adversary simulation* run by the existing ``RECON_AGENT`` (with a separately registered adversary-
simulation capability — no new AI role is minted for this phase):

* the model *selects* a registered adversary-simulation capability, a typed technique class and a
  registered controller-owned probe-profile id (see
  :class:`aegis.multi_agent.contracts.AdversarySimulationPlanOutput`); it never authors a raw shell
  string, raw argv, an arbitrary header, user agent, payload, target override, redirect destination,
  source address, spoofing/decoy parameter, or an attempt count / concurrency / pacing / stop
  condition;
* the controller-owned :class:`HttpDetectionControlProbeProfile` — never the model — owns the
  complete deterministic sequence (a recognizable baseline probe variant, one controller-approved
  alternate probe variant, the fixed route, concurrency 1, pacing, the maximum requests, the
  redirect policy, the timeout, the stop conditions, the evidence fields and the reset behaviour);
* the :class:`AdversaryBroker` deterministically renders that typed plan into a **shell-free**
  bounded HTTP probe set (a fixed method, a fixed route, concurrency 1) and fails closed on anything
  outside the registered capability's scope. A model-supplied variant count is a non-authoritative
  hint; the broker always renders the profile's own effective sequence and records the model-vs-
  controller fields separately;
* :func:`sanitize_probe_response` runs at the source (inside the disposable worker) so the raw
  controller-owned sentinel marker is redacted to a SHA-256 digest before it leaves the probe
  boundary — only a response's status, whether it was denied by the detection control, whether the
  protected-operation sentinel was present (as a boolean) and its digest are carried forward;
* target-controlled response content is untrusted DATA: instruction-like content is flagged
  (reusing the Phase 1.7-D marker set), never obeyed;
* the agent **never confirms**: observations, hypotheses and the submission all carry
  ``unconfirmed=True`` at the type level. Only the independent deterministic range verifier promotes
  the vulnerable case to CONFIRMED or the patched case to PASS, from controller-owned ground truth
  this module never sees — and it adjudicates the *worker's* evidence, generating no substitute
  bypass traffic.

The :class:`AdvSimTaskQueue` is the real inter-agent boundary: a real ``LEAD_ORCHESTRATOR`` job is
persisted and consumed, it produces a persisted typed delegation, and a separate real
``RECON_AGENT`` job (carrying that delegation id and the producer job id) is persisted and consumed.
Every record links the producer job, the consumer job, the delegation, the task type and the
source-evidence digest, so the audit trail proves a real hand-off — not just role labels.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

import httpx
from pydantic import Field

from aegis.multi_agent.contracts import AdversarySimulationPlanOutput, StrictModel, now_utc
from aegis.multi_agent.injection import HOSTILE_INSTRUCTION_MARKERS

# --------------------------------------------------------------------------- #
# Capability registry (kept in lockstep with aegis.multi_agent.registry / .contracts).
# --------------------------------------------------------------------------- #

CAP_DETECTION_CONTROL_PROBE = "aegis.ops.detection_control_probe"
ADV_CAPABILITIES: frozenset[str] = frozenset({CAP_DETECTION_CONTROL_PROBE})

# The bounded technique classes the model may hypothesize. Kept identical to the gateway contract's
# ``_GwAdvTechniqueClass`` literal by the drift-guard test.
ADV_TECHNIQUE_CLASSES: frozenset[str] = frozenset(
    {"HTTP_DETECTION_CONTROL_BYPASS", "REQUEST_SIGNATURE_EVASION"}
)

# The single registered target scope for this capability. The model's ``target_ref`` is re-validated
# against this set broker-side; a target override fails closed.
ADV_TARGET_REFS: frozenset[str] = frozenset({"range-ops"})

_FINDING_DOMAIN = "ADVERSARY_SIMULATION"
_PHASE_ID = "ops-detection-control-bypass-v1"

# The single registered protected-operation route/method for this capability. The model never
# selects these; the broker fixes them, so no route or verb is model-controllable.
_PROBE_ROUTE = "/api/ops/incident-export"
_PROBE_METHOD: Literal["GET"] = "GET"

# Hard controller limits. The model may hint fewer, never more.
REQUEST_CEILING = 4
CONCURRENCY = 1


# --------------------------------------------------------------------------- #
# Controller-owned probe-profile registry (model-blind).
# --------------------------------------------------------------------------- #
# The model selects a registered probe-profile id; the controller resolves it into the complete
# deterministic effective sequence. The profile — never the model — owns the baseline and alternate
# probe variants, the route, concurrency, pacing, the maximum requests, the redirect policy, the
# timeout, the stop conditions, the evidence fields and the reset requirement. None of these values
# is ever placed in a model prompt, projection, observation, queue payload or report.

_ProbeVariant = Literal["BASELINE", "ALTERNATE"]


class HttpDetectionControlProbeProfile(StrictModel):
    """A controller-owned, typed probe profile. Fully resolved controller-side; model-blind."""

    profile_id: Literal["http_detection_control_probe_v1"]
    technique_class: Literal["HTTP_DETECTION_CONTROL_BYPASS"] = "HTTP_DETECTION_CONTROL_BYPASS"
    # The complete deterministic variant sequence: a recognizable baseline probe first, then one
    # controller-approved alternate variant. The controller owns the order and membership.
    variant_sequence: tuple[_ProbeVariant, ...] = Field(min_length=2, max_length=REQUEST_CEILING)
    method: Literal["GET"] = "GET"
    concurrency: Literal[1] = 1
    pacing_seconds: float = Field(ge=0.0, le=5.0)
    max_requests: int = Field(ge=2, le=REQUEST_CEILING)
    redirect_policy: Literal["DENY"] = "DENY"
    timeout_seconds: float = Field(gt=0.0, le=10.0)
    stop_conditions: tuple[str, ...] = Field(min_length=1)
    evidence_fields: tuple[str, ...] = Field(min_length=1)
    reset_required: bool = True


HTTP_DETECTION_CONTROL_PROBE_V1: Literal["http_detection_control_probe_v1"] = (
    "http_detection_control_probe_v1"
)

# The single registered profile: a two-request bounded sequence (baseline then alternate), well
# within ``REQUEST_CEILING`` and concurrency 1, following no redirects.
ADV_PROBE_PROFILES: dict[str, HttpDetectionControlProbeProfile] = {
    HTTP_DETECTION_CONTROL_PROBE_V1: HttpDetectionControlProbeProfile(
        profile_id=HTTP_DETECTION_CONTROL_PROBE_V1,
        variant_sequence=("BASELINE", "ALTERNATE"),
        pacing_seconds=0.0,
        max_requests=2,
        timeout_seconds=5.0,
        stop_conditions=(
            "PROTECTED_SENTINEL_REACHED",
            "MAX_REQUESTS_REACHED",
        ),
        evidence_fields=("status_code", "blocked", "sentinel_present", "sentinel_digest"),
        reset_required=True,
    )
}
ADV_PROBE_PROFILE_IDS: frozenset[str] = frozenset(ADV_PROBE_PROFILES)

# ------------------------- Controller / broker secret path ------------------------- #
# The concrete probe-variant signature marker values live ONLY here (and in the rendered request
# specs the broker hands to the disposable worker). They are never placed in a model prompt,
# projection, observation, queue payload or report. The synthetic detection control recognizes the
# baseline marker in both modes and the alternate marker only in the patched mode.
_SIGNATURE_HEADER = "X-Ops-Signature"
_SIGNATURE_RESOLUTION: dict[str, str] = {
    "BASELINE": "ops-scan-baseline-v1",
    "ALTERNATE": "ops-scan-alternate-v1",
}

# Defence-in-depth: a rendered route must carry no shell metacharacter or whitespace.
_SHELL_METACHARACTERS = frozenset({";", "|", "&", "$", "`", "\n", "\r", " ", "\t", ">", "<"})
_SAFE_ROUTE_RE = re.compile(r"^/[A-Za-z0-9/_.-]+$")

# The controller-owned sentinel field the protected operation returns when reached. Only its digest
# ever leaves the worker; the raw value is redacted at the ingestion boundary.
_SENTINEL_FIELD = "sentinel"


class AdversaryRejection(ValueError):
    """Raised when an adversary-simulation selection escapes the controller allowlist or scope."""


# --------------------------------------------------------------------------- #
# Tool Broker: typed plan -> shell-free bounded probe execution.
# --------------------------------------------------------------------------- #

_ProbeLabel = Literal["BASELINE_PROBE", "ALTERNATE_PROBE"]

_VARIANT_LABEL: dict[str, _ProbeLabel] = {
    "BASELINE": "BASELINE_PROBE",
    "ALTERNATE": "ALTERNATE_PROBE",
}


class BrokeredAdvProbe(StrictModel):
    """One controller-rendered, shell-free HTTP probe. No raw header, payload or shell text.

    ``variant`` says which controller-owned probe-variant signature the broker injects at send time;
    the signature value itself is never represented here.
    """

    label: _ProbeLabel
    method: Literal["GET"]
    route: str = Field(min_length=1, max_length=200)
    variant: _ProbeVariant


class BrokeredAdvExecution(StrictModel):
    """The full shell-free bounded probe execution the broker renders from a typed plan."""

    capability_id: Literal["aegis.ops.detection_control_probe"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    finding_domain: Literal["ADVERSARY_SIMULATION"] = "ADVERSARY_SIMULATION"
    technique_class: str = Field(min_length=3, max_length=64)
    # Model-requested vs controller-effective fields, kept strictly separate. The profile id and the
    # variant-count hint are what the model asked for; the effective fields are what the controller
    # deterministically rendered. A hint never changes the effective sequence.
    model_requested_profile_id: str = Field(min_length=3, max_length=80)
    model_requested_probe_variants: int = Field(ge=1, le=REQUEST_CEILING)
    controller_effective_profile_id: str = Field(min_length=3, max_length=80)
    controller_effective_probe_variants: int = Field(ge=2, le=REQUEST_CEILING)
    controller_adjustment_reason: str = Field(min_length=3, max_length=120)
    total_requests: int = Field(ge=2, le=REQUEST_CEILING)
    concurrency: Literal[1]
    redirect_policy: Literal["DENY"]
    probes: list[BrokeredAdvProbe] = Field(min_length=2, max_length=REQUEST_CEILING)
    shell_free: bool


class AdversaryBroker:
    """Convert a typed :class:`AdversarySimulationPlanOutput` to a shell-free bounded probe set.

    It re-validates every model selection against the controller allowlist (capability id, technique
    class, target scope, registered profile id), renders the profile's own deterministic variant
    sequence — never the model's hint — against the fixed route/method at concurrency 1, proves the
    rendering is shell-free and never emits a raw header, payload or shell string.
    """

    def render(self, plan: AdversarySimulationPlanOutput) -> BrokeredAdvExecution:
        if plan.capability_id not in ADV_CAPABILITIES:
            raise AdversaryRejection("ADV_CAPABILITY_NOT_REGISTERED")
        if plan.technique_class not in ADV_TECHNIQUE_CLASSES:
            raise AdversaryRejection("ADV_TECHNIQUE_CLASS_NOT_REGISTERED")
        # Target scope: a target override outside the single registered scope fails closed.
        if plan.target_ref not in ADV_TARGET_REFS:
            raise AdversaryRejection("ADV_TARGET_NOT_IN_SCOPE")
        probe = plan.probe
        if probe.concurrency != CONCURRENCY:
            raise AdversaryRejection("ADV_CONCURRENCY_NOT_ALLOWED")
        profile = ADV_PROBE_PROFILES.get(probe.probe_profile_id)
        if profile is None:
            raise AdversaryRejection("ADV_PROBE_PROFILE_NOT_REGISTERED")

        # Deterministic controller rendering: the effective sequence is the profile's own variant
        # sequence, NEVER the model's hint. A hint that differs from the effective count is recorded
        # but cannot change the rendered sequence.
        model_hint = probe.requested_probe_variants
        variants = list(profile.variant_sequence)
        effective = len(variants)
        if effective < 2 or effective > profile.max_requests or effective > REQUEST_CEILING:
            raise AdversaryRejection("ADV_PROFILE_SEQUENCE_UNRENDERABLE")
        if model_hint == effective:
            adjustment_reason = f"MODEL_HINT_MATCHED_PROFILE_SEQUENCE_{effective}"
        else:
            adjustment_reason = (
                f"MODEL_HINT_{model_hint}_OVERRIDDEN_BY_PROFILE_SEQUENCE_{effective}"
            )

        probes = [
            BrokeredAdvProbe(
                label=_VARIANT_LABEL[variant],
                method=_PROBE_METHOD,
                route=_PROBE_ROUTE,
                variant=variant,
            )
            for variant in variants
        ]
        shell_free = all(self._is_shell_free(item) for item in probes)
        if not shell_free:
            raise AdversaryRejection("ADV_EXECUTION_NOT_SHELL_FREE")
        total = len(probes)
        if total > REQUEST_CEILING or total > profile.max_requests:
            raise AdversaryRejection("ADV_REQUEST_CEILING_EXCEEDED")
        return BrokeredAdvExecution(
            capability_id=plan.capability_id,
            target_ref=plan.target_ref,
            technique_class=plan.technique_class,
            model_requested_profile_id=probe.probe_profile_id,
            model_requested_probe_variants=model_hint,
            controller_effective_profile_id=profile.profile_id,
            controller_effective_probe_variants=effective,
            controller_adjustment_reason=adjustment_reason,
            total_requests=total,
            concurrency=CONCURRENCY,
            redirect_policy=profile.redirect_policy,
            probes=probes,
            shell_free=shell_free,
        )

    @staticmethod
    def _is_shell_free(probe: BrokeredAdvProbe) -> bool:
        if probe.method != _PROBE_METHOD:
            return False
        if not _SAFE_ROUTE_RE.match(probe.route):
            return False
        return not any(ch in probe.route for ch in _SHELL_METACHARACTERS)


def adversary_probe_requests(execution: BrokeredAdvExecution) -> list[dict[str, object]]:
    """Resolve a rendered execution into concrete request specs. Broker secret path only.

    The probe-variant signature marker values are resolved controller-side here and handed only to
    the disposable worker. This output must never be persisted into an artifact, projection or queue
    payload.
    """

    specs: list[dict[str, object]] = []
    for probe in execution.probes:
        signature = _SIGNATURE_RESOLUTION[probe.variant]
        specs.append(
            {
                "label": probe.label,
                "variant": probe.variant,
                "method": probe.method,
                "route": probe.route,
                "headers": {_SIGNATURE_HEADER: signature},
            }
        )
    return specs


# --------------------------------------------------------------------------- #
# Source-side sanitization of the untrusted probe response (redaction boundary).
# --------------------------------------------------------------------------- #


def sanitize_probe_response(
    label: str,
    status_code: int,
    body: object,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    """Reduce one raw probe response to sanitized, effect-free facts.

    Runs at the source (inside the disposable worker). It records only the response status, whether
    the detection control denied the request (a boolean), whether the protected-operation sentinel
    was present (a boolean), the sentinel's SHA-256 digest (never the raw marker), and whether
    target-controlled instruction-like content was observed (flagged as DATA, never obeyed). The raw
    sentinel value never leaves.
    """

    headers = headers or {}
    blocked = int(status_code) == 403
    sentinel_present = False
    sentinel_digest = ""
    if isinstance(body, dict):
        if body.get("blocked") is True:
            blocked = True
        value = body.get(_SENTINEL_FIELD)
        if isinstance(value, str) and value:
            sentinel_present = True
            sentinel_digest = hashlib.sha256(value.encode()).hexdigest()
    lowered = _stringify(body).lower()
    instruction_like = any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS)
    return {
        "label": label,
        "status_code": int(status_code),
        "blocked": blocked,
        "sentinel_present": sentinel_present,
        "sentinel_digest": sentinel_digest,
        "instruction_like_content": instruction_like,
    }


def _stringify(body: object) -> str:
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body)


# --------------------------------------------------------------------------- #
# Bounded disposable probe worker (runs in the throwaway container / offline test).
# --------------------------------------------------------------------------- #


def run_bounded_detection_probes(
    request_specs: list[dict[str, object]],
    *,
    base_url: str,
    target_ref: str = "range-ops",
    transport: httpx.BaseTransport | None = None,
) -> dict[str, object]:
    """Execute the controller-rendered bounded probe set and return sanitized facts only.

    Concurrency is fixed at 1 and redirects are never followed. Each probe carries a controller-
    owned probe-variant signature header (broker secret path); the raw sentinel marker, if the
    alternate probe reaches the protected operation, is redacted to a digest at the source. The
    worker itself executes both the baseline and the alternate probe.
    """

    sanitized: list[dict[str, object]] = []
    with httpx.Client(
        base_url=base_url, timeout=5, trust_env=False, follow_redirects=False, transport=transport
    ) as client:
        for spec in request_specs:
            label = str(spec.get("label", ""))
            route = str(spec.get("route", _PROBE_ROUTE))
            raw_headers = spec.get("headers")
            request_headers = (
                {str(k): str(v) for k, v in raw_headers.items()}
                if isinstance(raw_headers, dict)
                else {}
            )
            try:
                response = client.get(route, headers=request_headers)
                try:
                    parsed: object = response.json()
                except ValueError:
                    parsed = None
                sanitized.append(
                    sanitize_probe_response(
                        label, response.status_code, parsed, dict(response.headers)
                    )
                )
            except httpx.HTTPError as exc:
                sanitized.append(
                    {
                        "label": label,
                        "status_code": 0,
                        "blocked": False,
                        "sentinel_present": False,
                        "sentinel_digest": "",
                        "instruction_like_content": False,
                        "error": type(exc).__name__,
                    }
                )
    return {"sanitized": sanitized, "target_ref": target_ref}


def detection_adjudication_input(
    sanitized_results: list[dict[str, object]] | None,
) -> dict[str, object]:
    """Build the compact baseline/alternate evidence the independent verifier adjudicates.

    The verifier consumes this WORKER-produced evidence; it never sends the baseline or alternate
    probe itself. A missing arm yields an empty dict for that arm (never a fabricated pass).
    """

    baseline: dict[str, object] = {}
    alternate: dict[str, object] = {}
    for item in sanitized_results or []:
        label = str(item.get("label", ""))
        status_raw = item.get("status_code", 0)
        fact = {
            "status_code": status_raw if isinstance(status_raw, int) else 0,
            "blocked": bool(item.get("blocked")),
            "sentinel_present": bool(item.get("sentinel_present")),
            "sentinel_digest": str(item.get("sentinel_digest", "")),
        }
        if label == "BASELINE_PROBE":
            baseline = fact
        elif label == "ALTERNATE_PROBE":
            alternate = fact
    return {"baseline": baseline, "alternate": alternate}


# --------------------------------------------------------------------------- #
# Bounded stdin transport for the worker evidence handed to the independent verifier.
# --------------------------------------------------------------------------- #
# The verifier runs in a separate process/container, so the worker evidence must cross a process
# boundary. It is transported over stdin (never a host environment variable, which `docker compose
# exec` does not forward into the container and which silently arrives empty): canonical serialized
# bytes, an explicit maximum size, and a SHA-256 digest bound to those exact bytes. The receiver
# fails closed on missing, malformed, oversized or digest-mismatched input — there is no
# environment-variable fallback that could silently succeed.

MAX_WORKER_EVIDENCE_BYTES = 8192


class _ProbeFact(StrictModel):
    """One probe arm's sanitized facts. Defaults model an arm that produced nothing (INCOMPLETE)."""

    status_code: int = Field(default=0, ge=0, le=599)
    blocked: bool = False
    sentinel_present: bool = False
    sentinel_digest: str = Field(default="", max_length=64)


class WorkerAdjudicationEvidence(StrictModel):
    """Strict schema for the worker evidence the verifier adjudicates. Extra fields forbidden."""

    baseline: _ProbeFact = Field(default_factory=_ProbeFact)
    alternate: _ProbeFact = Field(default_factory=_ProbeFact)


def serialize_worker_evidence(evidence: dict[str, object]) -> bytes:
    """Canonically serialize validated worker evidence to bounded bytes (fail closed if too big)."""

    validated = WorkerAdjudicationEvidence.model_validate(evidence)
    raw = validated.model_dump_json().encode()
    if len(raw) > MAX_WORKER_EVIDENCE_BYTES:
        raise AdversaryRejection("WORKER_EVIDENCE_OVERSIZED")
    return raw


def worker_evidence_digest(raw: bytes) -> str:
    """SHA-256 of the exact transported bytes (used to bind the transport end to end)."""

    return hashlib.sha256(raw).hexdigest()


def load_worker_evidence(
    raw: bytes | None,
    *,
    expected_digest: str | None = None,
    max_bytes: int = MAX_WORKER_EVIDENCE_BYTES,
) -> dict[str, object]:
    """Fail-closed receiver for stdin-transported worker evidence.

    Rejects (raises :class:`AdversaryRejection`) on missing, oversized, malformed, non-object,
    schema-invalid or digest-mismatched input. Structurally valid but semantically empty evidence
    (e.g. ``{}`` or ``{"baseline": {}, "alternate": {}}``) is accepted and normalized — the
    *decision* layer, not this transport, returns INCOMPLETE for it. There is no env-variable
    fallback: the only accepted source is the bytes passed here.
    """

    if raw is None or len(raw) == 0:
        raise AdversaryRejection("WORKER_EVIDENCE_MISSING")
    if len(raw) > max_bytes:
        raise AdversaryRejection("WORKER_EVIDENCE_OVERSIZED")
    if expected_digest is not None and worker_evidence_digest(raw) != expected_digest:
        raise AdversaryRejection("WORKER_EVIDENCE_DIGEST_MISMATCH")
    try:
        parsed: object = json.loads(raw)
    except ValueError as exc:
        raise AdversaryRejection("WORKER_EVIDENCE_MALFORMED") from exc
    if not isinstance(parsed, dict):
        raise AdversaryRejection("WORKER_EVIDENCE_NOT_OBJECT")
    try:
        validated = WorkerAdjudicationEvidence.model_validate(parsed)
    except ValueError as exc:
        raise AdversaryRejection("WORKER_EVIDENCE_SCHEMA_INVALID") from exc
    return validated.model_dump()


# --------------------------------------------------------------------------- #
# Typed, effect-free, reference-only observations.
# --------------------------------------------------------------------------- #


class DetectionProbeObservation(StrictModel):
    kind: Literal["DETECTION_PROBE_RESPONSE"] = "DETECTION_PROBE_RESPONSE"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    label: _ProbeLabel
    status_code: int = Field(ge=0, le=599)
    blocked: bool = False
    sentinel_present: bool = False
    instruction_like_content: bool = False


class SentinelSignalObservation(StrictModel):
    kind: Literal["PROTECTED_SENTINEL_REACHED", "PROTECTED_SENTINEL_ABSENT"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")


class DetectionControlActiveObservation(StrictModel):
    kind: Literal["DETECTION_CONTROL_ACTIVE"] = "DETECTION_CONTROL_ACTIVE"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    active: bool


class AdvNoFinding(StrictModel):
    kind: Literal["NO_FINDING"] = "NO_FINDING"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    detail: str = Field(default="", max_length=120)


class AdvIncompleteObservation(StrictModel):
    kind: Literal["INCOMPLETE_TOOL_ERROR"] = "INCOMPLETE_TOOL_ERROR"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    reason: str = Field(min_length=1, max_length=120)


AdvObservationModel = (
    DetectionProbeObservation
    | SentinelSignalObservation
    | DetectionControlActiveObservation
    | AdvNoFinding
    | AdvIncompleteObservation
)

_VALID_LABELS = ("BASELINE_PROBE", "ALTERNATE_PROBE")


def normalize_adv_observations(
    target_ref: str, sanitized_results: list[dict[str, object]] | None
) -> list[AdvObservationModel]:
    """Turn sanitized probe facts into typed, effect-free, reference-only observations.

    A ``None`` or empty result set (a tool error) yields a single INCOMPLETE observation, never a
    clean NO_FINDING — an absent observation is never silently a pass.
    """

    if not sanitized_results:
        return [
            AdvIncompleteObservation(
                target_ref=target_ref,
                capability_id=CAP_DETECTION_CONTROL_PROBE,
                reason="detection probe worker produced no result",
            )
        ]
    observations: list[AdvObservationModel] = []
    baseline_denied = False
    alternate_sentinel = False
    saw_alternate = False
    for item in sanitized_results:
        label = str(item.get("label", ""))
        if label not in _VALID_LABELS:
            observations.append(
                AdvIncompleteObservation(
                    target_ref=target_ref,
                    capability_id=CAP_DETECTION_CONTROL_PROBE,
                    reason="probe response missing request label",
                )
            )
            continue
        raw_status = str(item.get("status_code", ""))
        status = int(raw_status) if raw_status.isdigit() else 0
        typed_label: _ProbeLabel = label  # type: ignore[assignment]
        blocked = bool(item.get("blocked"))
        sentinel_present = bool(item.get("sentinel_present"))
        observations.append(
            DetectionProbeObservation(
                target_ref=target_ref,
                label=typed_label,
                status_code=status,
                blocked=blocked,
                sentinel_present=sentinel_present,
                instruction_like_content=bool(item.get("instruction_like_content")),
            )
        )
        if label == "BASELINE_PROBE" and blocked and not sentinel_present:
            baseline_denied = True
        if label == "ALTERNATE_PROBE":
            saw_alternate = True
            alternate_sentinel = sentinel_present and not blocked
    if saw_alternate:
        signal_kind: Literal["PROTECTED_SENTINEL_REACHED", "PROTECTED_SENTINEL_ABSENT"] = (
            "PROTECTED_SENTINEL_REACHED" if alternate_sentinel else "PROTECTED_SENTINEL_ABSENT"
        )
        observations.append(SentinelSignalObservation(kind=signal_kind, target_ref=target_ref))
    observations.append(
        DetectionControlActiveObservation(target_ref=target_ref, active=baseline_denied)
    )
    return observations


def observation_warnings(observations: list[AdvObservationModel]) -> list[str]:
    """Instruction-resistance warnings: target-controlled instruction-like content, as data."""

    if any(
        isinstance(obs, DetectionProbeObservation) and obs.instruction_like_content
        for obs in observations
    ):
        return ["target-controlled instruction-like content observed; treated as data"]
    return []


# --------------------------------------------------------------------------- #
# Real, persisted, addressable LEAD_ORCHESTRATOR / RECON_AGENT job + delegation queue.
# --------------------------------------------------------------------------- #

_JOB_ADDRESS_SCHEME = "agentjob"
_DELEGATION_ADDRESS_SCHEME = "agentqueue"
_JOB_AGENTS = ("LEAD_ORCHESTRATOR", "RECON_AGENT")


class AdvSimTaskQueueError(RuntimeError):
    """A queue-level failure (duplicate id, malformed address, illegal transition). Fails closed."""


class AdvAgentJob(StrictModel):
    """A real, persisted, addressable inbound job for one Phase 2.2 agent.

    A LEAD_ORCHESTRATOR job carries no producer link; a RECON_AGENT job carries the persisted
    delegation id it was created from and the producer (lead) job id. Neither carries a mode,
    ground-truth id, verdict, severity, credential or origin.
    """

    job_id: str = Field(pattern=r"^agjob-[a-f0-9]{16}$")
    to_agent: Literal["LEAD_ORCHESTRATOR", "RECON_AGENT"]
    finding_domain: Literal["ADVERSARY_SIMULATION"] = "ADVERSARY_SIMULATION"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    technique_class: str = Field(min_length=3, max_length=64)
    task_type: str = Field(pattern=r"^[A-Z_]+$", max_length=80)
    objective: str = Field(min_length=3, max_length=300)
    from_delegation_id: str = Field(default="", max_length=40)
    producer_job_id: str = Field(default="", max_length=40)
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        return f"{_JOB_ADDRESS_SCHEME}://{self.to_agent}/{self.job_id}"


class PersistedAdvDelegation(StrictModel):
    """A real, persisted, addressable LEAD_ORCHESTRATOR -> RECON_AGENT delegation.

    It carries only references and links: the producer (lead) job id, a registered capability, a
    target reference, the technique class and the source-evidence digest. No payload, mode, verdict
    or credential is representable. ``reference_only=False`` distinguishes it from a non-persisted
    stub; ``confirmed``/``unconfirmed`` restate that a delegation never confirms.
    """

    delegation_id: str = Field(pattern=r"^adelg-[a-f0-9]{16}$")
    from_agent: Literal["LEAD_ORCHESTRATOR"] = "LEAD_ORCHESTRATOR"
    to_agent: Literal["RECON_AGENT"] = "RECON_AGENT"
    finding_domain: Literal["ADVERSARY_SIMULATION"] = "ADVERSARY_SIMULATION"
    producer_job_id: str = Field(pattern=r"^agjob-[a-f0-9]{16}$")
    capability_id: str = Field(pattern=r"^aegis\.[a-z0-9_.]+$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    technique_class: str = Field(min_length=3, max_length=64)
    task_type: Literal["PLAN_ADVERSARY_SIMULATION"] = "PLAN_ADVERSARY_SIMULATION"
    source_evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reference_only: Literal[False] = False
    confirmed: Literal[False] = False
    unconfirmed: Literal[True] = True
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def delegation_address(self) -> str:
        return f"{_DELEGATION_ADDRESS_SCHEME}://{self.to_agent}/{self.delegation_id}"


def parse_adv_job_address(address: str) -> tuple[str, str]:
    prefix = f"{_JOB_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise AdvSimTaskQueueError("JOB_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, job_id = rest.partition("/")
    if not sep or to_agent not in _JOB_AGENTS or not job_id:
        raise AdvSimTaskQueueError("JOB_ADDRESS_MALFORMED")
    return to_agent, job_id


def parse_adv_delegation_address(address: str) -> tuple[str, str]:
    prefix = f"{_DELEGATION_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise AdvSimTaskQueueError("DELEGATION_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, delegation_id = rest.partition("/")
    if not sep or to_agent != "RECON_AGENT" or not delegation_id:
        raise AdvSimTaskQueueError("DELEGATION_ADDRESS_MALFORMED")
    return to_agent, delegation_id


class AdvSimTaskQueue:
    """A durable, addressable inbound job + delegation queue for the Phase 2.2 hand-off, on SQLite.

    It persists two addressable agent jobs (LEAD_ORCHESTRATOR and RECON_AGENT) and the typed
    delegation that links them, records every job state transition, and resolves each record by its
    durable address. There is no field through which a payload, mode, verdict, severity or secret
    could be persisted.
    """

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS adv_agent_jobs (
                    job_id TEXT PRIMARY KEY,
                    to_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    task_type TEXT NOT NULL,
                    from_delegation_id TEXT NOT NULL,
                    producer_job_id TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS adv_agent_job_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS adv_delegations (
                    delegation_id TEXT PRIMARY KEY,
                    from_agent TEXT NOT NULL,
                    to_agent TEXT NOT NULL,
                    producer_job_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    source_evidence_sha256 TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_adv_agent_jobs_agent_status
                    ON adv_agent_jobs(to_agent, status);
                """
            )

    # --------------------------- jobs --------------------------- #

    def enqueue_job(self, job: AdvAgentJob) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO adv_agent_jobs(
                        job_id, to_agent, status, address, task_type,
                        from_delegation_id, producer_job_id, enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        job.job_id,
                        job.to_agent,
                        job.status,
                        job.address,
                        job.task_type,
                        job.from_delegation_id,
                        job.producer_job_id,
                        job.enqueued_at.isoformat(),
                        job.model_dump_json(),
                    ),
                )
                self._record_transition(connection, job.job_id, "NONE", job.status)
            except sqlite3.IntegrityError as exc:
                raise AdvSimTaskQueueError("JOB_ID_ALREADY_ENQUEUED") from exc
        return job.address

    def get_job(self, job_id: str) -> AdvAgentJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM adv_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return AdvAgentJob.model_validate_json(row["payload"]) if row else None

    def resolve_job(self, address: str) -> AdvAgentJob | None:
        to_agent, job_id = parse_adv_job_address(address)
        job = self.get_job(job_id)
        if job is not None and job.to_agent != to_agent:
            raise AdvSimTaskQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
        return job

    def claim_job(self, address: str) -> AdvAgentJob:
        return self._transition(address, expected="QUEUED", new="CLAIMED")

    def close_job(self, address: str) -> AdvAgentJob:
        return self._transition(address, expected="CLAIMED", new="CLOSED")

    def _transition(self, address: str, *, expected: str, new: str) -> AdvAgentJob:
        to_agent, job_id = parse_adv_job_address(address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM adv_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise AdvSimTaskQueueError("JOB_NOT_FOUND")
            job = AdvAgentJob.model_validate_json(row["payload"])
            if job.to_agent != to_agent:
                raise AdvSimTaskQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
            if row["status"] != expected:
                raise AdvSimTaskQueueError(f"JOB_ILLEGAL_TRANSITION_{row['status']}_TO_{new}")
            updated = job.model_copy(update={"status": new})
            connection.execute(
                "UPDATE adv_agent_jobs SET status = ?, payload = ? WHERE job_id = ?",
                (new, updated.model_dump_json(), job_id),
            )
            self._record_transition(connection, job_id, expected, new)
        return updated

    def job_transitions(self, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_status, to_status, at FROM adv_agent_job_transitions
                WHERE job_id = ? ORDER BY id""",
                (job_id,),
            ).fetchall()
        return [{"from": r["from_status"], "to": r["to_status"], "at": r["at"]} for r in rows]

    def count_jobs(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM adv_agent_jobs").fetchone()
        return int(row["n"])

    # ------------------------ delegations ------------------------ #

    def persist_delegation(self, delegation: PersistedAdvDelegation) -> str:
        with self._connect() as connection:
            # The producer job must already exist and be a LEAD_ORCHESTRATOR job — a delegation
            # cannot be fabricated without its producer.
            producer = connection.execute(
                "SELECT to_agent FROM adv_agent_jobs WHERE job_id = ?",
                (delegation.producer_job_id,),
            ).fetchone()
            if producer is None or producer["to_agent"] != "LEAD_ORCHESTRATOR":
                raise AdvSimTaskQueueError("DELEGATION_PRODUCER_JOB_INVALID")
            try:
                connection.execute(
                    """INSERT INTO adv_delegations(
                        delegation_id, from_agent, to_agent, producer_job_id, task_type,
                        capability_id, address, source_evidence_sha256, enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        delegation.delegation_id,
                        delegation.from_agent,
                        delegation.to_agent,
                        delegation.producer_job_id,
                        delegation.task_type,
                        delegation.capability_id,
                        delegation.delegation_address,
                        delegation.source_evidence_sha256,
                        delegation.enqueued_at.isoformat(),
                        delegation.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AdvSimTaskQueueError("DELEGATION_ID_ALREADY_PERSISTED") from exc
        return delegation.delegation_address

    def get_delegation(self, delegation_id: str) -> PersistedAdvDelegation | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM adv_delegations WHERE delegation_id = ?", (delegation_id,)
            ).fetchone()
        return PersistedAdvDelegation.model_validate_json(row["payload"]) if row else None

    def resolve_delegation(self, address: str) -> PersistedAdvDelegation | None:
        to_agent, delegation_id = parse_adv_delegation_address(address)
        delegation = self.get_delegation(delegation_id)
        if delegation is not None and delegation.to_agent != to_agent:
            raise AdvSimTaskQueueError("DELEGATION_ADDRESS_ROUTING_MISMATCH")
        return delegation

    def handoff_linked(self, delegation_id: str) -> bool:
        """True iff the delegation, its producer lead job and a consumer RECON_AGENT job carrying
        that delegation id are all persisted and mutually linked."""

        delegation = self.get_delegation(delegation_id)
        if delegation is None:
            return False
        producer = self.get_job(delegation.producer_job_id)
        if producer is None or producer.to_agent != "LEAD_ORCHESTRATOR":
            return False
        with self._connect() as connection:
            consumer = connection.execute(
                """SELECT to_agent FROM adv_agent_jobs
                WHERE from_delegation_id = ? AND producer_job_id = ? AND to_agent = ?""",
                (delegation_id, delegation.producer_job_id, "RECON_AGENT"),
            ).fetchone()
        return consumer is not None

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection, job_id: str, from_status: str, to_status: str
    ) -> None:
        connection.execute(
            """INSERT INTO adv_agent_job_transitions(job_id, from_status, to_status, at)
            VALUES (?, ?, ?, ?)""",
            (job_id, from_status, to_status, now_utc().isoformat()),
        )


def evidence_sha256_of(payload: object) -> str:
    """Deterministic digest of a mode-blind context, for delegation provenance linking."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
