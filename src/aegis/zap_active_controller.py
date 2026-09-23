"""Controller orchestration for one controlled ZAP active reflected-XSS scan (Phase 1.5).

This module is the single place that sequences an active run, and the single source of the
Operator Console's ZAP Active view. It exists so that the ordering rules live in one readable
place instead of being spread between an API handler, an adapter and a script:

    countersign -> job -> signed lease -> arm at the runner -> reset -> execute
                -> correlate (never promote) -> independent verifier -> revoke -> reset

Every step can refuse, and a refusal before ``execute`` produces zero target traffic.

The console projection is built by :meth:`ZapActiveController.view`. It is deliberately assembled
here rather than in the API layer, because the redaction rules are a property of the domain, not of
the transport: the browser must never receive the lease-signing secret, a raw lease token, a raw
attack payload, a response body, cookie or authorization data, or any ground-truth answer key. The
view carries digests, counts, classifications and bounded labels only.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis import zap_active_verifier
from aegis.engine.contracts import EngineEnvironment
from aegis.engine.policy import EnginePolicyRejection
from aegis.engine.zap_active import (
    ACTIVE_CAPABILITY_ID,
    ACTIVE_PROFILE_ID,
    ZapActiveAdapter,
    ZapActiveAdapterResult,
    ZapActiveEngineJob,
    build_zap_active_job,
)
from aegis.safety import SafetyController
from aegis.settings import Settings
from aegis.zap_active_lease import (
    CONFIRMATION_PHRASE,
    ActiveLeaseBinding,
    ActiveScanActivationRequest,
    ActiveScanLease,
    ActiveScanLeaseStore,
    LeaseError,
    new_budget_id,
)
from aegis_zap_active.contracts import ZapActiveAlertRecord, ZapActiveLeaseStatusResponse
from aegis_zap_active.countersign import CountersignStatus, verify_countersign
from aegis_zap_active.inventory import ZAP_ACTIVE_TARGETS, ZapActiveTarget
from aegis_zap_active.manifest import load_manifest, manifest_digest

SessionState = Literal["IDLE", "ARMED", "RUNNING", "COMPLETED", "FAILED", "STOPPED"]
AlertState = Literal["TOOL_REPORTED", "AEGIS_CORRELATED", "VERIFIED", "REVIEW_REQUIRED", "REJECTED"]

# Two things an operator must never infer from this screen. They are shown as text, every time.
SEVERITY_WARNING = (
    "Scanner severity and confidence are untrusted tool metadata. They are never Aegis severity: "
    "only the independent Aegis verifier sets a verified conclusion."
)
ZERO_ALERT_WARNING = (
    "Zero ZAP alerts is not a PASS. A patched PASS requires complete projection, import and queue "
    "coverage plus a fresh independent verifier proof of contextual output encoding."
)
NO_BROWSER_EXECUTION = (
    "No browser executes the payload. The verifier proves that controller-controlled input reaches "
    "an executable HTML context unescaped; it never claims script execution."
)


class ZapActiveActivation(BaseModel):
    """The operator's ceremony input. Nothing here can widen the profile, rule or environment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Public aliases deliberately do not disclose the fixture's vulnerable/patched ground truth.
    scenario: Literal["scenario-a", "scenario-b"]
    confirmation_phrase: str = Field(max_length=120)
    operator_id: str = Field(pattern=r"^[A-Za-z0-9._@-]{3,80}$")
    ttl_seconds: int = Field(default=900, ge=60, le=900)


@dataclass
class AlertProjection:
    plugin_id: int
    rule_name: str
    method: str
    path: str
    param: str
    claimed_risk: str
    claimed_confidence: str
    attack_class: str
    attack_sha256: str
    evidence_sha256: str
    record_digest: str
    state: AlertState
    reason: str = ""


@dataclass
class ZapActiveSession:
    """Everything one active run produced. Bounded, redacted and safe to project to a browser."""

    session_id: str
    state: SessionState = "IDLE"
    scenario: str = ""
    operator_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    scan_id: str = ""
    execution_id: str = ""
    job: ZapActiveEngineJob | None = None
    lease: ActiveScanLease | None = None
    armed_lease: dict[str, Any] | None = None
    result: ZapActiveAdapterResult | None = None
    alerts: list[AlertProjection] = field(default_factory=list)
    verification: zap_active_verifier.ZapXssVerification | None = None
    verifier_facts: list[zap_active_verifier.ZapXssProbeFacts] = field(default_factory=list)
    reset_before: bool = False
    reset_after: bool = False
    stop_steps: dict[str, bool] = field(default_factory=dict)
    terminal_reason: str = ""
    evidence_digest: str = ""

    def touch(self, state: SessionState | None = None) -> None:
        if state is not None:
            # STOPPED is terminal. An in-flight completion landing afterwards never overwrites it.
            if self.state == "STOPPED" and state != "STOPPED":
                return
            self.state = state
        self.updated_at = datetime.now(UTC)


class ZapActiveController:
    """Sequences activation, execution, correlation, verification, revocation and cleanup."""

    _SCENARIO_TARGETS = {
        "scenario-a": "synthetic-zap-active-vulnerable",
        "scenario-b": "synthetic-zap-active-patched",
    }

    def __init__(
        self,
        settings: Settings,
        safety: SafetyController,
        *,
        adapter: ZapActiveAdapter | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.safety = safety
        self._transport = transport
        self.adapter = adapter or ZapActiveAdapter(
            settings.zap_active_runner_url,
            enabled=settings.zap_active_enabled,
            adapter_version="zap-active/1.5.0",
            timeout_seconds=settings.zap_active_rpc_timeout_seconds,
            runner_client_token=(
                settings.require_zap_active_runner_client_secret()
                if settings.zap_active_enabled
                else ""
            ),
            transport=transport,
        )
        self._lease_store: ActiveScanLeaseStore | None = None
        self.session = ZapActiveSession(session_id="session-idle")
        self._lock = asyncio.Lock()

    # --- configuration -----------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self.settings.zap_active_enabled

    def lease_store(self) -> ActiveScanLeaseStore:
        """Built lazily so that a deployment with ZAP Active disabled never needs a secret."""

        if self._lease_store is None:
            self._lease_store = ActiveScanLeaseStore(
                self.settings.require_zap_active_lease_secret()
            )
        return self._lease_store

    def countersign(self) -> CountersignStatus:
        return verify_countersign(
            capability_id=ACTIVE_CAPABILITY_ID,
            profile_id=ACTIVE_PROFILE_ID,
            environment=EngineEnvironment.SYNTHETIC_LAB.value,
            target_ref="synthetic-zap-active-vulnerable",
        )

    def config(self) -> dict[str, Any]:
        manifest = load_manifest()
        rule = manifest.rules_for_capability(ACTIVE_CAPABILITY_ID)[0]
        countersign = self.countersign()
        return {
            "enabled": self.enabled,
            "profile_id": ACTIVE_PROFILE_ID,
            "capability_id": ACTIVE_CAPABILITY_ID,
            "activity": "ACTIVE",
            "passive_profile_id": "ZAP_LAB_PASSIVE_V1",
            "environment": EngineEnvironment.SYNTHETIC_LAB.value,
            "confirmation_phrase": CONFIRMATION_PHRASE,
            "manifest_version": manifest.manifest_version,
            "manifest_digest": manifest_digest(),
            "engine_version": manifest.engine.version,
            "image_index_digest": manifest.engine.image.index_digest,
            "admitted_rule": {
                "plugin_id": rule.plugin_id,
                "name": rule.name,
                "strength": rule.strength,
                "threshold": rule.threshold,
                "cwe_id": rule.cwe_id,
                "quality": rule.quality,
            },
            "neutralised_dependency_ids": list(manifest.neutralised_dependency_ids),
            "countersign": countersign.model_dump(mode="json"),
            "scenarios": [
                {
                    "scenario": scenario,
                    "title": f"Controlled synthetic scenario {letter}",
                }
                for scenario, letter in (("scenario-a", "A"), ("scenario-b", "B"))
            ],
            "warnings": {
                "severity": SEVERITY_WARNING,
                "zero_alerts": ZERO_ALERT_WARNING,
                "browser_execution": NO_BROWSER_EXECUTION,
            },
        }

    # --- preflight ---------------------------------------------------------------------------

    async def preflight(self) -> dict[str, Any]:
        """Everything the console needs to decide whether activation is even offerable."""

        countersign = self.countersign()
        attestation = await self.adapter.attest() if self.enabled else None
        lease_status: ZapActiveLeaseStatusResponse = (
            await self.adapter.lease_status()
            if self.enabled
            else ZapActiveLeaseStatusResponse(admission_reachable=False)
        )
        secret_configured = True
        try:
            self.settings.require_zap_active_lease_secret()
        except RuntimeError:
            secret_configured = False
        blockers: list[str] = []
        if not self.enabled:
            blockers.append("ADAPTER_DISABLED")
        if not countersign.valid:
            blockers.append(f"COUNTERSIGN_{countersign.code}")
        if not secret_configured:
            blockers.append("LEASE_SECRET_UNAVAILABLE")
        if attestation is None or not attestation.ready:
            blockers.append("RUNNER_NOT_ATTESTED")
        if not lease_status.admission_reachable:
            blockers.append("ADMISSION_UNREACHABLE")
        if attestation is not None and not attestation.guard.reachable:
            blockers.append("SCOPE_GUARD_UNREACHABLE")
        return {
            "ready": not blockers,
            "blockers": blockers,
            "countersign": countersign.model_dump(mode="json"),
            "lease_secret_configured": secret_configured,
            "runner": _attestation_projection(attestation),
            "lease_status": lease_status.model_dump(mode="json"),
        }

    # --- activation --------------------------------------------------------------------------

    async def activate(self, request: ZapActiveActivation) -> ZapActiveSession:
        """The ceremony. Builds the job, issues one signed lease, and arms it at the runner."""

        async with self._lock:
            if self.session.state in {"ARMED", "RUNNING"}:
                raise LeaseError("LEASE_ALREADY_ACTIVE")
            if request.confirmation_phrase != CONFIRMATION_PHRASE:
                raise LeaseError("CONFIRMATION_PHRASE_MISMATCH")
            if not self.enabled:
                raise LeaseError("ADAPTER_DISABLED")
            target = ZAP_ACTIVE_TARGETS[self._SCENARIO_TARGETS[request.scenario]]
            scan_id = f"scan-{_rand(12)}"
            session = ZapActiveSession(
                session_id=f"session-{_rand(12)}",
                state="IDLE",
                scenario=request.scenario,
                operator_id=request.operator_id,
                scan_id=scan_id,
                execution_id=f"exec-{_rand(12)}",
            )
            self.session = session
            try:
                job, projection = build_zap_active_job(
                    profile_id=ACTIVE_PROFILE_ID,
                    capability_id=ACTIVE_CAPABILITY_ID,
                    run_id=scan_id,
                    environment=EngineEnvironment.SYNTHETIC_LAB,
                    target_ref=target.target_ref,
                    allowed_origins=[target.origin],
                    adapter_enabled=self.enabled,
                )
            except EnginePolicyRejection as rejection:
                session.terminal_reason = rejection.error.code.value
                session.touch("FAILED")
                raise LeaseError(rejection.error.code.value) from None
            session.job = job
            lease = self.lease_store().issue(
                ActiveScanActivationRequest(
                    target_ref=target.target_ref,
                    origin=target.origin,
                    classification="SYNTHETIC_LAB",
                    profile_id=ACTIVE_PROFILE_ID,
                    capability_id=ACTIVE_CAPABILITY_ID,
                    allowed_methods=("GET",),
                    allowed_path=projection.path,
                    query_param=projection.query_param,
                    max_requests=job.max_requests,
                    rate_per_second=min(10.0, 1000 / max(1, job.delay_ms)),
                    ttl_seconds=request.ttl_seconds,
                    confirmation_phrase=request.confirmation_phrase,
                ),
                binding=ActiveLeaseBinding(
                    projection_digest=projection.digest,
                    allowlist_digest=projection.allowlist_digest,
                    manifest_digest=job.manifest_digest,
                    budget_id=new_budget_id(),
                ),
            )
            session.lease = lease
            armed = await self.adapter.arm_lease(lease.token)
            if isinstance(armed, str):
                self.lease_store().revoke(lease.lease_id, "arm_rejected")
                session.terminal_reason = f"LEASE:{armed}"
                session.touch("FAILED")
                raise LeaseError(armed)
            session.armed_lease = armed.model_dump(mode="json")
            session.touch("ARMED")
            return session

    # --- execution ---------------------------------------------------------------------------

    async def execute(self) -> ZapActiveSession:
        """Reset, run under the armed lease, correlate, verify independently, revoke and reset."""

        session = self.session
        if session.state != "ARMED" or session.job is None or session.lease is None:
            raise LeaseError("NO_LIVE_LEASE")
        target = ZAP_ACTIVE_TARGETS[session.job.target_ref]
        session.touch("RUNNING")
        session.reset_before = await self._reset(target)
        result = await self.adapter.run(
            session.job,
            session.scan_id,
            execution_id=session.execution_id,
            lease_store=self.lease_store(),
        )
        session.result = result
        response = result.response
        session.alerts = (
            self._correlate(session.job, response.alerts) if response is not None else []
        )
        # The verifier runs whatever the scanner said, including when it said nothing at all: a
        # patched PASS must be proved, not inferred from silence.
        if not result.stopped:
            marker = zap_active_verifier.fresh_marker()
            session.verifier_facts = await zap_active_verifier.collect(
                target=target,
                scan_id=session.scan_id,
                marker=marker,
                safety=self.safety,
                transport=self._transport,
                timeout_seconds=15.0,
            )
            session.verification = zap_active_verifier.evaluate(session.verifier_facts)
            self._promote(session)
        session.reset_after = await self._reset(target)
        if result.stopped:
            session.terminal_reason = "EMERGENCY_STOP"
            session.touch("STOPPED")
        elif result.execution.status.value != "COMPLETED":
            session.terminal_reason = result.validation_code or "EXECUTION_FAILED"
            session.touch("FAILED")
        else:
            session.terminal_reason = "COMPLETE"
            session.touch("COMPLETED")
        session.evidence_digest = _evidence_digest(session)
        return session

    async def stop(self, operator_id: str) -> ZapActiveSession:
        """Operator emergency stop. Order and terminality are enforced by the runner."""

        session = self.session
        session.operator_id = operator_id or session.operator_id
        lease = session.lease
        steps = await self.adapter.emergency_stop() if self.enabled else {}
        if lease is not None:
            self.lease_store().emergency_stop("operator_stop")
            steps["controller_lease_revoked"] = True
            steps["runner_lease_revoked"] = await self.adapter.revoke_lease(
                lease.lease_id, "operator_stop"
            ) or steps.get("lease_revoked", False)
        session.stop_steps = steps
        session.terminal_reason = "EMERGENCY_STOP"
        session.touch("STOPPED")
        return session

    # --- correlation and promotion -------------------------------------------------------------

    def _correlate(
        self, job: ZapActiveEngineJob, alerts: tuple[ZapActiveAlertRecord, ...]
    ) -> list[AlertProjection]:
        """Every alert starts TOOL_REPORTED. Correlation is a controller decision about scope and
        admission only — it is never a security conclusion and never a promotion."""

        projections: list[AlertProjection] = []
        for alert in alerts:
            state: AlertState = "TOOL_REPORTED"
            reason = ""
            if alert.plugin_id != job.rule_id:
                state, reason = "REJECTED", "UNADMITTED_RULE"
            elif (alert.method, alert.path) != (job.method, job.path):
                state, reason = "REJECTED", "OUT_OF_SCOPE_OPERATION"
            elif alert.param != job.query_param:
                state, reason = "REJECTED", "UNEXPECTED_PARAMETER"
            else:
                state, reason = "AEGIS_CORRELATED", "IN_SCOPE_ADMITTED_RULE"
            projections.append(
                AlertProjection(
                    plugin_id=alert.plugin_id,
                    rule_name=alert.rule_name,
                    method=alert.method,
                    path=alert.path,
                    param=alert.param,
                    claimed_risk=alert.claimed_risk,
                    claimed_confidence=alert.claimed_confidence,
                    attack_class=alert.attack_class,
                    attack_sha256=alert.attack_sha256,
                    evidence_sha256=alert.evidence_sha256,
                    record_digest=alert.record_digest,
                    state=state,
                    reason=reason,
                )
            )
        return projections

    @staticmethod
    def _promote(session: ZapActiveSession) -> None:
        """Only the independent verifier promotes. A correlated alert with no CONFIRMED proof
        becomes REVIEW_REQUIRED; it never becomes VERIFIED and never silently disappears."""

        verification = session.verification
        for alert in session.alerts:
            if alert.state != "AEGIS_CORRELATED":
                continue
            if verification is not None and verification.status == "CONFIRMED":
                alert.state, alert.reason = "VERIFIED", "VERIFIER_CONFIRMED_RAW_EXECUTABLE"
            else:
                alert.state, alert.reason = (
                    "REVIEW_REQUIRED",
                    f"VERIFIER_{verification.status if verification else 'NOT_RUN'}",
                )

    async def _reset(self, target: ZapActiveTarget) -> bool:
        """Deterministic target reset. A failed reset is reported, never assumed."""

        url = f"{target.origin.rstrip('/')}/lab/zap-active/{target.variant}/reset"
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=False, trust_env=False, transport=self._transport
            ) as client:
                response = await client.get(url)
        except httpx.HTTPError:
            return False
        if response.status_code != 200:
            return False
        try:
            body = response.json()
        except ValueError:
            return False
        return bool(body.get("reset")) and body.get("variant") == target.variant

    # --- projection --------------------------------------------------------------------------

    def verdict(self) -> dict[str, str]:
        """The run's conclusion, stated with its owner. Never derived from an alert count."""

        session = self.session
        if session.state == "STOPPED":
            return {"outcome": "STOPPED", "owner": "OPERATOR", "detail": "Emergency stop"}
        if session.state != "COMPLETED":
            return {
                "outcome": "INCOMPLETE",
                "owner": "CONTROLLER",
                "detail": session.terminal_reason or "Not run",
            }
        verification = session.verification
        response = session.result.response if session.result else None
        complete = bool(response is not None and response.coverage_complete)
        if verification is None:
            return {"outcome": "INCOMPLETE", "owner": "VERIFIER", "detail": "Verifier did not run"}
        if verification.status == "CONFIRMED":
            return {
                "outcome": "VERIFIED_VULNERABLE",
                "owner": "AEGIS_VERIFIER",
                "detail": verification.summary,
            }
        if verification.status == "PASS" and complete:
            return {
                "outcome": "PASS",
                "owner": "AEGIS_VERIFIER",
                "detail": "Verifier proved contextual entity encoding under complete coverage.",
            }
        return {
            "outcome": "REVIEW_REQUIRED",
            "owner": "AEGIS_VERIFIER",
            "detail": verification.summary,
        }

    def view(self, lease_status: ZapActiveLeaseStatusResponse | None = None) -> dict[str, Any]:
        """The console projection. Redaction is enforced here, not by the transport layer."""

        session = self.session
        response = session.result.response if session.result else None
        traffic = response.traffic if response is not None else None
        job = session.job
        return {
            "session_id": session.session_id,
            "state": session.state,
            "profile_id": ACTIVE_PROFILE_ID,
            "activity": "ACTIVE",
            "capability_id": ACTIVE_CAPABILITY_ID,
            "scenario": session.scenario,
            "operator_id": session.operator_id,
            "scan_id": session.scan_id,
            "execution_id": session.execution_id,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "environment": EngineEnvironment.SYNTHETIC_LAB.value,
            "target": None
            if job is None
            else {
                "method": job.method,
                "query_param": job.query_param,
            },
            "rule": None
            if job is None
            else {
                "plugin_id": job.rule_id,
                "strength": job.strength,
                "threshold": job.threshold,
            },
            "provenance": _provenance(session, job),
            "countersign": self.countersign().model_dump(mode="json"),
            # The lease is projected redacted. The token exists only in controller memory and in
            # the one RPC body that carried it; it is never in this dictionary.
            "lease": None
            if session.lease is None
            else {
                "lease_id": session.lease.lease_id,
                "profile_id": session.lease.profile_id,
                "capability_id": session.lease.capability_id,
                "projection_digest": session.lease.binding.projection_digest,
                "allowlist_digest": session.lease.binding.allowlist_digest,
                "manifest_digest": session.lease.binding.manifest_digest,
                "audience": session.lease.binding.audience,
                "budget_id": session.lease.binding.budget_id,
                "state": session.lease.state,
                "issued_at": session.lease.issued_at.isoformat(),
                "expires_at": session.lease.expires_at.isoformat(),
                "lifetime_seconds": round(
                    (session.lease.expires_at - session.lease.issued_at).total_seconds()
                ),
                "termination_reason": session.lease.termination_reason,
            },
            # Admission returns controller-only scope material (target ref, origin, path and
            # digests). The browser needs lifecycle state only; projecting the full admission
            # record would disclose the exact hidden fixture route.
            "armed_lease": None
            if session.armed_lease is None
            else {
                key: session.armed_lease.get(key)
                for key in ("state", "issued_at", "expires_at", "termination_reason")
            },
            "lease_status": (lease_status.model_dump(mode="json") if lease_status else None),
            "budgets": None
            if job is None
            else {
                "max_requests": job.max_requests,
                "time_budget_ms": job.time_budget_ms,
                "delay_ms": job.delay_ms,
                "max_alerts": job.max_alerts,
                "max_report_bytes": job.max_report_bytes,
            },
            "traffic": None
            if traffic is None
            else {
                "received": traffic.received,
                "forwarded": traffic.forwarded,
                "blocked": traffic.blocked,
                "blocked_reasons": [list(item) for item in traffic.blocked_reasons],
                "redirects": traffic.redirects,
                "budget_exceeded": traffic.budget_exceeded,
            },
            "progress": _progress(response),
            "alerts": [alert.__dict__ for alert in session.alerts],
            "alert_states": {
                state: sum(1 for alert in session.alerts if alert.state == state)
                for state in (
                    "TOOL_REPORTED",
                    "AEGIS_CORRELATED",
                    "VERIFIED",
                    "REVIEW_REQUIRED",
                    "REJECTED",
                )
            },
            "verification": None
            if session.verification is None
            else session.verification.model_dump(mode="json"),
            "verifier_probes": [
                {
                    "name": fact.name,
                    "role": fact.role,
                    "status_code": fact.status_code,
                    "content_class": fact.content_class,
                    "body_bytes": fact.body_bytes,
                    "body_sha256": fact.body_sha256,
                    "variant_marker_ok": fact.variant_marker_ok,
                    "reflection": fact.reflection,
                }
                for fact in session.verifier_facts
            ],
            "cleanup": {
                "reset_before": session.reset_before,
                "reset_after": session.reset_after,
                "session_destroyed": bool(response.session_destroyed) if response else False,
                "lease_revoked": bool(response.lease.revoked_after_execution)
                if response
                else False,
            },
            "stop_steps": session.stop_steps,
            "terminal_reason": session.terminal_reason,
            "verdict": self.verdict(),
            "evidence_digest": session.evidence_digest,
            "warnings": {
                "severity": SEVERITY_WARNING,
                "zero_alerts": ZERO_ALERT_WARNING,
                "browser_execution": NO_BROWSER_EXECUTION,
            },
        }


def _rand(size: int) -> str:
    import secrets

    return secrets.token_hex(size // 2)


def _attestation_projection(attestation: Any) -> dict[str, Any] | None:
    if attestation is None:
        return None
    # The runner's attestation binds the manifest by digest; the image index digest is the
    # controller's own pin for that exact manifest, shown only when the two sides agree.
    manifest = load_manifest()
    image_index_digest = (
        manifest.engine.image.index_digest
        if attestation.manifest_digest == manifest_digest()
        else None
    )
    return {
        "ready": attestation.ready,
        "runner_version": attestation.runner_version,
        "failure_codes": list(attestation.failure_codes),
        "zap_version": attestation.engine.zap_version,
        "image_index_digest": image_index_digest,
        "add_on_inventory_digest": attestation.engine.add_on_inventory_digest,
        "manifest_digest": attestation.manifest_digest,
        "admitted_rule_ids": list(attestation.admitted_rule_ids),
        "addonlist_verified": attestation.addonlist_verified,
        "java_verified": attestation.java_verified,
        "neutralised_dependency_ids": list(attestation.neutralised_dependency_ids),
        "guard": {
            "reachable": attestation.guard.reachable,
            "guard_version": attestation.guard.guard_version,
            "state": attestation.guard.state,
            "allowed_origins": list(attestation.guard.allowed_origins),
        },
    }


def _provenance(session: ZapActiveSession, job: ZapActiveEngineJob | None) -> dict[str, Any]:
    attestation = session.result.attestation if session.result else None
    return {
        "manifest_digest": job.manifest_digest if job else None,
        "add_on_inventory_digest": job.add_on_inventory_digest if job else None,
        "projection_digest": job.projection_digest if job else None,
        "allowlist_digest": job.allowlist_digest if job else None,
        "source_sha256": job.source_sha256 if job else None,
        "runner": _attestation_projection(attestation),
    }


def _progress(response: Any) -> dict[str, Any]:
    if response is None:
        return {"stage": "NOT_STARTED", "percent": 0}
    stages = response.stages
    checkpoints = [
        ("PLAN_VALIDATED", stages.plan_validated),
        ("ENGINE_STARTED", stages.zap_started),
        ("OPENAPI_IMPORTED", stages.import_completed),
        ("ACTIVE_SCAN_STARTED", stages.active_scan_started),
        ("ACTIVE_SCAN_COMPLETED", stages.active_scan_completed),
        ("PASSIVE_QUEUE_DRAINED", stages.pscan_drained),
        ("REPORT_GENERATED", stages.report_generated),
    ]
    reached = [name for name, done in checkpoints if done]
    return {
        "stage": reached[-1] if reached else "NOT_STARTED",
        "percent": round(100 * len(reached) / len(checkpoints)),
        "checkpoints": [{"name": name, "reached": done} for name, done in checkpoints],
        "coverage_complete": response.coverage_complete,
        "exit_class": response.exit_class,
        "error_code": response.error_code.value if response.error_code else None,
        "duration_ms": response.duration_ms,
        "report_sha256": response.report_sha256,
        "stdout_sha256": response.stdout_sha256,
    }


def _evidence_digest(session: ZapActiveSession) -> str:
    """A checksum over the bounded, redacted evidence this run produced. No body, no payload."""

    response = session.result.response if session.result else None
    parts = [
        session.session_id,
        session.scan_id,
        session.execution_id,
        session.scenario,
        session.state,
        session.terminal_reason,
        response.report_sha256 or "" if response else "",
        response.stdout_sha256 or "" if response else "",
        *(alert.record_digest for alert in session.alerts),
        *(fact.body_sha256 or "" for fact in session.verifier_facts),
        session.verification.status if session.verification else "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
