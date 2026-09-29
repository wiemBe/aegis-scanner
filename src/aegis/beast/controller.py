from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any
from uuid import uuid4

import httpx

from aegis.beast.contracts import (
    BEAST_MAX_LEASE_SECONDS,
    BEAST_PROFILE_ID,
    TOOLBOX_PROFILE_SCENARIOS,
    BeastCommandDecision,
    BeastDecisionRequest,
    BeastDecisionResponse,
    BeastLease,
    BeastMode,
    BeastPreflight,
    BeastRun,
    BeastRunRequest,
    BeastStopDecision,
    CommandResult,
    CommandTransport,
    EnvironmentClass,
    LeaseRequest,
    LeaseState,
    ResourceEnvelope,
    RunState,
    SandboxDestroyResult,
    SandboxSessionRequest,
)
from aegis.beast.inventory import LAUNCHABLE_BEAST_TARGETS, target
from aegis.beast.observe import decision_requirements, evidence_sufficient, normalize
from aegis.beast.store import BeastStore
from aegis.beast.toolbox import sandbox_toolbox
from aegis.beast.verifier import BeastVerifier
from aegis.settings import Settings

_OBJECTIVES = {
    "endpoint_discovery": (
        "Retrieve and preserve the public representation at the supplied base path, follow only "
        "documentation or discovery references actually observed in responses, and map the public "
        "API paths. Retain observed paths as evidence and stop when the useful surface is mapped."
    ),
    "information_exposure": (
        "Determine whether source-control metadata or configuration is publicly exposed below the "
        "authorized base path. Use non-destructive requests and retain direct response evidence."
    ),
    "bola_readonly": (
        "Determine whether synthetic public user A can read an account object owned by synthetic "
        "public user B. Establish useful controls and perform read-only requests only."
    ),
    "safe_injection": (
        "Determine whether the synthetic catalog search safely handles injection-like input. "
        "Compare a benign control with a bounded non-destructive probe."
    ),
}
# The disposable execution boundary is provider-independent: the model only proposes typed command
# text through the credential-free gateway, while the controller/sandbox still own scope, budgets,
# execution and verification. The adversary always runs on the operator's currently selected
# gateway model (the gateway's reviewed allowlist governs what can be selected), and each decision
# is identity-checked against that selection at run time. Only providers with a real adversary
# decide route are admitted: Ollama, DeepSeek and OpenRouter. The internal OpenAI-compatible
# profile has no adversary route (the gateway rejects it with BEAST_REQUIRES_SUPPORTED_PROVIDER),
# so admitting it here would let a run pass preflight and fail on its first decision call.
_SUPPORTED_BEAST_PROVIDERS = frozenset({"ollama", "deepseek", "openrouter"})
# Ollama reports a local content digest and reproducible seed; hosted public-egress models can only
# record the reported model id, request parameters, token counts and timings. Provenance is verified
# against the field set the provider family can actually attest — never invented for the other.
_OLLAMA_PROVENANCE_FIELDS = frozenset(
    {
        "provider_type",
        "runtime_version",
        "model_digest",
        "context_length",
        "temperature",
        "seed",
        "prompt_eval_count",
        "eval_count",
        "total_duration_ms",
    }
)
_HOSTED_PROVENANCE_FIELDS = frozenset(
    {
        "provider_type",
        "runtime",
        "model",
        "temperature",
        "seed",
        "prompt_eval_count",
        "eval_count",
    }
)
_PUBLIC_ACCOUNTS = [
    {
        "profile": "public_user_a",
        "bearer_token": "lab-token-user-a",
        "account_id": "A-100",
    },
    {
        "profile": "public_user_b",
        "bearer_token": "lab-token-user-b",
        "account_id": "B-200",
    },
]


class BeastRejected(ValueError):
    pass


class BeastController:
    def __init__(
        self,
        settings: Settings,
        store: BeastStore,
        *,
        gateway_transport: httpx.AsyncBaseTransport | None = None,
        sandbox_transport: httpx.AsyncBaseTransport | None = None,
        verifier_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.gateway_transport = gateway_transport
        self.sandbox_transport = sandbox_transport
        self.verifier = BeastVerifier(settings.lab_base_url, verifier_transport)
        self.resources = ResourceEnvelope()
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def preflight(self, target_ref: str) -> BeastPreflight:
        try:
            selected = target(target_ref)
        except ValueError as exc:
            raise BeastRejected(str(exc)) from None
        self._eligible(selected)
        block = self.store.target_block(selected.target_ref)
        if block is not None:
            raise BeastRejected(f"TARGET_REACTIVATION_BLOCKED:{block['reason']}")
        return BeastPreflight(
            target=selected,
            enabled_capabilities=list(_OBJECTIVES),
            enabled_engines=["AI_ADVERSARY_SHELL", "DETERMINISTIC_VERIFIER"],
            resources=self.resources,
            automatic_expiry_seconds=min(
                self.settings.beast_lease_seconds, BEAST_MAX_LEASE_SECONDS
            ),
            emergency_stop=(
                "Immediately revoke the lease, stop admission, kill the command process tree, "
                "disarm target access, preserve audit evidence, and require operator review."
            ),
        )

    def _eligible(self, selected: Any) -> None:
        if not self.settings.beast_enabled:
            raise BeastRejected("BEAST_MODE_DISABLED")
        if self.settings.ai_provider not in _SUPPORTED_BEAST_PROVIDERS:
            raise BeastRejected("BEAST_REQUIRES_SUPPORTED_PROVIDER")
        # The adversary runs on the model the operator currently selected in the console — the
        # gateway's reviewed allowlist governs what can be selected, and each decision response is
        # identity-checked against that selection in the run loop (MODEL_IDENTITY_MISMATCH).
        if selected.origin != "http://beast-target:8080":
            raise BeastRejected("TARGET_ORIGIN_NOT_IN_IMMUTABLE_NETWORK_SCOPE")
        if (
            "*" in selected.allowed_path_prefix
            or selected.allowed_path_prefix != selected.base_path
        ):
            raise BeastRejected("WILDCARD_OR_MISMATCHED_PATH_SCOPE_REJECTED")
        if selected.environment is not EnvironmentClass.SYNTHETIC_LAB:
            # Phase 1.4 deliberately does not enable staging, even if inventory is later extended.
            raise BeastRejected("PHASE_1_4_SYNTHETIC_LAB_ONLY")
        if not selected.active_testing_authorized:
            raise BeastRejected("ACTIVE_TESTING_NOT_AUTHORIZED")
        if not selected.reset_available:
            raise BeastRejected("RESET_CAPABILITY_REQUIRED")
        if not selected.synthetic_data_only or selected.health != "GREEN":
            raise BeastRejected("TARGET_HEALTH_OR_DATA_CLASSIFICATION_REJECTED")

    def issue_lease(self, request: LeaseRequest) -> BeastLease:
        request_id = f"request-{uuid4().hex[:12]}"
        self.store.audit(
            request_id,
            "BEAST_MODE_REQUESTED",
            "OPERATOR",
            {"operator_id": request.operator_id, "target_ref": request.target_ref},
        )
        self.store.audit(request_id, "BEAST_PREFLIGHT_STARTED", "CONTROLLER")
        try:
            preflight = self.preflight(request.target_ref)
            expected = f"ASSESS {preflight.target.name}"
            if request.actor_type != "OPERATOR":
                raise BeastRejected("MODEL_CANNOT_ACTIVATE_BEAST_MODE")
            if request.profile_id != BEAST_PROFILE_ID:
                raise BeastRejected("PROFILE_MISMATCH")
            if request.confirmation != expected:
                raise BeastRejected("ACTIVATION_PHRASE_MISMATCH")
            if request.operator_profile_id is not None and (
                request.operator_profile_id not in TOOLBOX_PROFILE_SCENARIOS
            ):
                raise BeastRejected("OPERATOR_PROFILE_NOT_TOOLBOX_BOUND")
            if request.requested_resources is not None:
                baseline = self.resources.model_dump()
                requested = request.requested_resources.model_dump()
                if any(requested[key] > baseline[key] for key in baseline):
                    raise BeastRejected("RESOURCE_ENVELOPE_EXPANSION_REJECTED")
        except (BeastRejected, ValueError) as exc:
            self.store.audit(
                request_id,
                "BEAST_PREFLIGHT_REJECTED",
                "CONTROLLER",
                {"code": str(exc)},
            )
            raise BeastRejected(str(exc)) from None
        now = datetime.now(UTC)
        # A lease issued under an operator-facing TOOLBOX profile authorizes exactly that
        # profile's bound scenario — create_run then rejects every other scenario server-side.
        capability_set = (
            [TOOLBOX_PROFILE_SCENARIOS[request.operator_profile_id]]
            if request.operator_profile_id is not None
            else list(_OBJECTIVES)
        )
        lease = BeastLease(
            lease_id=f"beast-lease-{uuid4().hex[:16]}",
            operator_id=request.operator_id,
            target_ref=request.target_ref,
            profile_id=request.profile_id,
            operator_profile_id=request.operator_profile_id,
            capability_set=capability_set,
            resources=request.requested_resources or self.resources,
            state=LeaseState.ACTIVE,
            issued_at=now,
            expires_at=now
            + timedelta(seconds=min(self.settings.beast_lease_seconds, BEAST_MAX_LEASE_SECONDS)),
        )
        self.store.save_lease(lease)
        self.store.audit(
            lease.lease_id,
            "BEAST_APPROVAL_RECORDED",
            "OPERATOR",
            {
                "operator_id": lease.operator_id,
                "approval_reference": preflight.target.approval_reference,
            },
        )
        self.store.audit(
            lease.lease_id,
            "BEAST_LEASE_ISSUED",
            "CONTROLLER",
            {
                "target_ref": lease.target_ref,
                "profile_id": lease.profile_id,
                "operator_profile_id": lease.operator_profile_id,
                "expires_at": lease.expires_at.isoformat(),
                "single_run": True,
            },
        )
        return lease

    def create_run(self, request: BeastRunRequest) -> BeastRun:
        lease = self.store.get_lease(request.lease_id)
        if lease is None:
            raise BeastRejected("LEASE_NOT_FOUND")
        if not lease.active_at():
            if lease.state is LeaseState.ACTIVE:
                lease.state = LeaseState.EXPIRED
                self.store.save_lease(lease)
                self.store.audit(lease.lease_id, "BEAST_LEASE_EXPIRED", "CONTROLLER")
            raise BeastRejected("LEASE_NOT_ACTIVE")
        # A profile-bound lease authorizes exactly one scenario; the generic sandbox lease keeps
        # the full objective set. Both paths fail closed on anything the lease did not authorize.
        if request.scenario_id not in lease.capability_set:
            raise BeastRejected("SCENARIO_NOT_AUTHORIZED_BY_LEASE")
        if self.store.active_runs():
            # There is one disposable sandbox and one target gateway. Concurrent admission would
            # let a second run disarm or replace the first run's exact network scope.
            raise BeastRejected("BEAST_SANDBOX_ALREADY_ACTIVE")
        selected = target(lease.target_ref)
        self._eligible(selected)
        run = BeastRun(
            run_id=f"beast-run-{uuid4().hex[:16]}",
            lease_id=lease.lease_id,
            target_ref=lease.target_ref,
            scenario_id=request.scenario_id,
            state=RunState.QUEUED,
            model=self.settings.ai_model,
            operator_profile_id=lease.operator_profile_id,
            resources=lease.resources,
            created_at=datetime.now(UTC),
            lease_expires_at=lease.expires_at,
        )
        lease.state = LeaseState.CONSUMED
        lease.run_id = run.run_id
        self.store.save_lease(lease)
        self.store.save_run(run)
        self.store.audit(
            run.run_id,
            "BEAST_MODE_ACTIVATED",
            "CONTROLLER",
            {
                "lease_id": lease.lease_id,
                "target_ref": lease.target_ref,
                "scenario_id": request.scenario_id,
                "operator_profile_id": lease.operator_profile_id,
            },
        )
        return run

    def schedule(self, run_id: str) -> None:
        self._tasks[run_id] = asyncio.create_task(self.run(run_id))

    async def _post(
        self,
        url: str,
        payload: dict[str, Any] | None = None,
        *,
        sandbox: bool = False,
        request_timeout_seconds: float = 90,
    ) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        transport = self.gateway_transport
        if sandbox:
            transport = self.sandbox_transport
            token = self.settings.beast_supervisor_token
            if token is None or not token.get_secret_value():
                raise BeastRejected("SANDBOX_SUPERVISOR_TOKEN_MISSING")
            headers["X-Beast-Supervisor-Token"] = token.get_secret_value()
        async with httpx.AsyncClient(
            timeout=request_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise BeastRejected("NON_OBJECT_COMPONENT_RESPONSE")
            return value

    async def run(self, run_id: str) -> None:
        run = self.store.get_run(run_id)
        if run is None:
            return
        lease = self.store.get_lease(run.lease_id)
        if lease is None:
            return
        selected = target(run.target_ref)
        run.state = RunState.RUNNING
        run.started_at = datetime.now(UTC)
        self.store.save_run(run)
        started = monotonic()
        session_created = False
        try:
            session = await self._post(
                f"{self.settings.beast_supervisor_url}/v1/sessions",
                SandboxSessionRequest(
                    run_id=run.run_id,
                    target_origin=selected.origin,
                    allowed_path_prefix=selected.allowed_path_prefix,
                    allowed_methods=selected.allowed_methods,
                    resources=lease.resources,
                ).model_dump(mode="json"),
                sandbox=True,
            )
            session_created = bool(session.get("ready"))
            if not session_created:
                raise BeastRejected("SANDBOX_NOT_READY")
            self.store.audit(
                run.run_id,
                "BEAST_CAPABILITY_AUTHORIZED",
                "CONTROLLER",
                {
                    "profile_id": BEAST_PROFILE_ID,
                    "sandbox_instance_id": session.get("sandbox_instance_id"),
                },
            )
            parent: str | None = None
            explicit_stop = False
            for sequence in range(1, lease.resources.max_commands + 1):
                fresh_lease = self.store.get_lease(run.lease_id)
                elapsed = monotonic() - started
                if run.emergency_stopped or (
                    fresh_lease and fresh_lease.state is LeaseState.REVOKED
                ):
                    raise BeastRejected("EMERGENCY_STOP")
                if datetime.now(UTC) >= lease.expires_at:
                    self.store.audit(run.run_id, "BEAST_LEASE_EXPIRED", "CONTROLLER")
                    raise BeastRejected("LEASE_EXPIRED")
                if elapsed >= lease.resources.total_wall_time_seconds:
                    self.store.audit(
                        run.run_id,
                        "SANDBOX_RESOURCE_LIMIT_REACHED",
                        "CONTROLLER",
                        {"resource": "total_wall_time"},
                    )
                    raise BeastRejected("TOTAL_WALL_TIME_EXHAUSTED")
                decision_request = BeastDecisionRequest(
                    run_id=run.run_id,
                    scenario_id=run.scenario_id,
                    objective=_OBJECTIVES[run.scenario_id],
                    target_origin=selected.origin,
                    target_base_path=selected.base_path,
                    synthetic_public_accounts=_PUBLIC_ACCOUNTS,
                    sequence=sequence,
                    remaining_commands=lease.resources.max_commands - sequence + 1,
                    remaining_time_seconds=max(
                        0, lease.resources.total_wall_time_seconds - int(elapsed)
                    ),
                    objective_evidence_sufficient=evidence_sufficient(
                        run.scenario_id, run.observations
                    ),
                    decision_requirements=decision_requirements(run.scenario_id, run.observations),
                    observations=run.observations,
                    available_tools=sandbox_toolbox(),
                )
                model_result = BeastDecisionResponse.model_validate(
                    await self._post(
                        f"{self.settings.llm_gateway_url}/v1/beast/decide",
                        decision_request.model_dump(mode="json"),
                        request_timeout_seconds=self.settings.model_timeout_seconds + 5,
                    )
                )
                current_run = self.store.get_run(run.run_id)
                current_lease = self.store.get_lease(run.lease_id)
                if (current_run and current_run.emergency_stopped) or (
                    current_lease and current_lease.state is LeaseState.REVOKED
                ):
                    raise BeastRejected("EMERGENCY_STOP")
                if model_result.model != self.settings.ai_model:
                    raise BeastRejected("MODEL_IDENTITY_MISMATCH")
                # Provenance is verified per provider family. Local Ollama attests a content
                # digest, runtime version, context length and a reproducible seed; hosted
                # public-egress models (DeepSeek / OpenRouter) attest the reported model id,
                # request parameters, token counts and timings — a digest simply does not exist
                # upstream, so none is claimed.
                provider_type = str(model_result.metadata.get("provider_type", ""))
                if provider_type == "ollama":
                    provenance_complete = _OLLAMA_PROVENANCE_FIELDS <= model_result.metadata.keys()
                elif provider_type in {"deepseek", "openrouter"}:
                    provenance_complete = _HOSTED_PROVENANCE_FIELDS <= model_result.metadata.keys()
                else:
                    provenance_complete = False
                if not provenance_complete:
                    raise BeastRejected("LIVE_MODEL_PROVENANCE_INCOMPLETE")
                model_call = {
                    "sequence": sequence,
                    "model": model_result.model,
                    "usage": model_result.usage,
                    "metadata": model_result.metadata,
                    "decision_type": model_result.decision.decision_type,
                    "input_observation_ids": [
                        item.observation_id for item in decision_request.observations
                    ],
                }
                run.model_calls.append(model_call)
                self.store.audit(run.run_id, "AI_ADVERSARY_DECISION", "AI_MODEL", model_call)
                if isinstance(model_result.decision, BeastStopDecision):
                    known = {item.observation_id for item in run.observations}
                    if not set(model_result.decision.evidence_observation_ids) <= known:
                        raise BeastRejected("MODEL_STOP_REFERENCES_UNKNOWN_OBSERVATION")
                    if not evidence_sufficient(run.scenario_id, run.observations):
                        raise BeastRejected("MODEL_STOP_WITH_INSUFFICIENT_OBSERVATION")
                    explicit_stop = True
                    self.store.audit(
                        run.run_id,
                        "AI_ADVERSARY_STOPPED",
                        "AI_MODEL",
                        model_result.decision.model_dump(mode="json"),
                    )
                    break
                decision = model_result.decision
                if not isinstance(decision, BeastCommandDecision):
                    raise BeastRejected("UNKNOWN_MODEL_DECISION")
                command = CommandTransport(
                    command_id=f"cmd-{run.run_id}-{sequence:03d}",
                    parent_command_id=parent,
                    run_id=run.run_id,
                    sequence=sequence,
                    command_text=decision.command_text,
                    working_directory_reference=f"workspace:{run.run_id}",
                    timeout_seconds=min(
                        lease.resources.per_command_timeout_seconds,
                        max(1, lease.resources.total_wall_time_seconds - int(elapsed)),
                    ),
                    output_limit_bytes=lease.resources.stdout_stderr_bytes,
                    artifact_limit_bytes=lease.resources.artifact_bytes,
                    expected_intent=decision.expected_intent,
                    hypothesis_reference=decision.hypothesis,
                )
                run.commands.append(command)
                command_details = command.model_dump(mode="json")
                command_details["command_sha256"] = hashlib.sha256(
                    command.command_text.encode()
                ).hexdigest()
                self.store.audit(
                    run.run_id, "AI_SHELL_COMMAND_PROPOSED", "AI_MODEL", command_details
                )
                self.store.audit(
                    run.run_id,
                    "AI_SHELL_COMMAND_STARTED",
                    "SANDBOX_SUPERVISOR",
                    {"command_id": command.command_id, "sequence": sequence},
                )
                result = CommandResult.model_validate(
                    await self._post(
                        f"{self.settings.beast_supervisor_url}/v1/commands",
                        command.model_dump(mode="json"),
                        sandbox=True,
                        request_timeout_seconds=command.timeout_seconds + 10,
                    )
                )
                run.results.append(result)
                event = (
                    "AI_SHELL_COMMAND_TIMED_OUT"
                    if result.timed_out
                    else "AI_SHELL_COMMAND_TERMINATED"
                    if result.terminated
                    else "AI_SHELL_COMMAND_COMPLETED"
                )
                self.store.audit(
                    run.run_id, event, "SANDBOX_SUPERVISOR", result.model_dump(mode="json")
                )
                if result.output_truncated:
                    self.store.audit(
                        run.run_id,
                        "AI_SHELL_OUTPUT_REDACTED",
                        "SANDBOX_SUPERVISOR",
                        {"command_id": command.command_id, "reason": "OUTPUT_LIMIT"},
                    )
                observation = normalize(run.run_id, sequence, result, command.command_text)
                run.observations.append(observation)
                self.store.audit(
                    run.run_id,
                    "AI_ADVERSARY_OBSERVATION",
                    "CONTROLLER",
                    observation.model_dump(mode="json"),
                )
                parent = command.command_id
                current_run = self.store.get_run(run.run_id)
                current_lease = self.store.get_lease(run.lease_id)
                if (current_run and current_run.emergency_stopped) or (
                    current_lease and current_lease.state is LeaseState.REVOKED
                ):
                    run.emergency_stopped = True
                    run.state = RunState.STOPPED
                    run.stop_reason = "EMERGENCY_STOP"
                    self.store.save_run(run)
                    raise BeastRejected("EMERGENCY_STOP")
                self.store.save_run(run)
                if lease.resources.max_commands - sequence == 2:
                    self.store.audit(
                        run.run_id,
                        "BEAST_BUDGET_WARNING",
                        "CONTROLLER",
                        {"resource": "max_commands", "remaining": 2},
                    )
            if not explicit_stop:
                self.store.audit(
                    run.run_id,
                    "BEAST_BUDGET_EXHAUSTED",
                    "CONTROLLER",
                    {"resource": "max_commands"},
                )
                raise BeastRejected("MODEL_DID_NOT_EXPLICITLY_STOP")
            current_run = self.store.get_run(run.run_id)
            current_lease = self.store.get_lease(run.lease_id)
            if (current_run and current_run.emergency_stopped) or (
                current_lease and current_lease.state is LeaseState.REVOKED
            ):
                raise BeastRejected("EMERGENCY_STOP")
            self.store.audit(
                run.run_id, "VERIFICATION_STARTED", "VERIFIER", {"scenario_id": run.scenario_id}
            )
            conclusion = await self.verifier.verify(selected, run.scenario_id)
            run.verifier_conclusion = conclusion
            self.store.audit(run.run_id, "VERIFICATION_COMPLETED", "VERIFIER", conclusion)
            status = str(conclusion.get("status"))
            if status in {"CONFIRMED", "VERIFIED"}:
                run.state = RunState.VERIFIED
            elif status == "PASS":
                run.state = RunState.PASS
            else:
                run.state = RunState.REVIEW_REQUIRED
            run.stop_reason = f"VERIFIER_{status}"
        except (BeastRejected, httpx.HTTPError, ValueError) as exc:
            latest = self.store.get_run(run_id)
            if latest and latest.emergency_stopped:
                run.emergency_stopped = True
                run.state = RunState.STOPPED
                run.stop_reason = "EMERGENCY_STOP"
            else:
                run.state = RunState.INCOMPLETE
                run.stop_reason = str(exc)[:160]
            self.store.audit(
                run.run_id, "BEAST_CAPABILITY_REJECTED", "CONTROLLER", {"code": run.stop_reason}
            )
        finally:
            self.store.audit(run.run_id, "BEAST_CLEANUP_STARTED", "CONTROLLER")
            try:
                if session_created:
                    destroyed = SandboxDestroyResult.model_validate(
                        await self._post(
                            f"{self.settings.beast_supervisor_url}/v1/runs/{run.run_id}/destroy",
                            {},
                            sandbox=True,
                            request_timeout_seconds=20,
                        )
                    )
                    run.workspace_destroyed = destroyed.destroyed
                    run.cleanup_verified = destroyed.destroyed
                    if not destroyed.destroyed:
                        raise BeastRejected("SANDBOX_DESTROY_NOT_VERIFIED")
                    for artifact in destroyed.artifacts:
                        if "reference" in artifact:
                            self.store.audit(
                                run.run_id, "AI_ARTIFACT_CREATED", "SANDBOX_SUPERVISOR", artifact
                            )
                            self.store.audit(
                                run.run_id,
                                (
                                    "AI_ARTIFACT_ADMITTED"
                                    if artifact.get("disposition") == "ADMITTED"
                                    else "AI_ARTIFACT_REJECTED"
                                ),
                                "SANDBOX_SUPERVISOR",
                                artifact,
                            )
                        boundary = (
                            artifact.get("network_boundary") if isinstance(artifact, dict) else None
                        )
                        if isinstance(boundary, dict):
                            for blocked in boundary.get("blocked", []):
                                self.store.audit(
                                    run.run_id,
                                    "SANDBOX_NETWORK_BLOCKED",
                                    "SANDBOX_SUPERVISOR",
                                    blocked,
                                )
                    self.store.audit(
                        run.run_id,
                        "SANDBOX_DESTROYED",
                        "SANDBOX_SUPERVISOR",
                        {"destroyed": destroyed.destroyed},
                    )
                    self.store.audit(
                        run.run_id,
                        "BEAST_CLEANUP_COMPLETED",
                        "CONTROLLER",
                        {"verified": destroyed.destroyed},
                    )
                else:
                    run.workspace_destroyed = True
                    run.cleanup_verified = True
                    self.store.audit(
                        run.run_id,
                        "BEAST_CLEANUP_COMPLETED",
                        "CONTROLLER",
                        {"verified": True, "session_created": False},
                    )
            except (httpx.HTTPError, ValueError, BeastRejected) as exc:
                run.cleanup_verified = False
                run.state = RunState.REVIEW_REQUIRED
                run.stop_reason = "CLEANUP_FAILED"
                self.store.block_target(run.target_ref, "CLEANUP_FAILED", run.run_id)
                self.store.audit(
                    run.run_id, "BEAST_CLEANUP_FAILED", "CONTROLLER", {"code": type(exc).__name__}
                )
            latest_run = self.store.get_run(run.run_id)
            if latest_run is not None and latest_run.emergency_stopped:
                run.emergency_stopped = True
                run.state = RunState.STOPPED
                run.stop_reason = "EMERGENCY_STOP"
                run.verifier_conclusion = None
            latest_lease = self.store.get_lease(run.lease_id)
            if latest_lease is not None:
                latest_lease.state = LeaseState.REVOKED
                latest_lease.revocation_reason = run.stop_reason or "RUN_COMPLETED"
                self.store.save_lease(latest_lease)
            if run.emergency_stopped:
                self.store.block_target(
                    run.target_ref, "EMERGENCY_STOP_REVIEW_REQUIRED", run.run_id
                )
            run.completed_at = datetime.now(UTC)
            self.store.save_run(run)
            self.store.audit(
                run.run_id,
                "BEAST_MODE_COMPLETED",
                "CONTROLLER",
                {"state": run.state.value, "stop_reason": run.stop_reason},
            )

    async def emergency_stop(self, run_id: str, operator_id: str) -> BeastRun:
        run = self.store.get_run(run_id)
        if run is None:
            raise BeastRejected("RUN_NOT_FOUND")
        lease = self.store.get_lease(run.lease_id)
        self.store.audit(
            run_id, "BEAST_EMERGENCY_STOP_REQUESTED", "OPERATOR", {"operator_id": operator_id}
        )
        if lease:
            lease.state = LeaseState.REVOKED
            lease.revocation_reason = "EMERGENCY_STOP"
            self.store.save_lease(lease)
        run.emergency_stopped = True
        run.state = RunState.STOPPED
        run.stop_reason = "EMERGENCY_STOP"
        self.store.save_run(run)
        self.store.block_target(run.target_ref, "EMERGENCY_STOP_REVIEW_REQUIRED", run.run_id)
        result: dict[str, Any] = {}
        try:
            result = await self._post(
                f"{self.settings.beast_supervisor_url}/v1/runs/{run_id}/destroy",
                {},
                sandbox=True,
                request_timeout_seconds=10,
            )
            latest = self.store.get_run(run_id) or run
            latest.emergency_stopped = True
            latest.state = RunState.STOPPED
            latest.stop_reason = "EMERGENCY_STOP"
            latest.verifier_conclusion = None
            latest.workspace_destroyed = bool(result.get("destroyed"))
            latest.cleanup_verified = bool(result.get("destroyed"))
            self.store.save_run(latest)
            run = latest
        finally:
            self.store.audit(run_id, "BEAST_EMERGENCY_STOP_COMPLETED", "CONTROLLER", result)
        return run

    async def restore_target(self, target_ref: str, operator_id: str) -> dict[str, Any]:
        selected = target(target_ref)
        self._eligible(selected)
        block = self.store.target_block(target_ref)
        if block is None:
            return {"target_ref": target_ref, "health": "GREEN", "reactivation_blocked": False}
        health = await self.verifier.health(selected)
        if not health.get("healthy"):
            raise BeastRejected("TARGET_HEALTH_RESTORE_FAILED")
        self.store.clear_target_block(target_ref)
        self.store.audit(
            block["run_id"],
            "BEAST_TARGET_HEALTH_RESTORED",
            "OPERATOR",
            {"operator_id": operator_id, "target_ref": target_ref, "health": health},
        )
        return {"target_ref": target_ref, "health": "GREEN", "reactivation_blocked": False}

    def config(self) -> dict[str, Any]:
        tools = sandbox_toolbox()
        return {
            "enabled": self.settings.beast_enabled,
            "mode": BeastMode.SAFE_PASSIVE,
            "available_mode": BeastMode.BEAST_ACTIVE if self.settings.beast_enabled else None,
            "profile_id": BEAST_PROFILE_ID,
            # The adversary runs on the model the operator currently selected in the console; the
            # gateway's reviewed allowlist governs what can be selected. This is therefore the
            # live selection, not a fixed boot-time requirement.
            "required_model": self.settings.ai_model,
            "synthetic_lab_only": True,
            "target_refs": list(LAUNCHABLE_BEAST_TARGETS),
            "tools": [tool.model_dump(mode="json") for tool in tools],
            "technical_subtitle": "Autonomous assessment toolbox",
            "boundary_description": (
                "Tool execution inside a controller-bounded disposable environment."
            ),
        }

    async def toolbox_health(self) -> dict[str, Any]:
        """Return a live, bounded execution probe for every advertised assessment tool."""

        inventory = sandbox_toolbox()
        checked_at = datetime.now(UTC).isoformat()
        if not self.settings.beast_enabled:
            return {
                "state": "UNAVAILABLE",
                "checked_at": checked_at,
                "reason": "The disposable toolbox service is not enabled in this deployment.",
                "tools": [
                    {
                        **tool.model_dump(mode="json"),
                        "status": "UNAVAILABLE",
                        "detail": "service disabled",
                    }
                    for tool in inventory
                ],
            }

        try:
            async with httpx.AsyncClient(
                transport=self.sandbox_transport,
                timeout=35,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(f"{self.settings.beast_supervisor_url}/health")
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError):
            payload = {}

        raw_checks = payload.get("tool_checks") if isinstance(payload, dict) else None
        checks = raw_checks if isinstance(raw_checks, dict) else {}
        projected: list[dict[str, Any]] = []
        for tool in inventory:
            raw = checks.get(tool.name)
            check = raw if isinstance(raw, dict) else {}
            status = str(check.get("status", "UNAVAILABLE"))
            if status not in {"READY", "MISSING", "ERROR", "UNAVAILABLE"}:
                status = "ERROR"
            projected.append(
                {
                    **tool.model_dump(mode="json"),
                    "status": status,
                    "detail": str(check.get("detail", "health check unavailable"))[:160],
                }
            )
        ready = sum(tool["status"] == "READY" for tool in projected)
        total = len(projected)
        return {
            "state": "READY" if ready == total else "DEGRADED" if ready else "UNAVAILABLE",
            "checked_at": checked_at,
            "reason": ""
            if ready == total
            else (
                f"{total - ready} of {total} toolbox commands failed their runtime check."
                if ready
                else "The toolbox supervisor did not return a successful tool probe."
            ),
            "ready": ready,
            "total": total,
            "tools": projected,
        }
