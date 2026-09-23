"""Controller-owned Lead/Surface/Authorization vertical slice for Aegis Bank BOLA."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import TypeVar
from uuid import uuid4

import httpx
from pydantic import BaseModel

from aegis.multi_agent.broker import ControlledToolBroker
from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentActionRequest,
    AgentActionResult,
    AgentAuditEvent,
    AgentHypothesis,
    AgentObservation,
    AgentRole,
    AgentRun,
    AgentRunState,
    AgentTask,
    AgentTaskContext,
    AgentTaskState,
    AuthorizationAgentOutput,
    BudgetLimit,
    BudgetUsage,
    EvaluationVerdict,
    FindingCandidate,
    LeadTaskOutput,
    ObservationType,
    RunEvaluation,
    RunMetrics,
    SingleAgentOutput,
    SurfaceAgentOutput,
    VerifierResultRef,
)
from aegis.multi_agent.model import AgentModel
from aegis.multi_agent.store import MultiAgentStore
from aegis_range.controller import RangeController
from aegis_range.runtime import Mode

T = TypeVar("T", bound=BaseModel)

_TERMINAL = {
    AgentRunState.COMPLETED,
    AgentRunState.FAILED,
    AgentRunState.CANCELLED,
}
_RUN_TRANSITIONS: dict[AgentRunState, frozenset[AgentRunState]] = {
    AgentRunState.QUEUED: frozenset({AgentRunState.RESETTING, AgentRunState.CANCELLED}),
    AgentRunState.RESETTING: frozenset(
        {AgentRunState.RUNNING, AgentRunState.FAILED, AgentRunState.CANCELLED}
    ),
    AgentRunState.RUNNING: frozenset(
        {AgentRunState.VERIFYING, AgentRunState.FAILED, AgentRunState.CANCELLED}
    ),
    AgentRunState.VERIFYING: frozenset(
        {AgentRunState.CLEANING_UP, AgentRunState.FAILED, AgentRunState.CANCELLED}
    ),
    AgentRunState.CLEANING_UP: frozenset(
        {AgentRunState.COMPLETED, AgentRunState.FAILED, AgentRunState.CANCELLED}
    ),
    AgentRunState.COMPLETED: frozenset(),
    AgentRunState.FAILED: frozenset(),
    AgentRunState.CANCELLED: frozenset(),
}


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:16]}"


class MultiAgentRuntime:
    def __init__(
        self,
        model: AgentModel,
        controller: RangeController,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        *,
        store: MultiAgentStore | None = None,
        global_limit: BudgetLimit | None = None,
        per_agent_limit: BudgetLimit | None = None,
    ) -> None:
        self.model = model
        self.controller = controller
        self.transports = transports or {}
        self.store = store
        self.global_limit = global_limit or BudgetLimit(
            model_calls=6,
            tokens=12_000,
            target_requests=8,
            commands=0,
            elapsed_ms=30_000,
            evidence_bytes=524_288,
        )
        self.per_agent_limit = per_agent_limit or BudgetLimit(
            model_calls=6,
            tokens=12_000,
            target_requests=8,
            commands=0,
            elapsed_ms=30_000,
            evidence_bytes=524_288,
        )
        self._runs: dict[str, AgentRun] = {}
        self._tasks: dict[str, list[AgentTask]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def transition(run: AgentRun, target: AgentRunState) -> None:
        if target not in _RUN_TRANSITIONS[run.state]:
            raise ValueError("INVALID_RUN_STATE_TRANSITION")
        run.state = target
        if target in _TERMINAL:
            run.completed_at = datetime.now(UTC)

    async def cancel(self, run_id: str) -> None:
        run = self._runs.get(run_id)
        if run is None:
            raise ValueError("RUN_NOT_FOUND")
        async with self._locks[run_id]:
            if run.state in _TERMINAL:
                raise ValueError("TERMINAL_RUN_IMMUTABLE")
            run.stop_requested = True
            self.transition(run, AgentRunState.CANCELLED)
            run.verdict = EvaluationVerdict.CANCELLED
            for task in self._tasks.get(run_id, []):
                if task.state in {AgentTaskState.QUEUED, AgentTaskState.RUNNING}:
                    task.state = AgentTaskState.CANCELLED
                    task.completed_at = datetime.now(UTC)

    @staticmethod
    def _context(scenario_id: str, observations: list[str] | None = None) -> AgentTaskContext:
        return AgentTaskContext(
            target_ref="range-bank",
            scenario_ref=scenario_id,
            allowed_operation_ids=["getAccount", "listAccountTransactions"],
            credential_aliases=["cred-bank-alex", "cred-bank-blair"],
            resource_refs=["resource-account-owner", "resource-account-alternate"],
            observation_refs=observations or [],
        )

    def _task(
        self,
        run: AgentRun,
        agent_id: str,
        role: AgentRole,
        task_type: str,
        *,
        parent: AgentTask | None = None,
        observations: list[str] | None = None,
    ) -> AgentTask:
        task = AgentTask(
            task_id=_id("task"),
            run_id=run.run_id,
            agent_id=agent_id,
            role=role,
            task_type=task_type,  # type: ignore[arg-type]
            parent_task_id=parent.task_id if parent else None,
            context=self._context(run.scenario_id, observations),
        )
        self._tasks[run.run_id].append(task)
        return task

    @staticmethod
    def _audit(
        events: list[AgentAuditEvent],
        run: AgentRun,
        event_type: str,
        summary: str,
        *,
        actor: str = "CONTROLLER",
        task: AgentTask | None = None,
    ) -> None:
        events.append(
            AgentAuditEvent(
                event_id=_id("maevt"),
                run_id=run.run_id,
                task_id=task.task_id if task else None,
                agent_id=task.agent_id if task else None,
                actor=actor,  # type: ignore[arg-type]
                event_type=event_type,
                summary=summary,
            )
        )

    @staticmethod
    def _ensure_active(run: AgentRun) -> None:
        if run.stop_requested or run.state is AgentRunState.CANCELLED:
            raise asyncio.CancelledError

    async def _generate(
        self,
        budget: AtomicBudget,
        run: AgentRun,
        task: AgentTask,
        context: dict[str, object],
        output_type: type[T],
    ) -> T:
        self._ensure_active(run)
        await budget.consume(task.agent_id, BudgetUsage(model_calls=1))
        result = await self.model.generate(
            task.role,
            task.task_type,
            context,
            output_type.model_json_schema(),
        )
        self._ensure_active(run)
        await budget.consume(
            task.agent_id,
            BudgetUsage(
                input_tokens=result.usage.input_tokens,
                output_tokens=result.usage.output_tokens,
            ),
        )
        # JSON-mode validation makes strict models accept JSON primitives while still rejecting
        # unknown fields and coercion from non-JSON Python values.
        output = output_type.model_validate_json(result.payload_json)
        serialized = output.model_dump_json().lower()
        if any(
            marker in serialized for marker in ("http://", "https://", "range-user-", "bearer ")
        ):
            raise ValueError("AGENT_OUTPUT_FORBIDDEN_CONTENT")
        return output

    async def execute(
        self,
        *,
        mode: Mode,
        execution_mode: str = "multi_agent",
        scenario_id: str = "bank-object-access-v1",
    ) -> RunEvaluation:
        if execution_mode not in {"single_agent", "multi_agent"}:
            raise ValueError("EXECUTION_MODE_INVALID")
        run = AgentRun(
            run_id=_id("marun"),
            target_ref="range-bank",
            application_id="aegis-bank",
            scenario_id=scenario_id,
            execution_mode=execution_mode,  # type: ignore[arg-type]
        )
        self._runs[run.run_id] = run
        self._tasks[run.run_id] = []
        self._locks[run.run_id] = asyncio.Lock()
        events: list[AgentAuditEvent] = []
        observations: list[AgentObservation] = []
        hypotheses: list[AgentHypothesis] = []
        action_requests: list[AgentActionRequest] = []
        actions: list[AgentActionResult] = []
        candidates: list[FindingCandidate] = []
        verifier_refs: list[VerifierResultRef] = []
        budget = AtomicBudget(run.run_id, self.global_limit)
        broker = ControlledToolBroker(budget, self.transports)
        started = time.monotonic()
        cleanup_ok = False
        before_generation: int | None = None
        try:
            self.transition(run, AgentRunState.RESETTING)
            before = await self.controller.reset_application("aegis-bank")
            if not before.healthy or before.reset_generation is None:
                raise RuntimeError("RANGE_RESET_FAILED")
            run.reset_generation_before = before.reset_generation
            before_generation = before.reset_generation
            await self.controller.select_mode("aegis-bank", scenario_id, mode)
            self.controller.link_run(run.run_id, "aegis-bank", scenario_id)
            self._audit(events, run, "RANGE_RESET", "Controller reset and selected the scenario.")
            self.transition(run, AgentRunState.RUNNING)

            if execution_mode == "multi_agent":
                auth_task = await self._multi_path(
                    run, budget, broker, events, observations, hypotheses
                )
            else:
                auth_task = await self._single_path(
                    run, budget, broker, events, observations, hypotheses
                )

            proposal = hypotheses[-1]
            issued = datetime.now(UTC)
            request = AgentActionRequest(
                action_id=_id("action"),
                nonce=uuid4().hex,
                run_id=run.run_id,
                task_id=auth_task.task_id,
                agent_id=auth_task.agent_id,
                role=auth_task.role,
                capability_id="aegis.authorization.compare",
                operation_id=proposal.operation_id,
                credential_aliases=[
                    proposal.owner_credential_alias,
                    proposal.alternate_credential_alias,
                ],
                resource_refs=[proposal.owner_resource_ref, proposal.alternate_resource_ref],
                issued_at=issued,
                expires_at=issued + timedelta(seconds=30),
            )
            action_requests.append(request)
            result, observation = await broker.execute(request, auth_task, _id("obs"))
            actions.append(result)
            observations.append(observation)
            candidate = FindingCandidate(
                candidate_id=_id("candidate"),
                run_id=run.run_id,
                hypothesis_id=proposal.hypothesis_id,
                observation_ref=observation.observation_id,
                category="BOLA",
            )
            candidates.append(candidate)
            auth_task.state = AgentTaskState.COMPLETED
            auth_task.completed_at = datetime.now(UTC)
            self._audit(
                events,
                run,
                "BROKER_ACTION_COMPLETED",
                "Controlled broker completed the bounded comparison.",
                actor="TOOL_BROKER",
                task=auth_task,
            )

            self.transition(run, AgentRunState.VERIFYING)
            run.active_role = None
            # The independent verifier performs three fresh requests for this scenario. They are
            # admitted to the central target-request budget before verification starts.
            await budget.consume(None, BudgetUsage(target_requests=3))
            verified = await self.controller.verify("aegis-bank", scenario_id)
            reference = _id("verify")
            verifier_ref = VerifierResultRef(
                reference=reference,
                run_id=run.run_id,
                authority="DETERMINISTIC_RANGE_VERIFIER",
                status=verified.status.value,
                evidence_sha256=verified.evidence_sha256,
                evidence_bytes=verified.evidence_bytes,
                summary="Independent verifier confirmed the candidate."
                if verified.status.value == "CONFIRMED"
                else "Independent verifier rejected the hypothesis with complete controls."
                if verified.status.value == "PASS"
                else "Independent verifier could not reach a complete result.",
            )
            await budget.consume(None, BudgetUsage(evidence_bytes=verified.evidence_bytes))
            verifier_refs.append(verifier_ref)
            run.verifier_result_ref = reference
            candidate.verifier_confirmed = verified.status.value == "CONFIRMED"
            run.verdict = EvaluationVerdict(verified.status.value)
            if execution_mode == "multi_agent":
                lead_task = next(
                    item
                    for item in reversed(self._tasks[run.run_id])
                    if item.role is AgentRole.LEAD_ORCHESTRATOR
                )
                handoff = json.dumps(
                    {
                        "reference": verifier_ref.reference,
                        "status": verifier_ref.status,
                        "summary": verifier_ref.summary,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                await budget.consume(lead_task.agent_id, BudgetUsage(evidence_bytes=len(handoff)))
                observations.append(
                    AgentObservation(
                        observation_id=_id("obs"),
                        run_id=run.run_id,
                        task_id=lead_task.task_id,
                        agent_id=lead_task.agent_id,
                        observation_type=ObservationType.VERIFIER_SUMMARY,
                        summary=verifier_ref.summary,
                        evidence_sha256=hashlib.sha256(handoff).hexdigest(),
                        evidence_bytes=len(handoff),
                    )
                )
            self._audit(
                events,
                run,
                "VERIFIER_RESULT",
                verifier_ref.summary,
                actor="VERIFIER",
            )

            self.transition(run, AgentRunState.CLEANING_UP)
            after = await self.controller.reset_application("aegis-bank")
            health = await self.controller.health("aegis-bank")
            cleanup_ok = bool(
                after.healthy
                and health.healthy
                and after.reset_generation is not None
                and after.reset_generation > before.reset_generation
            )
            run.reset_generation_after = after.reset_generation
            run.cleanup_succeeded = cleanup_ok
            if not cleanup_ok:
                raise RuntimeError("RANGE_CLEANUP_FAILED")
            await budget.reconcile_elapsed()
            self.transition(run, AgentRunState.COMPLETED)
            self._audit(events, run, "RUN_COMPLETED", "Evaluation and verified cleanup completed.")
        except asyncio.CancelledError:
            after = await self.controller.reset_application("aegis-bank")
            health = await self.controller.health("aegis-bank")
            cleanup_ok = after.healthy and health.healthy
            run.reset_generation_after = after.reset_generation
            run.cleanup_succeeded = cleanup_ok
            if run.state not in _TERMINAL:
                self.transition(run, AgentRunState.CANCELLED)
            run.verdict = EvaluationVerdict.CANCELLED
            self._audit(events, run, "RUN_CANCELLED", "Stop propagated to active and queued work.")
        except Exception:
            try:
                after = await self.controller.reset_application("aegis-bank")
                health = await self.controller.health("aegis-bank")
                cleanup_ok = bool(
                    after.healthy
                    and health.healthy
                    and after.reset_generation is not None
                    and (before_generation is None or after.reset_generation > before_generation)
                )
                run.reset_generation_after = after.reset_generation
                run.cleanup_succeeded = cleanup_ok
            except Exception:
                run.cleanup_succeeded = False
            if run.state not in _TERMINAL:
                self.transition(run, AgentRunState.FAILED)
            for task in self._tasks[run.run_id]:
                if task.state in {AgentTaskState.QUEUED, AgentTaskState.RUNNING}:
                    task.state = AgentTaskState.FAILED
                    task.completed_at = datetime.now(UTC)
            self._audit(events, run, "RUN_FAILED", "Runtime failed closed.")
            raise
        finally:
            await budget.reconcile_elapsed()

        metrics = RunMetrics(
            surface_discovery=sum(
                1 for item in observations if item.observation_type.value == "SURFACE"
            ),
            valid_hypotheses=len(hypotheses),
            verifier_confirmed_findings=sum(item.verifier_confirmed for item in candidates),
            false_positives=sum(
                1
                for item in candidates
                if not item.verifier_confirmed and run.verdict is not EvaluationVerdict.PASS
            ),
            model_calls=budget.global_ledger.usage.model_calls,
            input_tokens=budget.global_ledger.usage.input_tokens,
            output_tokens=budget.global_ledger.usage.output_tokens,
            target_requests=budget.global_ledger.usage.target_requests,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            adaptation_after_failed_approach=False,
            cleanup_reset_succeeded=cleanup_ok,
        )
        evaluation = RunEvaluation(
            run=run,
            tasks=self._tasks[run.run_id],
            observations=observations,
            hypotheses=hypotheses,
            action_requests=action_requests,
            action_results=actions,
            finding_candidates=candidates,
            verifier_results=verifier_refs,
            global_budget=budget.global_ledger,
            agent_budgets=list(budget.agent_ledgers.values()),
            metrics=metrics,
            audit_events=events,
        )
        if self.store is not None:
            self.store.save(evaluation)
        return evaluation

    async def _multi_path(
        self,
        run: AgentRun,
        budget: AtomicBudget,
        broker: ControlledToolBroker,
        events: list[AgentAuditEvent],
        observations: list[AgentObservation],
        hypotheses: list[AgentHypothesis],
    ) -> AgentTask:
        lead_id, surface_id, auth_id = _id("agent"), _id("agent"), _id("agent")
        for agent_id in (lead_id, surface_id, auth_id):
            budget.register_agent(agent_id, self.per_agent_limit)
        lead_surface = self._task(run, lead_id, AgentRole.LEAD_ORCHESTRATOR, "PLAN_SURFACE")
        run.active_role = AgentRole.LEAD_ORCHESTRATOR
        lead_surface.state = AgentTaskState.RUNNING
        plan = await self._generate(
            budget,
            run,
            lead_surface,
            {"target_ref": run.target_ref, "objective": "discover documented business surface"},
            LeadTaskOutput,
        )
        if plan.task_type != "OBSERVE_SURFACE":
            raise ValueError("LEAD_TASK_TYPE_INVALID")
        lead_surface.state = AgentTaskState.COMPLETED
        lead_surface.completed_at = datetime.now(UTC)
        surface = self._task(
            run,
            surface_id,
            AgentRole.SURFACE_AGENT,
            "OBSERVE_SURFACE",
            parent=lead_surface,
        )
        surface.state = AgentTaskState.RUNNING
        run.active_role = AgentRole.SURFACE_AGENT
        raw_observation = await broker.discover_surface(
            run_id=run.run_id, task=surface, target_ref=run.target_ref, observation_id=_id("obs")
        )
        output = await self._generate(
            budget,
            run,
            surface,
            {
                "target_ref": run.target_ref,
                "operation_ids": raw_observation.operation_ids,
                "resource_refs": raw_observation.resource_refs,
            },
            SurfaceAgentOutput,
        )
        if not set(output.operation_ids) <= set(raw_observation.operation_ids):
            raise ValueError("SURFACE_OUTPUT_INVENTED_OPERATION")
        if not set(output.resource_refs) <= set(raw_observation.resource_refs):
            raise ValueError("SURFACE_OUTPUT_INVENTED_RESOURCE")
        raw_observation.summary = output.summary
        raw_observation.operation_ids = output.operation_ids
        raw_observation.resource_refs = output.resource_refs
        observations.append(raw_observation)
        surface.state = AgentTaskState.COMPLETED
        surface.completed_at = datetime.now(UTC)
        self._audit(
            events,
            run,
            "SURFACE_VALIDATED",
            "Controller validated the surface output.",
            task=surface,
        )

        lead_auth = self._task(
            run,
            lead_id,
            AgentRole.LEAD_ORCHESTRATOR,
            "PLAN_AUTHORIZATION",
            parent=surface,
            observations=[raw_observation.observation_id],
        )
        lead_auth.state = AgentTaskState.RUNNING
        run.active_role = AgentRole.LEAD_ORCHESTRATOR
        auth_plan = await self._generate(
            budget,
            run,
            lead_auth,
            {
                "target_ref": run.target_ref,
                "validated_observation": {
                    "operation_ids": output.operation_ids,
                    "resource_refs": output.resource_refs,
                },
            },
            LeadTaskOutput,
        )
        if auth_plan.task_type != "TEST_AUTHORIZATION":
            raise ValueError("LEAD_TASK_TYPE_INVALID")
        lead_auth.state = AgentTaskState.COMPLETED
        lead_auth.completed_at = datetime.now(UTC)
        auth = self._task(
            run,
            auth_id,
            AgentRole.AUTHORIZATION_AGENT,
            "TEST_AUTHORIZATION",
            parent=lead_auth,
            observations=[raw_observation.observation_id],
        )
        auth.context.allowed_operation_ids = list(output.operation_ids)
        auth.context.resource_refs = list(output.resource_refs)
        auth.state = AgentTaskState.RUNNING
        run.active_role = AgentRole.AUTHORIZATION_AGENT
        auth_output = await self._generate(
            budget,
            run,
            auth,
            {
                "target_ref": run.target_ref,
                "operation_ids": output.operation_ids,
                "resource_refs": output.resource_refs,
                "credential_aliases": auth.context.credential_aliases,
            },
            AuthorizationAgentOutput,
        )
        self._append_hypothesis(run, auth, auth_output, hypotheses)
        return auth

    async def _single_path(
        self,
        run: AgentRun,
        budget: AtomicBudget,
        broker: ControlledToolBroker,
        events: list[AgentAuditEvent],
        observations: list[AgentObservation],
        hypotheses: list[AgentHypothesis],
    ) -> AgentTask:
        agent_id = _id("agent")
        budget.register_agent(agent_id, self.per_agent_limit)
        task = self._task(run, agent_id, AgentRole.AUTHORIZATION_AGENT, "SINGLE_AGENT_BOLA")
        task.state = AgentTaskState.RUNNING
        run.active_role = AgentRole.AUTHORIZATION_AGENT
        raw_observation = await broker.discover_surface(
            run_id=run.run_id, task=task, target_ref=run.target_ref, observation_id=_id("obs")
        )
        output = await self._generate(
            budget,
            run,
            task,
            {
                "target_ref": run.target_ref,
                "operation_ids": raw_observation.operation_ids,
                "resource_refs": raw_observation.resource_refs,
                "credential_aliases": task.context.credential_aliases,
            },
            SingleAgentOutput,
        )
        if not set(output.operation_ids) <= set(raw_observation.operation_ids):
            raise ValueError("SURFACE_OUTPUT_INVENTED_OPERATION")
        raw_observation.summary = output.summary
        raw_observation.operation_ids = output.operation_ids
        raw_observation.resource_refs = output.resource_refs
        observations.append(raw_observation)
        self._append_hypothesis(run, task, output.authorization, hypotheses)
        self._audit(
            events,
            run,
            "BASELINE_OUTPUT_VALIDATED",
            "Controller validated baseline output.",
            task=task,
        )
        return task

    @staticmethod
    def _append_hypothesis(
        run: AgentRun,
        task: AgentTask,
        output: AuthorizationAgentOutput,
        hypotheses: list[AgentHypothesis],
    ) -> None:
        if output.operation_id not in task.context.allowed_operation_ids:
            raise ValueError("HYPOTHESIS_OPERATION_NOT_AUTHORIZED")
        aliases = {output.owner_credential_alias, output.alternate_credential_alias}
        resources = {output.owner_resource_ref, output.alternate_resource_ref}
        if not aliases <= set(task.context.credential_aliases):
            raise ValueError("HYPOTHESIS_CREDENTIAL_NOT_AUTHORIZED")
        if not resources <= set(task.context.resource_refs):
            raise ValueError("HYPOTHESIS_RESOURCE_NOT_AUTHORIZED")
        hypotheses.append(
            AgentHypothesis(
                hypothesis_id=_id("hyp"),
                run_id=run.run_id,
                task_id=task.task_id,
                agent_id=task.agent_id,
                category=output.category,
                operation_id=output.operation_id,
                owner_credential_alias=output.owner_credential_alias,
                alternate_credential_alias=output.alternate_credential_alias,
                owner_resource_ref=output.owner_resource_ref,
                alternate_resource_ref=output.alternate_resource_ref,
                rationale=output.rationale,
            )
        )


def console_projection(evaluation: RunEvaluation) -> dict[str, object]:
    """Minimal bounded Operator Console view; deliberately excludes payloads and model text."""

    return {
        "run_id": evaluation.run.run_id,
        "scenario_id": evaluation.run.scenario_id,
        "execution_mode": evaluation.run.execution_mode,
        "state": evaluation.run.state.value,
        "active_role": evaluation.run.active_role.value if evaluation.run.active_role else None,
        "tasks": [
            {"task_id": item.task_id, "role": item.role.value, "state": item.state.value}
            for item in evaluation.tasks
        ],
        "validated_hypotheses": len(evaluation.hypotheses),
        "requested_capabilities": sorted(
            {item.capability_id for item in evaluation.action_requests}
        ),
        "selected_capabilities": sorted(
            {item.capability_id for item in evaluation.action_results if item.accepted}
        ),
        "observations": [
            {
                "type": item.observation_type.value,
                "summary": item.summary,
                "statuses": item.statuses,
                "evidence_bytes": item.evidence_bytes,
            }
            for item in evaluation.observations
        ],
        "verifier_findings": [item.model_dump(mode="json") for item in evaluation.verifier_results],
        "global_budget": evaluation.global_budget.model_dump(mode="json"),
        "agent_budgets": [item.model_dump(mode="json") for item in evaluation.agent_budgets],
        "stop_requested": evaluation.run.stop_requested,
        "cleanup_succeeded": evaluation.run.cleanup_succeeded,
        "metrics": evaluation.metrics.model_dump(mode="json"),
    }
