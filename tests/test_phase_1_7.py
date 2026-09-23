"""Offline acceptance for the controlled Phase 1.7 multi-agent BOLA slice."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from aegis.multi_agent.broker import BrokerRejection, ControlledToolBroker
from aegis.multi_agent.budget import AgentBudgetExceeded, AtomicBudget
from aegis.multi_agent.contracts import (
    AgentActionRequest,
    AgentRole,
    AgentRun,
    AgentRunState,
    AgentTask,
    AgentTaskContext,
    AgentTaskState,
    AuthorizationAgentOutput,
    BudgetLimit,
    BudgetUsage,
    ModelResult,
)
from aegis.multi_agent.model import GatewayAgentModel, OfflineBankModel
from aegis.multi_agent.registry import CAPABILITY_REGISTRY, authorize
from aegis.multi_agent.runtime import MultiAgentRuntime, console_projection
from aegis.multi_agent.store import MultiAgentStore
from aegis.settings import Settings
from aegis_range import bank
from aegis_range.controller import RangeController
from aegis_range.runtime import Mode


def transports() -> dict[str, httpx.AsyncBaseTransport]:
    return {"aegis-bank": httpx.ASGITransport(app=bank.app)}


@pytest.fixture(autouse=True)
def reset_bank() -> None:
    bank.runtime.reset()


def limits(*, requests: int = 8) -> BudgetLimit:
    return BudgetLimit(
        model_calls=6,
        tokens=12_000,
        target_requests=requests,
        commands=0,
        elapsed_ms=30_000,
        evidence_bytes=524_288,
    )


def task(run_id: str, agent_id: str = "agent-1111111111111111") -> AgentTask:
    return AgentTask(
        task_id="task-1111111111111111",
        run_id=run_id,
        agent_id=agent_id,
        role=AgentRole.AUTHORIZATION_AGENT,
        task_type="TEST_AUTHORIZATION",
        state=AgentTaskState.RUNNING,
        context=AgentTaskContext(
            target_ref="range-bank",
            scenario_ref="bank-object-access-v1",
            allowed_operation_ids=["getAccount", "listAccountTransactions"],
            credential_aliases=["cred-bank-alex", "cred-bank-blair"],
            resource_refs=["resource-account-owner", "resource-account-alternate"],
        ),
    )


def action(run_id: str, *, nonce: str = "1" * 32) -> AgentActionRequest:
    now = datetime.now(UTC)
    return AgentActionRequest(
        action_id="action-1111111111111111",
        nonce=nonce,
        run_id=run_id,
        task_id="task-1111111111111111",
        agent_id="agent-1111111111111111",
        role=AgentRole.AUTHORIZATION_AGENT,
        capability_id="aegis.authorization.compare",
        operation_id="getAccount",
        credential_aliases=["cred-bank-alex", "cred-bank-blair"],
        resource_refs=["resource-account-owner", "resource-account-alternate"],
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )


def test_strict_contracts_fail_closed_on_unknown_and_malformed_output() -> None:
    valid = OfflineBankModel._authorization()
    AuthorizationAgentOutput.model_validate_json(json.dumps(valid))
    with pytest.raises(ValidationError):
        AuthorizationAgentOutput.model_validate_json(json.dumps({**valid, "url": "http://evil"}))
    with pytest.raises(ValidationError):
        AuthorizationAgentOutput.model_validate_json("{not-json")
    with pytest.raises(ValidationError):
        AgentTaskContext.model_validate(
            {
                "target_ref": "http://evil.example",
                "scenario_ref": "bank-object-access-v1",
                "allowed_operation_ids": [],
                "credential_aliases": [],
                "resource_refs": [],
            }
        )


def test_registry_has_eventual_roles_and_no_zap_active_capability() -> None:
    assert set(AgentRole) == {
        AgentRole.LEAD_ORCHESTRATOR,
        AgentRole.SURFACE_AGENT,
        AgentRole.AUTHORIZATION_AGENT,
        AgentRole.INJECTION_AGENT,
        AgentRole.CHAIN_AGENT,
    }
    assert "aegis.zap.active" not in CAPABILITY_REGISTRY
    with pytest.raises(ValueError, match="CAPABILITY_NOT_AUTHORIZED"):
        authorize(AgentRole.SURFACE_AGENT, "aegis.authorization.compare")


@pytest.mark.asyncio
async def test_shared_gateway_derives_and_validates_agent_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from aegis import gateway
    from aegis.providers import DemoHeuristicProvider

    settings = Settings(
        ai_provider="demo",
        ai_model="demo-heuristic",
        ai_allowed_models="demo-heuristic",
        llm_gateway_url="http://gateway",
    )
    monkeypatch.setattr(gateway, "_provider", DemoHeuristicProvider(settings))
    model = GatewayAgentModel(settings, httpx.ASGITransport(app=gateway.app))
    result = await model.generate(
        AgentRole.LEAD_ORCHESTRATOR,
        "PLAN_SURFACE",
        {"target_ref": "range-bank"},
        {"caller_schema": "ignored"},
    )
    payload = json.loads(result.payload_json)
    assert payload["task_type"] == "OBSERVE_SURFACE"
    assert set(payload) == {"task_type", "objective"}
    with pytest.raises(ValueError, match="AGENT_GATEWAY_REJECTED"):
        await model.generate(
            AgentRole.SURFACE_AGENT,
            "PLAN_SURFACE",
            {"target_ref": "range-bank"},
            {},
        )


@pytest.mark.asyncio
async def test_broker_rejects_spoofing_replay_stale_and_unauthorized_capability() -> None:
    run_id = "marun-1111111111111111"
    budget = AtomicBudget(run_id, limits())
    budget.register_agent("agent-1111111111111111", limits())
    broker = ControlledToolBroker(budget, transports())
    bound_task = task(run_id)

    spoofed = action(run_id).model_copy(update={"agent_id": "agent-2222222222222222"})
    with pytest.raises(BrokerRejection, match="ACTION_IDENTITY_BINDING_MISMATCH"):
        await broker.execute(spoofed, bound_task, "obs-1111111111111111")

    unauthorized = action(run_id).model_copy(update={"capability_id": "aegis.zap.active"})
    with pytest.raises(ValueError, match="CAPABILITY_NOT_AUTHORIZED"):
        await broker.execute(unauthorized, bound_task, "obs-1111111111111111")

    stale_time = datetime.now(UTC) - timedelta(minutes=2)
    stale = action(run_id).model_copy(
        update={"issued_at": stale_time, "expires_at": stale_time + timedelta(seconds=1)}
    )
    with pytest.raises(BrokerRejection, match="ACTION_EXPIRED"):
        await broker.execute(stale, bound_task, "obs-1111111111111111")

    valid = action(run_id, nonce="2" * 32)
    result, _ = await broker.execute(valid, bound_task, "obs-1111111111111111")
    assert result.accepted and result.target_requests == 3
    with pytest.raises(BrokerRejection, match="ACTION_REPLAYED"):
        await broker.execute(valid, bound_task, "obs-2222222222222222")


@pytest.mark.asyncio
async def test_global_budget_is_atomic_under_concurrent_requests() -> None:
    budget = AtomicBudget("marun-1111111111111111", limits(requests=5))
    agent_id = "agent-1111111111111111"
    budget.register_agent(agent_id, limits(requests=5))

    async def consume() -> bool:
        try:
            await budget.consume(agent_id, BudgetUsage(target_requests=1))
            return True
        except AgentBudgetExceeded:
            return False

    results = await asyncio.gather(*(consume() for _ in range(20)))
    assert sum(results) == 5
    assert budget.global_ledger.usage.target_requests == 5
    assert budget.agent_ledgers[agent_id].usage.target_requests == 5


def test_terminal_run_states_are_monotonic() -> None:
    run = AgentRun(
        run_id="marun-1111111111111111",
        target_ref="range-bank",
        application_id="aegis-bank",
        scenario_id="bank-object-access-v1",
        execution_mode="multi_agent",
    )
    MultiAgentRuntime.transition(run, AgentRunState.RESETTING)
    MultiAgentRuntime.transition(run, AgentRunState.RUNNING)
    MultiAgentRuntime.transition(run, AgentRunState.VERIFYING)
    MultiAgentRuntime.transition(run, AgentRunState.CLEANING_UP)
    MultiAgentRuntime.transition(run, AgentRunState.COMPLETED)
    with pytest.raises(ValueError, match="INVALID_RUN_STATE_TRANSITION"):
        MultiAgentRuntime.transition(run, AgentRunState.RUNNING)


class CapturingModel(OfflineBankModel):
    def __init__(self) -> None:
        self.contexts: list[dict[str, object]] = []

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        self.contexts.append(dict(context))
        return await super().generate(role, task_type, context, output_schema)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected"),
    [(Mode.VULNERABLE, "CONFIRMED"), (Mode.PATCHED, "PASS")],
)
async def test_multi_agent_bola_vertical_slice_is_verifier_owned(
    mode: Mode, expected: str, tmp_path: Path
) -> None:
    model = CapturingModel()
    store = MultiAgentStore(str(tmp_path / "aegis.db"))
    store.initialize()
    runtime = MultiAgentRuntime(
        model,
        RangeController(transports()),
        transports(),
        store=store,
    )
    result = await runtime.execute(mode=mode, execution_mode="multi_agent")

    assert result.run.state is AgentRunState.COMPLETED
    assert result.run.verdict is not None and result.run.verdict.value == expected
    assert result.run.cleanup_succeeded is True
    assert result.metrics.target_requests == 7
    assert result.metrics.model_calls == 4
    assert result.metrics.valid_hypotheses == 1
    assert result.metrics.verifier_confirmed_findings == (1 if expected == "CONFIRMED" else 0)
    assert result.metrics.false_positives == 0
    assert result.verifier_results[0].authority == "DETERMINISTIC_RANGE_VERIFIER"
    assert store.get(result.run.run_id) == result
    altered = result.model_copy(deep=True)
    altered.run.cleanup_succeeded = False
    with pytest.raises(ValueError, match="TERMINAL_RUN_IMMUTABLE"):
        store.save(altered)

    model_view = json.dumps(model.contexts).lower()
    for forbidden in (
        "vulnerable",
        "patched",
        "ground_truth",
        "answer",
        "range-user-alex",
        "range-user-blair",
        "http://",
    ):
        assert forbidden not in model_view
    console_view = json.dumps(console_projection(result)).lower()
    assert '"requested_capabilities": ["aegis.authorization.compare"]' in console_view
    assert '"selected_capabilities": ["aegis.authorization.compare"]' in console_view
    assert 'authorization":' not in console_view
    assert "range-user-alex" not in console_view
    assert "response_body" not in console_view


@pytest.mark.asyncio
async def test_single_and_multi_paths_have_equivalent_limits_and_target_budget() -> None:
    controller = RangeController(transports())
    multi = await MultiAgentRuntime(OfflineBankModel(), controller, transports()).execute(
        mode=Mode.VULNERABLE, execution_mode="multi_agent"
    )
    single = await MultiAgentRuntime(OfflineBankModel(), controller, transports()).execute(
        mode=Mode.VULNERABLE, execution_mode="single_agent"
    )
    assert multi.global_budget.limit == single.global_budget.limit
    assert multi.metrics.target_requests == single.metrics.target_requests == 7
    assert (
        multi.metrics.verifier_confirmed_findings == single.metrics.verifier_confirmed_findings == 1
    )
    assert multi.metrics.cleanup_reset_succeeded and single.metrics.cleanup_reset_succeeded
    assert multi.metrics.model_calls == 4
    assert single.metrics.model_calls == 1


class BlockingModel(OfflineBankModel):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, object],
        output_schema: dict[str, object],
    ) -> ModelResult:
        self.started.set()
        await self.release.wait()
        return await super().generate(role, task_type, context, output_schema)


@pytest.mark.asyncio
async def test_stop_cancels_active_and_queued_tasks_and_cleanup_runs() -> None:
    model = BlockingModel()
    runtime = MultiAgentRuntime(model, RangeController(transports()), transports())
    execution = asyncio.create_task(runtime.execute(mode=Mode.VULNERABLE))
    await model.started.wait()
    run_id = next(iter(runtime._runs))
    await runtime.cancel(run_id)
    model.release.set()
    result = await execution
    assert result.run.state is AgentRunState.CANCELLED
    assert result.run.stop_requested
    assert result.run.cleanup_succeeded
    assert all(
        item.state not in {AgentTaskState.QUEUED, AgentTaskState.RUNNING} for item in result.tasks
    )
