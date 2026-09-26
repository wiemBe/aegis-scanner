"""Atomic global and per-agent budget admission."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from aegis.multi_agent.contracts import AgentBudgetLedger, BudgetLimit, BudgetUsage
from aegis.settings import Settings, get_settings


class AgentBudgetExceeded(ValueError):
    pass


@dataclass(frozen=True)
class CampaignCeiling:
    """Operator-configurable hard upper bound on a single campaign/run's global model spend.

    A campaign's global :class:`BudgetLimit` may be set anywhere in the codebase (each runtime
    supplies its own calibrated default). This ceiling is the deployment-wide backstop: no run may
    be configured to spend more model calls or tokens than the operator permits, which matters most
    for the paid public-egress providers (DeepSeek/OpenRouter) where a mis-set budget is real money.
    """

    tokens: int
    model_calls: int

    @classmethod
    def from_settings(cls, settings: Settings) -> CampaignCeiling:
        return cls(
            tokens=settings.max_tokens_per_campaign,
            model_calls=settings.max_model_calls_per_campaign,
        )


class AtomicBudget:
    def __init__(
        self,
        run_id: str,
        global_limit: BudgetLimit,
        *,
        ceiling: CampaignCeiling | None = None,
    ) -> None:
        # Fail closed if the configured global budget exceeds the operator campaign ceiling. This is
        # the single chokepoint every runtime's AtomicBudget passes through, so no campaign can be
        # constructed to spend beyond the deployment-wide bound. The ceiling defaults to the process
        # settings; pass an explicit one in tests or to tighten a specific run.
        ceiling = ceiling or CampaignCeiling.from_settings(get_settings())
        if global_limit.tokens > ceiling.tokens:
            raise AgentBudgetExceeded("CAMPAIGN_TOKEN_CEILING")
        if global_limit.model_calls > ceiling.model_calls:
            raise AgentBudgetExceeded("CAMPAIGN_MODEL_CALL_CEILING")
        self.ceiling = ceiling
        self.global_ledger = AgentBudgetLedger(run_id=run_id, limit=global_limit)
        self.agent_ledgers: dict[str, AgentBudgetLedger] = {}
        self._started = time.monotonic()
        self._lock = asyncio.Lock()

    def register_agent(self, agent_id: str, limit: BudgetLimit) -> None:
        if agent_id in self.agent_ledgers:
            raise ValueError("AGENT_BUDGET_ALREADY_REGISTERED")
        self.agent_ledgers[agent_id] = AgentBudgetLedger(
            run_id=self.global_ledger.run_id, agent_id=agent_id, limit=limit
        )

    @staticmethod
    def _check(ledger: AgentBudgetLedger, delta: BudgetUsage, elapsed_ms: int) -> None:
        current = ledger.usage
        limit = ledger.limit
        if current.model_calls + delta.model_calls > limit.model_calls:
            raise AgentBudgetExceeded("MODEL_CALL_BUDGET")
        if current.tokens + delta.tokens > limit.tokens:
            raise AgentBudgetExceeded("TOKEN_BUDGET")
        if current.target_requests + delta.target_requests > limit.target_requests:
            raise AgentBudgetExceeded("TARGET_REQUEST_BUDGET")
        if current.commands + delta.commands > limit.commands:
            raise AgentBudgetExceeded("COMMAND_BUDGET")
        if current.evidence_bytes + delta.evidence_bytes > limit.evidence_bytes:
            raise AgentBudgetExceeded("EVIDENCE_BUDGET")
        if elapsed_ms > limit.elapsed_ms:
            raise AgentBudgetExceeded("ELAPSED_TIME_BUDGET")

    @staticmethod
    def _apply(usage: BudgetUsage, delta: BudgetUsage, elapsed_ms: int) -> None:
        usage.model_calls += delta.model_calls
        usage.input_tokens += delta.input_tokens
        usage.output_tokens += delta.output_tokens
        usage.target_requests += delta.target_requests
        usage.commands += delta.commands
        usage.evidence_bytes += delta.evidence_bytes
        usage.elapsed_ms = elapsed_ms

    async def consume(self, agent_id: str | None, delta: BudgetUsage) -> None:
        async with self._lock:
            elapsed_ms = round((time.monotonic() - self._started) * 1000)
            self._check(self.global_ledger, delta, elapsed_ms)
            agent = self.agent_ledgers.get(agent_id) if agent_id else None
            if agent_id is not None and agent is None:
                raise ValueError("AGENT_BUDGET_NOT_REGISTERED")
            if agent is not None:
                self._check(agent, delta, elapsed_ms)
            self._apply(self.global_ledger.usage, delta, elapsed_ms)
            if agent is not None:
                self._apply(agent.usage, delta, elapsed_ms)

    async def reconcile_elapsed(self) -> None:
        await self.consume(None, BudgetUsage())
