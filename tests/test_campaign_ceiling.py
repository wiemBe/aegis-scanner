"""Operator campaign spend-ceiling admission on AtomicBudget."""

import pytest

from aegis.multi_agent.budget import AgentBudgetExceeded, AtomicBudget, CampaignCeiling
from aegis.multi_agent.contracts import BudgetLimit
from aegis.settings import Settings

RUN_ID = "marun-" + "a" * 16


def _limit(*, tokens: int = 12_000, model_calls: int = 6) -> BudgetLimit:
    return BudgetLimit(
        model_calls=model_calls,
        tokens=tokens,
        target_requests=8,
        commands=0,
        elapsed_ms=30_000,
        evidence_bytes=524_288,
    )


def test_ceiling_from_settings_reads_operator_fields() -> None:
    settings = Settings(max_tokens_per_campaign=50_000, max_model_calls_per_campaign=12)
    ceiling = CampaignCeiling.from_settings(settings)
    assert ceiling.tokens == 50_000
    assert ceiling.model_calls == 12


def test_default_gate_budget_is_within_default_ceiling() -> None:
    # The calibrated per-phase default (12_000 tokens / 6 calls) must construct unchanged.
    budget = AtomicBudget(RUN_ID, _limit())
    assert budget.ceiling.tokens == Settings().max_tokens_per_campaign


def test_global_token_budget_over_ceiling_fails_closed() -> None:
    ceiling = CampaignCeiling(tokens=10_000, model_calls=40)
    with pytest.raises(AgentBudgetExceeded, match="CAMPAIGN_TOKEN_CEILING"):
        AtomicBudget(RUN_ID, _limit(tokens=10_001), ceiling=ceiling)


def test_global_model_call_budget_over_ceiling_fails_closed() -> None:
    ceiling = CampaignCeiling(tokens=200_000, model_calls=4)
    with pytest.raises(AgentBudgetExceeded, match="CAMPAIGN_MODEL_CALL_CEILING"):
        AtomicBudget(RUN_ID, _limit(model_calls=5), ceiling=ceiling)


def test_global_budget_exactly_at_ceiling_is_admitted() -> None:
    ceiling = CampaignCeiling(tokens=12_000, model_calls=6)
    budget = AtomicBudget(RUN_ID, _limit(tokens=12_000, model_calls=6), ceiling=ceiling)
    assert budget.ceiling == ceiling
