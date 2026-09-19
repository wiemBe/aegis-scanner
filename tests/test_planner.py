import pytest

from aegis.planner import DemoPlanner


@pytest.mark.asyncio
async def test_demo_planner_selects_cross_owner_test() -> None:
    spec = {"paths": {"/api/v1/accounts/{account_id}": {"get": {"summary": "Get account"}}}}
    plan = await DemoPlanner().create_plan(spec)
    assert plan.hypotheses[0].category == "BOLA"
    assert [r.name for r in plan.hypotheses[0].requests] == [
        "owner-control",
        "cross-owner-probe",
    ]


@pytest.mark.asyncio
async def test_demo_planner_refuses_unknown_api() -> None:
    with pytest.raises(ValueError, match="No object-level authorization candidate"):
        await DemoPlanner().create_plan({"paths": {}})
