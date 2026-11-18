import pytest

from agent.planner import Planner


class FakeReasoning:
    enabled = True

    def __init__(self, plan=None, followup=None):
        self.plan_payload = plan or {}
        self.followup_payload = followup or {}

    async def plan(self, **kwargs):
        return self.plan_payload

    async def follow_up(self, **kwargs):
        return self.followup_payload


def test_fallback_plan_has_sandbox_and_analyzer():
    planner = Planner(
        FakeReasoning(),
        available_tools={
            "sandbox_url_investigation",
            "analyze_url_evidence",
        },
        max_steps=5,
        max_followups=1,
    )
    plan = planner.fallback("url")
    assert [step.tool for step in plan.steps] == [
        "sandbox_url_investigation",
        "analyze_url_evidence",
    ]


@pytest.mark.asyncio
async def test_llm_plan_rejects_unknown_tools_and_keeps_sandbox():
    reasoning = FakeReasoning(
        plan={
            "goal": "test",
            "steps": [
                {"tool": "run_shell", "arguments": {}},
                {"tool": "analyze_url_evidence", "arguments": {}},
            ],
        }
    )
    planner = Planner(
        reasoning,
        available_tools={"sandbox_url_investigation", "analyze_url_evidence"},
        max_steps=4,
        max_followups=1,
    )
    plan = await planner.create_plan(
        target="https://example.com",
        target_type="url",
        tool_schemas=[],
    )
    assert plan.source == "llm"
    assert plan.steps[0].tool == "sandbox_url_investigation"
    assert "run_shell" not in plan.tools


@pytest.mark.asyncio
async def test_followup_is_limited_to_safe_phase():
    reasoning = FakeReasoning(
        followup={
            "stop": False,
            "actions": [
                {"tool": "run_readonly_command", "arguments": {"command": ["file", "x"]}},
                {"tool": "sandbox_url_investigation", "arguments": {}},
            ],
        }
    )
    planner = Planner(
        reasoning,
        available_tools={"sandbox_url_investigation", "run_readonly_command"},
        max_steps=4,
        max_followups=1,
    )
    steps = await planner.follow_up(
        target="https://example.com",
        target_type="url",
        evidence={"coverage": []},
        completed_tools=["sandbox_url_investigation", "analyze_url_evidence"],
        tool_schemas=[],
    )
    assert [step.tool for step in steps] == ["run_readonly_command"]
