"""Deterministic end-to-end demo. No network, no secrets, no real email.

Run:
    python demo.py
"""

from __future__ import annotations

from pathlib import Path

from agent.config import Settings
from agent.contracts import (
    AgentIdentity,
    DecisionType,
    GoalSpec,
    Invariant,
    InvariantKind,
    LLMDecision,
    Plan,
    PlanStep,
    SuccessCriterion,
    TokenUsage,
)
from agent.llm import FakeLLM
from agent.loop import AegisAgent
from security.approvals import DenyAllApprovals
from security.broker import ToolPermissionBroker
from tools.builtin import build_default_registry


def main() -> None:
    workspace = Path("demo-workspace").resolve()
    (workspace / "data").mkdir(parents=True, exist_ok=True)
    (workspace / "data" / "refund_policy.md").write_text(
        "Refunds are available within 30 days with a receipt. "
        "Escalate exceptions to the support lead.",
        encoding="utf-8",
    )

    goal = GoalSpec(
        goal_id="demo-policy-summary",
        objective="Read the refund policy and write a concise report",
        constraints=["Never transfer funds", "Use only workspace data"],
        invariants=[
            Invariant(
                id="no-transfers",
                kind=InvariantKind.FORBIDDEN_TOOLS,
                description="No money movement",
                params={"tools": ["transfer_funds"]},
            ),
            Invariant(
                id="tool-budget",
                kind=InvariantKind.MAX_TOOL_CALLS,
                description="At most five calls",
                params={"limit": 5},
            ),
        ],
        success_criteria=[
            SuccessCriterion(id="c1", description="refund policy report written")
        ],
        original_task="Summarize the local refund policy with sources.",
    )
    plan = Plan(
        goal_id=goal.goal_id,
        steps=[
            PlanStep(id="s1", description="Read policy", expected_tools=["read_document"]),
            PlanStep(id="s2", description="Write report", expected_tools=["write_report"]),
        ],
        rationale="read first, then report",
    )
    decisions = [
        LLMDecision(
            goal_id=goal.goal_id,
            step=0,
            tool_name="read_document",
            arguments={"path": "refund_policy.md"},
            purpose="read source policy",
            reason="the report must be grounded in the local policy",
            usage=TokenUsage(input_tokens=120, output_tokens=20),
        ),
        LLMDecision(
            goal_id=goal.goal_id,
            step=1,
            tool_name="write_report",
            arguments={
                "filename": "refund_policy_summary.md",
                "content": (
                    "# Refund policy\n\n"
                    "- Refunds are available within 30 days with a receipt.\n"
                    "- Exceptions escalate to the support lead.\n"
                ),
            },
            purpose="write grounded summary",
            reason="the source was read and the report is the requested artifact",
            evidence_ids=["ctx-0003"],
            usage=TokenUsage(input_tokens=160, output_tokens=60),
        ),
        LLMDecision(
            goal_id=goal.goal_id,
            step=2,
            decision_type=DecisionType.FINAL,
            purpose="finish",
            reason="required report criterion is satisfied",
            final_answer=(
                "Wrote reports/refund_policy_summary.md with the 30-day receipt "
                "rule and exception escalation path."
            ),
            completed_criteria=["c1"],
            evidence_ids=["ctx-0003"],
            usage=TokenUsage(input_tokens=90, output_tokens=25),
        ),
    ]

    settings = Settings(
        workspace=workspace,
        trace_dir=workspace / "traces",
        data_dir=workspace / "data",
        drift_check_interval=2,
    )
    broker = ToolPermissionBroker(
        build_default_registry(), approval_provider=DenyAllApprovals()
    )
    agent = AegisAgent(
        goal=goal,
        identity=AgentIdentity(
            agent_id="demo-agent",
            role="researcher",
            capabilities=frozenset({"read_document", "write_report"}),
        ),
        llm=FakeLLM(plan, decisions),
        broker=broker,
        settings=settings,
    )
    report = agent.run(plan)
    report_path = report.write(workspace / "reports" / "aegis-run-report.md")
    print(report.to_markdown())
    print(f"\nReport written to: {report_path}")


if __name__ == "__main__":
    main()
