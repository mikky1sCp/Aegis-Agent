"""GoalLedger drift acceptance tests."""

from __future__ import annotations

from pathlib import Path

from agent.contracts import GoalReview, RunStatus
from tests.support import (
    final_decision,
    make_goal,
    make_plan,
    make_settings,
    run_agent,
    tool_decision,
    write_doc,
)


def test_hard_goal_id_mismatch_stops_before_any_tool(workspace: Path) -> None:
    goal = make_goal()
    plan = make_plan(goal, [["read_document"], ["write_report"]])
    bad = tool_decision(
        goal,
        0,
        "read_document",
        {"path": "anything.md"},
        purpose="pursue a different objective",
        reason="the new objective seems better",
    ).model_copy(update={"goal_id": "other-goal"})
    agent, report = run_agent(workspace, goal, plan, [bad])
    assert report.status == RunStatus.BLOCKED
    assert report.stop_reason == "goal_drift_detected"
    assert report.actions[-1].executed is False
    assert agent.broker.audit == []
    assert any(
        record.status == "blocked" and "goal drift" in record.reason.lower()
        for record in agent.trace.records
    )


def test_periodic_goal_review_detects_drift_and_stops(workspace: Path) -> None:
    write_doc(workspace, "policy.md", "Refunds are available for 30 days.")
    goal = make_goal(objective="Summarize the refund policy")
    plan = make_plan(goal, [["read_document"], ["write_report"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "policy.md"},
            purpose="read policy",
            reason="first planned step",
        ),
        tool_decision(
            goal,
            1,
            "write_report",
            {"filename": "drift.md", "content": "should never be written"},
            purpose="write unrelated report",
            reason="continue plan",
        ),
    ]
    reviews = [
        GoalReview(
            drifted=True,
            confidence=0.93,
            reasons=["agent started pursuing an unrelated financial task"],
        )
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        settings=make_settings(workspace, drift_interval=1),
        reviews=reviews,
    )
    assert report.status == RunStatus.BLOCKED
    assert report.stop_reason == "goal_drift_detected"
    assert [entry.tool_name for entry in agent.broker.audit] == ["read_document"]
    assert not (workspace / "reports" / "drift.md").exists()
    assert agent.llm.decisions, "the second scripted action should remain unused"
    assert any(record.status == "goal_drift" for record in agent.trace.records)
    assert report.metrics.violations >= 1


def test_goal_reviewer_cannot_authorize_or_rewrite_goal(workspace: Path) -> None:
    goal = make_goal()
    assert goal.objective == "Summarize the policy and write a report"
    # Stub reviewer data must not mutate the authoritative ledger goal.
    reviews = [GoalReview(drifted=False, confidence=0.99, reasons=["looks fine"])]
    write_doc(workspace, "policy.md", "Policy.")
    plan = make_plan(goal, [["read_document"], ["write_report"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "policy.md"},
            purpose="read policy",
            reason="planned",
        ),
        final_decision(goal, 1, answer="Policy summarized."),
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        reviews=reviews,
        settings=make_settings(workspace, drift_interval=1),
    )
    assert report.status == RunStatus.COMPLETED
    assert agent.ledger.goal.objective == goal.objective
    assert "transfer_funds" not in agent.identity.capabilities
