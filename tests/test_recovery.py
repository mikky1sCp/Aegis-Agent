"""Recovery from tool errors and bounded retry tests."""

from __future__ import annotations

from pathlib import Path

from tests.support import (
    final_decision,
    make_goal,
    make_plan,
    make_settings,
    run_agent,
    tool_decision,
    write_doc,
)


def test_tool_error_is_recovered_without_losing_goal_or_state(workspace: Path) -> None:
    write_doc(workspace, "actual.md", "Recovered content.")
    goal = make_goal(objective="Read the actual document")
    plan = make_plan(goal, [["read_document"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "missing.md"},
            purpose="read document",
            reason="first path guess",
        ),
        tool_decision(
            goal,
            1,
            "read_document",
            {"path": "actual.md"},
            purpose="retry read with corrected path",
            reason="previous document was missing",
        ),
        final_decision(goal, 2, answer="Read the recovered document."),
    ]
    agent, report = run_agent(workspace, goal, plan, decisions, settings=make_settings(workspace))
    assert report.status.value == "completed"
    assert report.metrics.recovery_steps == 1
    assert report.metrics.task_success_rate == 1.0
    assert [action.ok for action in report.actions] == [False, True]
    assert any(record.status == "tool_error" for record in agent.trace.records)
    assert report.metrics.trace_completeness == 1.0
    # The goal remains pinned after the error and retry.
    assert goal.objective in agent.context.snapshot().rendered


def test_recovery_budget_exhaustion_stops_safely(workspace: Path) -> None:
    goal = make_goal(objective="Read a missing document")
    plan = make_plan(goal, [["read_document"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "missing-one.md"},
            purpose="read",
            reason="first attempt",
        ),
        tool_decision(
            goal,
            1,
            "read_document",
            {"path": "missing-two.md"},
            purpose="read",
            reason="second attempt",
        ),
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        settings=make_settings(workspace, recovery=1),
    )
    assert report.status.value == "failed"
    assert report.stop_reason == "recovery_budget_exhausted"
    assert report.metrics.recovery_steps == 1
    assert agent.broker.audit[-1].executed is True


def test_step_budget_stops_before_extra_decisions(workspace: Path) -> None:
    write_doc(workspace, "policy.md", "Policy.")
    goal = make_goal(objective="Read one document")
    plan = make_plan(goal, [["read_document"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "policy.md"},
            purpose="read",
            reason="only permitted step",
        ),
        final_decision(goal, 1, answer="Should never be reached."),
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        settings=make_settings(workspace, max_steps=1),
    )
    assert report.status.value == "failed"
    assert report.stop_reason == "step_budget_exhausted"
    assert agent.llm.decisions, "step budget must stop before the next decision"
    assert report.final_answer is None
