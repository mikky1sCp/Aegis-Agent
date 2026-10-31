"""Observability: trace reasons, completeness, persistence, redaction."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from observability.trace import TraceLogger
from tests.support import (
    final_decision,
    make_goal,
    make_plan,
    run_agent,
    tool_decision,
    write_doc,
)


def test_every_trace_step_has_reason_and_complete_fields(workspace: Path) -> None:
    write_doc(workspace, "policy.md", "Policy: refunds within 30 days.")
    goal = make_goal()
    plan = make_plan(goal, [["read_document"], ["write_report"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "read_document",
            {"path": "policy.md"},
            purpose="read policy",
            reason="step one",
        ),
        tool_decision(
            goal,
            1,
            "write_report",
            {"filename": "summary.md", "content": "Refunds within 30 days."},
            purpose="write summary",
            reason="step two",
        ),
        final_decision(goal, 2),
    ]
    agent, report = run_agent(workspace, goal, plan, decisions)
    assert report.status.value == "completed"
    assert agent.trace is not None
    assert len(agent.trace.records) == 3
    assert all(record.reason.strip() for record in agent.trace.records)
    assert all(record.risk_level for record in agent.trace.records)
    for record in agent.trace.records[:2]:
        assert record.tool_call is not None
        assert record.result
    assert report.metrics.trace_completeness == 1.0
    assert report.trace_path
    persisted = agent.trace.read_persisted()
    assert len(persisted) == 3
    assert all(row["reason"] for row in persisted)


def test_trace_rejects_blank_reason(workspace: Path) -> None:
    logger = TraceLogger(
        run_id="run-trace", agent_id="agent", goal_id="goal", trace_dir=None
    )
    with pytest.raises(ValidationError):
        logger.record_step(
            step=0,
            input_summary="input",
            decision="decision",
            reason="   ",
            risk_level="low",
            result="result",
        )


def test_trace_redacts_secret_material() -> None:
    logger = TraceLogger(
        run_id="run-secret",
        agent_id="agent",
        goal_id="goal",
        trace_dir=None,
        redact=True,
    )
    record = logger.record_step(
        step=0,
        input_summary="api_key=sk-abcdefghijklmnopqrstuvwxyz",
        decision="call tool",
        reason="test redaction",
        risk_level="medium",
        result="ok",
        tool_call={"body": "password=hunter2"},
    )
    serialised = record.model_dump_json()
    assert "hunter2" not in serialised
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in serialised
    assert "[REDACTED]" in serialised
