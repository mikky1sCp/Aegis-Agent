"""Checkpoint and compensating rollback tests."""

from __future__ import annotations

from pathlib import Path

from agent.checkpoint import AgentState, CheckpointManager
from agent.contracts import RunAction, RunStatus
from security.goals import GoalLedger
from tests.support import make_goal
from tools.base import ToolContext
from tools.builtin import SendEmailTool, WriteReportTool


def _state(workspace: Path, goal, context, ledger) -> AgentState:
    return AgentState(
        run_id="run-checkpoint",
        goal_id=goal.goal_id,
        step=1,
        plan_index=1,
        status=RunStatus.RUNNING,
        ledger=ledger.export_state(),
        context=context.export_state(),
        actions=[
            RunAction(
                step=0,
                tool_name="read_document",
                purpose="read",
                reason="planned",
                risk="low",
                authorized=True,
                executed=True,
                ok=True,
                outcome="read",
            )
        ],
    )


def test_checkpoint_rollback_restores_state_and_removes_report(workspace: Path) -> None:
    goal = make_goal()
    ledger = GoalLedger(goal)
    from memory.context import ContextManager

    context = ContextManager(goal)
    manager = CheckpointManager(store_dir=workspace / "checkpoints")
    checkpoint = manager.save("before write", _state(workspace, goal, context, ledger))
    assert checkpoint.state.step == 1

    tool = WriteReportTool()
    ctx = ToolContext(run_id="run-checkpoint", agent_id="agent-test", workspace=workspace)
    output = tool.invoke(
        {"filename": "summary.md", "content": "A summary that must be rolled back."}, ctx
    )
    assert output.ok
    manager.note_effect(tool, output, "wrote report")
    report_path = workspace / "reports" / "summary.md"
    assert report_path.exists()

    rollback = manager.rollback_to(checkpoint.checkpoint_id, ctx)
    assert rollback.ok is True
    assert rollback.restored_state.step == 1
    assert rollback.restored_state.actions[0].tool_name == "read_document"
    assert not report_path.exists()
    assert rollback.compensations[0]["tool_name"] == "write_report"
    loaded = manager.load_checkpoint_file(
        workspace / "checkpoints" / f"{checkpoint.checkpoint_id}.json"
    )
    assert loaded.checkpoint_id == checkpoint.checkpoint_id


def test_irreversible_effect_is_not_falsely_reported_as_rolled_back(
    workspace: Path,
) -> None:
    goal = make_goal()
    ledger = GoalLedger(goal)
    from memory.context import ContextManager

    context = ContextManager(goal)
    manager = CheckpointManager()
    checkpoint = manager.save("before email", _state(workspace, goal, context, ledger))
    tool = SendEmailTool()
    ctx = ToolContext(run_id="run-checkpoint", agent_id="agent-test", workspace=workspace)
    output = tool.invoke(
        {
            "recipients": ["boss@example.org"],
            "subject": "Cannot unsend",
            "body": "External effect.",
        },
        ctx,
    )
    assert output.ok
    assert output.irreversible is True
    manager.note_effect(tool, output, "email sent")
    result = manager.rollback_to(checkpoint.checkpoint_id, ctx)
    assert result.ok is False
    assert result.compensations[0]["ok"] is False
    assert "irreversible" in result.compensations[0]["description"]
    assert (workspace / "outbox" / "sent.jsonl").exists()
