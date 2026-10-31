"""Tool boundary tests: traversal, validation, medium-risk effects."""

from __future__ import annotations

from pathlib import Path

from agent.contracts import AuthOutcome
from security.approvals import DenyAllApprovals
from tests.support import clean_taint, identity, make_broker
from tools.base import ToolContext


def _ctx(workspace: Path) -> ToolContext:
    return ToolContext(run_id="run-tools", agent_id="agent-test", workspace=workspace)


def test_path_traversal_is_denied_by_tool(workspace: Path) -> None:
    outside = workspace / "outside-secret.md"
    outside.write_text("SECRET", encoding="utf-8")
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["read_document"]),
        "read_document",
        {"path": "../outside-secret.md"},
        purpose="read",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.ALLOWED
    assert result.output is not None
    assert result.output.ok is False
    assert "escapes the permitted root" in (result.output.error or "")
    assert "SECRET" not in (result.output.content or "")


def test_invalid_arguments_never_reach_tool_execution(workspace: Path) -> None:
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {"recipients": ["not-an-address"], "subject": "x", "body": "y"},
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "invalid_arguments"
    assert result.executed is False
    assert not (workspace / "outbox" / "sent.jsonl").exists()


def test_unknown_tool_is_denied(workspace: Path) -> None:
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["read_document"]),
        "execute_shell",
        {"command": "whoami"},
        purpose="run command",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "unknown_tool"


def test_medium_risk_write_is_policy_allowed_and_reversible(workspace: Path) -> None:
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["write_report"]),
        "write_report",
        {"filename": "medium.md", "content": "Allowed medium-risk content."},
        purpose="write report",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.ALLOWED
    assert result.executed is True
    path = workspace / "reports" / "medium.md"
    assert path.exists()
    assert "AEGIS-PROVENANCE" in path.read_text(encoding="utf-8")


def test_recipient_domain_policy_can_reject_after_approval_preconditions(
    workspace: Path,
) -> None:
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {
            "recipients": ["person@not-allowed.example"],
            "subject": "x",
            "body": "y",
        },
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    # The approval gate denies before the tool-level domain check, so nothing executes.
    assert result.executed is False
