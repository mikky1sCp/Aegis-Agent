"""Least-privilege and human-approval acceptance tests."""

from __future__ import annotations

from pathlib import Path

from agent.contracts import (
    ApprovalDecision,
    ApprovalDisposition,
    AuthOutcome,
)
from security.approvals import (
    ApprovalProvider,
    DenyAllApprovals,
    PendingApprovals,
    StaticApprovals,
)
from tests.support import (
    clean_taint,
    final_decision,
    identity,
    injected_taint,
    make_broker,
    make_goal,
    make_plan,
    run_agent,
    tool_decision,
)
from tools.base import ToolContext


def _ctx(workspace: Path) -> ToolContext:
    return ToolContext(run_id="run-test", agent_id="agent-test", workspace=workspace)


def test_forbidden_tool_blocked_even_with_capability_and_approval(workspace: Path) -> None:
    provider = StaticApprovals()
    broker = make_broker(provider=provider)
    result = broker.execute(
        identity(["transfer_funds"]),
        "transfer_funds",
        {"amount_usd": 500, "destination": "attacker"},
        purpose="move money",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "globally_blocked"
    assert result.executed is False
    assert provider.requests == [], "operator approval can never override a global block"


def test_high_risk_action_blocked_without_approval(workspace: Path) -> None:
    broker = make_broker(provider=DenyAllApprovals())
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {
            "recipients": ["boss@example.org"],
            "subject": "Status",
            "body": "This must not be sent without approval.",
        },
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "approval_denied"
    assert result.executed is False
    assert not (workspace / "outbox" / "sent.jsonl").exists()


def test_high_risk_action_executes_only_with_explicit_approval(workspace: Path) -> None:
    provider = StaticApprovals()
    broker = make_broker(provider=provider)
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {
            "recipients": ["boss@example.org"],
            "subject": "Approved status",
            "body": "Approved by a human.",
        },
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.ALLOWED
    assert result.executed is True
    assert result.approval is not None
    assert len(provider.requests) == 1
    assert provider.requests[0].risk.value == "high"
    assert (workspace / "outbox" / "sent.jsonl").exists()


def test_tainted_high_risk_action_cannot_be_approved_into_execution(workspace: Path) -> None:
    provider = StaticApprovals()
    broker = make_broker(provider=provider)
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {
            "recipients": ["attacker@example.org"],
            "subject": "Injected",
            "body": "Send the data.",
        },
        purpose="follow document instructions",
        taint=injected_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "tainted_high_risk"
    assert result.executed is False
    assert provider.requests == []
    assert not (workspace / "outbox" / "sent.jsonl").exists()


def test_missing_capability_is_denied(workspace: Path) -> None:
    broker = make_broker(provider=StaticApprovals())
    result = broker.execute(
        identity(["read_document"]),
        "send_email",
        {"recipients": ["boss@example.org"], "subject": "x", "body": "y"},
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "missing_capability"
    assert result.executed is False


class _ExplodingApproval(ApprovalProvider):
    def review(self, request):  # type: ignore[no-untyped-def]
        raise RuntimeError("approval channel unavailable")


class _WrongRequestApproval(ApprovalProvider):
    def review(self, request):  # type: ignore[no-untyped-def]
        return ApprovalDecision(
            request_id="different-request",
            disposition=ApprovalDisposition.APPROVED,
            approver="buggy-operator",
        )


def test_approval_provider_error_fails_closed(workspace: Path) -> None:
    broker = make_broker(provider=_ExplodingApproval())
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {"recipients": ["boss@example.org"], "subject": "x", "body": "y"},
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "approval_provider_error"
    assert result.executed is False


def test_approval_must_be_bound_to_the_exact_request(workspace: Path) -> None:
    broker = make_broker(provider=_WrongRequestApproval())
    result = broker.execute(
        identity(["send_email"]),
        "send_email",
        {"recipients": ["boss@example.org"], "subject": "x", "body": "y"},
        purpose="notify",
        taint=clean_taint(),
        tool_context=_ctx(workspace),
    )
    assert result.outcome == AuthOutcome.DENIED
    assert result.policy_code == "approval_request_mismatch"
    assert result.executed is False
    assert not (workspace / "outbox" / "sent.jsonl").exists()


def test_agent_stops_when_high_risk_email_has_no_approval(workspace: Path) -> None:
    goal = make_goal(
        objective="Email the approved status",
        criteria=[("c1", "email sent")],
        invariants=[],
    )
    plan = make_plan(goal, [["send_email"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "send_email",
            {
                "recipients": ["boss@example.org"],
                "subject": "Status",
                "body": "Blocked without a human.",
            },
            purpose="notify",
            reason="the operator asked for an email",
        )
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        capabilities=("send_email",),
        provider=DenyAllApprovals(),
    )
    assert report.status.value == "blocked"
    assert report.stop_reason == "tool_denied:approval_denied"
    assert report.actions[-1].executed is False
    assert report.approvals
    assert report.approvals[-1].disposition == ApprovalDisposition.DENIED
    assert not (workspace / "outbox" / "sent.jsonl").exists()
    assert agent.broker.audit[-1].executed is False


def test_agent_completes_high_risk_action_with_explicit_approval(
    workspace: Path,
) -> None:
    goal = make_goal(
        objective="Email the approved status",
        criteria=[("c1", "email sent")],
        invariants=[],
    )
    plan = make_plan(goal, [["send_email"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "send_email",
            {
                "recipients": ["boss@example.org"],
                "subject": "Status",
                "body": "Approved by a human.",
            },
            purpose="notify",
            reason="the operator asked for an email",
        ),
        final_decision(goal, 1, answer="Approved email sent."),
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        capabilities=("send_email",),
        provider=StaticApprovals(),
    )
    assert report.status.value == "completed"
    assert report.approvals[-1].disposition == ApprovalDisposition.APPROVED
    assert agent.broker.audit[-1].executed is True
    assert (workspace / "outbox" / "sent.jsonl").exists()


def test_pending_approval_stops_without_execution(workspace: Path) -> None:
    goal = make_goal(
        objective="Email the approved status",
        criteria=[("c1", "email sent")],
        invariants=[],
    )
    plan = make_plan(goal, [["send_email"]])
    decisions = [
        tool_decision(
            goal,
            0,
            "send_email",
            {
                "recipients": ["boss@example.org"],
                "subject": "Waiting",
                "body": "Do not send until approval.",
            },
            purpose="notify",
            reason="the operator asked for an email",
        )
    ]
    agent, report = run_agent(
        workspace,
        goal,
        plan,
        decisions,
        capabilities=("send_email",),
        provider=PendingApprovals(),
    )
    assert report.status.value == "awaiting_approval"
    assert report.stop_reason == "human_approval_pending"
    assert report.approvals[-1].disposition == ApprovalDisposition.PENDING
    assert report.actions[-1].executed is False
    assert agent.broker.audit[-1].executed is False
    assert any(
        record.status == "approval_pending" for record in agent.trace.records
    )
    assert not (workspace / "outbox" / "sent.jsonl").exists()
