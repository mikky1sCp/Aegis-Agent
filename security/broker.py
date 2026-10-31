"""Deterministic policy for capabilities, risk, taint, and approvals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from agent.contracts import (
    AgentIdentity,
    ApprovalDisposition,
    ApprovalRequest,
    AuthOutcome,
    RiskLevel,
    TaintAssessment,
    TrustLevel,
)
from security.approvals import ApprovalProvider, DenyAllApprovals
from security.taint import redact_secrets
from tools.base import Tool, ToolContext, ToolOutput


@dataclass(frozen=True)
class PermissionPolicy:
    """Operator policy, independent of any LLM output."""

    globally_blocked_tools: frozenset[str] = frozenset({"transfer_funds"})
    approval_risk_levels: frozenset[RiskLevel] = frozenset(
        {RiskLevel.HIGH, RiskLevel.CRITICAL}
    )
    taint_blocked_risk_levels: frozenset[RiskLevel] = frozenset(
        {RiskLevel.HIGH, RiskLevel.CRITICAL}
    )


class PolicyVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: AuthOutcome
    code: str
    reason: str


class BrokerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: AuthOutcome
    authorized: bool
    executed: bool
    tool_name: str
    risk: RiskLevel
    reason: str
    policy_code: str
    approval: Any = None
    output: ToolOutput | None = None
    taint: TaintAssessment = TaintAssessment()

    @property
    def ok(self) -> bool:
        return self.executed and bool(self.output and self.output.ok)


class ToolPermissionBroker:
    """The only path from an LLM proposal to a tool effect.

    Capabilities come from an immutable AgentIdentity supplied by construction,
    never from model output, tool arguments, or another agent's message.
    """

    def __init__(
        self,
        registry: Any,
        *,
        policy: PermissionPolicy | None = None,
        approval_provider: ApprovalProvider | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy or PermissionPolicy()
        self.approval_provider = approval_provider or DenyAllApprovals()
        self.audit: list[BrokerResult] = []

    def evaluate(
        self,
        identity: AgentIdentity,
        tool: Tool,
        taint: TaintAssessment,
        *,
        extra_approval_tools: set[str] | None = None,
    ) -> PolicyVerdict:
        if tool.name in self.policy.globally_blocked_tools:
            return PolicyVerdict(
                outcome=AuthOutcome.DENIED,
                code="globally_blocked",
                reason=f"{tool.name} is globally forbidden by operator policy",
            )
        if not identity.has(tool.required_capability):
            return PolicyVerdict(
                outcome=AuthOutcome.DENIED,
                code="missing_capability",
                reason=(
                    f"{identity.agent_id} lacks immutable capability "
                    f"'{tool.required_capability}'"
                ),
            )
        if taint.tainted and tool.risk in self.policy.taint_blocked_risk_levels:
            return PolicyVerdict(
                outcome=AuthOutcome.DENIED,
                code="tainted_high_risk",
                reason=(
                    "high-risk action is derived from untrusted data; "
                    "it cannot be authorised by content"
                ),
            )
        approval_tools = set(extra_approval_tools or set())
        if (
            tool.risk in self.policy.approval_risk_levels
            or tool.name in approval_tools
        ):
            return PolicyVerdict(
                outcome=AuthOutcome.APPROVAL_REQUIRED,
                code="human_approval",
                reason=f"{tool.risk.value}-risk action requires explicit approval",
            )
        return PolicyVerdict(
            outcome=AuthOutcome.ALLOWED,
            code="least_privilege_allow",
            reason="capability, policy, and taint checks passed",
        )

    def execute(
        self,
        identity: AgentIdentity,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        purpose: str,
        taint: TaintAssessment,
        tool_context: ToolContext,
        extra_approval_tools: set[str] | None = None,
    ) -> BrokerResult:
        tool = self.registry.get(tool_name)
        if tool is None:
            return self._finish(
                BrokerResult(
                    outcome=AuthOutcome.DENIED,
                    authorized=False,
                    executed=False,
                    tool_name=tool_name,
                    risk=RiskLevel.HIGH,
                    reason=f"unknown tool '{tool_name}'",
                    policy_code="unknown_tool",
                    taint=taint,
                )
            )

        try:
            parsed = tool.input_model.model_validate(arguments)
        except Exception as exc:
            return self._finish(
                BrokerResult(
                    outcome=AuthOutcome.DENIED,
                    authorized=False,
                    executed=False,
                    tool_name=tool_name,
                    risk=tool.risk,
                    reason=f"invalid tool arguments: {exc}",
                    policy_code="invalid_arguments",
                    taint=taint,
                )
            )
        safe_args = parsed.model_dump(mode="json")
        verdict = self.evaluate(
            identity, tool, taint, extra_approval_tools=extra_approval_tools
        )
        if verdict.outcome == AuthOutcome.DENIED:
            return self._finish(
                BrokerResult(
                    outcome=AuthOutcome.DENIED,
                    authorized=False,
                    executed=False,
                    tool_name=tool_name,
                    risk=tool.risk,
                    reason=verdict.reason,
                    policy_code=verdict.code,
                    taint=taint,
                )
            )

        approval = None
        if verdict.outcome == AuthOutcome.APPROVAL_REQUIRED:
            request = ApprovalRequest(
                request_id=f"apr-{len(self.audit) + 1:04d}-{tool_name}",
                run_id=tool_context.run_id,
                agent_id=identity.agent_id,
                tool_name=tool_name,
                risk=tool.risk,
                arguments_preview=_preview(safe_args),
                purpose=purpose,
                reason=verdict.reason,
                tainted=taint.tainted,
                injection_signals=taint.injection_signals,
                proposed_effect=_proposed_effect(tool_name, safe_args),
            )
            try:
                approval = self.approval_provider.review(request)
            except Exception as exc:
                return self._finish(
                    BrokerResult(
                        outcome=AuthOutcome.DENIED,
                        authorized=False,
                        executed=False,
                        tool_name=tool_name,
                        risk=tool.risk,
                        reason=(
                            "approval provider failed closed: "
                            f"{type(exc).__name__}"
                        ),
                        policy_code="approval_provider_error",
                        taint=taint,
                    )
                )
            if approval is not None and approval.request_id != request.request_id:
                return self._finish(
                    BrokerResult(
                        outcome=AuthOutcome.DENIED,
                        authorized=False,
                        executed=False,
                        tool_name=tool_name,
                        risk=tool.risk,
                        reason="approval decision is not bound to this request",
                        policy_code="approval_request_mismatch",
                        approval=approval,
                        taint=taint,
                    )
                )
            if approval is None or approval.disposition == ApprovalDisposition.PENDING:
                return self._finish(
                    BrokerResult(
                        outcome=AuthOutcome.APPROVAL_REQUIRED,
                        authorized=False,
                        executed=False,
                        tool_name=tool_name,
                        risk=tool.risk,
                        reason="action paused: explicit human approval is pending",
                        policy_code="approval_pending",
                        approval=approval,
                        taint=taint,
                    )
                )
            if approval.disposition != ApprovalDisposition.APPROVED:
                return self._finish(
                    BrokerResult(
                        outcome=AuthOutcome.DENIED,
                        authorized=False,
                        executed=False,
                        tool_name=tool_name,
                        risk=tool.risk,
                        reason=(
                            "human approval denied"
                            + (f": {approval.comment}" if approval.comment else "")
                        ),
                        policy_code="approval_denied",
                        approval=approval,
                        taint=taint,
                    )
                )

        call_context = ToolContext(
            run_id=tool_context.run_id,
            agent_id=identity.agent_id,
            workspace=tool_context.workspace,
            taint=TrustLevel.UNTRUSTED if taint.tainted else TrustLevel.TRUSTED,
            metadata=dict(tool_context.metadata),
        )
        executed = True
        try:
            output = tool.invoke(safe_args, call_context)
        except Exception as exc:
            output = ToolOutput(ok=False, error=f"tool boundary error: {type(exc).__name__}: {exc}")
        result = BrokerResult(
            outcome=AuthOutcome.ALLOWED,
            authorized=True,
            executed=executed,
            tool_name=tool_name,
            risk=tool.risk,
            reason="approved call executed" if approval else "least-privilege call executed",
            policy_code=verdict.code,
            approval=approval,
            output=output,
            taint=taint,
        )
        return self._finish(result)

    def _finish(self, result: BrokerResult) -> BrokerResult:
        self.audit.append(result)
        return result


def _preview(arguments: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            redacted = redact_secrets(value)
            clean[key] = (
                redacted
                if len(redacted) <= 240
                else f"{redacted[:240]}... [truncated; {len(redacted)} chars total]"
            )
        elif isinstance(value, list):
            items = []
            for item in value[:5]:
                if isinstance(item, str):
                    redacted = redact_secrets(item)
                    items.append(
                        redacted
                        if len(redacted) <= 120
                        else f"{redacted[:120]}... [truncated]"
                    )
                else:
                    items.append(item)
            clean[key] = items
        else:
            clean[key] = value
    return clean


def _proposed_effect(tool_name: str, arguments: dict[str, Any]) -> str:
    if tool_name == "send_email":
        return f"send external email to {arguments.get('recipients')}"
    if tool_name == "write_report":
        return f"write reports/{arguments.get('filename')}"
    if tool_name == "transfer_funds":
        return f"transfer ${arguments.get('amount_usd')} to {arguments.get('destination')}"
    return f"invoke {tool_name}"
