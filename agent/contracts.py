"""Shared, typed contracts for Aegis-Agent.

The LLM only produces :class:`Plan` and :class:`LLMDecision` values. Security
decisions are never represented as model output that can grant authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TrustLevel(StrEnum):
    SYSTEM = "system"
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class DecisionType(StrEnum):
    TOOL_CALL = "tool_call"
    FINAL = "final"
    REFUSE = "refuse"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ApprovalDisposition(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"


class AuthOutcome(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"


class InjectionSignal(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    TOOL_INVOCATION = "tool_invocation"
    EXFILTRATION = "exfiltration"
    ROLE_HIJACK = "role_hijack"
    SECRET_REQUEST = "secret_request"
    CONCEALMENT = "concealment"


class InvariantKind(StrEnum):
    MAX_TOOL_CALLS = "max_tool_calls"
    MAX_STEPS = "max_steps"
    FORBIDDEN_TOOLS = "forbidden_tools"
    ALLOWED_TOOLS = "allowed_tools"
    RECIPIENT_DOMAINS = "recipient_domains"
    MAX_SPEND_USD = "max_spend_usd"
    APPROVAL_TOOLS = "approval_tools"
    REQUIRE_EVIDENCE = "require_evidence"
    PLAN_SCOPE = "plan_scope"
    SUCCESS_CRITERIA = "success_criteria"


class Provenance(BaseModel):
    """Where a piece of context came from and whether it may instruct the agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    trust: TrustLevel
    uri: str | None = None
    retrieved_at: datetime = Field(default_factory=utc_now)


class TaintAssessment(BaseModel):
    """Derived data flow state for one proposed action."""

    model_config = ConfigDict(extra="forbid")

    tainted: bool = False
    sources: list[str] = Field(default_factory=list)
    injection_signals: list[InjectionSignal] = Field(default_factory=list)
    reason: str = "no untrusted evidence referenced"

    @classmethod
    def clean(cls) -> "TaintAssessment":
        return cls()


class SuccessCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    required: bool = True


class Invariant(BaseModel):
    """A machine-checkable constraint from the GoalLedger."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    kind: InvariantKind
    description: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _valid_params(self) -> "Invariant":
        if self.kind in {
            InvariantKind.FORBIDDEN_TOOLS,
            InvariantKind.ALLOWED_TOOLS,
            InvariantKind.APPROVAL_TOOLS,
        }:
            tools = self.params.get("tools")
            if not isinstance(tools, list) or not all(
                isinstance(item, str) and item for item in tools
            ):
                raise ValueError(f"{self.kind.value} requires params.tools as a string list")
        elif self.kind in {InvariantKind.MAX_TOOL_CALLS, InvariantKind.MAX_STEPS}:
            limit = self.params.get("limit")
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                raise ValueError(f"{self.kind.value} requires a non-negative integer limit")
        elif self.kind == InvariantKind.RECIPIENT_DOMAINS:
            domains = self.params.get("domains")
            if not isinstance(domains, list) or not all(
                isinstance(item, str) and item for item in domains
            ):
                raise ValueError("recipient_domains requires a string list domains")
        elif self.kind == InvariantKind.MAX_SPEND_USD:
            limit = self.params.get("limit")
            if not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit < 0:
                raise ValueError("max_spend_usd requires a non-negative numeric limit")
        elif self.kind == InvariantKind.REQUIRE_EVIDENCE:
            minimum = self.params.get("min_items", 1)
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 0:
                raise ValueError("require_evidence requires a non-negative integer min_items")
        return self


class GoalSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal_id: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    constraints: list[str] = Field(default_factory=list)
    invariants: list[Invariant] = Field(default_factory=list)
    success_criteria: list[SuccessCriterion] = Field(default_factory=list)
    scope_keywords: list[str] = Field(default_factory=list)
    original_task: str = ""

    @model_validator(mode="after")
    def _unique_ids(self) -> "GoalSpec":
        for label, values in (
            ("invariant", [i.id for i in self.invariants]),
            ("criterion", [c.id for c in self.success_criteria]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {label} id")
        return self

    def goal_digest(self) -> str:
        lines = [f"OBJECTIVE: {self.objective}"]
        if self.constraints:
            lines.append("CONSTRAINTS: " + " | ".join(self.constraints))
        if self.success_criteria:
            lines.append(
                "SUCCESS CRITERIA: "
                + " | ".join(f"{c.id}={c.description}" for c in self.success_criteria)
            )
        return "\n".join(lines)


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    expected_tools: list[str] = Field(default_factory=list)
    success_check: str = ""


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal_id: str = Field(min_length=1)
    steps: list[PlanStep] = Field(min_length=1)
    strict_scope: bool = True
    rationale: str = ""

    @model_validator(mode="after")
    def _unique_step_ids(self) -> "Plan":
        ids = [s.id for s in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate plan step id")
        return self


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class LLMDecision(BaseModel):
    """A proposal from the LLM. It has no authority until the broker allows it."""

    model_config = ConfigDict(extra="forbid")

    goal_id: str = Field(min_length=1)
    step: int = Field(ge=0)
    decision_type: DecisionType = DecisionType.TOOL_CALL
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    expected_outcome: str = ""
    final_answer: str | None = None
    completed_criteria: list[str] = Field(default_factory=list)
    usage: TokenUsage = Field(default_factory=TokenUsage)

    @model_validator(mode="after")
    def _shape(self) -> "LLMDecision":
        if self.decision_type == DecisionType.TOOL_CALL and not self.tool_name:
            raise ValueError("tool_call decision requires tool_name")
        if self.decision_type == DecisionType.FINAL and not self.final_answer:
            raise ValueError("final decision requires final_answer")
        return self


class GoalReview(BaseModel):
    """Advisory opinion from the drift reviewer. It can stop work, never authorize it."""

    model_config = ConfigDict(extra="forbid")

    drifted: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class ActionSummary(BaseModel):
    """Trusted, structured view of an action, safe to send to a drift reviewer."""

    model_config = ConfigDict(extra="forbid")

    step: int
    tool_name: str | None
    purpose: str
    risk: RiskLevel
    executed: bool
    outcome: str


class RunAction(BaseModel):
    """Full action record used by checkpoints and the final report."""

    model_config = ConfigDict(extra="forbid")

    step: int
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    purpose: str
    reason: str
    risk: RiskLevel
    authorized: bool = False
    executed: bool = False
    ok: bool = False
    outcome: str
    approval: str | None = None
    tainted: bool = False
    irreversible: bool = False


class Violation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invariant_id: str
    kind: InvariantKind
    description: str
    step: int
    severity: RiskLevel = RiskLevel.HIGH


class DriftSignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1)


class LedgerAudit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    violations: list[Violation] = Field(default_factory=list)
    drift: DriftSignal | None = None
    notes: list[str] = Field(default_factory=list)

    @property
    def reason(self) -> str:
        if self.drift:
            return f"goal drift: {self.drift.reason}"
        if self.violations:
            return "; ".join(v.description for v in self.violations)
        return "ledger check passed"


class ApprovalRequest(BaseModel):
    """Sent to a human/policy approver. Contains no reusable authority token."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    run_id: str
    agent_id: str
    tool_name: str
    risk: RiskLevel
    arguments_preview: dict[str, Any]
    purpose: str
    reason: str
    tainted: bool
    injection_signals: list[InjectionSignal] = Field(default_factory=list)
    proposed_effect: str


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str
    disposition: ApprovalDisposition
    approver: str = Field(min_length=1)
    comment: str = ""


class AgentIdentity(BaseModel):
    """Immutable grant. Only construction/delegation code creates identities."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=1)
    role: str = Field(min_length=1)
    capabilities: frozenset[str] = Field(default_factory=frozenset)

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    def with_subset(self, child_id: str, role: str, delegated: set[str]) -> "AgentIdentity":
        safe = frozenset(delegated) & self.capabilities
        return AgentIdentity(agent_id=child_id, role=role, capabilities=safe)


class AgentMessage(BaseModel):
    """Inter-agent content is always data. It cannot mutate identity or grants."""

    model_config = ConfigDict(extra="forbid")

    message_id: str
    sender_id: str
    receiver_id: str
    content: str
    provenance: Provenance
    confidence: float = Field(ge=0.0, le=1.0)
    kind: str = "report"
    created_at: datetime = Field(default_factory=utc_now)


class DelegationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parent_id: str
    child_id: str
    child_role: str
    requested_capabilities: list[str]
    justification: str = Field(min_length=1)


class DelegationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    child_identity: AgentIdentity | None = None
