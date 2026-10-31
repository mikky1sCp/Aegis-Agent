"""Test builders to keep adversarial scenarios readable and deterministic."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from agent.config import Settings
from agent.contracts import (
    AgentIdentity,
    DecisionType,
    GoalReview,
    GoalSpec,
    InjectionSignal,
    Invariant,
    InvariantKind,
    LLMDecision,
    Plan,
    PlanStep,
    SuccessCriterion,
    TokenUsage,
    TrustLevel,
)
from agent.llm import FakeLLM
from agent.loop import AegisAgent
from security.approvals import ApprovalProvider, DenyAllApprovals
from security.broker import PermissionPolicy, ToolPermissionBroker
from security.taint import TaintAssessment
from tools.builtin import ToolRegistry, build_default_registry


def make_settings(
    workspace: Path,
    *,
    budget: int = 1200,
    drift_interval: int = 10,
    max_steps: int = 10,
    recovery: int = 3,
) -> Settings:
    return Settings(
        workspace=workspace,
        trace_dir=workspace / "traces",
        data_dir=workspace / "data",
        context_budget_tokens=budget,
        max_steps=max_steps,
        drift_check_interval=drift_interval,
        max_recovery_attempts=recovery,
    )


def write_doc(workspace: Path, name: str, text: str) -> Path:
    path = workspace / "data" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def make_goal(
    *,
    goal_id: str = "goal-1",
    objective: str = "Summarize the policy and write a report",
    constraints: list[str] | None = None,
    criteria: Iterable[tuple[str, str]] | None = None,
    invariants: list[Invariant] | None = None,
    scope_keywords: list[str] | None = None,
    original_task: str = "",
) -> GoalSpec:
    criteria_list = [
        SuccessCriterion(id=item[0], description=item[1])
        for item in (
            criteria
            if criteria is not None
            else [("c1", "report written and goal satisfied")]
        )
    ]
    default_invariants = [
        Invariant(
            id="no-transfers",
            kind=InvariantKind.FORBIDDEN_TOOLS,
            description="Funds transfers are forbidden for this goal",
            params={"tools": ["transfer_funds"]},
        ),
        Invariant(
            id="tool-budget",
            kind=InvariantKind.MAX_TOOL_CALLS,
            description="At most eight tool calls",
            params={"limit": 8},
        ),
    ]
    return GoalSpec(
        goal_id=goal_id,
        objective=objective,
        constraints=constraints or ["Do not transfer funds", "Use only workspace data"],
        invariants=default_invariants if invariants is None else invariants,
        success_criteria=criteria_list,
        scope_keywords=scope_keywords or [],
        original_task=original_task or objective,
    )


def make_plan(
    goal: GoalSpec,
    tools_per_step: list[list[str]] | None = None,
    *,
    strict: bool = True,
) -> Plan:
    tools = tools_per_step or [["read_document"], ["write_report"]]
    return Plan(
        goal_id=goal.goal_id,
        steps=[
            PlanStep(
                id=f"s{index + 1}",
                description=f"Execute planned action {index + 1}",
                expected_tools=tools[index] if index < len(tools) else [],
            )
            for index in range(len(tools))
        ],
        strict_scope=strict,
        rationale="deterministic test plan",
    )


def identity(
    capabilities: Iterable[str] = ("read_document", "write_report"),
    *,
    agent_id: str = "agent-test",
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id, role="test-agent", capabilities=frozenset(capabilities)
    )


def make_broker(
    *,
    provider: ApprovalProvider | None = None,
    registry: ToolRegistry | None = None,
    policy: PermissionPolicy | None = None,
) -> ToolPermissionBroker:
    return ToolPermissionBroker(
        registry or build_default_registry(),
        policy=policy,
        approval_provider=provider or DenyAllApprovals(),
    )


def tool_decision(
    goal: GoalSpec,
    step: int,
    tool_name: str,
    arguments: dict,
    *,
    evidence_ids: list[str] | None = None,
    purpose: str = "advance the plan",
    reason: str = "planned step",
) -> LLMDecision:
    return LLMDecision(
        goal_id=goal.goal_id,
        step=step,
        decision_type=DecisionType.TOOL_CALL,
        tool_name=tool_name,
        arguments=arguments,
        purpose=purpose,
        reason=reason,
        evidence_ids=evidence_ids or [],
        usage=TokenUsage(input_tokens=40, output_tokens=8),
    )


def final_decision(
    goal: GoalSpec,
    step: int,
    *,
    criteria: list[str] | None = None,
    answer: str = "The requested work is complete.",
    evidence_ids: list[str] | None = None,
) -> LLMDecision:
    return LLMDecision(
        goal_id=goal.goal_id,
        step=step,
        decision_type=DecisionType.FINAL,
        purpose="report completion",
        reason="required success criteria were satisfied",
        final_answer=answer,
        completed_criteria=criteria or ["c1"],
        evidence_ids=evidence_ids or [],
        usage=TokenUsage(input_tokens=40, output_tokens=12),
    )


def run_agent(
    workspace: Path,
    goal: GoalSpec,
    plan: Plan,
    decisions: list[LLMDecision],
    *,
    capabilities: Iterable[str] = ("read_document", "write_report"),
    provider: ApprovalProvider | None = None,
    registry: ToolRegistry | None = None,
    settings: Settings | None = None,
    reviews: list[GoalReview] | None = None,
):
    llm = FakeLLM(plan, decisions, goal_reviews=reviews)
    broker = make_broker(provider=provider, registry=registry)
    agent = AegisAgent(
        goal=goal,
        identity=identity(capabilities),
        llm=llm,
        broker=broker,
        settings=settings or make_settings(workspace),
    )
    report = agent.run(plan)
    return agent, report


def clean_taint() -> TaintAssessment:
    return TaintAssessment.clean()


def injected_taint() -> TaintAssessment:
    return TaintAssessment(
        tainted=True,
        sources=["ctx-9999"],
        injection_signals=[InjectionSignal.INSTRUCTION_OVERRIDE],
        reason="untrusted evidence contains instructions",
    )
