"""LLM boundary. Model output is a proposal, never an authorization."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.contracts import ActionSummary, GoalReview, GoalSpec, LLMDecision, Plan, PlanStep, TokenUsage


class LLMClientError(RuntimeError):
    pass


class DecisionContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal_id: str
    step: int
    plan_step: PlanStep
    goal_digest: str
    rendered_context: str
    tools: list[dict[str, Any]]
    recent_actions: list[ActionSummary] = Field(default_factory=list)
    untrusted_present: bool = False
    remaining_tool_calls: int


class LLMClient(ABC):
    """Provider-independent boundary used by the agent loop and FakeLLM."""

    @abstractmethod
    def plan(self, goal: GoalSpec, tool_catalog: list[dict[str, Any]]) -> Plan:
        raise NotImplementedError

    @abstractmethod
    def decide(self, context: DecisionContext) -> LLMDecision:
        raise NotImplementedError

    def review_goal(
        self, objective: str, constraints: list[str], actions: list[ActionSummary]
    ) -> GoalReview:
        """Advisory review only. The default abstains; it cannot grant authority."""
        return GoalReview(
            drifted=False,
            confidence=0.0,
            reasons=["reviewer not configured; structural ledger checks remain active"],
        )


class FakeLLM(LLMClient):
    """Deterministic scripted model for tests and evals."""

    def __init__(
        self,
        plan: Plan,
        decisions: list[LLMDecision],
        *,
        goal_reviews: list[GoalReview] | None = None,
        plan_usage: TokenUsage | None = None,
    ) -> None:
        self.scripted_plan = plan
        self.decisions = list(decisions)
        self.goal_reviews = list(goal_reviews or [])
        self.plan_usage = plan_usage or TokenUsage(input_tokens=40, output_tokens=20)
        self.seen_contexts: list[DecisionContext] = []
        self.calls = 0

    def plan(self, goal: GoalSpec, tool_catalog: list[dict[str, Any]]) -> Plan:
        return self.scripted_plan

    def decide(self, context: DecisionContext) -> LLMDecision:
        self.seen_contexts.append(context)
        if not self.decisions:
            raise LLMClientError("scripted decision queue exhausted")
        self.calls += 1
        return self.decisions.pop(0)

    def review_goal(
        self, objective: str, constraints: list[str], actions: list[ActionSummary]
    ) -> GoalReview:
        if self.goal_reviews:
            return self.goal_reviews.pop(0)
        return GoalReview(
            drifted=False,
            confidence=0.0,
            reasons=["no scripted drift review"],
        )
