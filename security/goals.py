"""GoalLedger: explicit goals, machine invariants, drift detection, success audit."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.contracts import (
    ActionSummary,
    DriftSignal,
    GoalReview,
    GoalSpec,
    Invariant,
    InvariantKind,
    LedgerAudit,
    LLMDecision,
    Plan,
    RiskLevel,
    Violation,
)


class LedgerState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    goal: GoalSpec
    completed_criteria: list[str] = Field(default_factory=list)
    tool_calls: int = 0
    spend_usd: float = 0.0
    violations: list[Violation] = Field(default_factory=list)
    actions: list[ActionSummary] = Field(default_factory=list)
    drift: DriftSignal | None = None


class GoalLedger:
    """The authoritative record of why the agent is acting and what is forbidden."""

    def __init__(self, goal: GoalSpec) -> None:
        self.goal = goal
        self.completed_criteria: set[str] = set()
        self.tool_calls = 0
        self.spend_usd = 0.0
        self.violations: list[Violation] = []
        self.actions: list[ActionSummary] = []
        self.drift: DriftSignal | None = None

    @property
    def required_criteria(self) -> set[str]:
        return {criterion.id for criterion in self.goal.success_criteria if criterion.required}

    @property
    def all_required_met(self) -> bool:
        return self.required_criteria.issubset(self.completed_criteria)

    def approval_tools(self) -> set[str]:
        tools: set[str] = set()
        for invariant in self.goal.invariants:
            if invariant.kind == InvariantKind.APPROVAL_TOOLS:
                tools.update(str(item) for item in invariant.params.get("tools", []))
        return tools

    def check_action(
        self,
        decision: LLMDecision,
        *,
        plan: Plan,
        plan_index: int,
    ) -> LedgerAudit:
        """Hard checks run before every tool call or final answer."""
        violations: list[Violation] = []

        if decision.goal_id != self.goal.goal_id:
            signal = DriftSignal(
                kind="goal_id_mismatch",
                confidence=1.0,
                reason=(
                    f"decision targets '{decision.goal_id}' but active goal is "
                    f"'{self.goal.goal_id}'"
                ),
            )
            self.drift = signal
            return LedgerAudit(ok=False, drift=signal)

        if decision.step < 0:
            violations.append(
                self._violation(
                    "step",
                    InvariantKind.MAX_STEPS,
                    "negative step index",
                    decision.step,
                )
            )

        if decision.decision_type.value == "final":
            violations.extend(self._criteria_violations(decision))
            for invariant in self.goal.invariants:
                if invariant.kind == InvariantKind.REQUIRE_EVIDENCE:
                    violations.extend(self._evaluate_pre_action(invariant, decision))
            return LedgerAudit(ok=not violations, violations=violations)

        if decision.decision_type.value == "refuse":
            return LedgerAudit(ok=True, notes=["agent refused the task"])

        tool_name = decision.tool_name or ""
        if plan.strict_scope and plan_index < len(plan.steps):
            expected = plan.steps[plan_index].expected_tools
            if expected and tool_name not in expected:
                violations.append(
                    self._violation(
                        f"plan.{plan.steps[plan_index].id}.scope",
                        InvariantKind.PLAN_SCOPE,
                        (
                            f"tool '{tool_name}' is outside plan step "
                            f"'{plan.steps[plan_index].id}' expected tools {expected}"
                        ),
                        decision.step,
                    )
                )

        for invariant in self.goal.invariants:
            try:
                violations.extend(self._evaluate_pre_action(invariant, decision))
            except Exception as exc:
                violations.append(
                    self._violation(
                        invariant.id,
                        invariant.kind,
                        f"invalid invariant configuration: {type(exc).__name__}: {exc}",
                        decision.step,
                    )
                )
        return LedgerAudit(ok=not violations, violations=violations)

    def _evaluate_pre_action(
        self, invariant: Invariant, decision: LLMDecision
    ) -> list[Violation]:
        tool_name = decision.tool_name or ""
        arguments = decision.arguments
        step = decision.step
        params = invariant.params
        kind = invariant.kind
        out: list[Violation] = []

        if kind == InvariantKind.FORBIDDEN_TOOLS:
            if tool_name in set(params.get("tools", [])):
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"forbidden tool requested: {tool_name}",
                        step,
                    )
                )
        elif kind == InvariantKind.ALLOWED_TOOLS:
            allowed = set(params.get("tools", []))
            if tool_name not in allowed:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"tool '{tool_name}' is not in the goal allowlist",
                        step,
                    )
                )
        elif kind == InvariantKind.MAX_TOOL_CALLS:
            limit = int(params.get("limit", self._default_limit(kind)))
            if self.tool_calls >= limit:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"tool-call budget exhausted ({limit})",
                        step,
                    )
                )
        elif kind == InvariantKind.MAX_STEPS:
            limit = int(params.get("limit", self._default_limit(kind)))
            if step >= limit:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"step budget exhausted ({limit})",
                        step,
                    )
                )
        elif kind == InvariantKind.RECIPIENT_DOMAINS:
            domains = {str(d).lower() for d in params.get("domains", [])}
            recipients = _recipients(arguments)
            bad = sorted(
                {
                    address.rsplit("@", 1)[-1].lower()
                    for address in recipients
                    if "@" in address and address.rsplit("@", 1)[-1].lower() not in domains
                }
            )
            if bad:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"recipient domains outside allowlist: {bad}",
                        step,
                    )
                )
        elif kind == InvariantKind.MAX_SPEND_USD:
            limit = float(params.get("limit", 0.0))
            amount = float(arguments.get("amount_usd", arguments.get("amount", 0.0)) or 0.0)
            if amount > limit:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"proposed spend ${amount:.2f} exceeds ${limit:.2f}",
                        step,
                    )
                )
        elif kind == InvariantKind.REQUIRE_EVIDENCE:
            minimum = int(params.get("min_items", 1))
            if decision.decision_type.value == "final" and len(decision.evidence_ids) < minimum:
                out.append(
                    self._violation(
                        invariant.id,
                        kind,
                        f"final answer cites {len(decision.evidence_ids)} evidence items; "
                        f"minimum is {minimum}",
                        step,
                    )
                )
        elif kind == InvariantKind.APPROVAL_TOOLS:
            pass  # enforced by the ToolPermissionBroker, never by the model
        elif kind == InvariantKind.PLAN_SCOPE:
            pass  # enforced structurally above
        elif kind == InvariantKind.SUCCESS_CRITERIA:
            pass  # finalised separately
        else:
            out.append(
                self._violation(
                    invariant.id,
                    kind,
                    f"unsupported invariant kind: {kind}",
                    step,
                )
            )
        return out

    def _criteria_violations(self, decision: LLMDecision) -> list[Violation]:
        claimed = set(decision.completed_criteria)
        unknown = claimed - {criterion.id for criterion in self.goal.success_criteria}
        missing = self.required_criteria - claimed
        out: list[Violation] = []
        if unknown:
            out.append(
                self._violation(
                    "goal.success_criteria",
                    InvariantKind.SUCCESS_CRITERIA,
                    f"final answer claims unknown criteria: {sorted(unknown)}",
                    decision.step,
                )
            )
        if missing:
            out.append(
                self._violation(
                    "goal.success_criteria",
                    InvariantKind.SUCCESS_CRITERIA,
                    f"final answer omits required criteria: {sorted(missing)}",
                    decision.step,
                )
            )
        return out

    def finalise(self, decision: LLMDecision) -> LedgerAudit:
        violations = self._criteria_violations(decision)
        if not violations and self.goal.scope_keywords:
            text = (decision.final_answer or "").lower()
            if not any(keyword.lower() in text for keyword in self.goal.scope_keywords):
                self.drift = DriftSignal(
                    kind="final_scope_mismatch",
                    confidence=0.8,
                    reason="final answer does not mention any in-scope keyword",
                )
                return LedgerAudit(ok=False, drift=self.drift)
        if not violations:
            self.completed_criteria.update(decision.completed_criteria)
        return LedgerAudit(ok=not violations, violations=violations)

    def check_after_action(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        step: int,
        result_spend_usd: float = 0.0,
    ) -> LedgerAudit:
        violations: list[Violation] = []
        for invariant in self.goal.invariants:
            if invariant.kind == InvariantKind.MAX_SPEND_USD:
                limit = float(invariant.params.get("limit", 0.0))
                if result_spend_usd and self.spend_usd + result_spend_usd > limit:
                    violations.append(
                        self._violation(
                            invariant.id,
                            invariant.kind,
                            f"actual spend ${self.spend_usd + result_spend_usd:.2f} "
                            f"exceeds ${limit:.2f}",
                            step,
                        )
                    )
            elif invariant.kind == InvariantKind.RECIPIENT_DOMAINS:
                domains = {str(d).lower() for d in invariant.params.get("domains", [])}
                bad = [
                    address
                    for address in _recipients(arguments)
                    if "@" in address and address.rsplit("@", 1)[-1].lower() not in domains
                ]
                if bad:
                    violations.append(
                        self._violation(
                            invariant.id,
                            invariant.kind,
                            f"post-action recipient violation: {bad}",
                            step,
                        )
                    )
        return LedgerAudit(ok=not violations, violations=violations)

    def record_tool_result(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        result_spend_usd: float = 0.0,
    ) -> None:
        self.tool_calls += 1
        self.spend_usd += max(0.0, result_spend_usd)

    def record_action(self, summary: ActionSummary) -> None:
        self.actions.append(summary)

    def record_audit(self, audit: LedgerAudit) -> None:
        if audit.drift:
            self.drift = audit.drift
        if audit.violations:
            self.violations.extend(audit.violations)

    def apply_drift_review(self, review: GoalReview, step: int) -> LedgerAudit:
        """Reviewer can stop work. It cannot grant permission or rewrite the goal."""
        if review.drifted and review.confidence >= 0.5:
            signal = DriftSignal(
                kind="periodic_review",
                confidence=review.confidence,
                reason="; ".join(review.reasons) or "goal reviewer reported drift",
            )
            self.drift = signal
            return LedgerAudit(ok=False, drift=signal, notes=[f"step {step}"])
        return LedgerAudit(ok=True, notes=["periodic goal review found no actionable drift"])

    def action_summaries(self) -> list[ActionSummary]:
        """Only trusted structured summaries are sent to a drift reviewer."""
        return list(self.actions)

    def export_state(self) -> LedgerState:
        return LedgerState(
            goal=self.goal,
            completed_criteria=sorted(self.completed_criteria),
            tool_calls=self.tool_calls,
            spend_usd=self.spend_usd,
            violations=list(self.violations),
            actions=list(self.actions),
            drift=self.drift,
        )

    @classmethod
    def from_state(cls, state: LedgerState) -> "GoalLedger":
        ledger = cls(state.goal)
        ledger.completed_criteria = set(state.completed_criteria)
        ledger.tool_calls = state.tool_calls
        ledger.spend_usd = state.spend_usd
        ledger.violations = list(state.violations)
        ledger.actions = list(state.actions)
        ledger.drift = state.drift
        return ledger

    def _violation(
        self, invariant_id: str, kind: InvariantKind, description: str, step: int
    ) -> Violation:
        return Violation(
            invariant_id=invariant_id,
            kind=kind,
            description=description,
            step=max(step, 0),
            severity=RiskLevel.HIGH,
        )

    @staticmethod
    def _default_limit(kind: InvariantKind) -> int:
        return 12 if kind == InvariantKind.MAX_STEPS else 20


def _recipients(arguments: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("recipients", "to", "email"):
        raw = arguments.get(key)
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return values
