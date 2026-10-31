"""Autonomous agent loop with deterministic gates around an LLM decision component."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agent.checkpoint import AgentState, CheckpointManager
from agent.config import Settings
from agent.contracts import (
    ActionSummary,
    AgentIdentity,
    ApprovalDecision,
    DecisionType,
    GoalSpec,
    LLMDecision,
    Plan,
    Provenance,
    RiskLevel,
    RISK_ORDER,
    RunAction,
    RunStatus,
    TrustLevel,
)
from agent.llm import DecisionContext, LLMClient, LLMClientError
from agent.report import LIMITATIONS, RunReport
from memory.context import ContextManager, ContextSnapshot
from observability.metrics import MetricsCollector
from observability.trace import TraceLogger
from security.broker import BrokerResult, ToolPermissionBroker
from security.goals import GoalLedger
from security.taint import TaintAssessment, scan_untrusted
from tools.base import ToolContext


class AegisAgent:
    """MVP autonomous agent. The LLM proposes; security code decides and records."""

    def __init__(
        self,
        *,
        goal: GoalSpec,
        identity: AgentIdentity,
        llm: LLMClient,
        broker: ToolPermissionBroker,
        settings: Settings | None = None,
        checkpoints: CheckpointManager | None = None,
    ) -> None:
        self.goal = goal
        self.identity = identity
        self.llm = llm
        self.broker = broker
        self.settings = settings or Settings.from_env()
        self.checkpoints = checkpoints or CheckpointManager(
            self.settings.workspace / "checkpoints"
        )
        self.run_id = f"run-{uuid4().hex[:12]}"
        self.started_at = datetime.now(timezone.utc)
        self.ledger = GoalLedger(goal)
        self.context = ContextManager(
            goal, budget_tokens=self.settings.context_budget_tokens
        )
        self.metrics = MetricsCollector()
        self.actions: list[RunAction] = []
        self.approvals: list[ApprovalDecision] = []
        self.risks: list[str] = []
        self.trace: TraceLogger | None = None
        self.plan: Plan | None = None
        self.plan_index = 0
        self.step = 0
        self.status = RunStatus.RUNNING
        self.stop_reason = ""
        self.final_answer: str | None = None
        self.consecutive_errors = 0
        self._injection_attempt_keys: set[tuple[str, str]] = set()
        self._injection_blocked_keys: set[tuple[str, str]] = set()
        self._report: RunReport | None = None
        self.report: RunReport | None = None

    def run(self, plan: Plan | None = None) -> RunReport:
        tool_catalog = self.broker.registry.descriptors()
        self.trace = TraceLogger(
            run_id=self.run_id,
            agent_id=self.identity.agent_id,
            goal_id=self.goal.goal_id,
            trace_dir=self.settings.trace_dir,
            redact=self.settings.trace_redact,
        )
        try:
            self.plan = plan or self.llm.plan(self.goal, tool_catalog)
        except Exception as exc:
            self.risks.append(f"planning failed: {type(exc).__name__}: {exc}")
            return self._final_report(
                RunStatus.FAILED, "llm_planning_error", final_answer=None
            )
        if self.plan.goal_id != self.goal.goal_id:
            self.risks.append("plan targets a different goal id")
            return self._final_report(
                RunStatus.BLOCKED,
                "plan_goal_mismatch",
                final_answer=None,
            )
        if self.plan.steps and len(self.plan.steps) > self.settings.max_steps:
            self.risks.append(
                f"plan has {len(self.plan.steps)} steps but max_steps="
                f"{self.settings.max_steps}"
            )
        unknown = {
            tool
            for step in self.plan.steps
            for tool in step.expected_tools
            if tool not in self.broker.registry.names()
        }
        if unknown:
            self.risks.append(f"plan references unknown tools: {sorted(unknown)}")

        self.context.add_trusted(
            f"TASK: {self.goal.original_task or self.goal.objective}\n"
            f"PLAN:\n"
            + "\n".join(
                f"- {step.id}: {step.description} (tools={step.expected_tools})"
                for step in self.plan.steps
            ),
            source_id=self.plan.goal_id,
            kind="plan",
        )
        self.checkpoints.save("initial", self._state())
        max_steps = self._max_steps()

        while self.step < max_steps:
            snapshot = self.context.snapshot()
            if snapshot.degraded:
                self.risks.append(snapshot.degradation.reason)
                self._trace_halt(
                    step=self.step,
                    decision="halt on context degradation",
                    result=snapshot.degradation.reason,
                    reason=snapshot.degradation.reason,
                    risk=RiskLevel.HIGH,
                )
                return self._final_report(
                    RunStatus.FAILED, "context_degraded", final_answer=None
                )
            if snapshot.degradation.signals:
                self._add_risk(snapshot.degradation.reason)

            plan_step = self.plan.steps[min(self.plan_index, len(self.plan.steps) - 1)]
            decision_context = DecisionContext(
                goal_id=self.goal.goal_id,
                step=self.step,
                plan_step=plan_step,
                goal_digest=self.goal.goal_digest(),
                rendered_context=snapshot.rendered,
                tools=tool_catalog,
                recent_actions=self.ledger.action_summaries(),
                untrusted_present=bool(snapshot.tainted_ids),
                remaining_tool_calls=max(
                    0, self._max_tool_calls() - self.ledger.tool_calls
                ),
            )
            self.metrics.steps += 1
            try:
                decision = self.llm.decide(decision_context)
            except LLMClientError as exc:
                self.risks.append(str(exc))
                self._trace_halt(
                    step=self.step,
                    decision="LLM decision failed",
                    result=str(exc),
                    reason=f"no safe action could be selected: {exc}",
                    risk=RiskLevel.HIGH,
                )
                return self._final_report(
                    RunStatus.FAILED, "llm_decision_error", final_answer=None
                )
            except Exception as exc:
                self.risks.append(f"LLM error: {type(exc).__name__}")
                self._trace_halt(
                    step=self.step,
                    decision="LLM decision failed",
                    result=type(exc).__name__,
                    reason="model boundary error; stopping rather than guessing",
                    risk=RiskLevel.HIGH,
                )
                return self._final_report(
                    RunStatus.FAILED, "llm_decision_error", final_answer=None
                )
            self.metrics.add_usage(
                decision.usage.input_tokens, decision.usage.output_tokens
            )

            if decision.decision_type == DecisionType.FINAL:
                return self._handle_final(decision, snapshot)
            if decision.decision_type == DecisionType.REFUSE:
                self.risks.append("model refused the task")
                self._record_action(
                    decision,
                    risk=RiskLevel.MEDIUM,
                    authorized=False,
                    executed=False,
                    ok=False,
                    outcome="refused",
                )
                self._trace_decision(
                    decision,
                    snapshot,
                    result="model refused",
                    reason=decision.reason,
                    risk=RiskLevel.MEDIUM,
                    tool_call=None,
                )
                return self._final_report(
                    RunStatus.BLOCKED, "model_refused", final_answer=None
                )

            tool_outcome = self._handle_tool_decision(
                decision, snapshot
            )
            if tool_outcome is not None:
                return tool_outcome
            continue

        self.risks.append(f"step budget exhausted at {max_steps}")
        self._trace_halt(
            step=self.step,
            decision="halt on step budget",
            result=f"max_steps={max_steps}",
            reason="step budget exhausted before success criteria were met",
            risk=RiskLevel.HIGH,
        )
        return self._final_report(
            RunStatus.FAILED, "step_budget_exhausted", final_answer=None
        )

    def _handle_final(
        self, decision: LLMDecision, snapshot: ContextSnapshot
    ) -> RunReport:
        audit = self.ledger.check_action(
            decision, plan=self.plan, plan_index=self.plan_index
        )
        if not audit.ok:
            self.ledger.record_audit(audit)
            self.metrics.violations += 1
            self.risks.append(audit.reason)
            self._trace_decision(
                decision,
                snapshot,
                result=f"final rejected: {audit.reason}",
                reason=audit.reason,
                risk=RiskLevel.HIGH,
                tool_call=None,
            )
            status = RunStatus.BLOCKED
            return self._final_report(
                status,
                "goal_drift_detected" if audit.drift else "success_criteria_not_met",
                final_answer=None,
            )
        final_audit = self.ledger.finalise(decision)
        if not final_audit.ok:
            self.ledger.record_audit(final_audit)
            self.metrics.violations += 1
            self.risks.append(final_audit.reason)
            self._trace_decision(
                decision,
                snapshot,
                result=f"final rejected: {final_audit.reason}",
                reason=final_audit.reason,
                risk=RiskLevel.HIGH,
                tool_call=None,
            )
            return self._final_report(
                RunStatus.BLOCKED,
                "goal_drift_detected" if final_audit.drift else "success_criteria_not_met",
                final_answer=None,
            )
        self.final_answer = decision.final_answer
        if decision.final_answer and scan_untrusted(decision.final_answer):
            self._add_risk(
                "final answer contains instruction-like text; it is output data, "
                "not an approval or command"
            )
        self._trace_decision(
            decision,
            snapshot,
            result=decision.final_answer or "",
            reason=decision.reason,
            risk=RiskLevel.LOW,
            tool_call=None,
            status="completed",
        )
        return self._final_report(
            RunStatus.COMPLETED, "success_criteria_met", final_answer=self.final_answer
        )

    def _handle_tool_decision(
        self,
        decision: LLMDecision,
        snapshot: ContextSnapshot,
    ) -> RunReport | None:
        tool = self.broker.registry.get(decision.tool_name or "")
        resolved_evidence = [
            evidence_id
            for evidence_id in decision.evidence_ids
            if self.context.taint.record(evidence_id) is not None
        ]
        force_untrusted = bool(
            tool
            and RISK_ORDER[tool.risk] >= RISK_ORDER[RiskLevel.HIGH]
            and snapshot.tainted_ids
            and (not decision.evidence_ids or not resolved_evidence)
        )
        taint = self.context.taint.assess(
            decision.evidence_ids,
            decision.arguments,
            force_untrusted=force_untrusted,
        )
        if taint.tainted:
            self._add_risk(
                f"action derived from untrusted data: {taint.reason}"
            )
        audit = self.ledger.check_action(
            decision, plan=self.plan, plan_index=self.plan_index
        )
        if not audit.ok:
            self.ledger.record_audit(audit)
            self.metrics.violations += 1
            self._mark_injection_blocked(taint, tool.risk if tool else RiskLevel.HIGH)
            self.risks.append(audit.reason)
            self._record_action(
                decision,
                risk=tool.risk if tool else RiskLevel.HIGH,
                authorized=False,
                executed=False,
                ok=False,
                outcome="blocked_by_goal_ledger",
                tainted=taint.tainted,
            )
            self._trace_decision(
                decision,
                snapshot,
                result=f"blocked by GoalLedger: {audit.reason}",
                reason=audit.reason,
                risk=tool.risk if tool else RiskLevel.HIGH,
                tool_call=self._tool_call_dict(decision),
                taint=taint.tainted,
                approval=None,
                status="blocked",
            )
            return self._final_report(
                RunStatus.BLOCKED,
                "goal_drift_detected" if audit.drift else "goal_constraint_blocked",
                final_answer=None,
            )

        checkpoint = self.checkpoints.save(f"before-step-{self.step}", self._state())
        context = ToolContext(
            run_id=self.run_id,
            agent_id=self.identity.agent_id,
            workspace=self.settings.workspace,
        )
        result = self.broker.execute(
            self.identity,
            decision.tool_name or "",
            decision.arguments,
            purpose=decision.purpose,
            taint=taint,
            tool_context=context,
            extra_approval_tools=self.ledger.approval_tools(),
        )
        if isinstance(result.approval, ApprovalDecision):
            self.approvals.append(result.approval)

        if result.outcome.value == "approval_required":
            self._add_risk(
                f"high-risk action paused for human approval: {result.reason}"
            )
            self._record_action(
                decision,
                risk=result.risk,
                authorized=False,
                executed=False,
                ok=False,
                outcome="approval_pending",
                approval="pending",
                tainted=taint.tainted,
            )
            self._trace_decision(
                decision,
                snapshot,
                result=result.reason,
                reason=result.reason,
                risk=result.risk,
                tool_call=self._tool_call_dict(decision),
                taint=taint.tainted,
                approval=self._approval_dict(result),
                status="approval_pending",
            )
            return self._final_report(
                RunStatus.AWAITING_APPROVAL,
                "human_approval_pending",
                final_answer=None,
            )

        if not result.authorized:
            self.metrics.violations += 1
            self._mark_injection_blocked(taint, result.risk)
            self.risks.append(f"denied tool call: {result.reason}")
            self._record_action(
                decision,
                risk=result.risk,
                authorized=False,
                executed=False,
                ok=False,
                outcome=f"denied:{result.policy_code}",
                approval=self._approval_disposition(result),
                tainted=taint.tainted,
            )
            self._trace_decision(
                decision,
                snapshot,
                result=f"denied: {result.reason}",
                reason=result.reason,
                risk=result.risk,
                tool_call=self._tool_call_dict(decision),
                taint=taint.tainted,
                approval=self._approval_dict(result),
                status="blocked",
            )
            return self._final_report(
                RunStatus.BLOCKED, f"tool_denied:{result.policy_code}", final_answer=None
            )

        output = result.output
        assert output is not None
        self.metrics.tool_calls += 1
        self._observe_output(result)
        if output.ok and tool is not None and RISK_ORDER[tool.risk] >= RISK_ORDER[
            RiskLevel.MEDIUM
        ]:
            self.checkpoints.note_effect(tool, output, f"step {self.step}: {tool.name}")

        if not output.ok:
            self.ledger.record_tool_result(
                tool_name=result.tool_name,
                arguments=decision.arguments,
                result_spend_usd=float(output.data.get("amount_usd", 0.0) or 0.0),
            )
            self.consecutive_errors += 1
            self.metrics.recovery_steps += 1
            self._add_risk(f"tool error recovered: {output.error}")
            self._record_action(
                decision,
                risk=result.risk,
                authorized=True,
                executed=True,
                ok=False,
                outcome=f"tool_error:{output.error}",
                approval=self._approval_disposition(result),
                tainted=taint.tainted,
            )
            self._trace_decision(
                decision,
                snapshot,
                result=f"tool error: {output.error}",
                reason=(
                    f"{decision.reason} | recoverable tool error; retrying within budget "
                    f"({self.consecutive_errors}/{self.settings.max_recovery_attempts})"
                ),
                risk=result.risk,
                tool_call=self._tool_call_dict(decision),
                taint=taint.tainted,
                approval=self._approval_dict(result),
                status="tool_error",
            )
            self.step += 1
            if self.consecutive_errors >= self.settings.max_recovery_attempts:
                return self._final_report(
                    RunStatus.FAILED, "recovery_budget_exhausted", final_answer=None
                )
            return None

        self.consecutive_errors = 0
        post_audit = self.ledger.check_after_action(
            tool_name=result.tool_name,
            arguments=decision.arguments,
            step=self.step,
            result_spend_usd=float(output.data.get("amount_usd", 0.0) or 0.0),
        )
        if post_audit.ok:
            self.ledger.record_tool_result(
                tool_name=result.tool_name,
                arguments=decision.arguments,
                result_spend_usd=float(output.data.get("amount_usd", 0.0) or 0.0),
            )
        failed_action = self._record_action(
            decision,
            risk=result.risk,
            authorized=True,
            executed=True,
            ok=True,
            outcome=output.summary(200),
            approval=self._approval_disposition(result),
            tainted=taint.tainted,
            irreversible=output.irreversible,
        )
        if not post_audit.ok:
            self.ledger.record_audit(post_audit)
            self.metrics.violations += len(post_audit.violations)
            rollback = self.checkpoints.rollback_to(checkpoint.checkpoint_id, context)
            self.metrics.rollbacks += 1
            if rollback.ok:
                self.ledger = GoalLedger.from_state(rollback.restored_state.ledger)
                self.context = ContextManager.from_state(rollback.restored_state.context)
                self.actions = list(rollback.restored_state.actions)
                self.plan_index = rollback.restored_state.plan_index
                self.status = RunStatus.ROLLED_BACK
                stop_reason = "post_action_invariant_violation"
            else:
                self.status = RunStatus.FAILED
                stop_reason = "post_action_invariant_violation_irreversible"
                self.risks.append(
                    "rollback could not compensate every effect; manual reconciliation required"
                )
            self.risks.append(post_audit.reason)
            self._trace_decision(
                decision,
                snapshot,
                result=f"invariant violation after effect: {post_audit.reason}",
                reason=post_audit.reason,
                risk=RiskLevel.CRITICAL,
                tool_call=self._tool_call_dict(decision),
                taint=taint.tainted,
                approval=self._approval_dict(result),
                status="rolled_back" if rollback.ok else "rollback_incomplete",
            )
            self.actions.append(
                failed_action.model_copy(
                    update={
                        "ok": False,
                        "outcome": "post-action invariant violation; "
                        + ("rolled back" if rollback.ok else "rollback incomplete"),
                    }
                )
            )
            return self._final_report(self.status, stop_reason, final_answer=None)

        self.plan_index = min(self.plan_index + 1, len(self.plan.steps) - 1)
        self._trace_decision(
            decision,
            snapshot,
            result=output.summary(),
            reason=decision.reason,
            risk=result.risk,
            tool_call=self._tool_call_dict(decision),
            taint=taint.tainted,
            approval=self._approval_dict(result),
            status="ok",
        )
        self.step += 1
        if (
            self.settings.drift_check_interval > 0
            and self.step % self.settings.drift_check_interval == 0
        ):
            try:
                review = self.llm.review_goal(
                    self.goal.objective,
                    list(self.goal.constraints),
                    self.ledger.action_summaries(),
                )
            except Exception as exc:
                self._add_risk(f"goal reviewer unavailable: {type(exc).__name__}")
                review = None
            if review is not None:
                drift_audit = self.ledger.apply_drift_review(review, self.step)
                if not drift_audit.ok:
                    self.metrics.violations += 1
                    self.ledger.record_audit(drift_audit)
                    self.risks.append(drift_audit.reason)
                    self._trace_halt(
                        step=self.step,
                        decision="periodic goal review",
                        result=review.model_dump_json(),
                        reason=drift_audit.reason,
                        risk=RiskLevel.HIGH,
                        status="goal_drift",
                    )
                    return self._final_report(
                        RunStatus.BLOCKED, "goal_drift_detected", final_answer=None
                    )
        return None

    def _observe_output(self, result: BrokerResult) -> None:
        output = result.output
        if not output:
            return
        if output.ok and output.content:
            key = (output.source_type, output.source_id)
            if output.taint == TrustLevel.UNTRUSTED and output.signals:
                if key not in self._injection_attempt_keys:
                    self._injection_attempt_keys.add(key)
                    self.metrics.injection_attempts += 1
                    self._add_risk(
                        "untrusted content contains instruction-like signals "
                        f"from {output.source_id}: "
                        + ", ".join(signal.value for signal in output.signals)
                    )
            provenance = Provenance(
                source_type=output.source_type,
                source_id=output.source_id,
                trust=output.taint,
                uri=output.uri,
            )
            self.context.add_observation(
                output.content,
                provenance,
                kind="tool_result",
                signals=output.signals,
            )
        elif not output.ok:
            error_text = f"Tool error from {result.tool_name}: {output.error}"
            signals = scan_untrusted(error_text)
            key = ("tool_error", result.tool_name)
            if signals and key not in self._injection_attempt_keys:
                self._injection_attempt_keys.add(key)
                self.metrics.injection_attempts += 1
                self._add_risk(
                    "tool error text contains instruction-like signals; "
                    "it is treated as untrusted data"
                )
            self.context.add_observation(
                error_text,
                Provenance(
                    source_type="tool_error",
                    source_id=result.tool_name,
                    trust=TrustLevel.UNTRUSTED,
                ),
                kind="tool_error",
                signals=signals,
            )

    def _mark_injection_blocked(
        self, taint: TaintAssessment, risk: RiskLevel
    ) -> None:
        if RISK_ORDER[risk] < RISK_ORDER[RiskLevel.HIGH] or not taint.tainted:
            return
        keys: set[tuple[str, str]] = set()
        for evidence_id in taint.sources:
            item = next((item for item in self.context.items if item.id == evidence_id), None)
            if item is None or not item.signals:
                continue
            keys.add((item.provenance.source_type, item.provenance.source_id))
        if not keys and taint.tainted:
            # Invalid/omitted evidence ids must not make an injected source
            # disappear from metrics. If a high-risk action was denied while an
            # injection attempt is live, attribute the block to that attempt.
            keys = set(self._injection_attempt_keys)
        for key in keys:
            if key in self._injection_attempt_keys and key not in self._injection_blocked_keys:
                self._injection_blocked_keys.add(key)
                self.metrics.injection_blocked += 1
                self._add_risk(
                    f"injection blocked from {key[1]}; attempted "
                    "privileged action was denied"
                )

    def _record_action(
        self,
        decision: LLMDecision,
        *,
        risk: RiskLevel,
        authorized: bool,
        executed: bool,
        ok: bool,
        outcome: str,
        approval: str | None = None,
        tainted: bool = False,
        irreversible: bool = False,
    ) -> RunAction:
        action = RunAction(
            step=self.step,
            tool_name=decision.tool_name,
            arguments=_safe_arguments(decision.arguments),
            purpose=decision.purpose,
            reason=decision.reason,
            risk=risk,
            authorized=authorized,
            executed=executed,
            ok=ok,
            outcome=outcome,
            approval=approval,
            tainted=tainted,
            irreversible=irreversible,
        )
        self.actions.append(action)
        self.ledger.record_action(
            ActionSummary(
                step=self.step,
                tool_name=decision.tool_name,
                purpose=decision.purpose,
                risk=risk,
                executed=executed,
                outcome=outcome[:300],
            )
        )
        return action

    def _trace_decision(
        self,
        decision: LLMDecision,
        snapshot: ContextSnapshot,
        *,
        result: str,
        reason: str,
        risk: RiskLevel,
        tool_call: dict[str, Any] | None,
        taint: bool = False,
        approval: dict[str, Any] | None = None,
        status: str = "ok",
    ) -> None:
        assert self.trace is not None
        self.trace.record_step(
            step=self.step,
            input_summary=(
                f"plan_step={self.plan.steps[min(self.plan_index, len(self.plan.steps)-1)].id}; "
                f"context={snapshot.used_tokens}/{snapshot.budget_tokens} tokens; "
                f"untrusted={'yes' if snapshot.tainted_ids else 'no'}"
            ),
            decision=(
                f"{decision.decision_type.value}: {decision.purpose} | "
                f"tool={decision.tool_name or 'none'}"
            ),
            reason=reason,
            risk_level=risk,
            result=result or "no result",
            tool_call=tool_call,
            approval=approval,
            taint=taint,
            tokens=decision.usage.input_tokens + decision.usage.output_tokens,
            status=status,
        )

    def _trace_halt(
        self,
        *,
        step: int,
        decision: str,
        result: str,
        reason: str,
        risk: RiskLevel,
        status: str = "halted",
    ) -> None:
        assert self.trace is not None
        self.trace.record_step(
            step=step,
            input_summary=f"halt check at step {step}",
            decision=decision,
            reason=reason,
            risk_level=risk,
            result=result,
            status=status,
        )

    def _final_report(
        self, status: RunStatus, stop_reason: str, final_answer: str | None
    ) -> RunReport:
        if self._report is not None:
            return self._report
        assert self.trace is not None
        self.status = status
        self.stop_reason = stop_reason
        self.final_answer = final_answer
        success = status == RunStatus.COMPLETED and self.ledger.all_required_met
        completeness = TraceLogger.completeness(self.trace.records)
        metrics = self.metrics.to_metrics(
            success=success,
            trace_completeness=completeness,
            input_price_per_1k=self.settings.input_cost_per_1k,
            output_price_per_1k=self.settings.output_cost_per_1k,
            notes=[
                "task success requires COMPLETED status and all required criteria attested",
                "injection block rate is 1.0 when no injection attempts were observed",
            ],
        )
        self._report = RunReport(
            run_id=self.run_id,
            trace_id=self.trace.trace_id,
            trace_path=str(self.trace.trace_path) if self.trace.trace_path else None,
            goal_id=self.goal.goal_id,
            objective=self.goal.objective,
            status=status,
            stop_reason=stop_reason,
            final_answer=final_answer,
            actions=self.actions,
            risks=_dedupe(self.risks),
            limitations=list(LIMITATIONS),
            criteria=self.goal.success_criteria,
            completed_criteria=sorted(self.ledger.completed_criteria),
            metrics=metrics,
            approvals=self.approvals,
            started_at=self.started_at,
        )
        self.report = self._report
        return self._report

    def _state(self) -> AgentState:
        return AgentState(
            run_id=self.run_id,
            goal_id=self.goal.goal_id,
            step=self.step,
            plan_index=self.plan_index,
            status=self.status,
            ledger=self.ledger.export_state(),
            context=self.context.export_state(),
            actions=list(self.actions),
            tool_calls=self.ledger.tool_calls,
            recovery_steps=self.metrics.recovery_steps,
            stop_reason=self.stop_reason or None,
            final_answer=self.final_answer,
        )

    def _max_steps(self) -> int:
        limits = [
            int(inv.params.get("limit", self.settings.max_steps))
            for inv in self.goal.invariants
            if inv.kind.value == "max_steps"
        ]
        return min([self.settings.max_steps, *limits])

    def _max_tool_calls(self) -> int:
        limits = [
            int(inv.params.get("limit", 20))
            for inv in self.goal.invariants
            if inv.kind.value == "max_tool_calls"
        ]
        return min(limits) if limits else 20

    def _tool_call_dict(self, decision: LLMDecision) -> dict[str, Any]:
        return {
            "tool": decision.tool_name,
            "arguments": _safe_arguments(decision.arguments),
            "purpose": decision.purpose,
        }

    @staticmethod
    def _approval_dict(result: BrokerResult) -> dict[str, Any] | None:
        approval = result.approval
        if approval is None:
            return None
        if isinstance(approval, ApprovalDecision):
            return approval.model_dump(mode="json")
        return {"raw": str(approval)}

    @staticmethod
    def _approval_disposition(result: BrokerResult) -> str | None:
        approval = result.approval
        if isinstance(approval, ApprovalDecision):
            return approval.disposition.value
        return None

    def _add_risk(self, risk: str) -> None:
        if risk and risk not in self.risks:
            self.risks.append(risk)


def _safe_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            result[key] = value[:500]
        elif isinstance(value, list):
            result[key] = value[:10]
        else:
            result[key] = value
    return result


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output
