"""Run metrics for acceptance and evals."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MetricsCollector:
    def __init__(self) -> None:
        self.steps = 0
        self.tool_calls = 0
        self.violations = 0
        self.injection_attempts = 0
        self.injection_blocked = 0
        self.recovery_steps = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.rollbacks = 0

    def add_usage(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens += max(0, input_tokens)
        self.output_tokens += max(0, output_tokens)

    def to_metrics(
        self,
        *,
        success: bool,
        trace_completeness: float,
        input_price_per_1k: float,
        output_price_per_1k: float,
        notes: list[str] | None = None,
    ) -> "RunMetrics":
        cost = (
            self.input_tokens / 1000.0 * input_price_per_1k
            + self.output_tokens / 1000.0 * output_price_per_1k
        )
        return RunMetrics(
            task_success_rate=1.0 if success else 0.0,
            violation_rate=round(self.violations / max(1, self.steps), 3),
            injection_block_rate=(
                1.0
                if self.injection_attempts == 0
                else round(self.injection_blocked / self.injection_attempts, 3)
            ),
            recovery_steps=self.recovery_steps,
            token_cost_usd=round(cost, 6),
            trace_completeness=trace_completeness,
            steps=self.steps,
            tool_calls=self.tool_calls,
            violations=self.violations,
            injection_attempts=self.injection_attempts,
            injection_blocked=self.injection_blocked,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            rollbacks=self.rollbacks,
            notes=notes or [],
        )


class RunMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_success_rate: float = Field(ge=0.0, le=1.0)
    violation_rate: float = Field(ge=0.0, le=1.0)
    injection_block_rate: float = Field(ge=0.0, le=1.0)
    recovery_steps: int = Field(ge=0)
    token_cost_usd: float = Field(ge=0.0)
    trace_completeness: float = Field(ge=0.0, le=1.0)
    steps: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    violations: int = Field(ge=0)
    injection_attempts: int = Field(ge=0)
    injection_blocked: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    rollbacks: int = Field(ge=0)
    notes: list[str] = Field(default_factory=list)


class EvalSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cases: int
    task_success_rate: float
    violation_rate: float
    injection_block_rate: float
    avg_recovery_steps: float
    total_token_cost_usd: float
    avg_trace_completeness: float
    per_case: list[dict]


__all__ = ["EvalSummary", "MetricsCollector", "RunMetrics"]
