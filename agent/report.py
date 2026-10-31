"""Final run report: actions, risks, approvals, metrics, and limitations."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from agent.contracts import ApprovalDecision, RunAction, RunStatus, SuccessCriterion
from observability.metrics import RunMetrics

LIMITATIONS: tuple[str, ...] = (
    "Tools are deterministic simulations: email is written to outbox/sent.jsonl and no funds move.",
    "Success criteria are attested by the model; they are not independently verified against external systems.",
    "Injection detection uses regex signals; obfuscated or multilingual attacks can evade detection.",
    "Taint is derived from cited context ids, explicit provenance, and substring overlap; paraphrased exfiltration args can be missed.",
    "Checkpoint snapshots persist data, but compensating rollback is process-local and cannot undo external side effects.",
    "An approval-pending run stops; resuming the same request after human approval is not implemented.",
    "Multi-agent messages have provenance and confidence but no cryptographic signatures or authenticated channels.",
    "The agent executes in-process; tools are not isolated by an OS/container sandbox.",
    "Token counts and costs are approximations, not provider billing records.",
    "Natural-language constraints are visible to the model but only structured invariants are machine-enforced.",
    "No distributed state store, lease, or exactly-once tool execution is provided.",
)


class RunReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    trace_id: str
    trace_path: str | None
    goal_id: str
    objective: str
    status: RunStatus
    stop_reason: str
    final_answer: str | None
    actions: list[RunAction] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))
    criteria: list[SuccessCriterion] = Field(default_factory=list)
    completed_criteria: list[str] = Field(default_factory=list)
    metrics: RunMetrics
    approvals: list[ApprovalDecision] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_markdown(self) -> str:
        lines = [
            f"# Aegis Run Report — {self.run_id}",
            "",
            f"- **Goal:** {self.objective}",
            f"- **Status:** `{self.status.value}`",
            f"- **Stop reason:** {self.stop_reason}",
            f"- **Trace:** `{self.trace_path or 'in-memory only'}`",
            "",
            "## Final answer",
            "",
            self.final_answer or "_No final answer was accepted._",
            "",
            "## Actions",
            "",
            "| Step | Tool | Risk | Authorized | Executed | Outcome | Reason |",
            "|---:|---|---|---|---|---|---|",
        ]
        for action in self.actions:
            lines.append(
                f"| {action.step} | `{action.tool_name or 'none'}` | {action.risk.value} | "
                f"{action.authorized} | {action.executed} | {action.outcome} | {action.reason} |"
            )
        lines += ["", "## Risks observed", ""]
        lines += [f"- {risk}" for risk in self.risks] or ["- None recorded."]
        lines += ["", "## Success criteria", ""]
        for criterion in self.criteria:
            mark = "x" if criterion.id in self.completed_criteria else " "
            lines.append(f"- [{mark}] `{criterion.id}`: {criterion.description}")
        lines += [
            "",
            "## Metrics",
            "",
            "```json",
            self.metrics.model_dump_json(indent=2),
            "```",
            "",
            "## Limitations",
            "",
        ]
        lines += [f"- {item}" for item in self.limitations]
        return "\n".join(lines) + "\n"

    def write(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_markdown(), encoding="utf-8")
        return path
