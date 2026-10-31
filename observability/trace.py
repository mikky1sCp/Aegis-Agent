"""Structured per-step traces with reasons, risk, and completeness scoring."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent.contracts import RiskLevel
from security.taint import redact_secrets


class TraceRecord(BaseModel):
    """One auditable step: input, decision, effect, result, reason, risk."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str
    run_id: str
    agent_id: str
    goal_id: str
    step: int = Field(ge=0)
    input_summary: str = Field(min_length=1)
    decision: str = Field(min_length=1)
    tool_call: dict[str, Any] | None = None
    result: str | None = None
    reason: str = Field(min_length=1)
    risk_level: RiskLevel
    approval: dict[str, Any] | None = None
    taint: bool = False
    tokens: int = Field(default=0, ge=0)
    status: str = "ok"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("reason")
    @classmethod
    def _reason_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("every trace step requires a non-empty reason")
        return value


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


class TraceLogger:
    def __init__(
        self,
        *,
        run_id: str,
        agent_id: str,
        goal_id: str,
        trace_dir: Path | None = None,
        redact: bool = True,
    ) -> None:
        self.trace_id = f"trace-{uuid4().hex[:12]}"
        self.run_id = run_id
        self.agent_id = agent_id
        self.goal_id = goal_id
        self.redact = redact
        self.records: list[TraceRecord] = []
        self.trace_dir = Path(trace_dir) if trace_dir else None
        self.trace_path: Path | None = None
        if self.trace_dir:
            self.trace_dir.mkdir(parents=True, exist_ok=True)
            self.trace_path = self.trace_dir / f"{run_id}.jsonl"

    def record_step(
        self,
        *,
        step: int,
        input_summary: str,
        decision: str,
        reason: str,
        risk_level: RiskLevel,
        result: str | None,
        tool_call: dict[str, Any] | None = None,
        approval: dict[str, Any] | None = None,
        taint: bool = False,
        tokens: int = 0,
        status: str = "ok",
    ) -> TraceRecord:
        payload = {
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "agent_id": self.agent_id,
            "goal_id": self.goal_id,
            "step": step,
            "input_summary": input_summary[:1000],
            "decision": decision[:1000],
            "tool_call": tool_call,
            "result": result[:1500] if result else result,
            "reason": reason,
            "risk_level": risk_level,
            "approval": approval,
            "taint": taint,
            "tokens": tokens,
            "status": status,
        }
        if self.redact:
            payload = _redact_value(payload)
        record = TraceRecord.model_validate(payload)
        self.records.append(record)
        if self.trace_path:
            with self.trace_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n"
                )
        return record

    @staticmethod
    def completeness(records: list[TraceRecord]) -> float:
        if not records:
            return 0.0
        checks = 0
        passed = 0
        for record in records:
            checks += 5
            passed += int(bool(record.input_summary.strip()))
            passed += int(bool(record.decision.strip()))
            passed += int(record.result is not None and bool(str(record.result).strip()))
            passed += int(bool(record.reason.strip()))
            passed += int(bool(record.risk_level))
            if record.tool_call is not None:
                checks += 1
                passed += int(bool(record.tool_call))
        return round(passed / checks, 3) if checks else 0.0

    def export(self) -> list[dict[str, Any]]:
        return [record.model_dump(mode="json") for record in self.records]

    def read_persisted(self) -> list[dict[str, Any]]:
        """Reader used by tests and operators; validates the JSONL format."""
        if not self.trace_path or not self.trace_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self.trace_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows
