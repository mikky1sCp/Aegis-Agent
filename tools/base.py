"""Tool contracts. Tools are dumb effectors; the broker is the policy point."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from agent.contracts import InjectionSignal, RiskLevel, TrustLevel


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class ToolContext:
    run_id: str
    agent_id: str
    workspace: Path
    taint: TrustLevel = TrustLevel.TRUSTED
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    content: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    taint: TrustLevel = TrustLevel.TRUSTED
    signals: list[InjectionSignal] = Field(default_factory=list)
    source_id: str = "tool"
    source_type: str = "tool"
    uri: str | None = None
    irreversible: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    def summary(self, limit: int = 500) -> str:
        if not self.ok:
            return f"ERROR: {self.error or 'tool failed'}"
        text = " ".join(self.content.split())
        return text[:limit] + ("..." if len(text) > limit else "")


class RollbackOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    description: str


class ToolDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    risk: RiskLevel
    required_capability: str
    irreversible: bool = False
    input_schema: dict[str, Any] = Field(default_factory=dict)


class Tool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    risk: ClassVar[RiskLevel]
    required_capability: ClassVar[str]
    input_model: ClassVar[type[ToolInput]]
    irreversible: ClassVar[bool] = False

    def descriptor(self) -> ToolDescriptor:
        return ToolDescriptor(
            name=self.name,
            description=self.description,
            risk=self.risk,
            required_capability=self.required_capability,
            irreversible=self.irreversible,
            input_schema=self.input_model.model_json_schema(),
        )

    def invoke(self, arguments: dict[str, Any], context: ToolContext) -> ToolOutput:
        parsed = self.input_model.model_validate(arguments)
        try:
            return self._run(parsed, context)
        except Exception as exc:  # tools convert failures into recoverable results
            return ToolOutput(ok=False, error=f"{type(exc).__name__}: {exc}")

    def rollback(self, output: ToolOutput, context: ToolContext) -> RollbackOutcome:
        return RollbackOutcome(ok=False, description="tool has no compensating action")

    @abstractmethod
    def _run(self, arguments: ToolInput, context: ToolContext) -> ToolOutput:
        raise NotImplementedError
