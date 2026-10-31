"""Checkpoints of agent state plus compensating rollback for reversible effects."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from agent.contracts import RunAction, RunStatus
from memory.context import ContextState
from security.goals import LedgerState
from tools.base import RollbackOutcome, Tool, ToolContext, ToolOutput


class AgentState(BaseModel):
    """Serializable state needed to resume/rollback a run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    goal_id: str
    step: int = 0
    plan_index: int = 0
    status: RunStatus = RunStatus.RUNNING
    ledger: LedgerState
    context: ContextState
    actions: list[RunAction] = Field(default_factory=list)
    tool_calls: int = 0
    recovery_steps: int = 0
    stop_reason: str | None = None
    final_answer: str | None = None


class Checkpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checkpoint_id: str
    label: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    state: AgentState
    journal_mark: int


@dataclass
class _Effect:
    tool: Tool
    output: ToolOutput
    description: str


@dataclass(frozen=True)
class Compensation:
    tool_name: str
    ok: bool
    description: str


class RollbackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checkpoint_id: str
    restored_state: AgentState
    compensations: list[dict[str, Any]] = Field(default_factory=list)
    all_compensations_ok: bool

    @property
    def ok(self) -> bool:
        return self.all_compensations_ok


class CheckpointManager:
    """In-memory checkpoint store with optional JSON snapshots.

    Compensations are intentionally process-local: Tool objects are code, not
    serializable state. A restart restores data but refuses to claim that remote
    effects were undone. This is documented as an MVP limitation.
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self.store_dir = Path(store_dir) if store_dir else None
        self.checkpoints: list[Checkpoint] = []
        self._effects: list[_Effect] = []
        if self.store_dir:
            self.store_dir.mkdir(parents=True, exist_ok=True)

    def save(self, label: str, state: AgentState) -> Checkpoint:
        checkpoint = Checkpoint(
            checkpoint_id=f"ckpt-{uuid4().hex[:12]}",
            label=label,
            state=AgentState.model_validate(state.model_dump(mode="json")),
            journal_mark=len(self._effects),
        )
        self.checkpoints.append(checkpoint)
        if self.store_dir:
            path = self.store_dir / f"{checkpoint.checkpoint_id}.json"
            path.write_text(
                json.dumps(checkpoint.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )
        return checkpoint

    def get(self, checkpoint_id: str) -> Checkpoint:
        for checkpoint in self.checkpoints:
            if checkpoint.checkpoint_id == checkpoint_id:
                return checkpoint
        raise KeyError(f"unknown checkpoint: {checkpoint_id}")

    def latest(self) -> Checkpoint | None:
        return self.checkpoints[-1] if self.checkpoints else None

    def note_effect(self, tool: Tool, output: ToolOutput, description: str = "") -> None:
        """Record a reversible effect after the broker executes it."""
        self._effects.append(
            _Effect(
                tool=tool,
                output=output.model_copy(deep=True),
                description=description or f"{tool.name} effect",
            )
        )

    def rollback_to(self, checkpoint_id: str, context: ToolContext) -> RollbackResult:
        checkpoint = self.get(checkpoint_id)
        effects = self._effects[checkpoint.journal_mark :]
        compensations: list[Compensation] = []
        for effect in reversed(effects):
            if effect.tool.irreversible:
                outcome = RollbackOutcome(
                    ok=False,
                    description=(
                        f"{effect.tool.name} is irreversible; manual reconciliation required"
                    ),
                )
            else:
                outcome = effect.tool.rollback(effect.output, context)
            compensations.append(
                Compensation(
                    tool_name=effect.tool.name,
                    ok=outcome.ok,
                    description=outcome.description,
                )
            )
        del self._effects[checkpoint.journal_mark :]
        restored = AgentState.model_validate(checkpoint.state.model_dump(mode="json"))
        return RollbackResult(
            checkpoint_id=checkpoint_id,
            restored_state=restored,
            compensations=[item.__dict__ for item in compensations],
            all_compensations_ok=all(item.ok for item in compensations),
        )

    def load_checkpoint_file(self, path: Path) -> Checkpoint:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return Checkpoint.model_validate(payload)
