"""Environment-based runtime configuration. No credentials are stored in code."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    workspace: Path
    trace_dir: Path
    data_dir: Path
    context_budget_tokens: int = 1400
    max_steps: int = 12
    drift_check_interval: int = 2
    approval_mode: str = "deny"
    input_cost_per_1k: float = 0.002
    output_cost_per_1k: float = 0.008
    max_recovery_attempts: int = 3
    trace_redact: bool = True

    @classmethod
    def from_env(cls, workspace: Path | None = None) -> "Settings":
        root = Path(workspace or os.getenv("AEGIS_WORKSPACE", ".")).resolve()
        trace = Path(os.getenv("AEGIS_TRACE_DIR", str(root / "traces"))).resolve()
        data = Path(os.getenv("AEGIS_DATA_DIR", str(root / "data"))).resolve()
        return cls(
            workspace=root,
            trace_dir=trace,
            data_dir=data,
            context_budget_tokens=_env_int("AEGIS_CONTEXT_BUDGET", 1400),
            max_steps=_env_int("AEGIS_MAX_STEPS", 12),
            drift_check_interval=_env_int("AEGIS_DRIFT_INTERVAL", 2),
            approval_mode=os.getenv("AEGIS_APPROVAL_MODE", "deny").strip().lower(),
            input_cost_per_1k=_env_float("AEGIS_INPUT_COST_PER_1K", 0.002),
            output_cost_per_1k=_env_float("AEGIS_OUTPUT_COST_PER_1K", 0.008),
            max_recovery_attempts=_env_int("AEGIS_MAX_RECOVERY_ATTEMPTS", 3),
            trace_redact=_env_bool("AEGIS_TRACE_REDACT", True),
        )
