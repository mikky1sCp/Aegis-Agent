"""Shared fixtures for the Aegis-Agent pytest suite."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

from agent.config import Settings


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name)[:80]


@pytest.fixture
def workspace(request: pytest.FixtureRequest) -> Path:
    """Workspace-local test directory (sandbox-safe; never system temp)."""
    base = Path(__file__).resolve().parent / ".artifacts"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{_safe_name(request.node.name)}-{uuid4().hex[:8]}"
    (path / "data").mkdir(parents=True, exist_ok=True)
    (path / "reports").mkdir(parents=True, exist_ok=True)
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def settings(workspace: Path) -> Settings:
    return Settings(
        workspace=workspace,
        trace_dir=workspace / "traces",
        data_dir=workspace / "data",
        context_budget_tokens=1200,
        max_steps=10,
        drift_check_interval=10,
        max_recovery_attempts=3,
    )
