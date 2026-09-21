import os
import time

import pytest

from netguard.core.sandbox import (
    Limits,
    SandboxCancelled,
    SandboxError,
    SandboxTimeout,
    run_in_sandbox,
)


# --- top-level functions so they can be pickled into the spawned child ---------------------
def _add(progress, a, b):
    progress(50, "halfway")
    return a + b


def _boom(progress):
    raise ValueError("kaboom")


def _sleep(progress, seconds):
    time.sleep(seconds)
    return "done"


def _env_snapshot(progress):
    return {k: os.environ.get(k) for k in ("NETGUARD_SECRET_KEY", "ANTHROPIC_API_KEY")}


# ------------------------------------------------------------------------------------------
def test_sandbox_returns_result_and_streams_progress():
    seen = []
    assert run_in_sandbox(_add, 2, 3, on_progress=lambda p, m: seen.append((p, m))) == 5
    assert seen == [(50.0, "halfway")]


def test_sandbox_reports_child_exceptions():
    with pytest.raises(SandboxError, match="ValueError: kaboom"):
        run_in_sandbox(_boom)


def test_sandbox_enforces_timeout():
    start = time.monotonic()
    with pytest.raises(SandboxTimeout):
        run_in_sandbox(_sleep, 30, limits=Limits(timeout_seconds=1))
    assert time.monotonic() - start < 15


def test_sandbox_honours_cancellation():
    with pytest.raises(SandboxCancelled):
        run_in_sandbox(_sleep, 30, is_cancelled=lambda: True)


def test_child_environment_has_no_secrets(monkeypatch):
    monkeypatch.setenv("NETGUARD_SECRET_KEY", "super-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    assert run_in_sandbox(_env_snapshot) == {"NETGUARD_SECRET_KEY": None, "ANTHROPIC_API_KEY": None}
