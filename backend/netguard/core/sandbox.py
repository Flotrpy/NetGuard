"""Run untrusted-input analysis in an isolated child process.

Scanners parse attacker-controlled files (uploaded repositories, packet captures, remote
responses). To contain crashes, runaway resource use and bugs in parsers we run each scanner in
a separate *spawned* process that:

* has no database access and a scrubbed environment (no NetGuard secrets, no API keys),
* is bounded by a wall-clock timeout and is killed when the scan is cancelled,
* has memory / CPU / file-size rlimits applied where the OS supports them (POSIX),
* communicates only through a pipe carrying progress and the (picklable) result.

Scanners never *execute* scanned code. This process boundary is defence in depth.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

try:  # POSIX only
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

# Environment variables the child keeps. Everything else (including secrets) is dropped.
_ENV_ALLOW = {
    "PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG", "LC_ALL",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PYTHONPATH", "PYTHONHASHSEED", "COMSPEC",
}


class SandboxError(RuntimeError):
    """The sandboxed task failed."""


class SandboxTimeout(SandboxError):
    pass


class SandboxCancelled(SandboxError):
    pass


@dataclass(frozen=True)
class Limits:
    timeout_seconds: float = 600
    memory_mb: int = 1024
    cpu_seconds: int = 900
    max_file_mb: int = 64


def _scrub_env() -> None:
    for key in [k for k in os.environ if k not in _ENV_ALLOW]:
        del os.environ[key]


def _apply_rlimits(limits: Limits) -> None:
    if resource is None:  # pragma: no cover - Windows: rely on timeout + process isolation
        return
    mem = limits.memory_mb * 1024 * 1024
    for res, value in (
        (getattr(resource, "RLIMIT_AS", None), mem),
        (getattr(resource, "RLIMIT_CPU", None), limits.cpu_seconds),
        (getattr(resource, "RLIMIT_FSIZE", None), limits.max_file_mb * 1024 * 1024),
        (getattr(resource, "RLIMIT_CORE", None), 0),
    ):
        if res is None:
            continue
        try:
            resource.setrlimit(res, (value, value))
        except (ValueError, OSError):
            pass  # e.g. limit lower than current usage; keep running with the default


def _child_main(conn, func: Callable[..., Any], args: tuple, limits: Limits) -> None:
    def progress(percent: float, message: str = "") -> None:
        try:
            conn.send(("progress", float(percent), str(message)))
        except (BrokenPipeError, OSError):
            pass

    try:
        _scrub_env()
        _apply_rlimits(limits)
        result = func(progress, *args)
        conn.send(("result", result))
    except MemoryError:
        conn.send(("error", "Scanner exceeded its memory limit"))
    except BaseException as exc:  # noqa: BLE001 - report everything to the parent
        conn.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def run_in_sandbox(
    func: Callable[..., Any],
    *args: Any,
    limits: Limits | None = None,
    on_progress: Callable[[float, str], None] | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> Any:
    """Run ``func(progress, *args)`` in a child process and return its result.

    ``func`` and ``args`` must be picklable (top-level function, plain data).
    """
    limits = limits or Limits()
    ctx = mp.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child_main, args=(child, func, args, limits), daemon=True)
    proc.start()
    child.close()
    deadline = time.monotonic() + limits.timeout_seconds
    outcome: tuple | None = None
    try:
        while outcome is None:
            if parent.poll(0.2):
                try:
                    msg = parent.recv()
                except EOFError:
                    break
                if msg[0] == "progress":
                    if on_progress:
                        on_progress(msg[1], msg[2])
                else:
                    outcome = msg
                continue
            if not proc.is_alive():
                if parent.poll(0):  # final message raced with exit
                    continue
                break
            if is_cancelled and is_cancelled():
                raise SandboxCancelled("Scan cancelled")
            if time.monotonic() > deadline:
                raise SandboxTimeout(f"Scanner timed out after {limits.timeout_seconds:.0f}s")
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(2)
            if proc.is_alive():
                proc.kill()
        proc.join(2)
        parent.close()

    if outcome is None:
        raise SandboxError(f"Scanner process exited unexpectedly (code {proc.exitcode})")
    if outcome[0] == "error":
        raise SandboxError(outcome[1])
    return outcome[1]
