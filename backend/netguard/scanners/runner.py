"""Top-level, picklable entry point used to run a scanner inside the sandbox."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netguard.scanners.base import ScanContext, ScanResult
from netguard.scanners.registry import get_scanner


def run_scanner_task(
    progress,  # noqa: ANN001 - callable injected by the sandbox
    scanner_name: str,
    root: str | None,
    config: dict[str, Any],
    max_file_bytes: int,
    only_paths: list[str] | None,
    runtime: dict[str, Any],
) -> ScanResult:
    ctx = ScanContext(
        root=Path(root) if root else None,
        config=config,
        max_file_bytes=max_file_bytes,
        progress=progress,
        only_paths=set(only_paths) if only_paths is not None else None,
        runtime=runtime,
    )
    return get_scanner(scanner_name).scan(ctx)
