"""Python AST analyzer (implemented in a following commit)."""

from __future__ import annotations

from netguard.scanners.base import RawFinding

RULE_COUNT = 0


def analyze(rel_path: str, source: str) -> list[RawFinding]:
    return []
