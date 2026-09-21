"""Aggregates the per-language rule modules into one catalog."""

from __future__ import annotations

from functools import lru_cache

from netguard.scanners.sast.rules import Rule


@lru_cache
def all_rules() -> list[Rule]:
    from netguard.scanners.sast import rules_js  # noqa: F401  (added below)

    rules: list[Rule] = []
    rules.extend(rules_js.RULES)
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate SAST rule id"
    return rules
