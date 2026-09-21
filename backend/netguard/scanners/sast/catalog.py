"""Aggregates the per-language rule modules into one catalog."""

from __future__ import annotations

from functools import lru_cache

from netguard.scanners.sast.rules import Rule


@lru_cache
def all_rules() -> list[Rule]:
    from netguard.scanners.sast import rules_js, rules_jvm_dotnet, rules_scripting

    rules: list[Rule] = [*rules_js.RULES, *rules_jvm_dotnet.RULES, *rules_scripting.RULES]
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate SAST rule id"
    return rules
