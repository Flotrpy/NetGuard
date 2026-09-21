"""SAST rule model.

A :class:`Rule` is a *detection rule*: every SAST finding NetGuard reports originates from one
of these (or from the Python AST analyzer, which uses the same metadata). Rules carry the human
guidance (impact, remediation) shown in the UI, so nothing displayed is invented at runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netguard.enums import Confidence, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str  # vulnerability type, e.g. "SQL Injection"
    severity: Severity
    confidence: Confidence
    cwe: str
    languages: tuple[str, ...]
    description: str
    impact: str
    remediation: str
    pattern: re.Pattern[str] | None = None
    # A match is discarded if the same line also matches this (reduces false positives).
    unless: re.Pattern[str] | None = None
    multiline: bool = False  # apply ``pattern`` to the whole file instead of line by line
    exploitability: str = "medium"
    references: tuple[str, ...] = ()
    # Id of a deterministic fixer in netguard.services.fixers (if one exists)
    fixer: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def applies_to(self, language: str) -> bool:
        return "*" in self.languages or language in self.languages


def rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def owasp(topic: str) -> str:
    return f"https://owasp.org/www-community/{topic}"


def cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html"
