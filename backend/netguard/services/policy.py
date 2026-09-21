"""CI/CD security gate policy.

A policy decides whether a build/PR should fail. It is data (stored per project as JSON) and every
threshold is optional, so teams choose what blocks them. Low-severity findings never fail a build
unless a policy explicitly asks for it.

Default policy:  fail when Critical > 0, when NEW High > 0, or when a secret is detected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from netguard.enums import SEVERITY_RANK, Severity

CONF_RANK = {"low": 0, "medium": 1, "high": 2}


class Policy(BaseModel):
    max_critical: int | None = Field(default=0, ge=0, description="fail if Critical > N")
    max_high: int | None = Field(default=None, ge=0, description="fail if High > N (all)")
    max_new_high: int | None = Field(default=0, ge=0, description="fail if NEW High > N")
    max_new_medium: int | None = Field(default=None, ge=0)
    fail_on_secrets: bool = True
    fail_on_severity: Literal["critical", "high", "medium", "low"] | None = Field(
        default=None, description="fail if ANY finding is at least this severity"
    )
    min_confidence: Literal["low", "medium", "high"] = "low"
    ignore_statuses: list[str] = Field(
        default_factory=lambda: ["fixed", "false_positive", "accepted_risk"]
    )
    ignore_scanners: list[str] = Field(default_factory=list)


@dataclass
class PolicyFinding:
    severity: str
    scanner: str
    confidence: str = "high"
    status: str = "open"
    is_new: bool = False
    title: str = ""


@dataclass
class Violation:
    rule: str
    message: str
    count: int


@dataclass
class PolicyResult:
    passed: bool
    violations: list[Violation]
    counts: dict[str, int]
    new_counts: dict[str, int]
    evaluated: int

    def as_dict(self) -> dict:
        return {
            "passed": self.passed,
            "violations": [v.__dict__ for v in self.violations],
            "counts": self.counts,
            "new_counts": self.new_counts,
            "evaluated": self.evaluated,
        }


def evaluate(findings: list[PolicyFinding], policy: Policy | None = None) -> PolicyResult:
    policy = policy or Policy()
    considered = [
        f
        for f in findings
        if f.status not in policy.ignore_statuses
        and f.scanner not in policy.ignore_scanners
        and CONF_RANK.get(f.confidence, 0) >= CONF_RANK[policy.min_confidence]
    ]
    counts = {s.value: 0 for s in Severity}
    new_counts = dict(counts)
    for f in considered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        if f.is_new:
            new_counts[f.severity] = new_counts.get(f.severity, 0) + 1

    violations: list[Violation] = []

    def check(rule: str, actual: int, limit: int | None, label: str) -> None:
        if limit is not None and actual > limit:
            message = f"{label}: {actual} found (allowed: {limit})"
            violations.append(Violation(rule, message, actual))

    check("max_critical", counts["critical"], policy.max_critical, "Critical findings")
    check("max_high", counts["high"], policy.max_high, "High findings")
    check("max_new_high", new_counts["high"], policy.max_new_high, "New High findings")
    check("max_new_medium", new_counts["medium"], policy.max_new_medium, "New Medium findings")
    if policy.fail_on_secrets:
        secrets = sum(1 for f in considered if f.scanner == "secrets")
        if secrets:
            violations.append(Violation("fail_on_secrets", f"Secrets detected: {secrets}", secrets))
    if policy.fail_on_severity:
        floor = SEVERITY_RANK[Severity(policy.fail_on_severity)]
        n = sum(1 for f in considered if SEVERITY_RANK[Severity(f.severity)] >= floor)
        if n:
            message = f"{n} finding(s) at {policy.fail_on_severity} or above"
            violations.append(Violation("fail_on_severity", message, n))
    return PolicyResult(not violations, violations, counts, new_counts, len(considered))
