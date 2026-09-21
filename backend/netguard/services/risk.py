"""Centralized risk model.

The risk score is a transparent, documented formula (see :data:`METHODOLOGY`), not a black box.
It is a *prioritisation aid*: severity is always the scanner's own rating and is never changed
by the risk engine.

    risk = severity_base x confidence_factor x exploitability_factor x exposure_factor

The result is on a 0-10 scale, rounded to one decimal.
"""

from __future__ import annotations

from typing import Any

from netguard.enums import Confidence, Severity

SEVERITY_BASE = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 0.5,
}
CONFIDENCE_FACTOR = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.85, Confidence.LOW: 0.6}
EXPLOITABILITY_FACTOR = {"high": 1.0, "medium": 0.9, "low": 0.75}
EXPOSURE_FACTOR = {"internet": 1.0, "internal": 0.85, "local": 0.7, "unknown": 0.9}

METHODOLOGY: dict[str, Any] = {
    "formula": "risk = severity_base x confidence x exploitability x exposure  (0-10)",
    "notes": [
        "Severity is assigned by the detection rule or trusted data source, and is never "
        "modified by the risk engine.",
        "Confidence reflects how likely a detection is a true positive (rule precision).",
        "Exploitability is a qualitative estimate from the detection rule, not a proof of "
        "exploitation. NetGuard never attempts exploitation.",
        "Exposure is 'internet' or 'internal' only when the scanner observed it (for example, "
        "a public vs. private IP). Otherwise it is 'unknown'.",
        "The score only orders findings for triage. It is not a probability of compromise.",
    ],
    "severity_base": {k.value: v for k, v in SEVERITY_BASE.items()},
    "confidence_factor": {k.value: v for k, v in CONFIDENCE_FACTOR.items()},
    "exploitability_factor": EXPLOITABILITY_FACTOR,
    "exposure_factor": EXPOSURE_FACTOR,
}


def compute_risk(
    severity: str | Severity,
    confidence: str | Confidence,
    exploitability: str = "medium",
    exposure: str = "unknown",
) -> float:
    sev = Severity.parse(severity)
    conf = Confidence(str(confidence).lower())
    score = (
        SEVERITY_BASE[sev]
        * CONFIDENCE_FACTOR[conf]
        * EXPLOITABILITY_FACTOR.get(exploitability, EXPLOITABILITY_FACTOR["medium"])
        * EXPOSURE_FACTOR.get(exposure, EXPOSURE_FACTOR["unknown"])
    )
    return round(score, 1)


def severity_counts(severities: list[str]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for s in severities:
        counts[s] = counts.get(s, 0) + 1
    return counts
