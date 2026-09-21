"""SARIF 2.1.0 export (GitHub code scanning, GitLab, IDEs)."""

from __future__ import annotations

from typing import Any

from netguard import __version__
from netguard.scanners.base import RawFinding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5",
}


def to_sarif(findings: list[tuple[str, RawFinding, str]]) -> dict[str, Any]:
    """``findings`` are (scanner, finding, fingerprint) triples. Secrets are already redacted."""
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for scanner, f, fp in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.category.replace(" ", "") or f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "help": {"text": f.remediation or "See the finding description."},
                "defaultConfiguration": {"level": _LEVEL[f.severity.value]},
                "properties": {
                    "tags": ["security", scanner, *([f.cwe] if f.cwe else [])],
                    "security-severity": _SECURITY_SEVERITY[f.severity.value],
                },
            }
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _LEVEL[f.severity.value],
            "message": {"text": f"{f.title}. {f.remediation}".strip()},
            "partialFingerprints": {"netguard/v1": fp},
            "properties": {"severity": f.severity.value, "confidence": f.confidence.value,
                           "scanner": scanner},
        }
        if f.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {"artifactLocation": {"uri": f.file_path}}
            }
            if f.line:
                location["physicalLocation"]["region"] = {"startLine": f.line}
            result["locations"] = [location]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NetGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/Flotrpy/NetGuard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
