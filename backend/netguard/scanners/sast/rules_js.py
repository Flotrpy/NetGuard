"""JavaScript / TypeScript rules."""

from __future__ import annotations

from netguard.enums import Confidence, Severity
from netguard.scanners.sast.rules import Rule, owasp, rx

JS = ("javascript", "typescript")

RULES: list[Rule] = [
    Rule(
        id="js.eval",
        title="Use of eval() / Function constructor",
        category="Code Injection",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        cwe="CWE-95",
        languages=JS,
        pattern=rx(r"(?<![\w.$])eval\s*\(\s*(?!['\"`][^'\"`]*['\"`]\s*\))|new\s+Function\s*\("),
        description="eval() or the Function constructor executes a string as code.",
        impact="If any part of the string is attacker-controlled, the attacker can run arbitrary "
        "JavaScript in your application.",
        remediation="Avoid dynamic code execution. Use JSON.parse for data, or lookup tables / "
        "explicit functions for behaviour selection.",
        exploitability="high",
        references=(owasp("attacks/Code_Injection"),),
    ),
]
