"""SAST engine: walks source files and applies rules."""

from __future__ import annotations

import re

from netguard.core.files import context_lines, iter_files, read_text
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.sast.rules import Rule, cwe_url

# Inline suppression: `# netguard:ignore` (all rules) or `# netguard:ignore rule-id[, rule-id]`.
_IGNORE = re.compile(r"netguard[:\-]ignore(?:\s+([\w.\-, ]+))?", re.IGNORECASE)

_LINE_COMMENT = {
    "python": ("#",),
    "ruby": ("#",),
    "shell": ("#",),
    "yaml": ("#",),
    "javascript": ("//", "*", "/*"),
    "typescript": ("//", "*", "/*"),
    "java": ("//", "*", "/*"),
    "kotlin": ("//", "*", "/*"),
    "go": ("//", "*", "/*"),
    "csharp": ("//", "*", "/*"),
    "php": ("//", "#", "*", "/*"),
}

# Languages the SAST scanner analyses. Config/IaC files are handled by other scanners.
SAST_LANGUAGES = {
    "python", "javascript", "typescript", "java", "kotlin", "go", "php", "csharp", "ruby", "shell",
}


def is_comment(language: str, stripped_line: str) -> bool:
    return any(stripped_line.startswith(p) for p in _LINE_COMMENT.get(language, ()))


def suppressed(line: str, rule_id: str) -> bool:
    m = _IGNORE.search(line)
    if not m:
        return False
    listed = m.group(1)
    if not listed:
        return True
    return rule_id in {r.strip() for r in listed.split(",")}


def make_finding(
    rule: Rule,
    *,
    rel_path: str,
    language: str,
    lines: list[str],
    line_no: int,
    end_line: int | None = None,
    extra: dict | None = None,
    confidence=None,
    description_suffix: str = "",
) -> RawFinding:
    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
    return RawFinding(
        rule_id=rule.id,
        title=rule.title,
        category=rule.category,
        severity=rule.severity,
        confidence=confidence or rule.confidence,
        cwe=rule.cwe,
        description=rule.description + (f" {description_suffix}" if description_suffix else ""),
        impact=rule.impact,
        remediation=rule.remediation,
        file_path=rel_path,
        line=line_no,
        end_line=end_line or line_no,
        language=language,
        code_context=context_lines(lines, line_no, 2),
        references=list(rule.references) or [cwe_url(rule.cwe)],
        exploitability=rule.exploitability,
        extra={"fixer": rule.fixer, **(extra or {})},
        key=snippet,
    )


def scan_text_with_rules(
    rules: list[Rule], rel_path: str, language: str, text: str
) -> list[RawFinding]:
    lines = text.splitlines()
    findings: list[RawFinding] = []
    active = [r for r in rules if r.pattern is not None and r.applies_to(language)]
    for rule in active:
        assert rule.pattern is not None
        if rule.multiline:
            for m in rule.pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                if suppressed(lines[line_no - 1] if line_no <= len(lines) else "", rule.id):
                    continue
                findings.append(
                    make_finding(
                        rule, rel_path=rel_path, language=language, lines=lines, line_no=line_no
                    )
                )
            continue
        for n, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or is_comment(language, stripped):
                continue
            if not rule.pattern.search(line):
                continue
            if rule.unless is not None and rule.unless.search(line):
                continue
            if suppressed(line, rule.id):
                continue
            findings.append(
                make_finding(rule, rel_path=rel_path, language=language, lines=lines, line_no=n)
            )
    return findings


class SastScanner(Scanner):
    name = ScannerName.SAST
    display_name = "SAST Code Scanner"
    version = "1.0.0"
    description = (
        "Static analysis of source code: injection, XSS, path traversal, unsafe deserialization, "
        "weak crypto, insecure authentication and dangerous APIs."
    )
    supported_inputs = ("source",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        from netguard.scanners.sast import python_analyzer
        from netguard.scanners.sast.catalog import all_rules

        assert ctx.root is not None
        rules = all_rules()
        files = [
            f
            for f in iter_files(ctx.root, max_bytes=ctx.max_file_bytes, only_paths=ctx.only_paths)
            if f.language in SAST_LANGUAGES
        ]
        findings: list[RawFinding] = []
        warnings: list[str] = []
        analysed = 0
        for i, f in enumerate(files):
            ctx.check_cancelled()
            ctx.progress(100 * i / max(1, len(files)), f.rel_path)
            text = read_text(f.abs_path, ctx.max_file_bytes)
            if text is None:
                continue
            analysed += 1
            findings.extend(scan_text_with_rules(rules, f.rel_path, f.language, text))
            if f.language == "python":
                try:
                    findings.extend(python_analyzer.analyze(f.rel_path, text))
                except SyntaxError:
                    warnings.append(f"{f.rel_path}: Python syntax error; AST checks skipped")
        ctx.progress(100, "done")
        return ScanResult(
            findings=findings,
            warnings=warnings,
            metadata={"files_analyzed": analysed, "rules": len(rules) + python_analyzer.RULE_COUNT},
        )
