"""Secret scanner: finds exposed credentials without ever storing or displaying them in full."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from netguard.core.files import iter_files, read_text
from netguard.enums import Confidence
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.sast.engine import suppressed
from netguard.scanners.secrets.patterns import RULES, SecretRule, guidance_for
from netguard.scanners.secrets.util import (
    char_classes,
    is_placeholder,
    redact,
    shannon_entropy,
)

# Lockfiles / generated data are noisy (integrity hashes) and never contain live credentials.
_SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "pipfile.lock",
    "composer.lock", "gemfile.lock", "cargo.lock", "go.sum", "packages.lock.json",
}
_LOW_TRUST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture",
                   "examples", "example", "docs", "doc", "samples", "sample", "mock", "mocks",
                   "testdata", "e2e"}
_ORDERED = sorted(RULES, key=lambda r: (r.generic, r.id != "gcp-service-account"))
_IDENTIFIER_LIKE = re.compile(r"[A-Za-z_.\-]+")


@dataclass
class _Match:
    rule: SecretRule
    line: int  # 1-based
    start: int
    end: int
    value: str
    confidence: Confidence
    entropy: float
    low_trust_path: bool


def _is_dotenv(rel_path: str) -> bool:
    name = PurePosixPath(rel_path).name.lower()
    return name.startswith(".env") or name.endswith(".env") or name in ("env", "secrets.env")


def _lower(conf: Confidence) -> Confidence:
    return {Confidence.HIGH: Confidence.MEDIUM, Confidence.MEDIUM: Confidence.LOW}.get(
        conf, Confidence.LOW
    )


def _accept(rule: SecretRule, value: str) -> tuple[Confidence, float] | None:
    """Apply false-positive filters; returns (confidence, entropy) or ``None`` to discard."""
    entropy = shannon_entropy(value)
    if rule.generic:
        if is_placeholder(value):
            return None
        if rule.id == "jwt":
            return rule.confidence, entropy
        if entropy < 2.8 or char_classes(value) < 2:
            return None
        if _IDENTIFIER_LIKE.fullmatch(value) and entropy < 3.8:
            return None  # reads like an identifier/word, not a secret
        return (Confidence.MEDIUM if entropy >= 3.5 else Confidence.LOW), entropy
    low = value.lower()
    if "example" in low or len(set(value)) <= 3:
        return None  # documentation placeholders such as AKIA...EXAMPLE
    if rule.category == "database" and is_placeholder(value):
        return None
    return rule.confidence, entropy


def find_matches(rel_path: str, lines: list[str], salt_unused: str = "") -> list[_Match]:
    parts = {p.lower() for p in PurePosixPath(rel_path).parts[:-1]}
    low_trust = bool(parts & _LOW_TRUST_DIRS)
    dotenv = _is_dotenv(rel_path)
    matches: list[_Match] = []
    for n, line in enumerate(lines, 1):
        if len(line) > 4000 or not line.strip():
            continue
        claimed: list[tuple[int, int]] = []
        for rule in _ORDERED:
            if rule.id == "dotenv-secret" and not dotenv:
                continue
            for m in rule.pattern.finditer(line):
                start, end = m.span(rule.group)
                if start < 0 or any(start < ce and end > cs for cs, ce in claimed):
                    continue
                value = m.group(rule.group)
                verdict = _accept(rule, value)
                if verdict is None or suppressed(line, f"secret.{rule.id}"):
                    continue
                conf, entropy = verdict
                if low_trust:
                    conf = _lower(conf)
                claimed.append((start, len(line) if rule.redact_to_eol else end))
                matches.append(_Match(rule, n, start, end, value, conf, entropy, low_trust))
    return matches


def _redact_lines(lines: list[str], matches: list[_Match]) -> list[str]:
    out = list(lines)
    by_line: dict[int, list[_Match]] = {}
    for m in matches:
        by_line.setdefault(m.line, []).append(m)
    for n, ms in by_line.items():
        text = out[n - 1]
        for m in sorted(ms, key=lambda x: x.start, reverse=True):
            if m.rule.redact_to_eol:
                text = f"{text[: m.start]}{m.rule.prefix}****[key material omitted]"
            else:
                text = f"{text[: m.start]}{redact(m.value, m.rule.prefix)}{text[m.end :]}"
        out[n - 1] = text
    return out


def scan_text(rel_path: str, text: str, salt: str) -> list[RawFinding]:
    lines = text.splitlines()
    matches = find_matches(rel_path, lines)
    if not matches:
        return []
    red = _redact_lines(lines, matches)
    findings: list[RawFinding] = []
    for m in matches:
        preview = "[key material omitted]" if m.rule.redact_to_eol else redact(
            m.value, m.rule.prefix
        )
        if m.rule.redact_to_eol:  # never show the key body that follows the header line
            context = f"{m.line}: {red[m.line - 1].strip()}"
        else:
            lo, hi = max(1, m.line - 1), min(len(red), m.line + 1)
            context = "\n".join(f"{i}: {red[i - 1]}" for i in range(lo, hi + 1))
        digest = hmac.new(salt.encode(), f"{m.rule.id}|{m.value}".encode(), hashlib.sha256)
        provider = f" ({m.rule.provider})" if m.rule.provider else ""
        notes = []
        if m.low_trust_path:
            notes.append("Located in a test/example path, so confidence is reduced.")
        if m.rule.generic and m.confidence == Confidence.LOW:
            notes.append("Generic pattern with modest entropy; verify it is a real credential.")
        findings.append(
            RawFinding(
                rule_id=f"secret.{m.rule.id}",
                title=f"Exposed {m.rule.name}{provider}",
                category="Exposed Secret",
                severity=m.rule.severity,
                confidence=m.confidence,
                cwe=m.rule.cwe,
                description=(
                    f"A {m.rule.name.lower()} appears to be committed in source. "
                    f"Detected value: {preview}. " + " ".join(notes)
                ).strip(),
                impact="Anyone with read access to the repository (or its history, forks and "
                "build logs) can use this credential to act as your application or account.",
                remediation=guidance_for(m.rule),
                file_path=rel_path,
                line=m.line,
                language="",
                code_context=context,
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                exploitability="high",
                extra={
                    "secret_type": m.rule.id,
                    "provider": m.rule.provider,
                    "category": m.rule.category,
                    "redacted": preview,
                    "length": len(m.value),
                    "entropy": round(m.entropy, 2),
                },
                key=digest.hexdigest()[:32],
            )
        )
    return findings


class SecretScanner(Scanner):
    name = ScannerName.SECRETS
    display_name = "Secret Scanner"
    version = "1.0.0"
    description = (
        "Detects exposed API keys, tokens, private keys, passwords and connection strings. "
        "Values are redacted everywhere: only a short prefix and the last two characters are shown."
    )
    supported_inputs = ("source",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        assert ctx.root is not None
        salt = str(ctx.runtime.get("fingerprint_salt") or "netguard-secrets-default-salt")
        findings: list[RawFinding] = []
        files = [
            f
            for f in iter_files(ctx.root, max_bytes=ctx.max_file_bytes, only_paths=ctx.only_paths)
            if f.abs_path.name.lower() not in _SKIP_NAMES
        ]
        scanned = 0
        for i, f in enumerate(files):
            ctx.check_cancelled()
            ctx.progress(100 * i / max(1, len(files)), f.rel_path)
            text = read_text(f.abs_path, ctx.max_file_bytes)
            if text is None:
                continue
            scanned += 1
            findings.extend(scan_text(f.rel_path, text, salt))
        ctx.progress(100, "done")
        return ScanResult(
            findings=findings,
            metadata={"files_scanned": scanned, "rules": len(RULES), "history_scanned": False},
            warnings=[
                "Only the current snapshot was scanned. Secrets removed in earlier commits may "
                "still exist in git history."
            ],
        )
