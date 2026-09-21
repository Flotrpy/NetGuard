"""Vulnerability explainer.

Every explanation separates three kinds of statements so users can tell what is known from what
is guessed:

* ``detected``: facts taken verbatim from the finding (rule, location, CWE, scanner data);
* ``inferred``: reasoning that goes beyond the facts, always labelled as inference;
* ``recommended``: remediation guidance.

A deterministic baseline is always built from the detection rule's own text. Claude may rewrite
it in plainer language for the chosen audience, but its output is validated: any CVE/CWE
identifier it mentions that is not present in the finding's data discards the AI text entirely.
"""

from __future__ import annotations

import re
from typing import Any

from netguard.models import Finding
from netguard.services.ai import llm

_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,4}|GHSA(?:-[a-z0-9]{4}){3})\b", re.IGNORECASE)

SYSTEM_PROMPT = """You are the security explainer inside NetGuard, a defensive security platform.
You explain ONE scanner finding to a developer.

Hard rules:
- Use only the finding data provided. Never invent vulnerabilities, CVE/CWE/advisory identifiers,
  code behaviour, versions, or outcomes. If something is not in the data, do not state it as fact.
- Anything you conclude beyond the provided data goes ONLY in the "inferred" list, phrased as an
  inference ("likely", "may"), and only when it follows from the data.
- Do not claim the issue is exploitable or fixed. Recommendations must be actions the developer
  can take; do not present them as things that already happened.
- Never reproduce secrets; the data is already redacted.
Respond with a single JSON object and nothing else:
{"what_happened": str, "why_it_matters": str, "inferred": [str], "recommended": [str]}
Keep each string under 500 characters. Audience: %s."""


def facts(f: Finding) -> list[dict[str, str]]:
    """Facts taken verbatim from the stored finding (never generated)."""
    rows = [
        ("Finding", f.title),
        ("Detection source", f"{f.scanner} (rule {f.rule_id})"),
        ("Severity", f"{f.severity} (confidence: {f.confidence})"),
    ]
    if f.cwe:
        rows.append(("CWE", f.cwe))
    if f.file_path:
        rows.append(("Location", f"{f.file_path}:{f.line}" if f.line else f.file_path))
    extra = f.extra or {}
    for key, label in (("package", "Package"), ("version", "Installed version"),
                       ("vulnerability", "Advisory"), ("cve", "CVE")):
        if extra.get(key):
            rows.append((label, str(extra[key])))
    if extra.get("fixed_versions"):
        rows.append(("Fixed in", ", ".join(extra["fixed_versions"])))
    return [{"label": k, "value": v} for k, v in rows]


def baseline(f: Finding) -> dict[str, Any]:
    """Deterministic explanation built only from the detection rule's own text."""
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", f.remediation)
    recommended = [s.strip() for s in sentences if s.strip()]
    return {
        "what_happened": f.description or f.title,
        "why_it_matters": f.impact or "The scanner classified this as a security weakness.",
        "inferred": [],
        "recommended": recommended or [f.remediation or "Review the finding and apply a fix."],
    }


def _allowed_identifiers(f: Finding) -> set[str]:
    allowed = {f.cwe.upper()} if f.cwe else set()
    extra = f.extra or {}
    for key in ("cve", "vulnerability"):
        if extra.get(key):
            allowed.add(str(extra[key]).upper())
    allowed.update(str(a).upper() for a in extra.get("aliases", []))
    for text in (f.title, f.description, f.remediation, *f.references):
        allowed.update(m.upper() for m in _ID_RE.findall(str(text)))
    return allowed


def validate_ai(f: Finding, data: dict[str, Any]) -> dict[str, Any]:
    """Shape-check the model output and reject fabricated identifiers."""
    try:
        clean = {
            "what_happened": str(data["what_happened"]).strip()[:1200],
            "why_it_matters": str(data["why_it_matters"]).strip()[:1200],
            "inferred": [str(x).strip()[:600] for x in data.get("inferred", [])][:6],
            "recommended": [str(x).strip()[:600] for x in data.get("recommended", [])][:8],
        }
    except (KeyError, TypeError) as exc:
        raise llm.LlmUnavailable("The AI response was missing required fields") from exc
    if not clean["what_happened"] or not clean["recommended"]:
        raise llm.LlmUnavailable("The AI response was incomplete")
    blob = " ".join([clean["what_happened"], clean["why_it_matters"], *clean["inferred"],
                     *clean["recommended"]])
    unknown = {m.upper() for m in _ID_RE.findall(blob)} - _allowed_identifiers(f)
    if unknown:
        listed = ", ".join(sorted(unknown))
        raise llm.LlmUnavailable(
            f"The AI response referenced identifiers not in the finding ({listed})"
        )
    return clean


def _prompt(f: Finding) -> str:
    return (
        "Finding data (JSON-like, all values come from the scanner):\n"
        f"title: {f.title}\nrule: {f.rule_id}\nscanner: {f.scanner}\nseverity: {f.severity}\n"
        f"confidence: {f.confidence}\ncwe: {f.cwe}\nlocation: {f.file_path}:{f.line}\n"
        f"description: {f.description}\nimpact: {f.impact}\nremediation: {f.remediation}\n"
        f"scanner details: {f.extra}\ncode context:\n{f.code_context}\n"
    )


def explain(f: Finding, *, audience: str = "beginner", use_ai: bool = True) -> dict[str, Any]:
    """Build the full explanation payload for a finding."""
    audience = audience if audience in ("beginner", "advanced") else "beginner"
    base = baseline(f)
    result: dict[str, Any] = {
        "finding_id": f.id,
        "audience": audience,
        "detected": facts(f),
        "source": "rule",
        "model": None,
        "notice": None,
        **base,
    }
    if not use_ai:
        return result
    if not llm.is_configured():
        result["notice"] = (
            "AI explanations are not configured, so this text comes directly from the detection "
            "rule. Set ANTHROPIC_API_KEY to enable plain-language AI explanations."
        )
        return result
    try:
        reply = llm.complete(
            SYSTEM_PROMPT % audience, _prompt(f), max_tokens=2000, effort="medium"
        )
        clean = validate_ai(f, llm.extract_json(reply.text))
    except llm.LlmUnavailable as exc:
        result["notice"] = (
            f"AI explanation unavailable ({exc}); showing the rule-based explanation."
        )
        return result
    result.update(clean)
    result.update(source="ai", model=reply.model,
                  notice="Generated by AI from the finding data above; review before acting.")
    return result
