"""Security gate for a scan: policy evaluation and PR/MR comment formatting."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.enums import ACTIVE_STATUSES
from netguard.models import Finding, Project, Scan
from netguard.scanners.base import RawFinding, fingerprint
from netguard.services.policy import Policy, PolicyFinding, PolicyResult, evaluate
from netguard.services.providers import COMMENT_MARKER

MAX_EPHEMERAL_ITEMS = 300
_ORDER = ["critical", "high", "medium", "low", "info"]
_MODULE_LABELS = {
    "sast": "SAST",
    "dependencies": "Dependencies",
    "secrets": "Secrets",
    "iac": "IaC",
    "docker": "Containers",
}


def ephemeral_items(
    db: Session, scan: Scan, scanner: str, raws: list[RawFinding]
) -> list[dict[str, Any]]:
    """Compact, already-redacted finding summaries kept on the scan (not in the finding DB).

    ``is_new`` means: not currently known to the project. It is what "New High findings"
    policies gate on for pull requests.
    """
    known = set(
        db.scalars(select(Finding.fingerprint).where(Finding.project_id == scan.project_id))
    )
    counter: dict[str, int] = {}
    items = []
    for raw in raws:
        material = raw.fingerprint_material(scanner)
        n = counter.get(material, 0)
        counter[material] = n + 1
        fp = fingerprint(material, n)
        items.append(
            {
                "scanner": scanner,
                "rule_id": raw.rule_id,
                "title": raw.title,
                "severity": raw.severity.value,
                "confidence": raw.confidence.value,
                "file_path": raw.file_path,
                "line": raw.line,
                "is_new": fp not in known,
            }
        )
    items.sort(key=lambda i: _ORDER.index(i["severity"]))
    return items[:MAX_EPHEMERAL_ITEMS]


def scan_items(db: Session, scan: Scan) -> list[dict[str, Any]]:
    """All findings a scan is judged on (ephemeral items, or DB findings it observed)."""
    outcomes = (scan.summary or {}).get("scanners", {})
    if scan.config.get("ephemeral"):
        return [i for o in outcomes.values() for i in o.get("items", [])]
    started = scan.started_at.replace(tzinfo=None) if scan.started_at else None
    rows = db.scalars(
        select(Finding).where(
            Finding.scan_id == scan.id, Finding.status.in_([s.value for s in ACTIVE_STATUSES])
        )
    )
    return [
        {
            "scanner": f.scanner,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "line": f.line,
            "is_new": bool(started and f.first_seen.replace(tzinfo=None) >= started),
        }
        for f in rows
    ]


def load_policy(project: Project) -> Policy:
    try:
        return Policy.model_validate(project.policy or {})
    except ValueError:
        return Policy()  # a corrupt stored policy must not disable the gate: use the safe default


def gate_for_scan(db: Session, scan: Scan) -> PolicyResult:
    project = db.get(Project, scan.project_id)
    items = scan_items(db, scan)
    return evaluate(
        [
            PolicyFinding(
                i["severity"], i["scanner"], i["confidence"], "open", i["is_new"], i["title"]
            )
            for i in items
        ],
        load_policy(project),
    )


def module_lines(scan: Scan, items: list[dict[str, Any]]) -> list[str]:
    """✓ / ⚠ / ? per scanner: '?' when a scanner could not fully check (never a false ✓)."""
    outcomes = (scan.summary or {}).get("scanners", {})
    lines = []
    for name in scan.scanners:
        label = _MODULE_LABELS.get(name, name)
        o = outcomes.get(name, {})
        count = sum(1 for i in items if i["scanner"] == name)
        if o.get("state") != "completed" or not o.get("complete", True):
            lines.append(f"? {label} (could not fully check)")
        elif count:
            lines.append(f"⚠ {label}")
        else:
            lines.append(f"✓ {label}")
    return lines


def format_pr_comment(
    scan: Scan, result: PolicyResult, items: list[dict[str, Any]], link: str = ""
) -> str:
    lines = [COMMENT_MARKER, "### NetGuard Security Check", ""]
    lines += [f"- {m}" for m in module_lines(scan, items)]
    lines.append("")
    total = len(items)
    lines.append(
        f"**{total} finding{'s' if total != 1 else ''} detected**"
        if total
        else "No findings detected"
    )
    lines.append("")
    lines.append("✅ **Gate passed**" if result.passed else "❌ **Gate failed**")
    for v in result.violations:
        lines.append(f"- {v.message}")
    shown = [i for i in items if i["severity"] in ("critical", "high", "medium")][:10]
    if shown:
        lines += ["", "| Severity | Finding | Location |", "|---|---|---|"]
        for i in shown:
            loc = (
                f"`{i['file_path']}:{i['line']}`"
                if i["file_path"] and i["line"]
                else f"`{i['file_path']}`"
                if i["file_path"]
                else ""
            )
            title = i["title"].replace("|", "\\|")
            lines.append(f"| {i['severity'].upper()} | {title} | {loc} |")
        if total > len(shown):
            lines.append(f"\n_{total - len(shown)} more (lower severity) not shown._")
    if link:
        lines += ["", f"[Open in NetGuard]({link})"]
    return "\n".join(lines)
