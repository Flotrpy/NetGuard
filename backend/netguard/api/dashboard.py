"""Dashboard aggregation: everything the security overview needs in one call."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netguard.api.deps import (
    Principal,
    accessible_project_ids,
    get_principal,
    get_project_or_404,
)
from netguard.db import get_db
from netguard.enums import ACTIVE_STATUSES, FindingStatus, ScanStatus, Severity
from netguard.models import Asset, Finding, Repository, Scan
from netguard.scanners.registry import scanner_infos
from netguard.services.risk import severity_counts

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_ACTIVE = [s.value for s in ACTIVE_STATUSES]
TREND_DAYS = 30


def _day(dt: datetime | None) -> date | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).date()


def compute_trend(rows: list[tuple[datetime, datetime | None]], days: int = TREND_DAYS):
    """Daily opened / resolved counts and the running number of active findings."""
    today = datetime.now(UTC).date()
    start = today - timedelta(days=days - 1)
    opened: dict[date, int] = defaultdict(int)
    resolved: dict[date, int] = defaultdict(int)
    for first_seen, resolved_at in rows:
        opened[_day(first_seen)] += 1
        if resolved_at:
            resolved[_day(resolved_at)] += 1
    active = sum(n for d, n in opened.items() if d < start) - sum(
        n for d, n in resolved.items() if d < start
    )
    out = []
    for i in range(days):
        d = start + timedelta(days=i)
        active += opened.get(d, 0) - resolved.get(d, 0)
        out.append(
            {
                "date": d.isoformat(),
                "opened": opened.get(d, 0),
                "resolved": resolved.get(d, 0),
                "active": max(active, 0),
            }
        )
    return out


@router.get("")
def dashboard(
    project_id: str | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if project_id:
        get_project_or_404(db, principal, project_id)
        ids = [project_id]
    else:
        ids = accessible_project_ids(db, principal)
    scope = ids or [""]

    findings = db.execute(
        select(Finding.severity, Finding.status, Finding.scanner).where(
            Finding.project_id.in_(scope)
        )
    ).all()
    active = [f for f in findings if f.status in _ACTIVE]
    fixed = sum(1 for f in findings if f.status == FindingStatus.FIXED.value)
    triaged = sum(
        1
        for f in findings
        if f.status in (FindingStatus.FALSE_POSITIVE.value, FindingStatus.ACCEPTED_RISK.value)
    )
    denominator = len(active) + fixed
    totals = {
        "active": len(active),
        "fixed": fixed,
        "triaged": triaged,
        "total": len(findings),
        # Share of ever-actionable findings that have been fixed; not a "security score".
        "remediation_progress": round(fixed / denominator, 3) if denominator else None,
    }

    # Per-module status derived from real scan records, never assumed.
    scans = db.scalars(
        select(Scan)
        .where(
            Scan.project_id.in_(scope),
            Scan.status.in_([ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value]),
        )
        .order_by(Scan.finished_at.desc())
    ).all()
    last_scan: dict[str, datetime | None] = {}
    for scan in scans:
        for name, outcome in (scan.summary or {}).get("scanners", {}).items():
            if outcome.get("state") == "completed" and name not in last_scan:
                last_scan[name] = scan.finished_at
    active_by_scanner: dict[str, int] = defaultdict(int)
    for f in active:
        active_by_scanner[f.scanner] += 1
    modules = []
    for info in scanner_infos():
        scanned = info.name in last_scan
        if not info.available:
            status = "unavailable"
        elif not scanned:
            status = "not_scanned"
        elif active_by_scanner[info.name]:
            status = "attention"
        else:
            status = "ok"
        modules.append(
            {
                "scanner": info.name,
                "name": info.display_name,
                "status": status,
                "open_findings": active_by_scanner[info.name],
                "last_scan_at": last_scan.get(info.name),
                "available": info.available,
            }
        )

    trend_rows = db.execute(
        select(Finding.first_seen, Finding.resolved_at).where(Finding.project_id.in_(scope))
    ).all()

    recently_fixed = db.execute(
        select(Finding.id, Finding.title, Finding.severity, Finding.file_path, Finding.resolved_at)
        .where(Finding.project_id.in_(scope), Finding.status == FindingStatus.FIXED.value)
        .order_by(Finding.resolved_at.desc())
        .limit(5)
    ).all()

    recent_scans = db.scalars(
        select(Scan).where(Scan.project_id.in_(scope)).order_by(Scan.created_at.desc()).limit(8)
    ).all()

    repo_rows = db.execute(
        select(Repository.id, Repository.name, Finding.severity, func.count())
        .join(Finding, Finding.repository_id == Repository.id)
        .where(Repository.project_id.in_(scope), Finding.status.in_(_ACTIVE))
        .group_by(Repository.id, Repository.name, Finding.severity)
    ).all()
    repos: dict[str, dict[str, Any]] = {}
    for rid, name, sev, n in repo_rows:
        entry = repos.setdefault(rid, {"id": rid, "name": name, "counts": severity_counts([])})
        entry["counts"][sev] = n

    host_rows = db.execute(
        select(Asset.id, Asset.name, Asset.identifier, Finding.severity, func.count())
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Asset.project_id.in_(scope), Asset.type == "host", Finding.status.in_(_ACTIVE))
        .group_by(Asset.id, Asset.name, Asset.identifier, Finding.severity)
    ).all()
    hosts: dict[str, dict[str, Any]] = {}
    for aid, name, ident, sev, n in host_rows:
        entry = hosts.setdefault(
            aid, {"id": aid, "name": name, "ip": ident, "counts": severity_counts([])}
        )
        entry["counts"][sev] = n

    return {
        "severity": severity_counts([f.severity for f in active]),
        "totals": totals,
        "modules": modules,
        "trend": compute_trend([(a, b) for a, b in trend_rows]),
        "recently_fixed": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "file_path": r.file_path,
                "resolved_at": r.resolved_at,
            }
            for r in recently_fixed
        ],
        "recent_scans": [
            {
                "id": s.id,
                "project_id": s.project_id,
                "status": s.status,
                "scanners": s.scanners,
                "created_at": s.created_at,
                "finished_at": s.finished_at,
                "severity": (s.summary or {}).get("severity"),
            }
            for s in recent_scans
        ],
        "affected_repositories": sorted(
            repos.values(), key=lambda r: (-r["counts"]["critical"], -r["counts"]["high"])
        ),
        "affected_hosts": sorted(
            hosts.values(), key=lambda h: (-h["counts"]["critical"], -h["counts"]["high"])
        ),
        "severity_order": [s.value for s in Severity],
    }
