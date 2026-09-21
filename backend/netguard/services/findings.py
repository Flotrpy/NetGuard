"""Finding ingestion and lifecycle: the unified finding database.

Scanners return :class:`RawFinding` objects. This module turns them into persistent
:class:`Finding` rows, de-duplicates them across scans by fingerprint, records history, reopens
regressions and (only after a *complete* rescan) marks findings that disappeared as fixed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.db import utcnow
from netguard.enums import ACTIVE_STATUSES, FindingStatus, VerificationState
from netguard.models import Asset, Finding, FindingEvent, Scan
from netguard.scanners.base import AssetRef, RawFinding, fingerprint
from netguard.services.risk import compute_risk

_MAX_CONTEXT = 4000


@dataclass
class IngestStats:
    new: int = 0
    seen_again: int = 0
    reopened: int = 0
    resolved: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "new": self.new,
            "seen_again": self.seen_again,
            "reopened": self.reopened,
            "resolved": self.resolved,
        }


def add_event(
    db: Session,
    finding: Finding,
    kind: str,
    message: str = "",
    *,
    data: dict[str, Any] | None = None,
    actor_id: str | None = None,
) -> FindingEvent:
    event = FindingEvent(
        finding_id=finding.id, kind=kind, message=message, data=data or {}, actor_id=actor_id
    )
    db.add(event)
    return event


def get_or_create_asset(db: Session, project_id: str, ref: AssetRef) -> Asset:
    asset = db.scalar(
        select(Asset).where(
            Asset.project_id == project_id,
            Asset.type == ref.type,
            Asset.identifier == ref.identifier,
        )
    )
    now = utcnow()
    if asset is None:
        asset = Asset(
            project_id=project_id,
            type=ref.type,
            identifier=ref.identifier,
            name=ref.name or ref.identifier,
            attributes=ref.attributes,
        )
        db.add(asset)
        db.flush()
    else:
        asset.last_seen = now
        if ref.attributes:
            asset.attributes = {**(asset.attributes or {}), **ref.attributes}
        if ref.name:
            asset.name = ref.name
    return asset


def _apply_raw(finding: Finding, raw: RawFinding) -> None:
    finding.title = raw.title[:300]
    finding.category = raw.category[:120]
    finding.description = raw.description
    finding.impact = raw.impact
    finding.remediation = raw.remediation
    finding.cwe = raw.cwe
    finding.references = list(raw.references)
    finding.severity = raw.severity.value
    finding.confidence = raw.confidence.value
    finding.exploitability = raw.exploitability
    finding.exposure = raw.exposure
    finding.risk_score = compute_risk(
        raw.severity, raw.confidence, raw.exploitability, raw.exposure
    )
    finding.file_path = raw.file_path
    finding.line = raw.line
    finding.end_line = raw.end_line or raw.line
    finding.language = raw.language
    finding.code_context = raw.code_context[:_MAX_CONTEXT]
    finding.extra = raw.extra


def ingest_findings(
    db: Session,
    *,
    project_id: str,
    scan: Scan,
    scanner: str,
    raws: list[RawFinding],
    repository_id: str | None = None,
    complete: bool = True,
    resolve_scope: Any = None,
) -> IngestStats:
    """Persist ``raws`` for ``scanner`` and reconcile against previously known findings.

    ``resolve_scope`` optionally narrows which existing findings may be auto-resolved (a
    callable ``Finding -> bool``); by default every finding of the same scanner in the same
    repository/asset scope is eligible.
    """
    stats = IngestStats()
    now = utcnow()
    occurrences: Counter[str] = Counter()
    seen_ids: set[str] = set()

    for raw in raws:
        material = raw.fingerprint_material(scanner)
        fp = fingerprint(material, occurrences[material])
        occurrences[material] += 1

        asset = get_or_create_asset(db, project_id, raw.asset) if raw.asset else None
        finding = db.scalar(
            select(Finding).where(Finding.project_id == project_id, Finding.fingerprint == fp)
        )
        if finding is None:
            finding = Finding(
                project_id=project_id,
                repository_id=repository_id,
                asset_id=asset.id if asset else None,
                scan_id=scan.id,
                scanner=scanner,
                rule_id=raw.rule_id,
                fingerprint=fp,
                severity=raw.severity.value,
                first_seen=now,
                last_seen=now,
            )
            _apply_raw(finding, raw)
            db.add(finding)
            db.flush()
            add_event(
                db,
                finding,
                "detected",
                f"Detected by {scanner} ({raw.rule_id})",
                data={"scan_id": scan.id, "severity": raw.severity.value},
            )
            stats.new += 1
        else:
            _apply_raw(finding, raw)
            finding.last_seen = now
            finding.scan_id = scan.id
            if asset:
                finding.asset_id = asset.id
            if finding.status == FindingStatus.FIXED.value:
                finding.status = FindingStatus.OPEN.value
                finding.resolved_at = None
                finding.verification = VerificationState.NONE.value
                add_event(
                    db,
                    finding,
                    "reopened",
                    "Detected again after being marked fixed (regression)",
                    data={"scan_id": scan.id},
                )
                stats.reopened += 1
            else:
                stats.seen_again += 1
        seen_ids.add(finding.id)

    if complete:
        stats.resolved = _resolve_missing(
            db,
            project_id=project_id,
            scan=scan,
            scanner=scanner,
            repository_id=repository_id,
            seen_ids=seen_ids,
            in_scope=resolve_scope,
        )
    db.flush()
    return stats


def _resolve_missing(
    db: Session,
    *,
    project_id: str,
    scan: Scan,
    scanner: str,
    repository_id: str | None,
    seen_ids: set[str],
    in_scope: Any,
) -> int:
    query = select(Finding).where(
        Finding.project_id == project_id,
        Finding.scanner == scanner,
        Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
    )
    if repository_id:
        query = query.where(Finding.repository_id == repository_id)
    count = 0
    for finding in db.scalars(query):
        if finding.id in seen_ids or (in_scope is not None and not in_scope(finding)):
            continue
        finding.status = FindingStatus.FIXED.value
        finding.resolved_at = utcnow()
        add_event(
            db,
            finding,
            "resolved",
            "No longer detected by a complete rescan",
            data={"scan_id": scan.id},
        )
        count += 1
    return count


def set_status(
    db: Session,
    finding: Finding,
    new_status: FindingStatus,
    *,
    actor_id: str | None,
    note: str = "",
) -> None:
    old = finding.status
    if old == new_status.value:
        return
    finding.status = new_status.value
    finding.resolved_at = utcnow() if new_status == FindingStatus.FIXED else None
    add_event(
        db,
        finding,
        "status_changed",
        note or f"Status changed from {old} to {new_status.value}",
        data={"from": old, "to": new_status.value},
        actor_id=actor_id,
    )
