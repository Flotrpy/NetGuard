"""Findings: the unified list, detail, triage and history endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session

from netguard.api.deps import (
    Principal,
    accessible_project_ids,
    get_principal,
    get_project_or_404,
)
from netguard.core.audit import audit
from netguard.db import get_db
from netguard.enums import DETECTION_SOURCE_LABELS, FindingStatus, ProjectRole, Scanner, Severity
from netguard.models import Asset, Finding, FindingEvent
from netguard.services.findings import add_event, set_status
from netguard.services.risk import METHODOLOGY

router = APIRouter(tags=["findings"])

_SEVERITY_ORDER = case(
    (Finding.severity == "critical", 4),
    (Finding.severity == "high", 3),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 1),
    else_=0,
)
_SORTS = {
    "severity": _SEVERITY_ORDER,
    "risk": Finding.risk_score,
    "last_seen": Finding.last_seen,
    "first_seen": Finding.first_seen,
    "file": Finding.file_path,
    "status": Finding.status,
    "scanner": Finding.scanner,
    "title": Finding.title,
}


class FindingOut(BaseModel):
    id: str
    project_id: str
    repository_id: str | None
    asset_id: str | None
    asset: str | None = None
    scanner: str
    detection_source: str
    rule_id: str
    title: str
    category: str
    cwe: str
    severity: str
    confidence: str
    exploitability: str
    exposure: str
    risk_score: float
    file_path: str
    line: int
    language: str
    status: str
    verification: str
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None


class EventOut(BaseModel):
    id: str
    kind: str
    message: str
    data: dict[str, Any]
    actor_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingDetail(FindingOut):
    description: str
    impact: str
    remediation: str
    references: list[str]
    end_line: int
    code_context: str
    extra: dict[str, Any]
    events: list[EventOut]


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int


class StatusUpdate(BaseModel):
    status: FindingStatus
    note: str = Field(default="", max_length=2000)


class CommentIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


def to_out(f: Finding, asset_name: str | None = None) -> FindingOut:
    try:
        source = DETECTION_SOURCE_LABELS[Scanner(f.scanner)]
    except ValueError:
        source = f.scanner
    return FindingOut(
        id=f.id,
        project_id=f.project_id,
        repository_id=f.repository_id,
        asset_id=f.asset_id,
        asset=asset_name,
        scanner=f.scanner,
        detection_source=source,
        rule_id=f.rule_id,
        title=f.title,
        category=f.category,
        cwe=f.cwe,
        severity=f.severity,
        confidence=f.confidence,
        exploitability=f.exploitability,
        exposure=f.exposure,
        risk_score=f.risk_score,
        file_path=f.file_path,
        line=f.line,
        language=f.language,
        status=f.status,
        verification=f.verification,
        first_seen=f.first_seen,
        last_seen=f.last_seen,
        resolved_at=f.resolved_at,
    )


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def filtered_query(
    db: Session,
    principal: Principal,
    *,
    project_id: str | None,
    severity: str | None = None,
    scanner: str | None = None,
    status: str | None = None,
    language: str | None = None,
    category: str | None = None,
    file: str | None = None,
    q: str | None = None,
    repository_id: str | None = None,
    asset_id: str | None = None,
    min_confidence: str | None = None,
) -> Select:
    if project_id:
        get_project_or_404(db, principal, project_id)
        project_ids = [project_id]
    else:
        project_ids = accessible_project_ids(db, principal)
    query = select(Finding).where(Finding.project_id.in_(project_ids or [""]))
    for column, raw in (
        (Finding.severity, severity),
        (Finding.scanner, scanner),
        (Finding.status, status),
        (Finding.language, language),
        (Finding.category, category),
    ):
        values = _csv(raw)
        if values:
            query = query.where(column.in_(values))
    if file:
        query = query.where(Finding.file_path.ilike(f"%{file}%"))
    if repository_id:
        query = query.where(Finding.repository_id == repository_id)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if min_confidence:
        allowed = {"low": ["low", "medium", "high"], "medium": ["medium", "high"], "high": ["high"]}
        query = query.where(Finding.confidence.in_(allowed.get(min_confidence, [])))
    if q:
        like = f"%{q}%"
        query = query.where(
            or_(
                Finding.title.ilike(like),
                Finding.file_path.ilike(like),
                Finding.rule_id.ilike(like),
                Finding.cwe.ilike(like),
                Finding.description.ilike(like),
            )
        )
    return query


@router.get("/api/findings", response_model=FindingPage)
def list_findings(
    project_id: str | None = None,
    severity: str | None = Query(None, description="comma-separated"),
    scanner: str | None = None,
    status: str | None = None,
    language: str | None = None,
    category: str | None = None,
    file: str | None = None,
    q: str | None = None,
    repository_id: str | None = None,
    asset_id: str | None = None,
    min_confidence: str | None = None,
    sort: str = "severity",
    order: str = "desc",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> FindingPage:
    for value in _csv(severity):
        if value not in {s.value for s in Severity}:
            raise HTTPException(status_code=422, detail=f"Invalid severity: {value}")
    for value in _csv(status):
        if value not in {s.value for s in FindingStatus}:
            raise HTTPException(status_code=422, detail=f"Invalid status: {value}")
    if sort not in _SORTS:
        raise HTTPException(status_code=422, detail=f"Cannot sort by {sort}")
    query = filtered_query(
        db,
        principal,
        project_id=project_id,
        severity=severity,
        scanner=scanner,
        status=status,
        language=language,
        category=category,
        file=file,
        q=q,
        repository_id=repository_id,
        asset_id=asset_id,
        min_confidence=min_confidence,
    )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    column = _SORTS[sort]
    ordering = column.desc() if order == "desc" else column.asc()
    rows = db.scalars(
        query.order_by(ordering, Finding.risk_score.desc(), Finding.id).limit(limit).offset(offset)
    ).all()
    asset_ids = {f.asset_id for f in rows if f.asset_id}
    names = (
        {a.id: a.name for a in db.scalars(select(Asset).where(Asset.id.in_(asset_ids)))}
        if asset_ids
        else {}
    )
    return FindingPage(items=[to_out(f, names.get(f.asset_id)) for f in rows], total=total)


@router.get("/api/findings/facets")
def finding_facets(
    project_id: str | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, list[str]]:
    """Distinct values for the filter dropdowns."""
    base = filtered_query(db, principal, project_id=project_id).subquery()
    out: dict[str, list[str]] = {}
    for key in ("language", "category", "scanner", "status", "severity"):
        col = getattr(base.c, key)
        out[key] = sorted(v for v in db.scalars(select(col).distinct()) if v)
    return out


@router.get("/api/risk/methodology")
def risk_methodology(_: Principal = Depends(get_principal)) -> dict[str, Any]:
    return METHODOLOGY


def load_finding(
    db: Session, principal: Principal, finding_id: str, role: ProjectRole = ProjectRole.VIEWER
) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    get_project_or_404(db, principal, finding.project_id, role)
    return finding


def _detail(db: Session, f: Finding) -> FindingDetail:
    asset = db.get(Asset, f.asset_id) if f.asset_id else None
    base = to_out(f, asset.name if asset else None).model_dump()
    events = db.scalars(
        select(FindingEvent)
        .where(FindingEvent.finding_id == f.id)
        .order_by(FindingEvent.created_at, FindingEvent.id)
    ).all()
    return FindingDetail(
        **base,
        description=f.description,
        impact=f.impact,
        remediation=f.remediation,
        references=list(f.references or []),
        end_line=f.end_line,
        code_context=f.code_context,
        extra=f.extra or {},
        events=[EventOut.model_validate(e) for e in events],
    )


@router.get("/api/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> FindingDetail:
    return _detail(db, load_finding(db, principal, finding_id))


@router.patch("/api/findings/{finding_id}", response_model=FindingDetail)
def update_finding_status(
    finding_id: str,
    body: StatusUpdate,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> FindingDetail:
    finding = load_finding(db, principal, finding_id, ProjectRole.EDITOR)
    set_status(db, finding, body.status, actor_id=principal.user.id, note=body.note)
    audit(
        db,
        "finding.status",
        request=request,
        user_id=principal.user.id,
        target_type="finding",
        target_id=finding.id,
        details={"status": body.status.value},
    )
    db.commit()
    return _detail(db, finding)


@router.post("/api/findings/{finding_id}/comments", response_model=FindingDetail, status_code=201)
def add_comment(
    finding_id: str,
    body: CommentIn,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> FindingDetail:
    finding = load_finding(db, principal, finding_id, ProjectRole.EDITOR)
    add_event(db, finding, "comment", body.message.strip(), actor_id=principal.user.id)
    db.commit()
    return _detail(db, finding)
