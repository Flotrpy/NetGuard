"""Scans: start, monitor, cancel and list scan history."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.core.audit import audit
from netguard.db import get_db
from netguard.enums import ProjectRole, ScanStatus
from netguard.models import Repository, Scan, Snapshot
from netguard.scanners.registry import scanner_infos
from netguard.services.scans import ScanRequestError, create_scan

router = APIRouter(tags=["scans"])

_TERMINAL = {
    ScanStatus.COMPLETED.value,
    ScanStatus.PARTIAL.value,
    ScanStatus.FAILED.value,
    ScanStatus.CANCELLED.value,
}


class ScanCreate(BaseModel):
    scanners: list[str] = Field(min_length=1, max_length=16)
    repository_id: str | None = None
    snapshot_id: str | None = None  # defaults to the repository's latest snapshot


class ScanOut(BaseModel):
    id: str
    project_id: str
    repository_id: str | None
    snapshot_id: str | None
    kind: str
    scanners: list[str]
    status: str
    progress: dict[str, Any]
    summary: dict[str, Any]
    trigger: str
    ref: str
    error: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None

    model_config = {"from_attributes": True}


class ScannerOut(BaseModel):
    name: str
    display_name: str
    version: str
    description: str
    supported_inputs: list[str]
    available: bool
    status_note: str


@router.get("/api/scanners", response_model=list[ScannerOut])
def list_scanners(_: Principal = Depends(get_principal)) -> list[ScannerOut]:
    """Every scanner module, with honest availability (planned scanners are marked)."""
    return [
        ScannerOut(**{**i.__dict__, "supported_inputs": list(i.supported_inputs)})
        for i in scanner_infos()
    ]


@router.post("/api/projects/{project_id}/scans", response_model=ScanOut, status_code=202)
def start_scan(
    project_id: str,
    body: ScanCreate,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ScanOut:
    project = get_project_or_404(db, principal, project_id, ProjectRole.EDITOR)
    repo = snapshot = None
    if body.repository_id:
        repo = db.get(Repository, body.repository_id)
        if repo is None or repo.project_id != project.id:
            raise HTTPException(status_code=404, detail="Repository not found")
        if body.snapshot_id:
            snapshot = db.get(Snapshot, body.snapshot_id)
            if snapshot is None or snapshot.repository_id != repo.id:
                raise HTTPException(status_code=404, detail="Snapshot not found")
        else:
            snapshot = db.scalar(
                select(Snapshot)
                .where(Snapshot.repository_id == repo.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
    try:
        scan = create_scan(
            db,
            project=project,
            scanners=body.scanners,
            kind="code",
            repository=repo,
            snapshot=snapshot,
            user_id=principal.user.id,
            trigger="ci" if principal.api_token else "manual",
        )
    except ScanRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(
        db,
        "scan.start",
        request=request,
        user_id=principal.user.id,
        target_type="scan",
        target_id=scan.id,
        details={"scanners": scan.scanners},
    )
    db.commit()
    return ScanOut.model_validate(scan)


def load_scan(db: Session, principal: Principal, scan_id: str, role=ProjectRole.VIEWER) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    get_project_or_404(db, principal, scan.project_id, role)
    return scan


@router.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> ScanOut:
    return ScanOut.model_validate(load_scan(db, principal, scan_id))


@router.post("/api/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ScanOut:
    scan = load_scan(db, principal, scan_id, ProjectRole.EDITOR)
    if scan.status in _TERMINAL:
        raise HTTPException(status_code=409, detail=f"Scan already {scan.status}")
    scan.status = ScanStatus.CANCELLED.value
    audit(
        db,
        "scan.cancel",
        request=request,
        user_id=principal.user.id,
        target_type="scan",
        target_id=scan.id,
    )
    db.commit()
    return ScanOut.model_validate(scan)


@router.get("/api/projects/{project_id}/scans", response_model=list[ScanOut])
def list_scans(
    project_id: str,
    limit: int = 50,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> list[ScanOut]:
    project = get_project_or_404(db, principal, project_id)
    limit = max(1, min(limit, 200))
    scans = db.scalars(
        select(Scan)
        .where(Scan.project_id == project.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    return [ScanOut.model_validate(s) for s in scans]
