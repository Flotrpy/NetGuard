"""SBOM export (CycloneDX / SPDX) for a repository's latest snapshot."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal
from netguard.api.repositories import load_repository
from netguard.db import get_db
from netguard.enums import ACTIVE_STATUSES, ProjectRole
from netguard.models import Finding, Project, Snapshot
from netguard.scanners.dependencies.scanner import inventory
from netguard.services import sbom
from netguard.services.snapshots import snapshot_root

router = APIRouter(tags=["sbom"])


def build_sbom(db: Session, repo_id: str, principal: Principal, fmt: str) -> tuple[dict, str]:
    repo = load_repository(db, principal, repo_id, ProjectRole.VIEWER)
    snap = db.scalar(select(Snapshot).where(Snapshot.repository_id == repo.id)
                     .order_by(Snapshot.created_at.desc()).limit(1))
    if snap is None:
        raise HTTPException(status_code=409, detail="Upload code for this repository first")
    packages, warnings, manifests = inventory(snapshot_root(snap))
    if not packages:
        raise HTTPException(status_code=422,
                            detail="No dependency manifests with exact versions were found")
    project = db.get(Project, repo.project_id)
    name = f"{project.name}/{repo.name}"
    if fmt == "spdx":
        return sbom.spdx(packages, project_name=name), "spdx.json"
    findings = db.scalars(select(Finding).where(
        Finding.repository_id == repo.id, Finding.scanner == "dependencies",
        Finding.status.in_([s.value for s in ACTIVE_STATUSES]))).all()
    return sbom.cyclonedx(packages, project_name=name,
                          vulnerabilities=sbom.vulnerabilities_from_findings(list(findings))), \
        "cdx.json"


@router.get("/api/repositories/{repo_id}/sbom")
def download_sbom(
    repo_id: str,
    format: str = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Response:
    doc, suffix = build_sbom(db, repo_id, principal, format)
    return Response(
        content=json.dumps(doc, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="sbom-{repo_id[:8]}.{suffix}"'},
    )
