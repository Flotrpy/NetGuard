"""Security report generation for a project (HTML, PDF, JSON, CSV)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.db import get_db
from netguard.enums import ProjectRole
from netguard.services.reports import FORMATS, RENDERERS, build_report_data

router = APIRouter(tags=["reports"])


@router.get("/api/projects/{project_id}/report")
def download_report(
    project_id: str,
    format: str = Query("html", pattern="^(html|pdf|json|csv)$"),
    title: str = "",
    min_severity: str = Query("info", pattern="^(critical|high|medium|low|info)$"),
    scanners: str | None = None,
    include_fixed: bool = True,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Response:
    if format not in FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of {', '.join(FORMATS)}")
    project = get_project_or_404(db, principal, project_id, ProjectRole.VIEWER)
    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()] if scanners else None
    data = build_report_data(
        db, project, title=title, min_severity=min_severity,
        scanners=scanner_list, include_fixed=include_fixed,
    )
    render, media_type = RENDERERS[format]
    body = render(data)
    suffix = {"html": "html", "pdf": "pdf", "json": "json", "csv": "csv"}[format]
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="report-{project_id[:8]}.{suffix}"'},
    )
