"""Authorized network scanning API."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.api.scans import ScanOut, load_scan
from netguard.config import get_settings
from netguard.core.audit import audit
from netguard.core.middleware import client_ip
from netguard.core.targets import TargetError, parse_ports, resolve_target
from netguard.db import get_db, utcnow
from netguard.enums import ProjectRole
from netguard.models import Scan
from netguard.scanners.network.identify import TOP_PORTS
from netguard.scanners.network.scanner import SCAN_TYPES
from netguard.services import network as network_service
from netguard.services.scans import ScanRequestError, create_scan

router = APIRouter(tags=["network"])

AUTHORIZATION_TEXT = (
    "I confirm that I own the target systems or have explicit written authorization to assess them. "
    "I understand NetGuard sends network connection attempts to the targets."
)


class NetworkScanRequest(BaseModel):
    project_id: str
    target: str = Field(min_length=1, max_length=253)
    scan_type: str = "port_scan"
    ports: str | None = Field(default=None, max_length=500)
    timeout: float = Field(default=1.0, ge=0.2, le=5.0)
    authorized: bool = False
    authorization_statement: str = Field(default="", max_length=1000)


@router.get("/api/network/options")
def scan_options(_: Principal = Depends(get_principal)) -> dict[str, Any]:
    s = get_settings()
    return {
        "scan_types": [{"id": k, "description": v} for k, v in SCAN_TYPES.items()],
        "authorization_text": AUTHORIZATION_TEXT,
        "default_ports": TOP_PORTS,
        "max_hosts": s.max_scan_hosts,
        "max_ports": s.max_scan_ports,
        "public_targets_allowed": s.allow_public_targets,
    }


@router.post("/api/network/scans", response_model=ScanOut, status_code=202)
def start_network_scan(
    body: NetworkScanRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ScanOut:
    project = get_project_or_404(db, principal, body.project_id, ProjectRole.EDITOR)
    # The attestation is enforced server-side; the client cannot skip it.
    if not body.authorized or len(body.authorization_statement.strip()) < 20:
        raise HTTPException(
            status_code=422,
            detail="You must confirm you are authorized to scan this target before starting.",
        )
    if body.scan_type not in SCAN_TYPES:
        raise HTTPException(status_code=422, detail=f"Unknown scan type: {body.scan_type}")
    settings = get_settings()
    try:
        resolved = resolve_target(body.target, allow_public=settings.allow_public_targets,
                                  max_hosts=settings.max_scan_hosts)
        ports = parse_ports(body.ports, max_ports=settings.max_scan_ports, default=TOP_PORTS)
    except TargetError as exc:
        audit(db, "network.scan.denied", request=request, user_id=principal.user.id,
              target_type="project", target_id=project.id, details={"target": body.target[:100],
                                                                    "reason": str(exc)[:200]})
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    config = {
        "scan_type": body.scan_type, "targets": resolved.addresses, "ports": ports,
        "timeout": body.timeout, "hostname": resolved.hostname, "target_input": body.target,
        "authorization": {"statement": body.authorization_statement.strip()[:1000],
                          "by": principal.user.id, "at": utcnow().isoformat(),
                          "ip": client_ip(request)},
    }
    try:
        scan = create_scan(db, project=project, scanners=["network"], kind="network", config=config,
                           user_id=principal.user.id,
                           trigger="ci" if principal.api_token else "manual", ref=body.target[:200])
    except ScanRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(db, "network.scan.start", request=request, user_id=principal.user.id,
          target_type="scan", target_id=scan.id,
          details={"target": body.target[:100], "hosts": len(resolved.addresses),
                   "scan_type": body.scan_type, "authorized": True})
    db.commit()
    return ScanOut.model_validate(scan)


@router.get("/api/projects/{project_id}/network/scans", response_model=list[ScanOut])
def list_network_scans(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[ScanOut]:
    project = get_project_or_404(db, principal, project_id)
    rows = db.scalars(select(Scan).where(Scan.project_id == project.id, Scan.kind == "network")
                      .order_by(Scan.created_at.desc()).limit(100)).all()
    return [ScanOut.model_validate(s) for s in rows]


@router.get("/api/network/scans/{scan_id}")
def get_network_scan(
    scan_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    scan = _load(db, principal, scan_id)
    cfg = scan.config or {}
    return {
        "scan": ScanOut.model_validate(scan).model_dump(mode="json"),
        "target": cfg.get("target_input", ""),
        "scan_type": cfg.get("scan_type", ""),
        "authorization": {k: v for k, v in (cfg.get("authorization") or {}).items() if k != "ip"},
        "hosts": network_service.scan_hosts(db, scan.id),
    }


def _load(db: Session, principal: Principal, scan_id: str) -> Scan:
    scan = load_scan(db, principal, scan_id)
    if scan.kind != "network":
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/api/network/scans/{scan_id}/export")
def export_network_scan(
    scan_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Response:
    scan = _load(db, principal, scan_id)
    hosts = network_service.scan_hosts(db, scan.id)
    if format == "csv":
        return Response(network_service.export_csv(hosts), media_type="text/csv", headers={
            "Content-Disposition": f'attachment; filename="netguard-scan-{scan.id[:8]}.csv"'})
    payload = {"scan_id": scan.id, "target": (scan.config or {}).get("target_input"),
               "scan_type": (scan.config or {}).get("scan_type"), "status": scan.status,
               "started_at": scan.started_at, "finished_at": scan.finished_at, "hosts": hosts}
    return Response(json.dumps(payload, indent=2, default=str), media_type="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename="netguard-scan-{scan.id[:8]}.json"'})


@router.get("/api/projects/{project_id}/network/hosts")
def network_inventory(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    project = get_project_or_404(db, principal, project_id)
    return network_service.latest_inventory(db, project.id)


@router.get("/api/projects/{project_id}/network/map")
def network_map(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    project = get_project_or_404(db, principal, project_id)
    return network_service.topology(db, project.id)
