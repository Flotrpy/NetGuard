"""Packet analyzer API: import captures, browse packets, statistics, export."""

from __future__ import annotations

import hashlib
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.config import get_settings
from netguard.core.audit import audit
from netguard.db import get_db, new_id
from netguard.enums import ProjectRole
from netguard.models import PacketCapture, Scan
from netguard.scanners.packets.pcap import PcapError, detect_format
from netguard.services import packets as packet_service
from netguard.services.scans import ScanRequestError, create_scan

router = APIRouter(tags=["packets"])

PRIVACY_TEXT = (
    "I confirm that I am authorized to capture and analyze this traffic and that it does not "
    "contain data I am not permitted to inspect. Payload contents are not displayed; credentials "
    "seen in cleartext are flagged but never stored."
)


class CaptureOut(BaseModel):
    id: str
    project_id: str
    filename: str
    size_bytes: int
    packet_count: int
    sha256: str
    created_at: datetime
    scan_id: str | None = None
    scan_status: str | None = None
    summary: dict[str, Any] = {}


def _out(db: Session, c: PacketCapture, summary: bool = False) -> CaptureOut:
    scan = None
    for s in db.scalars(select(Scan).where(Scan.kind == "packets", Scan.project_id == c.project_id)
                        .order_by(Scan.created_at.desc()).limit(50)):
        if (s.config or {}).get("capture_id") == c.id:
            scan = s
            break
    return CaptureOut(
        id=c.id, project_id=c.project_id, filename=c.filename, size_bytes=c.size_bytes,
        packet_count=c.packet_count, sha256=c.sha256, created_at=c.created_at,
        scan_id=scan.id if scan else None, scan_status=scan.status if scan else None,
        summary=c.summary if summary else {},
    )


def _load(db: Session, principal: Principal, capture_id: str, role=ProjectRole.VIEWER) -> PacketCapture:
    c = db.get(PacketCapture, capture_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    get_project_or_404(db, principal, c.project_id, role)
    return c


@router.get("/api/packet-analysis/capabilities")
def capabilities(_: Principal = Depends(get_principal)) -> dict[str, Any]:
    s = get_settings()
    return {
        "import": {"available": True, "formats": ["pcap", "pcapng"], "max_mb": s.max_pcap_mb,
                   "max_packets": s.max_pcap_packets},
        "live_capture": {
            "available": False,
            "reason": "Live capture needs raw-socket privileges and a capture driver (libpcap/"
                      "Npcap), which this deployment does not provide. Capture with tcpdump or "
                      "Wireshark on the network you are authorized to monitor, then import the file.",
        },
        "authorization_text": PRIVACY_TEXT,
    }


@router.post("/api/packet-analysis", response_model=CaptureOut, status_code=202)
async def import_capture(
    request: Request,
    project_id: str = Form(...),
    authorized: bool = Form(False),
    authorization_statement: str = Form("", max_length=1000),
    file: UploadFile = File(...),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> CaptureOut:
    project = get_project_or_404(db, principal, project_id, ProjectRole.EDITOR)
    if not authorized or len(authorization_statement.strip()) < 20:
        raise HTTPException(status_code=422,
                            detail="You must confirm you are authorized to analyze this traffic.")
    settings = get_settings()
    (settings.uploads_dir / "captures").mkdir(parents=True, exist_ok=True)
    rel = f"captures/{new_id()}.cap"  # server-chosen name
    dest, size, digest = settings.uploads_dir / rel, 0, hashlib.sha256()
    limit = settings.max_pcap_mb * 1024 * 1024
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"Capture exceeds {settings.max_pcap_mb} MB")
                digest.update(chunk)
                out.write(chunk)
        with open(dest, "rb") as fh:
            try:
                detect_format(fh.read(4))  # cheap magic check; full parsing happens in the sandbox
            except PcapError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
        capture = PacketCapture(
            project_id=project.id, filename=(file.filename or "capture")[:300], stored_path=rel,
            sha256=digest.hexdigest(), size_bytes=size,
            authorization=authorization_statement.strip()[:1000], created_by=principal.user.id,
        )
        db.add(capture)
        db.flush()
        scan = create_scan(
            db, project=project, scanners=["packets"], kind="packets",
            config={"pcap_path": rel, "capture_id": capture.id}, user_id=principal.user.id,
            trigger="ci" if principal.api_token else "manual", ref=capture.filename[:200])
    except (HTTPException, ScanRequestError) as exc:
        dest.unlink(missing_ok=True)
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(db, "packets.import", request=request, user_id=principal.user.id,
          target_type="capture", target_id=capture.id,
          details={"bytes": size, "sha256": capture.sha256[:16], "authorized": True})
    db.commit()
    out = _out(db, capture)
    out.scan_id, out.scan_status = scan.id, scan.status
    return out


@router.get("/api/projects/{project_id}/packet-captures", response_model=list[CaptureOut])
def list_captures(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[CaptureOut]:
    project = get_project_or_404(db, principal, project_id)
    rows = db.scalars(select(PacketCapture).where(PacketCapture.project_id == project.id)
                      .order_by(PacketCapture.created_at.desc())).all()
    return [_out(db, c) for c in rows]


@router.get("/api/packet-captures/{capture_id}", response_model=CaptureOut)
def get_capture(
    capture_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> CaptureOut:
    return _out(db, _load(db, principal, capture_id), summary=True)


@router.get("/api/packet-captures/{capture_id}/packets")
def list_packets(
    capture_id: str,
    protocol: str = Query("", max_length=100),
    q: str = Query("", max_length=200),
    ip: str = Query("", max_length=64),
    port: int | None = Query(None, ge=0, le=65535),
    min_size: int | None = Query(None, ge=0),
    max_size: int | None = Query(None, ge=0),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    c = _load(db, principal, capture_id)
    total, items = packet_service.query(c, protocol=protocol, q=q, ip=ip, port=port,
                                        min_size=min_size, max_size=max_size, offset=offset, limit=limit)
    return {"total": total, "items": items}


@router.get("/api/packet-captures/{capture_id}/packets/{n}")
def packet_detail(
    capture_id: str, n: int, principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    c = _load(db, principal, capture_id)
    detail = packet_service.packet_detail(c, n)
    if detail is None:
        raise HTTPException(status_code=404, detail="Packet not found")
    return detail


@router.get("/api/packet-captures/{capture_id}/export")
def export_capture(
    capture_id: str,
    protocol: str = Query("", max_length=100),
    q: str = Query("", max_length=200),
    ip: str = Query("", max_length=64),
    port: int | None = Query(None, ge=0, le=65535),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> Response:
    """Export the (optionally filtered) packets as a classic pcap file."""
    c = _load(db, principal, capture_id)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "export.pcap"
        n = packet_service.export_filtered(c, out, protocol=protocol, q=q, ip=ip, port=port)
        if n == 0:
            raise HTTPException(status_code=404, detail="No packets match the filter")
        data = out.read_bytes()
    return Response(data, media_type="application/vnd.tcpdump.pcap", headers={
        "Content-Disposition": f'attachment; filename="netguard-{c.id[:8]}-filtered.pcap"'})


@router.delete("/api/packet-captures/{capture_id}", status_code=204)
def delete_capture(
    capture_id: str, request: Request, principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> None:
    """Delete the stored capture and its index (privacy: captures are not kept longer than needed)."""
    c = _load(db, principal, capture_id, ProjectRole.EDITOR)
    packet_service.delete_capture_files(c)
    audit(db, "packets.delete", request=request, user_id=principal.user.id,
          target_type="capture", target_id=c.id)
    db.delete(c)
    db.commit()
