"""Authorized web API security scans."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.api.scans import ScanOut, load_scan
from netguard.config import get_settings
from netguard.core.audit import audit
from netguard.core.middleware import client_ip
from netguard.core.security import encrypt_secret
from netguard.core.targets import TargetError, resolve_target
from netguard.db import get_db, utcnow
from netguard.enums import ProjectRole
from netguard.models import Scan
from netguard.scanners.api.rules import RULES
from netguard.scanners.api.spec import SpecError, parse_spec
from netguard.services.scans import ScanRequestError, create_scan

router = APIRouter(tags=["api-scanner"])

AUTHORIZATION_TEXT = (
    "I confirm that I own this API or have explicit written authorization to test it. NetGuard sends "
    "read-only requests (GET/HEAD/OPTIONS) and never calls write endpoints, but it will generate "
    "traffic and some log noise against the target."
)
MAX_SPEC_CHARS = 2_000_000


class ApiScanRequest(BaseModel):
    project_id: str
    base_url: str = Field(min_length=8, max_length=500)
    spec: str | None = Field(default=None, max_length=MAX_SPEC_CHARS)
    auth_header_name: str = Field(default="Authorization", max_length=60, pattern=r"^[A-Za-z0-9\-]+$")
    auth_value: str | None = Field(default=None, max_length=4000)
    paths: list[str] = Field(default_factory=list, max_length=50)
    max_requests: int = Field(default=120, ge=10, le=300)
    authorized: bool = False
    authorization_statement: str = Field(default="", max_length=1000)


@router.get("/api/api-scanner/options")
def options(_: Principal = Depends(get_principal)) -> dict[str, Any]:
    s = get_settings()
    return {
        "authorization_text": AUTHORIZATION_TEXT,
        "public_targets_allowed": s.allow_public_targets,
        "safe_methods_only": True,
        "checks": sorted({r.title for r in RULES.values()}),
        "limitations": ["Object-level authorization (BOLA/IDOR) needs two identities and is not tested.",
                        "Write endpoints from the spec are analysed statically and never invoked."],
    }


@router.post("/api/api-scans", response_model=ScanOut, status_code=202)
def start_api_scan(
    body: ApiScanRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ScanOut:
    project = get_project_or_404(db, principal, body.project_id, ProjectRole.EDITOR)
    if not body.authorized or len(body.authorization_statement.strip()) < 20:
        raise HTTPException(status_code=422,
                            detail="You must confirm you are authorized to test this API before starting.")
    parts = urlsplit(body.base_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username \
            or parts.password or parts.query or parts.fragment:
        raise HTTPException(status_code=422,
                            detail="Base URL must be http(s)://host[:port][/path] without credentials or query")
    settings = get_settings()
    try:
        resolved = resolve_target(parts.hostname, allow_public=settings.allow_public_targets,
                                  max_hosts=settings.max_scan_hosts)
    except TargetError as exc:
        audit(db, "api.scan.denied", request=request, user_id=principal.user.id, target_type="project",
              target_id=project.id, details={"target": body.base_url[:150], "reason": str(exc)[:200]})
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if body.spec:
        try:
            parse_spec(body.spec)
        except SpecError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid OpenAPI spec: {exc}") from exc
    netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
    base_url = f"{parts.scheme}://{netloc}{parts.path.rstrip('/')}"
    config: dict[str, Any] = {
        "base_url": base_url, "ip": resolved.addresses[0], "spec_text": body.spec or "",
        "auth_header_name": body.auth_header_name,
        # Credentials are encrypted at rest; the worker decrypts them in memory for the sandbox.
        "auth_encrypted": encrypt_secret(body.auth_value) if body.auth_value else "",
        "paths": [p for p in body.paths if p.startswith("/")][:50], "max_requests": body.max_requests,
        "target_input": body.base_url,
        "authorization": {"statement": body.authorization_statement.strip()[:1000],
                          "by": principal.user.id, "at": utcnow().isoformat(), "ip": client_ip(request)},
    }
    try:
        scan = create_scan(db, project=project, scanners=["api"], kind="api", config=config,
                           user_id=principal.user.id, trigger="ci" if principal.api_token else "manual",
                           ref=base_url[:200])
    except ScanRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(db, "api.scan.start", request=request, user_id=principal.user.id, target_type="scan",
          target_id=scan.id, details={"target": base_url[:150], "authenticated": bool(body.auth_value),
                                      "spec_provided": bool(body.spec), "authorized": True})
    db.commit()
    return _out(scan)


def _out(scan: Scan) -> ScanOut:
    return ScanOut.model_validate(scan)


@router.get("/api/projects/{project_id}/api-scans", response_model=list[ScanOut])
def list_api_scans(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[ScanOut]:
    project = get_project_or_404(db, principal, project_id)
    rows = db.scalars(select(Scan).where(Scan.project_id == project.id, Scan.kind == "api")
                      .order_by(Scan.created_at.desc()).limit(100)).all()
    return [_out(s) for s in rows]


@router.get("/api/api-scans/{scan_id}")
def get_api_scan(
    scan_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    scan = load_scan(db, principal, scan_id)
    if scan.kind != "api":
        raise HTTPException(status_code=404, detail="Scan not found")
    cfg = scan.config or {}
    meta = ((scan.summary or {}).get("scanners", {}).get("api", {}) or {}).get("metadata", {})
    return {
        "scan": _out(scan).model_dump(mode="json"),
        "target": cfg.get("base_url", ""),
        "authenticated": bool(cfg.get("auth_encrypted")),
        "spec_provided": bool(cfg.get("spec_text")),
        "authorization": {k: v for k, v in (cfg.get("authorization") or {}).items() if k != "ip"},
        "checks": meta.get("checks", []),
        "requests_made": meta.get("requests_made"),
        "spec": meta.get("spec"),
        "warnings": ((scan.summary or {}).get("scanners", {}).get("api", {}) or {}).get("warnings", []),
    }
