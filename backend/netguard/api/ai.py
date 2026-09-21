"""AI endpoints: explain a finding, generate / apply / validate fixes."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404
from netguard.api.findings import load_finding
from netguard.core.audit import audit
from netguard.db import get_db
from netguard.enums import ProjectRole
from netguard.models import Finding, Patch
from netguard.services import patches as patch_service
from netguard.services.ai import explain as explain_service
from netguard.services.findings import add_event

router = APIRouter(tags=["ai"])


class PatchOut(BaseModel):
    id: str
    finding_id: str
    status: str
    generator: str
    explanation: str
    diff: str
    file_path: str
    caveats: list[str]
    verification: dict[str, Any]
    applied_snapshot_id: str | None
    created_at: datetime
    applied_at: datetime | None

    model_config = {"from_attributes": True}


class FixRequest(BaseModel):
    use_ai: bool = True


class ValidateRequest(BaseModel):
    patch_id: str | None = None


def _load_patch(
    db: Session, principal: Principal, patch_id: str, role: ProjectRole
) -> tuple[Patch, Finding]:
    patch = db.get(Patch, patch_id)
    finding = db.get(Finding, patch.finding_id) if patch else None
    if patch is None or finding is None:
        raise HTTPException(status_code=404, detail="Patch not found")
    get_project_or_404(db, principal, finding.project_id, role)
    return patch, finding


def _patch_error(exc: patch_service.PatchError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


class ExplainRequest(BaseModel):
    audience: str = "beginner"  # beginner | advanced
    refresh: bool = False
    use_ai: bool = True


@router.post("/api/findings/{finding_id}/explain")
def explain_finding(
    finding_id: str,
    request: Request,
    body: ExplainRequest | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    body = body or ExplainRequest()
    finding = load_finding(db, principal, finding_id, ProjectRole.VIEWER)
    audience = body.audience if body.audience in ("beginner", "advanced") else "beginner"
    cache = dict((finding.extra or {}).get("explanations", {}))
    if body.use_ai and not body.refresh and audience in cache:
        return {**cache[audience], "cached": True}
    result = explain_service.explain(finding, audience=audience, use_ai=body.use_ai)
    if result["source"] == "ai":  # only cache successful AI output (it costs money to produce)
        cache[audience] = result
        finding.extra = {**(finding.extra or {}), "explanations": cache}
        add_event(db, finding, "explained", f"AI explanation generated ({audience})",
                  data={"model": result["model"]}, actor_id=principal.user.id)
        audit(db, "finding.explain", request=request, user_id=principal.user.id,
              target_type="finding", target_id=finding.id)
        db.commit()
    return {**result, "cached": False}


@router.post("/api/findings/{finding_id}/generate-fix", response_model=PatchOut, status_code=201)
def generate_fix(
    finding_id: str,
    request: Request,
    body: FixRequest | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> PatchOut:
    """Propose a patch. Nothing is changed: the diff must be reviewed and applied explicitly."""
    finding = load_finding(db, principal, finding_id, ProjectRole.EDITOR)
    try:
        patch = patch_service.generate_patch(
            db, finding, user_id=principal.user.id, use_ai=(body or FixRequest()).use_ai
        )
    except patch_service.PatchError as exc:
        raise _patch_error(exc) from exc
    audit(db, "patch.generate", request=request, user_id=principal.user.id,
          target_type="patch", target_id=patch.id, details={"generator": patch.generator})
    db.commit()
    return PatchOut.model_validate(patch)


@router.get("/api/findings/{finding_id}/patches", response_model=list[PatchOut])
def list_patches(
    finding_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[PatchOut]:
    finding = load_finding(db, principal, finding_id, ProjectRole.VIEWER)
    rows = db.scalars(
        select(Patch).where(Patch.finding_id == finding.id).order_by(Patch.created_at.desc())
    ).all()
    return [PatchOut.model_validate(p) for p in rows]


@router.get("/api/patches/{patch_id}", response_model=PatchOut)
def get_patch(
    patch_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> PatchOut:
    patch, _ = _load_patch(db, principal, patch_id, ProjectRole.VIEWER)
    return PatchOut.model_validate(patch)


@router.post("/api/patches/{patch_id}/apply", response_model=PatchOut)
def apply_patch(
    patch_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> PatchOut:
    """Apply a reviewed patch to a NEW snapshot (the original snapshot is never modified)."""
    patch, finding = _load_patch(db, principal, patch_id, ProjectRole.EDITOR)
    try:
        patch_service.apply_patch(db, patch, finding, user_id=principal.user.id)
    except patch_service.PatchError as exc:
        raise _patch_error(exc) from exc
    audit(db, "patch.apply", request=request, user_id=principal.user.id,
          target_type="patch", target_id=patch.id)
    db.commit()
    return PatchOut.model_validate(patch)


@router.post("/api/patches/{patch_id}/reject", response_model=PatchOut)
def reject_patch(
    patch_id: str,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> PatchOut:
    patch, finding = _load_patch(db, principal, patch_id, ProjectRole.EDITOR)
    if patch.status != "proposed":
        raise HTTPException(status_code=409, detail=f"Patch is already {patch.status}")
    patch.status = "rejected"
    add_event(db, finding, "patch_rejected", "Proposed patch rejected", actor_id=principal.user.id,
              data={"patch_id": patch.id})
    db.commit()
    return PatchOut.model_validate(patch)


@router.post("/api/findings/{finding_id}/validate", status_code=202)
def validate_finding(
    finding_id: str,
    request: Request,
    body: ValidateRequest | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue a rescan whose result decides: verified fixed / still detected / unable to verify."""
    finding = load_finding(db, principal, finding_id, ProjectRole.EDITOR)
    patch = None
    patch_id = (body or ValidateRequest()).patch_id
    if patch_id:
        patch, owner = _load_patch(db, principal, patch_id, ProjectRole.EDITOR)
        if owner.id != finding.id:
            raise HTTPException(status_code=404, detail="Patch not found")
        if patch.status != "applied":
            raise HTTPException(status_code=409, detail="Apply the patch before verifying it")
    else:
        patch = db.scalar(
            select(Patch).where(Patch.finding_id == finding.id, Patch.status == "applied")
            .order_by(Patch.applied_at.desc()).limit(1)
        )
    try:
        scan = patch_service.request_verification(
            db, finding, patch, user_id=principal.user.id
        )
    except patch_service.PatchError as exc:
        raise _patch_error(exc) from exc
    audit(db, "finding.validate", request=request, user_id=principal.user.id,
          target_type="finding", target_id=finding.id)
    db.commit()
    return {"scan_id": scan.id, "status": scan.status, "patch_id": patch.id if patch else None}

