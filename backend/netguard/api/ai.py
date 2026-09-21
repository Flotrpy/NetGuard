"""AI endpoints: explain a finding, generate / apply / validate fixes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal
from netguard.api.findings import load_finding
from netguard.core.audit import audit
from netguard.db import get_db
from netguard.enums import ProjectRole
from netguard.services.ai import explain as explain_service
from netguard.services.findings import add_event

router = APIRouter(tags=["ai"])


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
