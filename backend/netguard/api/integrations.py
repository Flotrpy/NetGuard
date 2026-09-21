"""Provider integrations, CI tokens, security policy, and webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import (
    API_TOKEN_PREFIX,
    Principal,
    get_principal,
    get_project_or_404,
    require_user_session,
)
from netguard.api.repositories import RepositoryOut, load_repository, repository_out
from netguard.api.scans import ScanOut, load_scan
from netguard.core.audit import audit
from netguard.core.security import constant_time_equals, decrypt_secret, generate_token, hash_token
from netguard.db import get_db
from netguard.enums import ProjectRole
from netguard.logging import get_logger
from netguard.models import ApiToken, Repository
from netguard.services import integrations
from netguard.services.gate import gate_for_scan, load_policy
from netguard.services.policy import Policy
from netguard.services.providers import ProviderError
from netguard.services.scans import ScanRequestError

router = APIRouter(tags=["integrations"])
log = get_logger("webhooks")
MAX_WEBHOOK_BYTES = 1024 * 1024


class ConnectRequest(BaseModel):
    provider: str = Field(pattern="^(github|gitlab)$")
    external_id: str = Field(min_length=1, max_length=200)  # "owner/repo" or GitLab id/path
    token: str = Field(min_length=8, max_length=500)


class ConnectResponse(BaseModel):
    repository: RepositoryOut
    webhook_path: str
    webhook_secret: str  # shown once
    note: str


class RepoScanRequest(BaseModel):
    ref: str | None = None
    scanners: list[str] | None = None


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=lambda: ["read", "write"])
    expires_days: int | None = Field(default=None, ge=1, le=3650)


class TokenOut(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    last_used: datetime | None
    expires_at: datetime | None
    revoked: bool


@router.post(
    "/api/projects/{project_id}/repositories/connect",
    response_model=ConnectResponse,
    status_code=201,
)
def connect_repository(
    project_id: str,
    body: ConnectRequest,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> ConnectResponse:
    """Connect a GitHub/GitLab repository you are authorized to access (token stays encrypted)."""
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    try:
        repo, secret = integrations.connect_repository(
            db,
            project,
            provider=body.provider,
            external_id=body.external_id.strip(),
            token=body.token.strip(),
        )
    except ProviderError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(
        db,
        "repository.connect",
        request=request,
        user_id=principal.user.id,
        target_type="repository",
        target_id=repo.id,
        details={"provider": body.provider},
    )
    db.commit()
    return ConnectResponse(
        repository=repository_out(db, repo),
        webhook_path=f"/api/webhooks/{body.provider}",
        webhook_secret=secret,
        note="Add this URL and secret as a webhook (push + pull request events). "
        "The secret is not shown again.",
    )


@router.post("/api/repositories/{repo_id}/scan", response_model=ScanOut, status_code=202)
def scan_repository_ref(
    repo_id: str,
    request: Request,
    body: RepoScanRequest | None = None,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> ScanOut:
    repo = load_repository(db, principal, repo_id, ProjectRole.EDITOR)
    body = body or RepoScanRequest()
    try:
        scan = integrations.queue_repo_scan(
            db,
            repo,
            ref=body.ref or repo.default_branch,
            user_id=principal.user.id,
            trigger="ci" if principal.api_token else "manual",
            scanners=body.scanners,
        )
    except (ScanRequestError, ProviderError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    audit(
        db,
        "scan.start",
        request=request,
        user_id=principal.user.id,
        target_type="scan",
        target_id=scan.id,
        details={"ref": body.ref or repo.default_branch},
    )
    db.commit()
    return ScanOut.model_validate(scan)


@router.get("/api/scans/{scan_id}/gate")
def scan_gate(
    scan_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Policy verdict for a finished scan (what CI systems call to pass/fail a build)."""
    scan = load_scan(db, principal, scan_id)
    if scan.status not in ("completed", "partial"):
        raise HTTPException(status_code=409, detail=f"Scan is {scan.status}; no verdict yet")
    incomplete = [
        n
        for n, o in (scan.summary or {}).get("scanners", {}).items()
        if o.get("state") != "completed" or not o.get("complete", True)
    ]
    return {
        **gate_for_scan(db, scan).as_dict(),
        "incomplete_scanners": incomplete,
        "ephemeral": bool(scan.config.get("ephemeral")),
    }


@router.get("/api/projects/{project_id}/policy")
def get_policy(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> dict[str, Any]:
    project = get_project_or_404(db, principal, project_id)
    return load_policy(project).model_dump()


@router.put("/api/projects/{project_id}/policy")
def put_policy(
    project_id: str,
    policy: Policy,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    project.policy = policy.model_dump()
    audit(
        db,
        "policy.update",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
    )
    db.commit()
    return project.policy


@router.post("/api/projects/{project_id}/tokens", status_code=201)
def create_token(
    project_id: str,
    body: TokenCreate,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Create a project-scoped CI token. The raw token is returned exactly once."""
    from datetime import timedelta

    from netguard.db import utcnow

    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    scopes = [s for s in body.scopes if s in ("read", "write")] or ["read"]
    raw = API_TOKEN_PREFIX + generate_token(32)
    token = ApiToken(
        user_id=principal.user.id,
        project_id=project.id,
        name=body.name.strip(),
        prefix=raw[:12],
        token_hash=hash_token(raw),
        scopes=scopes,
        expires_at=utcnow() + timedelta(days=body.expires_days) if body.expires_days else None,
    )
    db.add(token)
    audit(
        db,
        "token.create",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
        details={"name": token.name},
    )
    db.commit()
    return {**TokenOut.model_validate(token, from_attributes=True).model_dump(), "token": raw}


@router.get("/api/projects/{project_id}/tokens", response_model=list[TokenOut])
def list_tokens(
    project_id: str,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> list[TokenOut]:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    rows = db.scalars(
        select(ApiToken)
        .where(ApiToken.project_id == project.id)
        .order_by(ApiToken.created_at.desc())
    ).all()
    return [TokenOut.model_validate(t, from_attributes=True) for t in rows]


@router.delete("/api/projects/{project_id}/tokens/{token_id}", status_code=204)
def revoke_token(
    project_id: str,
    token_id: str,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> None:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    token = db.get(ApiToken, token_id)
    if token is None or token.project_id != project.id:
        raise HTTPException(status_code=404, detail="Token not found")
    token.revoked = True
    audit(
        db,
        "token.revoke",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
    )
    db.commit()


# ---- webhooks -------------------------------------------------------------------------------------
async def _body(request: Request) -> bytes:
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413, detail="Payload too large")
    return raw


def _candidates(db: Session, provider: str, external_id: str) -> list[Repository]:
    return list(
        db.scalars(
            select(Repository).where(
                Repository.provider == provider, Repository.external_id == external_id
            )
        )
    )


def _github_signature_ok(secret: str, raw: bytes, header: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return constant_time_equals(expected, header)


@router.post("/api/webhooks/github", status_code=202)
async def github_webhook(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    raw = await _body(request)
    event = request.headers.get("x-github-event", "")
    sig = request.headers.get("x-hub-signature-256", "")
    try:
        payload = json.loads(raw or b"{}")
        full_name = payload.get("repository", {}).get("full_name", "")
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid payload") from None
    repos = [
        r
        for r in _candidates(db, "github", full_name)
        if r.webhook_secret and _github_signature_ok(decrypt_secret(r.webhook_secret), raw, sig)
    ]
    if not repos:  # same answer for unknown repos and bad signatures: no enumeration
        raise HTTPException(status_code=401, detail="Invalid signature")
    if event == "ping":
        return {"ok": True}
    queued = []
    for repo in repos:
        target = _github_target(event, payload)
        if target:
            queued.append(_queue(db, repo, target))
    db.commit()
    return {"queued": queued}


def _github_target(event: str, p: dict) -> dict[str, Any] | None:
    if event == "push":
        ref = p.get("ref", "")
        sha = p.get("after", "")
        if not ref.startswith("refs/heads/") or p.get("deleted") or set(sha) <= {"0"}:
            return None
        return {"ref": ref.removeprefix("refs/heads/"), "sha": sha, "pr": None}
    if event == "pull_request" and p.get("action") in ("opened", "synchronize", "reopened"):
        pr = p.get("pull_request", {})
        return {
            "ref": pr.get("head", {}).get("ref", ""),
            "sha": pr.get("head", {}).get("sha", ""),
            "pr": p.get("number") or pr.get("number"),
        }
    return None


@router.post("/api/webhooks/gitlab", status_code=202)
async def gitlab_webhook(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    raw = await _body(request)
    event = request.headers.get("x-gitlab-event", "")
    token = request.headers.get("x-gitlab-token", "")
    try:
        payload = json.loads(raw or b"{}")
        project = payload.get("project", {}).get("path_with_namespace", "")
        project_id = str(payload.get("project", {}).get("id", ""))
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid payload") from None
    repos = [
        r
        for r in _candidates(db, "gitlab", project) + _candidates(db, "gitlab", project_id)
        if r.webhook_secret and constant_time_equals(decrypt_secret(r.webhook_secret), token)
    ]
    if not repos:
        raise HTTPException(status_code=401, detail="Invalid token")
    queued = []
    for repo in repos:
        target = None
        if (
            event == "Push Hook"
            and payload.get("ref", "").startswith("refs/heads/")
            and payload.get("checkout_sha")
        ):
            target = {
                "ref": payload["ref"].removeprefix("refs/heads/"),
                "sha": payload["checkout_sha"],
                "pr": None,
            }
        elif event == "Merge Request Hook":
            attrs = payload.get("object_attributes", {})
            if attrs.get("action") in ("open", "update", "reopen"):
                target = {
                    "ref": attrs.get("source_branch", ""),
                    "sha": attrs.get("last_commit", {}).get("id", ""),
                    "pr": attrs.get("iid"),
                }
        if target:
            queued.append(_queue(db, repo, target))
    db.commit()
    return {"queued": queued}


def _queue(db: Session, repo: Repository, target: dict[str, Any]) -> str | None:
    try:
        scan = integrations.queue_repo_scan(
            db,
            repo,
            ref=target["ref"],
            sha=target["sha"],
            pr_number=target["pr"],
            trigger="webhook",
        )
        return scan.id
    except (ScanRequestError, ProviderError) as exc:
        log.warning("webhook scan rejected", extra={"repo": repo.id, "error": str(exc)[:200]})
        return None
