"""Request dependencies: authentication, CSRF enforcement and project authorization.

Authorization is always derived from the database. Nothing the client sends (roles, project
membership, token scopes) is trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlparse

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.config import get_settings
from netguard.core.security import constant_time_equals, hash_token
from netguard.db import get_db, utcnow
from netguard.enums import ProjectRole, Role
from netguard.models import ApiToken, Project, ProjectMember, User, UserSession

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_ROLE_ORDER = {ProjectRole.VIEWER: 0, ProjectRole.EDITOR: 1, ProjectRole.OWNER: 2}
API_TOKEN_PREFIX = "ngt_"


@dataclass
class Principal:
    user: User
    session: UserSession | None = None
    api_token: ApiToken | None = None

    @property
    def is_admin(self) -> bool:
        return self.user.role == Role.ADMIN.value


def _aware(dt):  # SQLite returns naive datetimes; treat them as UTC.
    from datetime import UTC

    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _check_origin(request: Request) -> None:
    """Reject cross-site state-changing requests whose Origin isn't one we serve."""
    origin = request.headers.get("origin")
    if not origin:
        return
    allowed = set(get_settings().cors_origins)
    host = request.headers.get("host", "")
    parsed = urlparse(origin)
    if origin in allowed or (parsed.netloc and parsed.netloc == host):
        return
    raise HTTPException(status_code=403, detail="Cross-origin request rejected")


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    settings = get_settings()
    now = utcnow()

    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
        if not raw.startswith(API_TOKEN_PREFIX):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = db.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(raw)))
        if (
            token is None
            or token.revoked
            or (token.expires_at and _aware(token.expires_at) < now)
        ):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        user = db.get(User, token.user_id)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token.last_used = now
        db.commit()
        # Bearer tokens are not ambient credentials, so no CSRF check is needed.
        return Principal(user=user, api_token=token)

    cookie = request.cookies.get(settings.cookie_name)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(cookie)))
    if session is None or session.revoked or _aware(session.expires_at) < now:
        raise HTTPException(status_code=401, detail="Session expired")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if request.method not in SAFE_METHODS:
        _check_origin(request)
        header = request.headers.get("x-csrf-token", "")
        if not header or not constant_time_equals(header, session.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")

    if now - _aware(session.last_seen) > timedelta(minutes=1):
        session.last_seen = now
        db.commit()
    return Principal(user=user, session=session)


def require_user_session(principal: Principal = Depends(get_principal)) -> Principal:
    """Endpoints that must be used by an interactive user, not a CI token."""
    if principal.session is None:
        raise HTTPException(status_code=403, detail="This endpoint requires a user session")
    return principal


def require_admin(principal: Principal = Depends(get_principal)) -> Principal:
    if not principal.is_admin or principal.session is None:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return principal


def project_role(db: Session, principal: Principal, project: Project) -> ProjectRole | None:
    if principal.api_token is not None:
        if principal.api_token.project_id != project.id:
            return None
        scopes = principal.api_token.scopes or []
        return ProjectRole.EDITOR if "write" in scopes else ProjectRole.VIEWER
    if principal.is_admin or project.owner_id == principal.user.id:
        return ProjectRole.OWNER
    member = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id, ProjectMember.user_id == principal.user.id
        )
    )
    return ProjectRole(member.role) if member else None


def get_project_or_404(
    db: Session, principal: Principal, project_id: str, min_role: ProjectRole = ProjectRole.VIEWER
) -> Project:
    """Load a project the caller may access at ``min_role``; 404 (not 403) hides existence."""
    project = db.get(Project, project_id)
    role = project_role(db, principal, project) if project else None
    if project is None or role is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if _ROLE_ORDER[role] < _ROLE_ORDER[min_role]:
        raise HTTPException(status_code=403, detail="Insufficient permissions for this project")
    return project


def accessible_project_ids(db: Session, principal: Principal) -> list[str]:
    if principal.api_token is not None:
        return [principal.api_token.project_id]
    if principal.is_admin:
        return list(db.scalars(select(Project.id)))
    owned = select(Project.id).where(Project.owner_id == principal.user.id)
    member = select(ProjectMember.project_id).where(ProjectMember.user_id == principal.user.id)
    return list(db.scalars(owned.union(member)))
