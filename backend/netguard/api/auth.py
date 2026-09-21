"""Registration, login/logout, current-user and session management."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, require_user_session
from netguard.config import get_settings
from netguard.core.audit import audit
from netguard.core.middleware import client_ip
from netguard.core.security import (
    PasswordPolicyError,
    dummy_verify,
    generate_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)
from netguard.db import get_db, utcnow
from netguard.enums import Role
from netguard.models import User, UserSession

router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Credentials(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        return v


class RegisterRequest(Credentials):
    name: str = Field(default="", max_length=200)


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class SessionInfo(BaseModel):
    user: UserOut
    csrf_token: str


def _set_session_cookies(response: Response, raw_token: str, csrf: str, ttl_minutes: int) -> None:
    s = get_settings()
    max_age = ttl_minutes * 60
    response.set_cookie(
        s.cookie_name,
        raw_token,
        max_age=max_age,
        httponly=True,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )
    # Readable by the SPA so it can echo the value in the X-CSRF-Token header.
    response.set_cookie(
        s.csrf_cookie_name,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=s.cookie_secure,
        samesite="lax",
        path="/",
    )


def _start_session(db: Session, request: Request, response: Response, user: User) -> str:
    s = get_settings()
    raw = generate_token()
    csrf = generate_token(24)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(raw),
            csrf_token=csrf,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:300],
            expires_at=utcnow() + timedelta(minutes=s.session_ttl_minutes),
        )
    )
    _set_session_cookies(response, raw, csrf, s.session_ttl_minutes)
    return csrf


@router.post("/register", response_model=SessionInfo, status_code=201)
def register(
    body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)
) -> SessionInfo:
    settings = get_settings()
    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    # The very first account bootstraps the installation as administrator.
    if user_count > 0 and not settings.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    try:
        validate_password_strength(body.password, body.email)
    except PasswordPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if db.scalar(select(User).where(User.email == body.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(
        email=body.email,
        name=body.name.strip(),
        password_hash=hash_password(body.password),
        role=Role.ADMIN.value if user_count == 0 else Role.MEMBER.value,
    )
    db.add(user)
    db.flush()
    csrf = _start_session(db, request, response, user)
    audit(
        db, "auth.register", request=request, user_id=user.id, target_type="user", target_id=user.id
    )
    db.commit()
    return SessionInfo(user=UserOut.model_validate(user), csrf_token=csrf)


@router.post("/login", response_model=SessionInfo)
def login(
    body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)
) -> SessionInfo:
    user = db.scalar(select(User).where(User.email == body.email))
    now = utcnow()
    generic = HTTPException(status_code=401, detail="Invalid email or password")
    if user is None:
        dummy_verify(body.password)  # keep timing similar to a real check
        audit(db, "auth.login_failed", request=request, details={"reason": "unknown_user"})
        db.commit()
        raise generic
    locked = user.locked_until is not None and user.locked_until.replace(tzinfo=None) > now.replace(
        tzinfo=None
    )
    if locked:
        audit(db, "auth.login_locked", request=request, user_id=user.id)
        db.commit()
        raise HTTPException(status_code=429, detail="Account temporarily locked. Try again later.")
    if not user.is_active or not verify_password(body.password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_logins = 0
        audit(db, "auth.login_failed", request=request, user_id=user.id)
        db.commit()
        raise generic
    user.failed_logins = 0
    user.locked_until = None
    csrf = _start_session(db, request, response, user)
    audit(db, "auth.login", request=request, user_id=user.id, target_type="user", target_id=user.id)
    db.commit()
    return SessionInfo(user=UserOut.model_validate(user), csrf_token=csrf)


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> Response:
    assert principal.session is not None
    principal.session.revoked = True
    audit(db, "auth.logout", request=request, user_id=principal.user.id)
    db.commit()
    s = get_settings()
    response.delete_cookie(s.cookie_name, path="/")
    response.delete_cookie(s.csrf_cookie_name, path="/")
    response.status_code = 204
    return response


@router.get("/me", response_model=SessionInfo)
def me(principal: Principal = Depends(require_user_session)) -> SessionInfo:
    assert principal.session is not None
    return SessionInfo(
        user=UserOut.model_validate(principal.user), csrf_token=principal.session.csrf_token
    )


@router.get("/whoami", response_model=UserOut)
def whoami(principal: Principal = Depends(get_principal)) -> UserOut:
    """Works for both session cookies and API tokens (useful for CI connectivity checks)."""
    return UserOut.model_validate(principal.user)
