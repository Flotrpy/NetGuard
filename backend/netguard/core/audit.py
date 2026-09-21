"""Audit logging for security-relevant actions.

Audit rows must never contain secrets: callers pass identifiers and coarse details only.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session
from starlette.requests import Request

from netguard.core.middleware import client_ip
from netguard.logging import get_logger
from netguard.models import AuditLog

log = get_logger("audit")

_SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "api_key", "cookie"}


def _scrub(details: dict[str, Any]) -> dict[str, Any]:
    return {k: ("[redacted]" if k.lower() in _SENSITIVE_KEYS else v) for k, v in details.items()}


def audit(
    db: Session,
    action: str,
    *,
    request: Request | None = None,
    user_id: str | None = None,
    target_type: str = "",
    target_id: str = "",
    details: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        ip=client_ip(request) if request is not None else "",
        details=_scrub(details or {}),
    )
    db.add(entry)
    db.flush()
    log.info(
        "audit",
        extra={"action": action, "user_id": user_id, "target": f"{target_type}:{target_id}"},
    )
    return entry
