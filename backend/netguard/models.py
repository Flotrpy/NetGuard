"""ORM models: the unified security-finding database."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netguard.db import Base, JSONType, new_id, utcnow
from netguard.enums import (
    Confidence,
    FindingStatus,
    JobStatus,
    ProjectRole,
    Role,
    ScanStatus,
    VerificationState,
)


def _id() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=new_id)


def _ts(**kw: Any) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = _id()
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=Role.MEMBER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = _ts()


class UserSession(Base):
    """Server-side session. Only a hash of the opaque cookie token is stored."""

    __tablename__ = "sessions"

    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship()


class ApiToken(Base):
    """Long-lived, project-scoped token for CI/CD. Only a hash is stored."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(12))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[list] = mapped_column(JSONType, default=list)
    created_at: Mapped[datetime] = _ts()
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = _id()
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    policy: Mapped[dict] = mapped_column(JSONType, default=dict)  # CI/CD gate policy
    created_at: Mapped[datetime] = _ts()

    members: Mapped[list[ProjectMember]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id"),)

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20), default=ProjectRole.VIEWER.value)

    project: Mapped[Project] = relationship(back_populates="members")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(20), default="upload")  # upload|github|gitlab
    name: Mapped[str] = mapped_column(String(300))
    url: Mapped[str] = mapped_column(String(500), default="")
    external_id: Mapped[str] = mapped_column(String(200), default="")  # "owner/repo" / project id
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    token_encrypted: Mapped[str] = mapped_column(Text, default="")
    webhook_secret: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = _ts()


class Snapshot(Base):
    """Immutable copy of a repository's files at a point in time (uploaded or cloned)."""

    __tablename__ = "snapshots"

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    repository_id: Mapped[str | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True
    )
    source: Mapped[str] = mapped_column(String(20), default="upload")
    ref: Mapped[str] = mapped_column(String(200), default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    path: Mapped[str] = mapped_column(String(500))  # relative to settings.snapshots_dir
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)  # patched-from
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()


class Asset(Base):
    """Something that can be affected by a finding: host, service, image, API, repo file."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "type", "identifier"),)

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(30))  # repository|host|container_image|api|iac|package
    identifier: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(300), default="")
    attributes: Mapped[dict] = mapped_column(JSONType, default=dict)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    repository_id: Mapped[str | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True
    )
    snapshot_id: Mapped[str | None] = mapped_column(
        ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(20), default="code")  # code|network|api|container
    scanners: Mapped[list] = mapped_column(JSONType, default=list)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED.value, index=True)
    progress: Mapped[dict] = mapped_column(JSONType, default=dict)  # scanner -> {state, percent}
    config: Mapped[dict] = mapped_column(JSONType, default=dict)
    summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    trigger: Mapped[str] = mapped_column(String(20), default="manual")  # manual|webhook|ci|verify
    ref: Mapped[str] = mapped_column(String(200), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    """Durable work queue entry, claimed by workers (SKIP LOCKED on PostgreSQL)."""

    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_status_created", "status", "created_at"),)

    id: Mapped[str] = _id()
    type: Mapped[str] = mapped_column(String(40))
    payload: Mapped[dict] = mapped_column(JSONType, default=dict)
    status: Mapped[str] = mapped_column(String(20), default=JobStatus.QUEUED.value)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_by: Mapped[str] = mapped_column(String(100), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = _ts()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    """A single security issue, regardless of which scanner produced it."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint"),
        Index("ix_findings_project_status", "project_id", "status"),
    )

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    repository_id: Mapped[str | None] = mapped_column(
        ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_id: Mapped[str | None] = mapped_column(  # most recent scan that observed it
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    scanner: Mapped[str] = mapped_column(String(20), index=True)
    rule_id: Mapped[str] = mapped_column(String(120))
    fingerprint: Mapped[str] = mapped_column(String(64))

    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(120), default="")  # vulnerability type
    description: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str] = mapped_column(String(20), default="")
    references: Mapped[list] = mapped_column(JSONType, default=list)

    severity: Mapped[str] = mapped_column(String(10), index=True)
    confidence: Mapped[str] = mapped_column(String(10), default=Confidence.MEDIUM.value)
    exploitability: Mapped[str] = mapped_column(String(10), default="medium")
    exposure: Mapped[str] = mapped_column(String(20), default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    file_path: Mapped[str] = mapped_column(String(1000), default="", index=True)
    line: Mapped[int] = mapped_column(Integer, default=0)
    end_line: Mapped[int] = mapped_column(Integer, default=0)
    language: Mapped[str] = mapped_column(String(30), default="")
    code_context: Mapped[str] = mapped_column(Text, default="")
    extra: Mapped[dict] = mapped_column(JSONType, default=dict)  # scanner-specific details

    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.OPEN.value, index=True)
    verification: Mapped[str] = mapped_column(String(20), default=VerificationState.NONE.value)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list[FindingEvent]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.created_at"
    )


class FindingEvent(Base):
    """Append-only history of what happened to a finding."""

    __tablename__ = "finding_events"

    id: Mapped[str] = _id()
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(40))
    message: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSONType, default=dict)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()

    finding: Mapped[Finding] = relationship(back_populates="events")


class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[str] = _id()
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="proposed")  # proposed|applied|rejected
    generator: Mapped[str] = mapped_column(String(20), default="rule")  # rule|ai
    explanation: Mapped[str] = mapped_column(Text, default="")
    diff: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str] = mapped_column(String(1000), default="")
    base_sha256: Mapped[str] = mapped_column(String(64), default="")  # hash of file patched from
    base_snapshot_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    new_content: Mapped[str] = mapped_column(Text, default="")
    caveats: Mapped[list] = mapped_column(JSONType, default=list)
    applied_snapshot_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    verification: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NetworkHost(Base):
    __tablename__ = "network_hosts"
    __table_args__ = (Index("ix_hosts_scan", "scan_id"),)

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    ip: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str] = mapped_column(String(300), default="")
    os_guess: Mapped[str] = mapped_column(String(200), default="")
    device_type: Mapped[str] = mapped_column(String(60), default="")
    status: Mapped[str] = mapped_column(String(10), default="up")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    scanned_at: Mapped[datetime] = _ts()

    services: Mapped[list[NetworkService]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class NetworkService(Base):
    __tablename__ = "network_services"

    id: Mapped[str] = _id()
    host_id: Mapped[str] = mapped_column(
        ForeignKey("network_hosts.id", ondelete="CASCADE"), index=True
    )
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(5), default="tcp")
    state: Mapped[str] = mapped_column(String(15), default="open")
    service: Mapped[str] = mapped_column(String(60), default="")
    version: Mapped[str] = mapped_column(String(300), default="")
    banner: Mapped[str] = mapped_column(String(500), default="")
    scanned_at: Mapped[datetime] = _ts()

    host: Mapped[NetworkHost] = relationship(back_populates="services")


class PacketCapture(Base):
    __tablename__ = "packet_captures"

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(300))
    stored_path: Mapped[str] = mapped_column(String(500))  # relative to uploads_dir
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    authorization: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = _id()
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    title: Mapped[str] = mapped_column(String(300))
    format: Mapped[str] = mapped_column(String(10))  # pdf|html|json|csv
    stored_path: Mapped[str] = mapped_column(String(500))
    params: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = _ts()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = _id()
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(40), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = _ts()
