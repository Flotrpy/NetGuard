"""Projects: the top-level container for repositories, scans, findings and assets."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from netguard.api.deps import (
    Principal,
    accessible_project_ids,
    get_principal,
    get_project_or_404,
    project_role,
    require_user_session,
)
from netguard.core.audit import audit
from netguard.db import get_db
from netguard.enums import ACTIVE_STATUSES, ProjectRole, Severity
from netguard.models import Finding, Project, ProjectMember, Repository, Scan, User

router = APIRouter(prefix="/api/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str
    owner_id: str
    role: str
    created_at: datetime
    open_findings: dict[str, int]
    repository_count: int = 0
    last_scan_at: datetime | None = None


class MemberIn(BaseModel):
    email: str = Field(max_length=320)
    role: ProjectRole = ProjectRole.VIEWER


class MemberOut(BaseModel):
    user_id: str
    email: str
    name: str
    role: str


def open_finding_counts(db: Session, project_ids: list[str]) -> dict[str, dict[str, int]]:
    """Active (open/confirmed/in-progress) finding counts by severity, per project."""
    result = {pid: {s.value: 0 for s in Severity} for pid in project_ids}
    if not project_ids:
        return result
    rows = db.execute(
        select(Finding.project_id, Finding.severity, func.count())
        .where(
            Finding.project_id.in_(project_ids),
            Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
        )
        .group_by(Finding.project_id, Finding.severity)
    )
    for pid, sev, n in rows:
        result[pid][sev] = n
    return result


def _out(db: Session, principal: Principal, project: Project, counts: dict[str, int]) -> ProjectOut:
    role = project_role(db, principal, project) or ProjectRole.VIEWER
    repos = db.scalar(
        select(func.count()).select_from(Repository).where(Repository.project_id == project.id)
    )
    last = db.scalar(select(func.max(Scan.finished_at)).where(Scan.project_id == project.id))
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=project.owner_id,
        role=role.value,
        created_at=project.created_at,
        open_findings=counts,
        repository_count=repos or 0,
        last_scan_at=last,
    )


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(
    body: ProjectCreate,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> ProjectOut:
    project = Project(
        name=body.name.strip(), description=body.description.strip(), owner_id=principal.user.id
    )
    db.add(project)
    db.flush()
    audit(
        db,
        "project.create",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
    )
    db.commit()
    return _out(db, principal, project, open_finding_counts(db, [project.id])[project.id])


@router.get("", response_model=list[ProjectOut])
def list_projects(
    principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[ProjectOut]:
    ids = accessible_project_ids(db, principal)
    if not ids:
        return []
    projects = db.scalars(select(Project).where(Project.id.in_(ids)).order_by(Project.name)).all()
    counts = open_finding_counts(db, ids)
    return [_out(db, principal, p, counts[p.id]) for p in projects]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> ProjectOut:
    project = get_project_or_404(db, principal, project_id)
    return _out(db, principal, project, open_finding_counts(db, [project.id])[project.id])


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: str,
    body: ProjectUpdate,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> ProjectOut:
    project = get_project_or_404(db, principal, project_id, ProjectRole.EDITOR)
    if body.name is not None:
        project.name = body.name.strip()
    if body.description is not None:
        project.description = body.description.strip()
    audit(
        db,
        "project.update",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
    )
    db.commit()
    return _out(db, principal, project, open_finding_counts(db, [project.id])[project.id])


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> Response:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    audit(
        db,
        "project.delete",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
        details={"name": project.name},
    )
    db.delete(project)
    db.commit()
    return Response(status_code=204)


@router.get("/{project_id}/members", response_model=list[MemberOut])
def list_members(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[MemberOut]:
    project = get_project_or_404(db, principal, project_id)
    owner = db.get(User, project.owner_id)
    out = [MemberOut(user_id=owner.id, email=owner.email, name=owner.name, role="owner")]
    rows = db.execute(
        select(ProjectMember, User).join(User, User.id == ProjectMember.user_id).where(
            ProjectMember.project_id == project.id
        )
    )
    out += [MemberOut(user_id=u.id, email=u.email, name=u.name, role=m.role) for m, u in rows]
    return out


@router.post("/{project_id}/members", response_model=MemberOut, status_code=201)
def add_member(
    project_id: str,
    body: MemberIn,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> MemberOut:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    if body.role == ProjectRole.OWNER:
        raise HTTPException(status_code=422, detail="A project has a single owner")
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if user is None:
        raise HTTPException(status_code=404, detail="No user with that email")
    if user.id == project.owner_id:
        raise HTTPException(status_code=409, detail="User already owns this project")
    member = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id, ProjectMember.user_id == user.id
        )
    )
    if member:
        member.role = body.role.value
    else:
        db.add(ProjectMember(project_id=project.id, user_id=user.id, role=body.role.value))
    audit(
        db,
        "project.member_set",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
        details={"member": user.id, "role": body.role.value},
    )
    db.commit()
    return MemberOut(user_id=user.id, email=user.email, name=user.name, role=body.role.value)


@router.delete("/{project_id}/members/{user_id}", status_code=204)
def remove_member(
    project_id: str,
    user_id: str,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> Response:
    project = get_project_or_404(db, principal, project_id, ProjectRole.OWNER)
    member = db.scalar(
        select(ProjectMember).where(
            ProjectMember.project_id == project.id, ProjectMember.user_id == user_id
        )
    )
    if member is None:
        raise HTTPException(status_code=404, detail="Member not found")
    db.delete(member)
    audit(
        db,
        "project.member_remove",
        request=request,
        user_id=principal.user.id,
        target_type="project",
        target_id=project.id,
        details={"member": user_id},
    )
    db.commit()
    return Response(status_code=204)
