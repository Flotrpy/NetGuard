"""Repositories and code snapshots (uploads)."""

from __future__ import annotations

import shutil
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.api.deps import Principal, get_principal, get_project_or_404, require_user_session
from netguard.config import get_settings
from netguard.core.archive import ArchiveError
from netguard.core.audit import audit
from netguard.core.files import confined_path, detect_language, iter_files, read_text
from netguard.db import get_db, new_id
from netguard.enums import ProjectRole
from netguard.models import Repository, Snapshot
from netguard.services.snapshots import create_snapshot_from_archive, snapshot_root

router = APIRouter(tags=["repositories"])


class RepositoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=300)


class RepositoryOut(BaseModel):
    id: str
    project_id: str
    provider: str
    name: str
    url: str
    default_branch: str
    created_at: datetime
    latest_snapshot_id: str | None = None

    model_config = {"from_attributes": True}


class SnapshotOut(BaseModel):
    id: str
    repository_id: str | None
    source: str
    ref: str
    commit_sha: str
    file_count: int
    size_bytes: int
    created_at: datetime

    model_config = {"from_attributes": True}


def repository_out(db: Session, repo: Repository) -> RepositoryOut:
    latest = db.scalar(
        select(Snapshot.id)
        .where(Snapshot.repository_id == repo.id)
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    )
    out = RepositoryOut.model_validate(repo)
    out.latest_snapshot_id = latest
    return out


def load_repository(
    db: Session, principal: Principal, repo_id: str, role: ProjectRole
) -> Repository:
    repo = db.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    get_project_or_404(db, principal, repo.project_id, role)
    return repo


def load_snapshot(db: Session, principal: Principal, snapshot_id: str) -> Snapshot:
    snap = db.get(Snapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    get_project_or_404(db, principal, snap.project_id)
    return snap


@router.post(
    "/api/projects/{project_id}/repositories", response_model=RepositoryOut, status_code=201
)
def create_repository(
    project_id: str,
    body: RepositoryCreate,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> RepositoryOut:
    project = get_project_or_404(db, principal, project_id, ProjectRole.EDITOR)
    repo = Repository(project_id=project.id, provider="upload", name=body.name.strip())
    db.add(repo)
    db.flush()
    audit(
        db,
        "repository.create",
        request=request,
        user_id=principal.user.id,
        target_type="repository",
        target_id=repo.id,
    )
    db.commit()
    return repository_out(db, repo)


@router.get("/api/projects/{project_id}/repositories", response_model=list[RepositoryOut])
def list_repositories(
    project_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[RepositoryOut]:
    project = get_project_or_404(db, principal, project_id)
    repos = db.scalars(
        select(Repository).where(Repository.project_id == project.id).order_by(Repository.name)
    ).all()
    return [repository_out(db, r) for r in repos]


@router.post("/api/repositories/{repo_id}/upload", response_model=SnapshotOut, status_code=201)
async def upload_snapshot(
    repo_id: str,
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
) -> SnapshotOut:
    repo = load_repository(db, principal, repo_id, ProjectRole.EDITOR)
    settings = get_settings()
    settings.ensure_dirs()
    limit = settings.max_upload_mb * 1024 * 1024
    tmp = settings.uploads_dir / f"{new_id()}.upload"  # server-chosen name: never the client's
    size = 0
    try:
        with open(tmp, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(
                        status_code=413, detail=f"Upload exceeds {settings.max_upload_mb} MB"
                    )
                out.write(chunk)
        try:
            snap = create_snapshot_from_archive(
                db, repo, tmp, user_id=principal.user.id, ref=(file.filename or "")[:200]
            )
        except ArchiveError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        tmp.unlink(missing_ok=True)
    audit(
        db,
        "snapshot.upload",
        request=request,
        user_id=principal.user.id,
        target_type="snapshot",
        target_id=snap.id,
        details={"files": snap.file_count, "bytes": snap.size_bytes},
    )
    db.commit()
    return SnapshotOut.model_validate(snap)


@router.get("/api/repositories/{repo_id}/snapshots", response_model=list[SnapshotOut])
def list_snapshots(
    repo_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[SnapshotOut]:
    repo = load_repository(db, principal, repo_id, ProjectRole.VIEWER)
    snaps = db.scalars(
        select(Snapshot)
        .where(Snapshot.repository_id == repo.id)
        .order_by(Snapshot.created_at.desc())
    ).all()
    return [SnapshotOut.model_validate(s) for s in snaps]


@router.delete("/api/repositories/{repo_id}", status_code=204)
def delete_repository(
    repo_id: str,
    request: Request,
    principal: Principal = Depends(require_user_session),
    db: Session = Depends(get_db),
):
    repo = load_repository(db, principal, repo_id, ProjectRole.OWNER)
    for snap in db.scalars(select(Snapshot).where(Snapshot.repository_id == repo.id)):
        shutil.rmtree(snapshot_root(snap), ignore_errors=True)
        db.delete(snap)
    audit(
        db,
        "repository.delete",
        request=request,
        user_id=principal.user.id,
        target_type="repository",
        target_id=repo.id,
    )
    db.delete(repo)
    db.commit()


@router.get("/api/snapshots/{snapshot_id}/files")
def list_snapshot_files(
    snapshot_id: str, principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> list[dict]:
    snap = load_snapshot(db, principal, snapshot_id)
    root = snapshot_root(snap)
    return [
        {"path": f.rel_path, "size": f.size, "language": f.language}
        for f in iter_files(root, max_bytes=get_settings().max_file_scan_kb * 1024)
    ]


@router.get("/api/snapshots/{snapshot_id}/file")
def read_snapshot_file(
    snapshot_id: str,
    path: str = Query(min_length=1, max_length=1000),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict:
    snap = load_snapshot(db, principal, snapshot_id)
    try:
        target = confined_path(snapshot_root(snap), path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid path") from exc
    if not target.is_file() or target.is_symlink():
        raise HTTPException(status_code=404, detail="File not found")
    text = read_text(target, get_settings().max_file_scan_kb * 1024)
    if text is None:
        raise HTTPException(status_code=415, detail="File is binary or too large to display")
    return {"path": path, "language": detect_language(path), "content": text}
