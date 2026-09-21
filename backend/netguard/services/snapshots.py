"""Repository snapshots: immutable copies of a codebase that scans and patches operate on."""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from netguard.config import get_settings
from netguard.core.archive import extract_archive, strip_single_root
from netguard.core.files import iter_files
from netguard.db import new_id
from netguard.models import Repository, Snapshot


def snapshot_root(snapshot: Snapshot) -> Path:
    return get_settings().snapshots_dir / snapshot.path


def _stats(root: Path) -> tuple[int, int]:
    files = list(iter_files(root, max_bytes=1 << 40))
    return len(files), sum(f.size for f in files)


def create_snapshot_from_archive(
    db: Session,
    repository: Repository,
    archive_path: Path,
    *,
    user_id: str | None,
    ref: str = "",
    commit_sha: str = "",
    source: str = "upload",
) -> Snapshot:
    settings = get_settings()
    snapshot_id = new_id()
    rel = f"{repository.project_id}/{snapshot_id}"
    dest = settings.snapshots_dir / rel
    extract_archive(
        archive_path,
        dest,
        max_files=settings.max_archive_files,
        max_bytes=settings.max_extracted_mb * 1024 * 1024,
    )
    strip_single_root(dest)
    count, size = _stats(dest)
    snap = Snapshot(
        id=snapshot_id,
        project_id=repository.project_id,
        repository_id=repository.id,
        source=source,
        ref=ref,
        commit_sha=commit_sha,
        path=rel,
        file_count=count,
        size_bytes=size,
        created_by=user_id,
    )
    db.add(snap)
    db.flush()
    return snap


def create_snapshot_from_directory(
    db: Session,
    repository: Repository,
    source_dir: Path,
    *,
    user_id: str | None,
    ref: str = "",
    commit_sha: str = "",
    source: str = "git",
    parent_id: str | None = None,
) -> Snapshot:
    """Copy a directory (e.g. a fresh clone or a patched workspace) into a new snapshot."""
    settings = get_settings()
    snapshot_id = new_id()
    rel = f"{repository.project_id}/{snapshot_id}"
    dest = settings.snapshots_dir / rel
    shutil.copytree(
        source_dir,
        dest,
        symlinks=False,
        ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__"),
    )
    count, size = _stats(dest)
    snap = Snapshot(
        id=snapshot_id,
        project_id=repository.project_id,
        repository_id=repository.id,
        source=source,
        ref=ref,
        commit_sha=commit_sha,
        path=rel,
        file_count=count,
        size_bytes=size,
        parent_id=parent_id,
        created_by=user_id,
    )
    db.add(snap)
    db.flush()
    return snap


def clone_snapshot_tree(snapshot: Snapshot, dest: Path) -> Path:
    """Make a private writable copy of a snapshot (used for patch validation)."""
    shutil.copytree(snapshot_root(snapshot), dest, symlinks=False)
    return dest


def delete_snapshot_files(snapshot: Snapshot) -> None:
    shutil.rmtree(snapshot_root(snapshot), ignore_errors=True)
