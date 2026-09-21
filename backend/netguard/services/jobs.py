"""Durable job queue backed by the ``jobs`` table.

Workers claim jobs with ``SELECT ... FOR UPDATE SKIP LOCKED`` (PostgreSQL) so several workers
can run safely in parallel; on SQLite (dev/tests) the lock hint is a no-op and a single worker is
expected.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.db import utcnow
from netguard.enums import JobStatus
from netguard.models import Job

MAX_ATTEMPTS = 2


def enqueue(db: Session, job_type: str, payload: dict[str, Any], scan_id: str | None = None) -> Job:
    job = Job(type=job_type, payload=payload, scan_id=scan_id)
    db.add(job)
    db.flush()
    return job


def claim_next(db: Session, worker_id: str) -> Job | None:
    job = db.scalar(
        select(Job)
        .where(Job.status == JobStatus.QUEUED.value)
        .order_by(Job.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        db.rollback()
        return None
    job.status = JobStatus.RUNNING.value
    job.locked_by = worker_id
    job.started_at = utcnow()
    job.attempts += 1
    db.commit()
    return job


def finish(db: Session, job: Job, error: str = "") -> None:
    job.status = JobStatus.FAILED.value if error else JobStatus.SUCCEEDED.value
    job.error = error[:4000]
    job.finished_at = utcnow()
    db.commit()


def requeue_stale(db: Session, older_than_seconds: int) -> int:
    """Return jobs stuck in RUNNING (worker crashed) to the queue, up to MAX_ATTEMPTS."""
    cutoff = utcnow() - timedelta(seconds=older_than_seconds)
    count = 0
    for job in db.scalars(select(Job).where(Job.status == JobStatus.RUNNING.value)):
        started = job.started_at
        if started is not None and started.replace(tzinfo=cutoff.tzinfo) >= cutoff:
            continue
        if job.attempts >= MAX_ATTEMPTS:
            job.status = JobStatus.FAILED.value
            job.error = "Worker stopped before the job finished"
            job.finished_at = utcnow()
        else:
            job.status = JobStatus.QUEUED.value
            job.locked_by = ""
        count += 1
    db.commit()
    return count
