from netguard.enums import JobStatus
from netguard.models import Job
from netguard.services import jobs
from tests.helpers import fresh_db


def test_jobs_are_claimed_once_in_fifo_order():
    db = fresh_db()
    a = jobs.enqueue(db, "scan", {"n": 1})
    db.commit()
    b = jobs.enqueue(db, "scan", {"n": 2})
    db.commit()
    first = jobs.claim_next(db, "w1")
    second = jobs.claim_next(db, "w2")
    assert (first.id, second.id) == (a.id, b.id)
    assert first.status == JobStatus.RUNNING.value and first.attempts == 1
    assert jobs.claim_next(db, "w3") is None


def test_finish_records_error_or_success():
    db = fresh_db()
    ok = jobs.enqueue(db, "scan", {})
    bad = jobs.enqueue(db, "scan", {})
    db.commit()
    jobs.finish(db, ok)
    jobs.finish(db, bad, error="x" * 10000)
    assert ok.status == "succeeded" and bad.status == "failed" and len(bad.error) == 4000


def test_stale_running_jobs_are_requeued_then_failed():
    db = fresh_db()
    job = jobs.enqueue(db, "scan", {})
    db.commit()
    claimed = jobs.claim_next(db, "dead-worker")
    assert jobs.requeue_stale(db, older_than_seconds=3600) == 0  # still fresh
    assert jobs.requeue_stale(db, older_than_seconds=-1) == 1
    assert db.get(Job, job.id).status == "queued"
    jobs.claim_next(db, "w2")  # second attempt
    jobs.requeue_stale(db, older_than_seconds=-1)
    final = db.get(Job, claimed.id)
    assert final.status == "failed" and "Worker stopped" in final.error
