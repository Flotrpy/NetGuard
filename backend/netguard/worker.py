"""Background worker: claims jobs from the database queue and executes them."""

from __future__ import annotations

import os
import signal
import socket
import threading
from collections.abc import Callable

from netguard.config import get_settings
from netguard.db import get_session_factory, init_db
from netguard.logging import configure_logging, get_logger
from netguard.models import Job
from netguard.services import jobs
from netguard.services.scans import execute_scan

log = get_logger("worker")

Handler = Callable[[Job], None]


def _handle_scan(job: Job) -> None:
    execute_scan(job.payload["scan_id"])
    # Verification scans carry a finding/patch; turn the rescan result into a verdict.
    from netguard.services.patches import evaluate_verification

    evaluate_verification(job.payload["scan_id"])


HANDLERS: dict[str, Handler] = {"scan": _handle_scan}


def process_one(worker_id: str) -> bool:
    """Claim and run a single job. Returns False when the queue is empty."""
    with get_session_factory()() as db:
        job = jobs.claim_next(db, worker_id)
        if job is None:
            return False
        handler = HANDLERS.get(job.type)
        error = ""
        try:
            if handler is None:
                raise RuntimeError(f"No handler for job type {job.type!r}")
            handler(job)
        except Exception as exc:  # noqa: BLE001 - a job failure must not kill the worker
            log.exception("job failed", extra={"job_id": job.id, "type": job.type})
            error = f"{type(exc).__name__}: {exc}"
        jobs.finish(db, job, error)
        return True


def run_worker(stop: threading.Event, worker_id: str | None = None) -> None:
    settings = get_settings()
    worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}"
    log.info("worker started", extra={"worker_id": worker_id})
    with get_session_factory()() as db:
        jobs.requeue_stale(db, older_than_seconds=settings.scan_timeout_seconds * 2)
    while not stop.is_set():
        try:
            if not process_one(worker_id):
                stop.wait(settings.worker_poll_seconds)
        except Exception:  # noqa: BLE001
            log.exception("worker loop error")
            stop.wait(settings.worker_poll_seconds)
    log.info("worker stopped", extra={"worker_id": worker_id})


def start_embedded_worker() -> tuple[threading.Thread, threading.Event]:
    stop = threading.Event()
    thread = threading.Thread(
        target=run_worker,
        args=(stop, f"embedded-{os.getpid()}"),
        name="netguard-worker",
        daemon=True,
    )
    thread.start()
    return thread, stop


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    settings.resolved_secret_key()
    settings.ensure_dirs()
    init_db(settings)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    run_worker(stop)


if __name__ == "__main__":
    main()
