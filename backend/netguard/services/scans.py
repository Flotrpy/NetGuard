"""Scan orchestration: create scans, run scanners (sandboxed) and persist their findings."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.config import Settings, get_settings
from netguard.core.sandbox import Limits, SandboxCancelled, SandboxError, run_in_sandbox
from netguard.db import get_session_factory, utcnow
from netguard.enums import ACTIVE_STATUSES, ScannerState, ScanStatus
from netguard.logging import get_logger
from netguard.models import Finding, Project, Repository, Scan, Snapshot
from netguard.scanners.base import ScanCancelled, ScanContext, ScanResult
from netguard.scanners.registry import get_scanner
from netguard.scanners.runner import run_scanner_task
from netguard.services import jobs
from netguard.services.findings import ingest_findings
from netguard.services.risk import severity_counts
from netguard.services.snapshots import snapshot_root

log = get_logger("scans")


class ScanRequestError(ValueError):
    """The requested scan is invalid (unknown/unavailable scanner, missing input...)."""


def create_scan(
    db: Session,
    *,
    project: Project,
    scanners: list[str],
    kind: str = "code",
    repository: Repository | None = None,
    snapshot: Snapshot | None = None,
    config: dict[str, Any] | None = None,
    user_id: str | None = None,
    trigger: str = "manual",
    ref: str = "",
) -> Scan:
    """Validate and enqueue a scan. Nothing runs here: a worker picks the job up."""
    if not scanners:
        raise ScanRequestError("Select at least one scanner")
    seen: list[str] = []
    for name in scanners:
        try:
            scanner = get_scanner(name)
        except KeyError as exc:
            raise ScanRequestError(f"Unknown scanner: {name}") from exc
        available, note = scanner.availability()
        if not available:
            raise ScanRequestError(f"{scanner.display_name} is not available: {note}")
        if name not in seen:
            seen.append(name)
    if kind == "code":
        if repository is None or snapshot is None:
            raise ScanRequestError("A code scan needs a repository with an uploaded snapshot")
        for name in seen:
            if "source" not in get_scanner(name).supported_inputs:
                raise ScanRequestError(f"{name} does not scan source code")

    scan = Scan(
        project_id=project.id,
        repository_id=repository.id if repository else None,
        snapshot_id=snapshot.id if snapshot else None,
        kind=kind,
        scanners=seen,
        config=config or {},
        trigger=trigger,
        ref=ref or (snapshot.ref if snapshot else ""),
        created_by=user_id,
        progress={n: {"state": ScannerState.PENDING.value, "percent": 0} for n in seen},
    )
    db.add(scan)
    db.flush()
    jobs.enqueue(db, "scan", {"scan_id": scan.id}, scan_id=scan.id)
    return scan


class _Progress:
    """Throttled progress writer using short independent transactions."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self._last = 0.0
        self._last_cancel_check = 0.0
        self._cancelled = False

    def update(self, scanner: str, **fields: Any) -> None:
        with get_session_factory()() as db:
            scan = db.get(Scan, self.scan_id)
            if scan is None:
                return
            progress = dict(scan.progress or {})
            progress[scanner] = {**progress.get(scanner, {}), **fields}
            scan.progress = progress
            db.commit()

    def throttled(self, scanner: str, percent: float, message: str = "") -> None:
        now = time.monotonic()
        if now - self._last < 0.4 and percent < 100:
            return
        self._last = now
        self.update(
            scanner,
            state=ScannerState.RUNNING.value,
            percent=round(percent),
            message=message,
        )

    def is_cancelled(self) -> bool:
        now = time.monotonic()
        if self._cancelled or now - self._last_cancel_check < 0.5:
            return self._cancelled
        self._last_cancel_check = now
        with get_session_factory()() as db:
            scan = db.get(Scan, self.scan_id)
            self._cancelled = scan is None or scan.status == ScanStatus.CANCELLED.value
        return self._cancelled


def _runtime(settings: Settings) -> dict[str, Any]:
    return {
        "osv_api_url": settings.osv_api_url,
        "osv_offline": settings.osv_offline,
        "osv_timeout": settings.osv_timeout_seconds,
        "cache_dir": str(settings.cache_dir),
        "allow_public_targets": settings.allow_public_targets,
        "max_scan_hosts": settings.max_scan_hosts,
        "max_scan_ports": settings.max_scan_ports,
    }


def _run_scanner(
    settings: Settings,
    scanner_name: str,
    root: Path | None,
    scan: Scan,
    progress: _Progress,
) -> ScanResult:
    only = sorted(scan.config.get("only_paths")) if scan.config.get("only_paths") else None
    args = (
        scanner_name,
        str(root) if root else None,
        scan.config,
        settings.max_file_scan_kb * 1024,
        only,
        _runtime(settings),
    )
    report = lambda pct, msg="": progress.throttled(scanner_name, pct, msg)  # noqa: E731
    if settings.scan_isolation == "inline":
        ctx = ScanContext(
            root=root,
            config=scan.config,
            max_file_bytes=args[3],
            progress=report,
            is_cancelled=progress.is_cancelled,
            only_paths=set(only) if only is not None else None,
            runtime=args[5],
        )
        return get_scanner(scanner_name).scan(ctx)
    try:
        return run_in_sandbox(
            run_scanner_task,
            *args,
            limits=Limits(
                timeout_seconds=settings.scan_timeout_seconds, memory_mb=settings.scan_memory_mb
            ),
            on_progress=report,
            is_cancelled=progress.is_cancelled,
        )
    except SandboxCancelled as exc:
        raise ScanCancelled() from exc


def execute_scan(scan_id: str) -> None:
    """Run every scanner of a scan and persist results. Called by workers."""
    settings = get_settings()
    factory = get_session_factory()
    with factory() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status == ScanStatus.CANCELLED.value:
            return
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = utcnow()
        scanner_names = list(scan.scanners)
        root: Path | None = None
        if scan.snapshot_id:
            snap = db.get(Snapshot, scan.snapshot_id)
            root = snapshot_root(snap) if snap else None
        db.commit()

    progress = _Progress(scan_id)
    outcomes: dict[str, dict[str, Any]] = {}
    failed = 0
    cancelled = False

    for name in scanner_names:
        if progress.is_cancelled():
            cancelled = True
            break
        progress.update(name, state=ScannerState.RUNNING.value, percent=0)
        try:
            with factory() as db:
                scan = db.get(Scan, scan_id)
                result = _run_scanner(settings, name, root, scan, progress)
            with factory() as db:
                scan = db.get(Scan, scan_id)
                only = scan.config.get("only_paths")
                stats = ingest_findings(
                    db,
                    project_id=scan.project_id,
                    scan=scan,
                    scanner=name,
                    raws=result.findings,
                    repository_id=scan.repository_id,
                    complete=result.complete,
                    resolve_scope=(lambda f, o=set(only): f.file_path in o) if only else None,
                )
                db.commit()
            outcomes[name] = {
                "state": ScannerState.COMPLETED.value,
                "findings": len(result.findings),
                "ingest": stats.as_dict(),
                "metadata": result.metadata,
                "warnings": result.warnings,
                "complete": result.complete,
            }
            progress.update(
                name, state=ScannerState.COMPLETED.value, percent=100, findings=len(result.findings)
            )
        except (ScanCancelled, SandboxCancelled):
            cancelled = True
            break
        except (SandboxError, Exception) as exc:  # noqa: BLE001
            failed += 1
            log.exception("scanner failed", extra={"scan_id": scan_id, "scanner": name})
            outcomes[name] = {"state": ScannerState.FAILED.value, "error": str(exc)[:500]}
            progress.update(name, state=ScannerState.FAILED.value, message=str(exc)[:200])

    _finalize(scan_id, outcomes, failed=failed, total=len(scanner_names), cancelled=cancelled)


def _finalize(
    scan_id: str, outcomes: dict[str, Any], *, failed: int, total: int, cancelled: bool
) -> None:
    with get_session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        active = [s.value for s in ACTIVE_STATUSES]
        severities = list(
            db.scalars(
                select(Finding.severity).where(
                    Finding.scan_id == scan.id, Finding.status.in_(active)
                )
            )
        )
        scan.summary = {"severity": severity_counts(severities), "scanners": outcomes}
        if cancelled:
            scan.status = ScanStatus.CANCELLED.value
        elif failed == 0:
            scan.status = ScanStatus.COMPLETED.value
        elif failed == total:
            scan.status = ScanStatus.FAILED.value
            scan.error = "; ".join(o.get("error", "") for o in outcomes.values() if o.get("error"))
        else:
            scan.status = ScanStatus.PARTIAL.value
        scan.finished_at = utcnow()
        db.commit()
    log.info("scan finished", extra={"scan_id": scan_id, "status": scan.status})
