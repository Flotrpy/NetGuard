"""Repository integrations: connect, fetch snapshots, queue branch/PR scans, report results."""

from __future__ import annotations

import secrets
from typing import Any

import httpx
from sqlalchemy.orm import Session

from netguard.config import get_settings
from netguard.core.archive import ArchiveError
from netguard.core.security import encrypt_secret
from netguard.db import get_session_factory, new_id, utcnow
from netguard.enums import ScanStatus
from netguard.logging import get_logger
from netguard.models import Project, Repository, Scan, Snapshot
from netguard.scanners.registry import get_scanner
from netguard.services.gate import format_pr_comment, gate_for_scan, scan_items
from netguard.services.providers import (
    ProviderError,
    client_for,
    validate_external_id,
    validate_ref,
)
from netguard.services.scans import ScanRequestError, create_scan
from netguard.services.snapshots import create_snapshot_from_archive

log = get_logger("integrations")
DEFAULT_SCANNERS = ("sast", "secrets", "dependencies")


def connect_repository(
    db: Session,
    project: Project,
    *,
    provider: str,
    external_id: str,
    token: str,
    http: httpx.Client | None = None,
) -> tuple[Repository, str]:
    """Validate credentials against the provider, then store the repo with an encrypted token.

    Returns (repository, webhook_secret). The webhook secret is shown to the user once.
    """
    if provider not in ("github", "gitlab"):
        raise ProviderError("Unsupported provider")
    validate_external_id(provider, external_id)
    probe = Repository(
        project_id=project.id,
        provider=provider,
        name=external_id,
        external_id=external_id,
        token_encrypted=encrypt_secret(token),
    )
    info = client_for(probe, http).get_repo(external_id)  # proves the token works and can read it
    secret = secrets.token_urlsafe(32)
    probe.url = info["url"]
    probe.default_branch = info["default_branch"]
    probe.webhook_secret = encrypt_secret(secret)
    db.add(probe)
    db.flush()
    return probe, secret


def fetch_snapshot(
    db: Session,
    repo: Repository,
    ref: str,
    *,
    user_id: str | None,
    http: httpx.Client | None = None,
) -> Snapshot:
    settings = get_settings()
    settings.ensure_dirs()
    validate_ref(ref)
    tmp = settings.uploads_dir / f"{new_id()}.fetch"
    try:
        client_for(repo, http).download_archive(
            repo.external_id, ref, tmp, settings.max_upload_mb * 1024 * 1024 * 4
        )
        snap = create_snapshot_from_archive(
            db,
            repo,
            tmp,
            user_id=user_id,
            ref=ref[:200],
            commit_sha=ref
            if len(ref) >= 7 and all(c in "0123456789abcdef" for c in ref.lower())
            else "",
            source="git",
        )
    except ArchiveError as exc:
        raise ProviderError(f"Repository archive rejected: {exc}") from exc
    finally:
        tmp.unlink(missing_ok=True)
    return snap


def queue_repo_scan(
    db: Session,
    repo: Repository,
    *,
    ref: str,
    sha: str = "",
    pr_number: int | None = None,
    user_id: str | None = None,
    trigger: str = "manual",
    scanners: list[str] | None = None,
) -> Scan:
    """Queue a scan of a provider ref. The worker downloads the code when it picks the job up."""
    if repo.provider not in ("github", "gitlab"):
        raise ScanRequestError("Repository is not connected to a provider")
    validate_ref(ref)
    names = [s for s in (scanners or DEFAULT_SCANNERS) if get_scanner(s).info().available]
    ephemeral = pr_number is not None or ref != repo.default_branch
    config: dict[str, Any] = {
        "fetch": {"ref": sha or ref},
        "ephemeral": ephemeral,
        "report": {"sha": sha, "pr": pr_number} if sha else {},
    }
    project = db.get(Project, repo.project_id)
    return create_scan(
        db,
        project=project,
        scanners=names,
        kind="code",
        repository=repo,
        snapshot=None,
        config=config,
        user_id=user_id,
        trigger=trigger,
        ref=f"pr-{pr_number}" if pr_number else ref,
    )


def prepare_scan(scan_id: str, http: httpx.Client | None = None) -> bool:
    """Download the code for a provider scan. Returns False (scan marked failed) on error."""
    with get_session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.snapshot_id or not scan.config.get("fetch"):
            return True
        repo = db.get(Repository, scan.repository_id)
        try:
            snap = fetch_snapshot(
                db, repo, scan.config["fetch"]["ref"], user_id=scan.created_by, http=http
            )
            scan.snapshot_id = snap.id
            db.commit()
            return True
        except (ProviderError, ValueError) as exc:
            scan.status = ScanStatus.FAILED.value
            scan.error = f"Could not fetch code: {exc}"[:500]
            scan.finished_at = utcnow()
            db.commit()
            return False


def report_scan(scan_id: str, http: httpx.Client | None = None) -> None:
    """Post the gate result to the provider (commit status + PR/MR comment). Never raises."""
    with get_session_factory()() as db:
        scan = db.get(Scan, scan_id)
        report = (scan.config or {}).get("report") if scan else None
        if not report or not report.get("sha") or scan.status not in ("completed", "partial"):
            return
        repo = db.get(Repository, scan.repository_id)
        outcome: dict[str, Any] = {"posted": False}
        try:
            result = gate_for_scan(db, scan)
            items = scan_items(db, scan)
            client = client_for(repo, http)
            settings = get_settings()
            link = (
                f"{settings.public_url.rstrip('/')}/projects/{scan.project_id}"
                if settings.public_url
                else ""
            )
            desc = (
                "No blocking findings"
                if result.passed
                else "; ".join(v.message for v in result.violations)[:130]
            )
            client.set_status(
                repo.external_id,
                report["sha"],
                "success" if result.passed else "failure",
                desc,
                link,
            )
            if report.get("pr"):
                client.upsert_pr_comment(
                    repo.external_id,
                    int(report["pr"]),
                    format_pr_comment(scan, result, items, link),
                )
            outcome = {"posted": True, "passed": result.passed}
        except (ProviderError, Exception) as exc:  # noqa: BLE001 - reporting must not fail the scan
            log.warning(
                "could not report scan", extra={"scan_id": scan_id, "error": str(exc)[:200]}
            )
            outcome = {"posted": False, "error": str(exc)[:200]}
        summary = dict(scan.summary or {})
        summary["report"] = outcome
        scan.summary = summary
        db.commit()
