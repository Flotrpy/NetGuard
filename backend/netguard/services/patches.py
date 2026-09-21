"""Patch lifecycle: generate -> review -> apply -> rescan -> verify.

Guarantees:
* A patch is only a *proposal* until a user applies it; nothing is modified silently.
* Applying never mutates the original snapshot: it creates a new one (history is preserved).
* "Fixed" is never inferred from the existence of a patch. Verification is a real rescan whose
  result decides between VERIFIED FIXED, STILL DETECTED and UNABLE TO VERIFY.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.core.files import confined_path
from netguard.db import get_session_factory, utcnow
from netguard.enums import ACTIVE_STATUSES, FindingStatus, ScanStatus, VerificationState
from netguard.models import Finding, Patch, Repository, Scan, Snapshot
from netguard.scanners.base import ScanContext
from netguard.scanners.registry import get_scanner
from netguard.services.ai import fixers, llm
from netguard.services.findings import add_event, set_status
from netguard.services.scans import create_scan
from netguard.services.snapshots import create_snapshot_from_directory, snapshot_root

MAX_FILE_BYTES = 512 * 1024
MAX_CHANGED_LINES = 80
MAX_REPLACEMENTS = 5


class PatchError(Exception):
    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def base_snapshot_for(db: Session, finding: Finding) -> Snapshot:
    scan = db.get(Scan, finding.scan_id) if finding.scan_id else None
    snap = db.get(Snapshot, scan.snapshot_id) if scan and scan.snapshot_id else None
    if snap is None:
        raise PatchError("This finding is not tied to a code snapshot, so it cannot be patched.")
    return snap


def make_diff(path: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def changed_line_count(old: str, new: str) -> int:
    sm = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
    return sum(max(i2 - i1, j2 - j1) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal")


def check_syntax(path: str, text: str) -> str | None:
    """Return an error string if a patched file would be syntactically invalid."""
    try:
        if path.endswith(".py"):
            ast.parse(text)
        elif path.endswith(".json"):
            json.loads(text)
    except (SyntaxError, ValueError) as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


AI_SYSTEM = """You fix ONE security finding in ONE source file for NetGuard, a defensive platform.
Rules:
- Make the smallest change that removes the vulnerability while preserving intended behaviour.
- Return ONLY a JSON object: {"explanation": str, "replacements": [{"old": str, "new": str}],
  "caveats": [str]}.
- Each "old" must be an EXACT, contiguous substring of the provided file that appears exactly once.
  Do not rewrite the whole file. At most %d replacements and %d changed lines in total.
- Do not add dependencies unless unavoidable; if you do, say so in caveats.
- Never include real secrets. If you cannot fix it safely, return an empty replacements list and
  explain why in "explanation".
- caveats must honestly list anything that may change behaviour or that you could not verify."""


def _ai_fix(finding: Finding, text: str) -> fixers.FixResult | None:
    lines = text.split("\n")
    if len(lines) <= 400:
        excerpt = text
    else:
        lo, hi = max(0, finding.line - 120), min(len(lines), finding.line + 120)
        excerpt = "\n".join(lines[lo:hi])
    prompt = (
        f"Finding: {finding.title} (rule {finding.rule_id}, {finding.cwe})\n"
        f"File: {finding.file_path}, flagged line: {finding.line}\n"
        f"Why it is a problem: {finding.description}\nSuggested remediation: {finding.remediation}\n"
        f"\nFile content{' (excerpt)' if excerpt is not text else ''}:\n<file>\n{excerpt}\n</file>"
    )
    reply = llm.complete(
        AI_SYSTEM % (MAX_REPLACEMENTS, MAX_CHANGED_LINES), prompt, max_tokens=6000, effort="high"
    )
    data = llm.extract_json(reply.text)
    reps = data.get("replacements")
    if not isinstance(reps, list) or not reps:
        raise PatchError(
            f"The AI could not produce a safe automatic fix: {str(data.get('explanation', ''))[:300]}"
        )
    if len(reps) > MAX_REPLACEMENTS:
        raise PatchError("The AI proposed too many edits; refusing to apply a broad change.")
    new_text = text
    for r in reps:
        old, new = r.get("old"), r.get("new")
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            raise PatchError("The AI returned a malformed edit.")
        if new_text.count(old) != 1:
            raise PatchError("The AI's edit did not match the file exactly once; nothing was changed.")
        new_text = new_text.replace(old, new, 1)
    caveats = [str(c)[:400] for c in (data.get("caveats") or [])][:6]
    caveats.append("This patch was written by AI. Review the diff carefully before applying.")
    return fixers.FixResult(new_text, str(data.get("explanation", ""))[:1500], caveats)


def preflight(finding: Finding, rel_path: str, new_text: str) -> dict[str, Any]:
    """Quick local check: does the detection rule still fire on the patched file?

    This is a *preview only*. It is not verification: that requires applying the patch and
    rescanning the whole snapshot.
    """
    if finding.scanner not in ("sast", "secrets"):
        return {"performed": False, "note": "Preflight is only available for code and secret findings."}
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new_text, encoding="utf-8")
        ctx = ScanContext(root=Path(tmp), runtime={"fingerprint_salt": "preflight"})
        result = get_scanner(finding.scanner).scan(ctx)
    still = [f for f in result.findings if f.rule_id == finding.rule_id]
    return {
        "performed": True,
        "rule_still_triggers": bool(still),
        "note": (
            "The detection rule still matches the patched file."
            if still
            else "The detection rule no longer matches the patched file (preview only, not verified)."
        ),
    }


def generate_patch(
    db: Session, finding: Finding, *, user_id: str | None, use_ai: bool = True
) -> Patch:
    if not finding.file_path:
        raise PatchError("This finding has no file to patch.")
    snap = base_snapshot_for(db, finding)
    try:
        target = confined_path(snapshot_root(snap), finding.file_path)
    except ValueError as exc:
        raise PatchError("Invalid file path.") from exc
    if not target.is_file() or target.stat().st_size > MAX_FILE_BYTES:
        raise PatchError("The file is missing or too large to patch automatically.")
    text = target.read_bytes().decode("utf-8", errors="strict") if _is_utf8(target) else None
    if text is None:
        raise PatchError("Only UTF-8 text files can be patched.")

    result: fixers.FixResult | None = None
    generator = "rule"
    fixer = fixers.get_fixer(finding.rule_id)
    if fixer:
        result = fixer(finding, text)
    if result is None:
        if not use_ai:
            raise PatchError("No automatic rule-based fix exists for this finding.")
        if not llm.is_configured():
            raise PatchError(
                "No rule-based fix exists for this finding and AI fixes are not configured "
                "(set ANTHROPIC_API_KEY). Follow the remediation guidance instead."
            )
        generator = "ai"
        try:
            result = _ai_fix(finding, text)
        except llm.LlmUnavailable as exc:
            raise PatchError(f"AI fix unavailable: {exc}", status=503) from exc
    assert result is not None
    if result.new_text == text:
        raise PatchError("The proposed fix changes nothing.")
    if changed_line_count(text, result.new_text) > MAX_CHANGED_LINES:
        raise PatchError("The proposed fix is too large to review safely; refusing.")
    syntax = check_syntax(finding.file_path, result.new_text)
    if syntax:
        raise PatchError(f"The proposed fix would break the file's syntax ({syntax}); discarded.")

    pre = preflight(finding, finding.file_path, result.new_text)
    patch = Patch(
        finding_id=finding.id,
        generator=generator,
        explanation=result.explanation,
        diff=make_diff(finding.file_path, text, result.new_text),
        file_path=finding.file_path,
        base_sha256=_sha(text),
        base_snapshot_id=snap.id,
        new_content=result.new_text,
        caveats=result.caveats,
        verification={"preflight": pre},
        created_by=user_id,
    )
    db.add(patch)
    db.flush()
    add_event(db, finding, "patch_generated", f"{generator} patch proposed for review",
              data={"patch_id": patch.id, "generator": generator}, actor_id=user_id)
    return patch


def _is_utf8(path: Path) -> bool:
    try:
        path.read_bytes().decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def apply_patch(db: Session, patch: Patch, finding: Finding, *, user_id: str | None) -> Snapshot:
    """Create a new snapshot containing the patched file. The base snapshot is untouched."""
    if patch.status != "proposed":
        raise PatchError(f"Patch is already {patch.status}.", status=409)
    base = db.get(Snapshot, patch.base_snapshot_id) if patch.base_snapshot_id else None
    if base is None:
        raise PatchError("The snapshot this patch was based on no longer exists.", status=409)
    latest = db.scalar(
        select(Snapshot)
        .where(Snapshot.repository_id == base.repository_id)
        .order_by(Snapshot.created_at.desc())
        .limit(1)
    )
    if latest is not None and latest.id != base.id:
        raise PatchError(
            "The repository has a newer snapshot than the one this patch was made for. "
            "Rescan and generate a fresh patch.", status=409)
    current = confined_path(snapshot_root(base), patch.file_path).read_bytes().decode("utf-8")
    if _sha(current) != patch.base_sha256:
        raise PatchError("The file changed since the patch was generated.", status=409)
    repo = db.get(Repository, base.repository_id)
    if repo is None:
        raise PatchError("Repository not found.", status=409)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "tree"
        shutil.copytree(snapshot_root(base), work, symlinks=False)
        confined_path(work, patch.file_path).write_bytes(patch.new_content.encode("utf-8"))
        snap = create_snapshot_from_directory(
            db, repo, work, user_id=user_id, ref=f"patch:{patch.id[:8]}", source="patch",
            parent_id=base.id,
        )
    patch.status = "applied"
    patch.applied_snapshot_id = snap.id
    patch.applied_at = utcnow()
    finding.verification = VerificationState.NONE.value
    if finding.status in (FindingStatus.OPEN.value, FindingStatus.CONFIRMED.value):
        set_status(db, finding, FindingStatus.IN_PROGRESS, actor_id=user_id,
                   note="Patch applied; awaiting verification rescan")
    add_event(db, finding, "patch_applied", "Patch applied to a new snapshot",
              data={"patch_id": patch.id, "snapshot_id": snap.id}, actor_id=user_id)
    return snap


def request_verification(
    db: Session, finding: Finding, patch: Patch | None, *, user_id: str | None
) -> Scan:
    """Queue a rescan of the (patched) snapshot; the verdict is computed when it finishes."""
    project_repo = db.get(Repository, finding.repository_id) if finding.repository_id else None
    if project_repo is None:
        raise PatchError("Only repository findings can be re-verified.")
    if patch is not None and patch.applied_snapshot_id:
        snap = db.get(Snapshot, patch.applied_snapshot_id)
    else:
        snap = db.scalar(
            select(Snapshot).where(Snapshot.repository_id == project_repo.id)
            .order_by(Snapshot.created_at.desc()).limit(1)
        )
    if snap is None:
        raise PatchError("No snapshot available to rescan.")
    config: dict[str, Any] = {"finding_id": finding.id, "patch_id": patch.id if patch else None}
    if finding.scanner in ("sast", "secrets") and finding.file_path:
        config["only_paths"] = [finding.file_path]
    from netguard.models import Project

    scan = create_scan(
        db, project=db.get(Project, finding.project_id), scanners=[finding.scanner], kind="code",
        repository=project_repo, snapshot=snap, config=config, user_id=user_id, trigger="verify",
        ref=f"verify:{finding.id[:8]}",
    )
    add_event(db, finding, "verification_requested", "Verification rescan queued",
              data={"scan_id": scan.id, "patch_id": patch.id if patch else None}, actor_id=user_id)
    return scan


def evaluate_verification(scan_id: str) -> dict[str, Any] | None:
    """Compute and store the verification verdict once a verify scan has finished."""
    with get_session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.trigger != "verify":
            return None
        finding = db.get(Finding, scan.config.get("finding_id", ""))
        if finding is None:
            return None
        patch = db.get(Patch, scan.config["patch_id"]) if scan.config.get("patch_id") else None
        verdict = _verdict(db, scan, finding, patch)
        finding.verification = verdict["state"]
        if patch is not None:
            patch.verification = {**(patch.verification or {}), **verdict}
        message = {
            VerificationState.VERIFIED_FIXED.value: "Verified fixed: the rescan no longer detects it",
            VerificationState.STILL_DETECTED.value: "Still detected after rescan",
            VerificationState.UNABLE_TO_VERIFY.value: "Unable to verify",
        }[verdict["state"]]
        add_event(db, finding, "verified", f"{message}. {verdict['summary']}", data=verdict)
        if verdict["state"] == VerificationState.STILL_DETECTED.value and \
                finding.status == FindingStatus.FIXED.value:
            set_status(db, finding, FindingStatus.OPEN, actor_id=None, note="Reopened by verification")
        db.commit()
        return verdict


def _verdict(db: Session, scan: Scan, finding: Finding, patch: Patch | None) -> dict[str, Any]:
    base = {"scan_id": scan.id, "checked_at": utcnow().isoformat(), "checks": [], "introduced": []}

    def unable(reason: str) -> dict[str, Any]:
        return {**base, "state": VerificationState.UNABLE_TO_VERIFY.value, "summary": reason}

    if scan.status not in (ScanStatus.COMPLETED.value, ScanStatus.PARTIAL.value):
        return unable(f"The verification scan did not complete ({scan.status}). {scan.error}".strip())
    outcome = (scan.summary or {}).get("scanners", {}).get(finding.scanner, {})
    if outcome.get("state") != "completed":
        return unable(f"The {finding.scanner} scanner did not complete.")
    if not outcome.get("complete", True):
        return unable(
            "The scanner could not analyse everything (for example vulnerability data was "
            "unreachable), so absence of the finding proves nothing."
        )
    db.refresh(finding)
    started = scan.started_at.replace(tzinfo=None) if scan.started_at else None

    def since_start(dt) -> bool:
        return started is not None and dt is not None and dt.replace(tzinfo=None) >= started

    if finding.status in [s.value for s in ACTIVE_STATUSES] and since_start(finding.last_seen):
        detected, gone = True, False
    elif finding.status == FindingStatus.FIXED.value and since_start(finding.resolved_at):
        detected, gone = False, True
    else:
        return unable(
            f"The finding is '{finding.status}' and was not re-evaluated by this scan."
        )
    introduced = []
    if patch is not None:
        rows = db.scalars(
            select(Finding).where(Finding.scan_id == scan.id, Finding.file_path == patch.file_path,
                                  Finding.id != finding.id)
        )
        introduced = [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity, "line": f.line}
            for f in rows if since_start(f.first_seen) and f.severity in ("critical", "high", "medium")
        ]
    syntax_ok = True
    if patch is not None:
        syntax_ok = check_syntax(patch.file_path, patch.new_content) is None
    checks = [
        {"name": "Original finding no longer detected", "passed": gone},
        {"name": "No new medium+ findings introduced in the patched file", "passed": not introduced},
        {"name": "Patched file is syntactically valid", "passed": syntax_ok},
    ]
    if gone and not introduced and syntax_ok:
        state = VerificationState.VERIFIED_FIXED.value
        summary = "The scanner re-ran on the patched code and the finding is gone."
        if finding.scanner == "secrets":
            summary += " The credential itself must still be rotated: it was exposed."
    else:
        state = VerificationState.STILL_DETECTED.value
        summary = (
            "The finding is still detected after the change."
            if detected
            else f"The original finding is gone but the change introduced {len(introduced)} new finding(s)."
        )
    return {**base, "state": state, "summary": summary, "checks": checks, "introduced": introduced}
