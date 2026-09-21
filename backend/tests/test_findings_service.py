from sqlalchemy import select

from netguard.enums import FindingStatus, Severity
from netguard.models import Asset, Finding
from netguard.scanners.base import AssetRef
from netguard.services.findings import ingest_findings, set_status
from tests.helpers import fresh_db, make_project, make_scan, raw


def _ingest(db, project, raws, scan=None, **kw):
    scan = scan or make_scan(db, project)
    return ingest_findings(
        db, project_id=project.id, scan=scan, scanner="sast", raws=raws, **kw
    ), scan


def test_new_findings_are_created_with_history_and_risk():
    db = fresh_db()
    project = make_project(db)
    stats, _ = _ingest(db, project, [raw(), raw(rule="r2", code="y = 2")])
    assert stats.new == 2
    f = db.scalar(select(Finding).where(Finding.rule_id == "r1"))
    assert f.status == "open" and f.risk_score > 0
    assert [e.kind for e in f.events] == ["detected"]


def test_rescan_deduplicates_and_updates_last_seen():
    db = fresh_db()
    project = make_project(db)
    _ingest(db, project, [raw(line=3)])
    stats, _ = _ingest(db, project, [raw(line=30)])  # same code, line moved
    assert stats.new == 0 and stats.seen_again == 1
    assert db.scalars(select(Finding)).all().__len__() == 1
    assert db.scalar(select(Finding)).line == 30


def test_identical_snippets_in_one_file_get_distinct_findings():
    db = fresh_db()
    project = make_project(db)
    stats, _ = _ingest(db, project, [raw(line=1, code="eval(x)"), raw(line=9, code="eval(x)")])
    assert stats.new == 2


def test_complete_rescan_resolves_missing_findings_and_regressions_reopen():
    db = fresh_db()
    project = make_project(db)
    _ingest(db, project, [raw(code="a"), raw(code="b")])
    stats, _ = _ingest(db, project, [raw(code="a")])
    assert stats.resolved == 1
    fixed = db.scalar(select(Finding).where(Finding.status == "fixed"))
    assert fixed.resolved_at is not None
    assert [e.kind for e in fixed.events] == ["detected", "resolved"]

    stats, _ = _ingest(db, project, [raw(code="a"), raw(code="b")])
    assert stats.reopened == 1
    db.expire_all()
    reopened = db.get(Finding, fixed.id)
    assert reopened.status == "open" and reopened.events[-1].kind == "reopened"


def test_incomplete_scan_never_resolves_findings():
    db = fresh_db()
    project = make_project(db)
    _ingest(db, project, [raw(code="a")])
    stats, _ = _ingest(db, project, [], complete=False)
    assert stats.resolved == 0
    assert db.scalar(select(Finding)).status == "open"


def test_triaged_findings_are_not_auto_resolved_or_reopened():
    db = fresh_db()
    project = make_project(db)
    _ingest(db, project, [raw(code="a")])
    f = db.scalar(select(Finding))
    set_status(db, f, FindingStatus.FALSE_POSITIVE, actor_id=None, note="test code")
    stats, _ = _ingest(db, project, [])
    assert stats.resolved == 0
    assert db.get(Finding, f.id).status == "false_positive"
    stats, _ = _ingest(db, project, [raw(code="a")])
    assert db.get(Finding, f.id).status == "false_positive"


def test_resolution_is_scoped_to_scanner_and_repository():
    db = fresh_db()
    project = make_project(db)
    scan = make_scan(db, project)
    ingest_findings(db, project_id=project.id, scan=scan, scanner="secrets", raws=[raw(code="s")])
    _ingest(db, project, [])  # SAST scan with no findings must not touch secrets findings
    assert db.scalar(select(Finding)).status == "open"


def test_assets_are_upserted_once():
    db = fresh_db()
    project = make_project(db)
    ref = AssetRef("host", "10.0.0.5", "web-01")
    _ingest(db, project, [raw(code="a", asset=ref), raw(code="b", asset=ref)])
    assert len(db.scalars(select(Asset)).all()) == 1


def test_severity_change_is_reflected_on_rescan():
    db = fresh_db()
    project = make_project(db)
    _ingest(db, project, [raw(code="a", sev=Severity.LOW)])
    _ingest(db, project, [raw(code="a", sev=Severity.CRITICAL)])
    assert db.scalar(select(Finding)).severity == "critical"
