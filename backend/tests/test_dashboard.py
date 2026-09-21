from datetime import UTC, datetime, timedelta

from netguard.api.dashboard import compute_trend
from netguard.db import get_session_factory
from netguard.enums import Severity
from netguard.models import Finding, Scan
from tests.helpers import raw
from tests.test_findings_api import seed


def test_empty_dashboard_is_honest(client):
    client.register()
    d = client.get("/api/dashboard").json()
    assert d["severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert d["totals"]["remediation_progress"] is None  # no fake "100% secure"
    statuses = {m["scanner"]: m["status"] for m in d["modules"]}
    assert statuses["packets"] == "unavailable"
    assert all(s in ("unavailable", "not_scanned") for s in statuses.values())
    assert d["recent_scans"] == [] and len(d["trend"]) == 30


def test_counts_modules_and_progress(client, fake_scanner):
    p = seed(
        client,
        {
            "sast": [raw(code="a", sev=Severity.HIGH), raw(code="b", sev=Severity.LOW)],
            "secrets": [raw(code="c", sev=Severity.CRITICAL)],
        },
    )
    with get_session_factory()() as db:
        scan = db.query(Scan).first()
        scan.status = "completed"
        scan.finished_at = datetime.now(UTC)
        scan.summary = {"scanners": {"sast": {"state": "completed"}}}
        db.query(Finding).filter(Finding.rule_id == "r1", Finding.severity == "low").update(
            {"status": "fixed", "resolved_at": datetime.now(UTC)}
        )
        db.commit()
    d = client.get("/api/dashboard", params={"project_id": p["id"]}).json()
    assert d["severity"]["critical"] == 1 and d["severity"]["high"] == 1 and d["severity"]["low"] == 0
    assert d["totals"] == {**d["totals"], "active": 2, "fixed": 1, "total": 3}
    assert d["totals"]["remediation_progress"] == round(1 / 3, 3)
    modules = {m["scanner"]: m for m in d["modules"]}
    assert modules["sast"]["status"] == "attention" and modules["sast"]["open_findings"] == 1
    assert modules["secrets"]["status"] == "not_scanned"  # findings exist, no completed scan record
    assert modules["packets"]["status"] == "unavailable"  # planned scanner: never shown as OK
    assert len(d["recently_fixed"]) == 1


def test_trend_tracks_running_active_total():
    now = datetime.now(UTC)
    rows = [
        (now - timedelta(days=5), now - timedelta(days=2)),
        (now - timedelta(days=5), None),
        (now - timedelta(days=40), None),  # opened before the window
    ]
    trend = compute_trend(rows, days=7)
    by_date = {t["date"]: t for t in trend}
    assert trend[0]["active"] == 1  # only the old finding at the start of the window
    assert by_date[(now - timedelta(days=5)).date().isoformat()]["opened"] == 2
    assert trend[-1]["active"] == 2 and trend[-1]["resolved"] == 0
    assert sum(t["resolved"] for t in trend) == 1


def test_dashboard_scoped_to_accessible_projects(client, make_client):
    seed(client, {"sast": [raw(code="a")]})
    other = make_client("other@example.com")
    assert other.get("/api/dashboard").json()["severity"]["high"] == 0
    assert client.get("/api/dashboard").json()["severity"]["high"] == 1
