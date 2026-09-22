import csv
import io
import json

from netguard.db import get_session_factory
from netguard.enums import Severity
from netguard.models import Scan
from netguard.services.findings import ingest_findings
from tests.helpers import raw


def seed(client):
    client.register()
    project = client.post("/api/projects", json={"name": "P"}).json()
    with get_session_factory()() as db:
        scan = Scan(project_id=project["id"], scanners=["sast"])
        db.add(scan)
        db.flush()
        ingest_findings(db, project_id=project["id"], scan=scan, scanner="sast", raws=[
            raw(rule="sqli", file="db/users.py", code="q1", sev=Severity.CRITICAL, title="SQL Injection"),
            raw(rule="xss", file="web/view.js", code="q2", sev=Severity.LOW, title="XSS"),
        ])
        db.commit()
    return project


def test_report_requires_project_access(client):
    seed(client)
    r = client.get("/api/projects/does-not-exist/report")
    assert r.status_code == 404


def test_json_report_contains_findings_and_summary(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report", params={"format": "json"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    data = json.loads(r.content)
    assert data["project"]["name"] == "P"
    assert {f["title"] for f in data["findings"]} == {"SQL Injection", "XSS"}
    assert data["summary"]["total_findings"] == 2


def test_min_severity_filters_findings(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report",
                    params={"format": "json", "min_severity": "high"})
    data = json.loads(r.content)
    assert [f["title"] for f in data["findings"]] == ["SQL Injection"]


def test_csv_report_lists_one_row_per_finding(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report", params={"format": "csv"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][0] == "severity"
    assert len(rows) == 3


def test_html_report_renders_title_and_escapes_content(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report",
                    params={"format": "html", "title": "<script>alert(1)</script>"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert b"<script>alert(1)</script>" not in r.content
    assert b"SQL Injection" in r.content


def test_pdf_report_returns_pdf_bytes(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report", params={"format": "pdf"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"


def test_unknown_format_is_rejected(client):
    project = seed(client)
    r = client.get(f"/api/projects/{project['id']}/report", params={"format": "xml"})
    assert r.status_code == 422
