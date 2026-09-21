from netguard.db import get_session_factory
from netguard.enums import Confidence, Severity
from netguard.models import Scan
from netguard.services.findings import ingest_findings
from tests.helpers import raw


def seed(client, items):
    """Create a project and ingest ``items`` (RawFinding) directly through the service."""
    client.register()
    project = client.post("/api/projects", json={"name": "P"}).json()
    with get_session_factory()() as db:
        scan = Scan(project_id=project["id"], scanners=["sast"])
        db.add(scan)
        db.flush()
        for scanner, findings in items.items():
            ingest_findings(
                db, project_id=project["id"], scan=scan, scanner=scanner, raws=findings
            )
        db.commit()
    return project


def test_list_filter_and_sort(client):
    p = seed(
        client,
        {
            "sast": [
                raw(rule="sqli", file="db/users.py", code="q1", sev=Severity.CRITICAL,
                    title="SQL Injection", language="python", category="injection"),
                raw(rule="xss", file="web/view.js", code="q2", sev=Severity.MEDIUM,
                    title="XSS", language="javascript", category="xss"),
            ],
            "secrets": [
                raw(rule="key", file="cfg/.env", code="q3", sev=Severity.HIGH, title="API key",
                    confidence=Confidence.LOW)
            ],
        },
    )
    all_ = client.get("/api/findings", params={"project_id": p["id"]}).json()
    assert all_["total"] == 3
    assert [f["severity"] for f in all_["items"]] == ["critical", "high", "medium"]  # severity desc
    assert all_["items"][0]["detection_source"] == "SAST"
    assert {f["detection_source"] for f in all_["items"]} == {"SAST", "Secret Scanner"}

    def ids(**params):
        r = client.get("/api/findings", params={"project_id": p["id"], **params})
        assert r.status_code == 200, r.text
        return sorted(f["title"] for f in r.json()["items"])

    assert ids(severity="critical,high") == ["API key", "SQL Injection"]
    assert ids(scanner="secrets") == ["API key"]
    assert ids(language="javascript") == ["XSS"]
    assert ids(category="injection") == ["SQL Injection"]
    assert ids(file="users") == ["SQL Injection"]
    assert ids(q="xss") == ["XSS"]
    assert ids(min_confidence="medium") == ["SQL Injection", "XSS"]
    assert ids(status="fixed") == []
    asc = client.get("/api/findings", params={"project_id": p["id"], "sort": "severity", "order": "asc"})
    assert asc.json()["items"][0]["severity"] == "medium"


def test_pagination_and_validation(client):
    p = seed(client, {"sast": [raw(code=f"c{i}", file=f"f{i}.py") for i in range(5)]})
    page = client.get("/api/findings", params={"project_id": p["id"], "limit": 2, "offset": 4}).json()
    assert page["total"] == 5 and len(page["items"]) == 1
    assert client.get("/api/findings", params={"severity": "bogus"}).status_code == 422
    assert client.get("/api/findings", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/findings", params={"sort": "password"}).status_code == 422
    assert client.get("/api/findings", params={"limit": 100000}).status_code == 422


def test_facets(client):
    p = seed(client, {"sast": [raw(language="python", category="injection", code="a")]})
    facets = client.get("/api/findings/facets", params={"project_id": p["id"]}).json()
    assert facets["language"] == ["python"] and facets["scanner"] == ["sast"]


def test_detail_status_change_and_history(client):
    p = seed(client, {"sast": [raw(description="desc", remediation="fix it", code="a")]})
    fid = client.get("/api/findings", params={"project_id": p["id"]}).json()["items"][0]["id"]
    detail = client.get(f"/api/findings/{fid}").json()
    assert detail["description"] == "desc" and detail["events"][0]["kind"] == "detected"

    r = client.patch(f"/api/findings/{fid}", json={"status": "confirmed", "note": "reproduced"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed"
    client.patch(f"/api/findings/{fid}", json={"status": "false_positive"})
    client.post(f"/api/findings/{fid}/comments", json={"message": "test data only"})
    kinds = [e["kind"] for e in client.get(f"/api/findings/{fid}").json()["events"]]
    assert kinds == ["detected", "status_changed", "status_changed", "comment"]
    assert client.patch(f"/api/findings/{fid}", json={"status": "nonsense"}).status_code == 422


def test_findings_are_isolated_between_users(client, make_client):
    p = seed(client, {"sast": [raw(code="a")]})
    fid = client.get("/api/findings", params={"project_id": p["id"]}).json()["items"][0]["id"]
    other = make_client("other@example.com")
    assert other.get(f"/api/findings/{fid}").status_code == 404
    assert other.patch(f"/api/findings/{fid}", json={"status": "fixed"}).status_code == 404
    assert other.get("/api/findings").json()["total"] == 0
    assert other.get("/api/findings", params={"project_id": p["id"]}).status_code == 404


def test_viewer_cannot_change_status(client, make_client):
    p = seed(client, {"sast": [raw(code="a")]})
    viewer = make_client("viewer@example.com")
    client.post(f"/api/projects/{p['id']}/members", json={"email": "viewer@example.com", "role": "viewer"})
    fid = client.get("/api/findings", params={"project_id": p["id"]}).json()["items"][0]["id"]
    assert viewer.get(f"/api/findings/{fid}").status_code == 200
    assert viewer.patch(f"/api/findings/{fid}", json={"status": "fixed"}).status_code == 403


def test_risk_methodology_endpoint(client):
    client.register()
    m = client.get("/api/risk/methodology").json()
    assert "formula" in m and m["severity_base"]["critical"] == 10.0
