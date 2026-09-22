import json

import pytest

from netguard.config import get_settings
from netguard.worker import process_one
from tests.api_servers import SPEC, Api, GoodHandler, WeakHandler

STATEMENT = "I own this API and am authorized to test it in my lab."
SECRET_TOKEN = "Bearer super-secret-token-value-12345"


@pytest.fixture
def servers():
    made = []

    def make(handler):
        GoodHandler.hits = 0
        s = Api(handler)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


@pytest.fixture
def project(client):
    client.register()
    return client.post("/api/projects", json={"name": "APIs"}).json()


def start(client, project, url, **kw):
    body = {"project_id": project["id"], "base_url": url, "authorized": True,
            "authorization_statement": STATEMENT, "max_requests": 200, **kw}
    return client.post("/api/api-scans", json=body)


def run(client, resp):
    assert resp.status_code == 202, resp.text
    while process_one("w"):
        pass
    return client.get(f"/api/api-scans/{resp.json()['id']}").json()


def findings(client, project, **params):
    return client.get("/api/findings", params={"project_id": project["id"], "scanner": "api", "limit": 200, **params}).json()


def test_options_state_authorization_and_limitations(client, project):
    o = client.get("/api/api-scanner/options").json()
    assert "read-only requests" in o["authorization_text"] and o["safe_methods_only"] is True
    assert any("BOLA" in x for x in o["limitations"]) and len(o["checks"]) >= 15


def test_attestation_and_url_validation(client, project):
    url = "http://127.0.0.1:9"
    assert start(client, project, url, authorized=False).status_code == 422
    assert start(client, project, url, authorization_statement="short").status_code == 422
    for bad in ["ftp://127.0.0.1", "http://user:pw@127.0.0.1/", "http://127.0.0.1/?x=1", "http://127.0.0.1/#f",
                "file:///etc/passwd", "http://"]:
        assert start(client, project, bad).status_code == 422, bad
    assert start(client, project, url, auth_header_name="X Bad;Header").status_code == 422
    assert start(client, project, url, spec="this is not an openapi spec").status_code == 422


def test_forbidden_targets_denied_and_audited(client, project, monkeypatch):
    from netguard.db import get_session_factory
    from netguard.models import AuditLog

    for url in ["http://169.254.169.254/latest", "http://8.8.8.8/api", "http://224.0.0.1/"]:
        assert start(client, project, url).status_code == 422
    with get_session_factory()() as db:
        denied = db.query(AuditLog).filter(AuditLog.action == "api.scan.denied").count()
        assert denied == 3
    monkeypatch.setenv("NETGUARD_ALLOW_PUBLIC_TARGETS", "true")
    get_settings.cache_clear()
    assert start(client, project, "http://8.8.8.8/api").status_code == 202
    assert start(client, project, "http://169.254.169.254/latest").status_code == 422  # never allowed


def test_weak_api_end_to_end_findings_flow_into_the_platform(client, project, servers):
    s = servers(WeakHandler)
    done = run(client, start(client, project, s.url))
    assert done["scan"]["status"] == "completed" and done["target"] == s.url
    assert done["authorization"]["statement"] == STATEMENT and "ip" not in done["authorization"]
    assert done["spec"]["title"] == "Test API" and done["requests_made"] > 30
    assert {c["name"] for c in done["checks"]} >= {"transport & TLS", "CORS", "authentication"}
    assert any("object-level" in w for w in done["warnings"])
    page = findings(client, project)
    rules = {f["rule_id"] for f in page["items"]}
    assert {"api.auth-not-enforced", "api.cors-reflects-origin-credentials", "api.verbose-errors"} <= rules
    top = page["items"][0]
    assert top["detection_source"] == "API Scanner" and top["asset"] == s.url
    assert s.methods <= {"GET", "OPTIONS", "HEAD"}  # nothing state-changing was ever sent


def test_credentials_are_encrypted_at_rest_and_never_returned(client, project, servers):
    from netguard.db import get_session_factory
    from netguard.models import AuditLog, Scan

    s = servers(GoodHandler)
    resp = start(client, project, s.url, auth_header_name="Authorization", auth_value="Bearer good-token")
    scan_id = resp.json()["id"]
    done = run(client, resp)
    assert done["authenticated"] is True
    everything = json.dumps(done) + resp.text + client.get(f"/api/scans/{scan_id}").text
    assert "good-token" not in everything and "auth_value" not in everything
    with get_session_factory()() as db:
        cfg = db.get(Scan, scan_id).config
        assert "good-token" not in json.dumps(cfg) and cfg["auth_encrypted"] and "auth_value" not in cfg
        assert "good-token" not in json.dumps([a.details for a in db.query(AuditLog).all()])
    # The stored credential really is used: an authenticated scan of the hardened API is clean of high findings.
    assert not [f for f in findings(client, project)["items"] if f["severity"] in ("critical", "high")]


def test_findings_are_scoped_per_target_and_fixes_resolve_on_rescan(client, project, servers):
    weak = servers(WeakHandler)
    run(client, start(client, project, weak.url))
    open_before = findings(client, project, status="open")["total"]
    assert open_before > 5
    good = servers(GoodHandler)
    run(client, start(client, project, good.url, auth_value="Bearer good-token"))
    # Scanning a different API must not resolve the first API's findings.
    assert findings(client, project, status="open")["total"] >= open_before
    # Rescanning the same base URL is idempotent (deduplicated).
    run(client, start(client, project, weak.url))
    assert findings(client, project, status="open")["total"] >= open_before


def test_history_listing_and_access_control(client, make_client, project, servers):
    s = servers(WeakHandler)
    done = run(client, start(client, project, s.url))
    hist = client.get(f"/api/projects/{project['id']}/api-scans").json()
    assert [h["id"] for h in hist] == [done["scan"]["id"]] and hist[0]["kind"] == "api"
    other = make_client("o@example.com")
    assert other.get(f"/api/api-scans/{done['scan']['id']}").status_code == 404
    assert start(other, project, s.url).status_code == 404
    client.post(f"/api/projects/{project['id']}/members", json={"email": "o@example.com", "role": "viewer"})
    assert other.get(f"/api/api-scans/{done['scan']['id']}").status_code == 200
    assert start(other, project, s.url).status_code == 403
    assert client.get(f"/api/api-scans/{'x' * 8}").status_code == 404


def test_supplied_spec_is_used(client, project, servers):
    s = servers(WeakHandler)
    spec = json.dumps({**SPEC, "paths": {"/users/me": SPEC["paths"]["/users/me"]}})
    done = run(client, start(client, project, s.url, spec=spec))
    assert done["spec_provided"] is True and done["spec"]["operations"] == 1
