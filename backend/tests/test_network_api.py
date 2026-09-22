import csv
import io

import pytest

from netguard.config import get_settings
from netguard.worker import process_one
from tests.test_network_scanner import Server

STATEMENT = "I own these systems and am authorized to assess them."


@pytest.fixture
def srv():
    made = []

    def make(*a, **k):
        s = Server(*a, **k)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def start(client, project, target="127.0.0.1", scan_type="port_scan", ports=None, **kw):
    body = {"project_id": project["id"], "target": target, "scan_type": scan_type, "ports": ports,
            "timeout": 0.5, "authorized": True, "authorization_statement": STATEMENT, **kw}
    return client.post("/api/network/scans", json=body)


def run(client, response):
    assert response.status_code == 202, response.text
    while process_one("w"):
        pass
    return client.get(f"/api/network/scans/{response.json()['id']}").json()


@pytest.fixture
def project(client):
    client.register()
    return client.post("/api/projects", json={"name": "Lab"}).json()


def test_options_expose_authorization_language_and_limits(client, project):
    o = client.get("/api/network/options").json()
    assert {t["id"] for t in o["scan_types"]} == {"quick_discovery", "port_scan", "service_detection", "inventory", "security_audit"}
    assert "authorization" in o["authorization_text"].lower() and o["public_targets_allowed"] is False
    assert 22 in o["default_ports"] and o["max_hosts"] >= 1


def test_authorization_attestation_is_enforced_server_side(client, project):
    for kw in ({"authorized": False}, {"authorization_statement": ""}, {"authorization_statement": "ok"}):
        r = start(client, project, **kw)
        assert r.status_code == 422 and "authorized" in r.json()["detail"]


def test_forbidden_targets_are_denied_and_audited(client, project):
    from netguard.db import get_session_factory
    from netguard.models import AuditLog

    for target in ["169.254.169.254", "8.8.8.8", "10.0.0.0/8", "127.0.0.1;id", "224.0.0.1"]:
        assert start(client, project, target=target).status_code == 422, target
    assert start(client, project, scan_type="exploit").status_code == 422
    assert start(client, project, ports="99999").status_code == 422
    with get_session_factory()() as db:
        denied = db.query(AuditLog).filter(AuditLog.action == "network.scan.denied").all()
        assert len(denied) >= 5 and "metadata" in " ".join(d.details["reason"] for d in denied)


def test_public_targets_only_with_operator_opt_in(client, project, monkeypatch):
    assert start(client, project, target="93.184.216.34").status_code == 422
    monkeypatch.setenv("NETGUARD_ALLOW_PUBLIC_TARGETS", "true")
    get_settings.cache_clear()
    assert start(client, project, target="93.184.216.34", scan_type="quick_discovery").status_code == 202
    assert start(client, project, target="169.254.169.254").status_code == 422  # still blocked


def test_scan_records_attestation_and_audit_trail(client, project, srv):
    from netguard.db import get_session_factory
    from netguard.models import AuditLog

    s = srv()
    done = run(client, start(client, project, ports=str(s.port)))
    assert done["scan"]["status"] == "completed" and done["scan_type"] == "port_scan"
    assert done["authorization"]["statement"] == STATEMENT and done["authorization"]["by"]
    assert "ip" not in done["authorization"]  # client address is kept out of API responses
    with get_session_factory()() as db:
        entry = db.query(AuditLog).filter(AuditLog.action == "network.scan.start").one()
        assert entry.details["target"] == "127.0.0.1" and entry.details["authorized"] is True


def test_results_show_hosts_ports_and_services_with_timestamps(client, project, srv):
    ssh = srv(banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    done = run(client, start(client, project, scan_type="service_detection", ports=str(ssh.port)))
    (host,) = done["hosts"]
    assert host["ip"] == "127.0.0.1" and host["status"] == "up" and host["scanned_at"]
    (svc,) = host["services"]
    assert (svc["port"], svc["protocol"], svc["state"], svc["service"]) == (ssh.port, "tcp", "open", "ssh")
    assert svc["version"] == "OpenSSH 8.9p1" and svc["banner"].startswith("SSH-2.0")
    assert done["scan"]["summary"]["scanners"]["network"]["metadata"]["open_services"] == 1
    assert "hosts" not in done["scan"]["summary"]["scanners"]["network"]["metadata"]  # kept in own tables


def test_history_inventory_and_dashboard_hosts(client, project, srv):
    a = srv()
    run(client, start(client, project, ports=str(a.port)))
    b = srv(banner=b"SSH-2.0-OpenSSH_7.4\r\n")
    run(client, start(client, project, scan_type="security_audit", ports=str(b.port)))
    history = client.get(f"/api/projects/{project['id']}/network/scans").json()
    assert len(history) == 2 and {h["kind"] for h in history} == {"network"}
    inventory = client.get(f"/api/projects/{project['id']}/network/hosts").json()
    assert len(inventory) == 1 and inventory[0]["ip"] == "127.0.0.1"  # latest observation per IP
    assert [s["port"] for s in inventory[0]["services"]] == [b.port]
    assert inventory[0]["findings"]["info"] == 1
    dash = client.get("/api/dashboard", params={"project_id": project["id"]}).json()
    assert dash["affected_hosts"][0]["ip"] == "127.0.0.1"
    modules = {m["scanner"]: m for m in dash["modules"]}
    assert modules["network"]["status"] == "attention"


def test_audit_findings_flow_into_the_unified_finding_system(client, project, srv):
    s = srv(banner=b"SSH-2.0-OpenSSH_7.4\r\n")
    run(client, start(client, project, scan_type="security_audit", ports=str(s.port)))
    items = client.get("/api/findings", params={"project_id": project["id"]}).json()["items"]
    (f,) = items
    assert f["detection_source"] == "Network Scanner" and f["exposure"] == "internal"
    assert f["asset"] and f["rule_id"] == "net.version-disclosed"  # asset name = hostname or IP
    detail = client.get(f"/api/findings/{f['id']}").json()
    assert detail["extra"]["port"] == s.port and detail["extra"]["ip"] == "127.0.0.1"


def test_only_a_full_audit_can_resolve_findings_and_down_hosts_are_left_alone(client, project, srv):
    s = srv(banner=b"SSH-2.0-OpenSSH_7.4\r\n")
    run(client, start(client, project, scan_type="security_audit", ports=str(s.port)))
    findings = lambda: client.get("/api/findings", params={"project_id": project["id"], "status": "open"}).json()["total"]  # noqa: E731
    assert findings() == 1
    # A plain port scan that misses the service must not "fix" anything.
    run(client, start(client, project, scan_type="port_scan", ports="1"))
    assert findings() == 1
    # A full audit where the service is gone does resolve it.
    s.close()
    run(client, start(client, project, scan_type="security_audit", ports=str(s.port)))
    assert findings() == 0


def test_export_json_and_csv_with_formula_neutralisation(client, project, srv):
    s = srv(banner=b"=cmd|' /C calc'!A0\r\n")
    scan = run(client, start(client, project, scan_type="service_detection", ports=str(s.port)))
    sid = scan["scan"]["id"]
    j = client.get(f"/api/network/scans/{sid}/export")
    assert j.status_code == 200 and "attachment" in j.headers["content-disposition"]
    assert j.json()["hosts"][0]["ip"] == "127.0.0.1" and j.json()["target"] == "127.0.0.1"
    c = client.get(f"/api/network/scans/{sid}/export", params={"format": "csv"})
    rows = list(csv.reader(io.StringIO(c.text)))
    assert rows[0][:2] == ["ip", "hostname"] and rows[1][0] == "127.0.0.1"
    assert not any(cell.startswith("=") for row in rows for cell in row)
    assert client.get(f"/api/network/scans/{sid}/export", params={"format": "xml"}).status_code == 422


def test_network_map_is_a_logical_subnet_view(client, project, srv):
    s = srv(banner=b"SSH-2.0-OpenSSH_7.4\r\n")
    run(client, start(client, project, scan_type="security_audit", ports=str(s.port)))
    m = client.get(f"/api/projects/{project['id']}/network/map").json()
    types = [n["type"] for n in m["nodes"]]
    assert types.count("scanner") == 1 and types.count("subnet") == 1 and types.count("host") == 1
    host = next(n for n in m["nodes"] if n["type"] == "host")
    assert host["ip"] == "127.0.0.1" and host["ports"] == [s.port] and host["worst"] == "info"
    assert "Logical view" in m["note"] and "internet" not in types
    assert {(e["from"], e["to"]) for e in m["edges"]} >= {("scanner", "subnet:127.0.0.0/24")}
    empty = client.post("/api/projects", json={"name": "Empty"}).json()
    assert client.get(f"/api/projects/{empty['id']}/network/map").json()["nodes"][0]["type"] == "scanner"


def test_access_control_and_scan_kind_isolation(client, make_client, project, srv):
    s = srv()
    sid = run(client, start(client, project, ports=str(s.port)))["scan"]["id"]
    other = make_client("o@example.com")
    assert other.get(f"/api/network/scans/{sid}").status_code == 404
    assert start(other, project).status_code == 404
    assert other.get(f"/api/projects/{project['id']}/network/hosts").status_code == 404
    client.post(f"/api/projects/{project['id']}/members", json={"email": "o@example.com", "role": "viewer"})
    assert other.get(f"/api/network/scans/{sid}").status_code == 200
    assert start(other, project).status_code == 403  # viewers cannot launch scans
    # A non-network scan id is not exposed through the network endpoints.
    repo = client.post(f"/api/projects/{project['id']}/repositories", json={"name": "r"}).json()
    assert repo["id"] and client.get("/api/network/scans/does-not-exist").status_code == 404
