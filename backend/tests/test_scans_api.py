import io
import zipfile

from netguard.worker import process_one


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)
    return buf.getvalue()


def upload(client, repo_id, files):
    return client.post(
        f"/api/repositories/{repo_id}/upload",
        files={"file": ("c.zip", make_zip(files), "application/zip")},
    )


def project_with_code(client, files):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "r"}).json()
    r = upload(client, repo["id"], files)
    assert r.status_code == 201, r.text
    return p, repo, r.json()


def start(client, project_id, repo_id, scanners=("sast",)):
    return client.post(
        f"/api/projects/{project_id}/scans",
        json={"scanners": list(scanners), "repository_id": repo_id},
    )


def test_scanner_catalog_marks_unimplemented_modules_unavailable(client):
    client.register()
    catalog = {s["name"]: s for s in client.get("/api/scanners").json()}
    assert set(catalog) >= {"sast", "network", "api"}
    assert catalog["api"]["available"] is False
    assert "Planned" in catalog["api"]["status_note"]


def test_scan_lifecycle_produces_findings_and_summary(client, fake_scanner):
    p, repo, snap = project_with_code(client, {"a.py": "ok\nBAD one\n", "b.py": "BAD two\n"})
    r = start(client, p["id"], repo["id"])
    assert r.status_code == 202, r.text
    scan = r.json()
    assert scan["status"] == "queued" and scan["progress"]["sast"]["state"] == "pending"

    assert process_one("test-worker") is True
    assert process_one("test-worker") is False  # queue drained

    done = client.get(f"/api/scans/{scan['id']}").json()
    assert done["status"] == "completed" and done["snapshot_id"] == snap["id"]
    assert done["progress"]["sast"]["state"] == "completed"
    assert done["progress"]["sast"]["percent"] == 100
    assert done["summary"]["severity"]["high"] == 2
    assert done["summary"]["scanners"]["sast"]["ingest"]["new"] == 2
    assert done["started_at"] and done["finished_at"]
    assert client.get(f"/api/projects/{p['id']}").json()["open_findings"]["high"] == 2


def test_unavailable_or_unknown_scanner_rejected(client, fake_scanner):
    p, repo, _ = project_with_code(client, {"a.py": "x"})
    r = start(client, p["id"], repo["id"], ["api"])
    assert r.status_code == 422 and "not available" in r.json()["detail"]
    assert start(client, p["id"], repo["id"], ["nope"]).status_code == 422


def test_code_scan_requires_uploaded_snapshot(client, fake_scanner):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "empty"}).json()
    assert start(client, p["id"], repo["id"]).status_code == 422


def test_cancel_before_run_skips_execution(client, fake_scanner):
    p, repo, _ = project_with_code(client, {"a.py": "BAD"})
    scan = start(client, p["id"], repo["id"]).json()
    assert client.post(f"/api/scans/{scan['id']}/cancel").json()["status"] == "cancelled"
    process_one("w")
    assert client.get(f"/api/scans/{scan['id']}").json()["status"] == "cancelled"
    assert client.get(f"/api/projects/{p['id']}").json()["open_findings"]["high"] == 0
    assert client.post(f"/api/scans/{scan['id']}/cancel").status_code == 409


def test_failing_scanner_marks_scan_failed_without_crashing_worker(client):
    from netguard.enums import Scanner as Name
    from netguard.scanners import registry
    from netguard.scanners.base import Scanner

    class Exploding(Scanner):
        name = Name.SAST
        display_name = "Exploding"

        def scan(self, ctx):
            raise RuntimeError("parser bug")

    registry.all_scanners()
    original = registry._REGISTRY["sast"]
    registry._REGISTRY["sast"] = Exploding()
    try:
        p, repo, _ = project_with_code(client, {"a.py": "x"})
        scan = start(client, p["id"], repo["id"]).json()
        assert process_one("w") is True
        done = client.get(f"/api/scans/{scan['id']}").json()
        assert done["status"] == "failed" and "parser bug" in done["error"]
    finally:
        registry._REGISTRY["sast"] = original


def test_rescan_after_fixing_code_resolves_finding(client, fake_scanner):
    p, repo, _ = project_with_code(client, {"a.py": "BAD\n"})
    start(client, p["id"], repo["id"])
    process_one("w")
    assert client.get(f"/api/projects/{p['id']}").json()["open_findings"]["high"] == 1
    upload(client, repo["id"], {"a.py": "fine\n"})
    start(client, p["id"], repo["id"])
    process_one("w")
    assert client.get(f"/api/projects/{p['id']}").json()["open_findings"]["high"] == 0


def test_scan_history_and_access_control(client, make_client, fake_scanner):
    p, repo, _ = project_with_code(client, {"a.py": "BAD"})
    scan = start(client, p["id"], repo["id"]).json()
    assert [s["id"] for s in client.get(f"/api/projects/{p['id']}/scans").json()] == [scan["id"]]
    other = make_client("other@example.com")
    assert other.get(f"/api/scans/{scan['id']}").status_code == 404
    assert other.post(f"/api/scans/{scan['id']}/cancel").status_code == 404
    assert start(other, p["id"], repo["id"]).status_code == 404
