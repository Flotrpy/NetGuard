import io
import json
import zipfile

import httpx
import pytest

from netguard.scanners.base import ScanContext
from netguard.scanners.dependencies import osv as osv_module
from netguard.scanners.registry import get_scanner
from netguard.worker import process_one

# Synthetic advisories used only by these tests (served by a mock transport, never the network).
ADVISORIES = {
    "GHSA-test-qs01": {
        "id": "GHSA-test-qs01",
        "aliases": ["CVE-2099-0001"],
        "summary": "Test advisory for qs",
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
        "references": [{"url": "https://example.test/qs"}],
        "affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.11.1"}]}]}],
    },
    "PYSEC-test-0001": {
        "id": "PYSEC-test-0001",
        "aliases": [],
        "summary": "Test advisory for django",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "django"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.5"}]}]}],
    },
}
REAL_OSV_CLIENT = osv_module.OsvClient  # captured before any test patches it
VULNERABLE = {("npm", "qs", "6.11.0"): ["GHSA-test-qs01"], ("PyPI", "django", "3.2.0"): ["PYSEC-test-0001"]}


def install_mock_osv(monkeypatch, fail=False, vulnerable=None):
    vulnerable = VULNERABLE if vulnerable is None else vulnerable

    def handler(request):
        if fail:
            return httpx.Response(503)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for q in queries:
                key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
                results.append({"vulns": [{"id": i} for i in vulnerable.get(key, [])]})
            return httpx.Response(200, json={"results": results})
        vid = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ADVISORIES[vid]) if vid in ADVISORIES else httpx.Response(404)

    real = REAL_OSV_CLIENT

    def factory(base_url, **kw):
        kw["client"] = httpx.Client(transport=httpx.MockTransport(handler))
        kw["offline"] = False
        return real(base_url, **kw)

    monkeypatch.setattr(osv_module, "OsvClient", factory)


LOCK = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"express": "^4.18.0"}},
    "node_modules/express": {"version": "4.18.2", "dependencies": {"qs": "6.11.0"}},
    "node_modules/qs": {"version": "6.11.0"},
}}


def project_dir(tmp_path, extra=None):
    files = {"package-lock.json": json.dumps(LOCK, indent=2), "requirements.txt": "Django==3.2.0\nrequests>=2\n"}
    files.update(extra or {})
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


def run(tmp_path, offline=False, cache=True):
    runtime = {"osv_api_url": "https://osv.test", "osv_offline": offline,
               "cache_dir": str(tmp_path / "_cache") if cache else ""}
    return get_scanner("dependencies").scan(ScanContext(root=tmp_path, runtime=runtime))


def test_scanner_registered_and_available():
    info = get_scanner("dependencies").info()
    assert info.available and info.display_name == "Dependency Scanner"


def test_finds_vulnerable_packages_with_paths_and_fixed_versions(tmp_path, monkeypatch):
    install_mock_osv(monkeypatch)
    res = run(project_dir(tmp_path))
    assert res.complete and len(res.findings) == 2
    qs = next(f for f in res.findings if f.extra["package"] == "qs")
    assert qs.severity.value == "high" and qs.cwe == "CWE-1321" and qs.confidence.value == "high"
    assert qs.extra["fixed_versions"] == ["6.11.1"] and qs.extra["dependency_path"] == ["express", "qs"]
    assert qs.extra["cve"] == "CVE-2099-0001" and not qs.extra["direct"]
    assert qs.file_path == "package-lock.json" and qs.line > 0
    assert "Upgrade qs to 6.11.1" in qs.remediation
    assert "GHSA-test-qs01 / CVE-2099-0001" in qs.title
    assert qs.references[0] == "https://osv.dev/vulnerability/GHSA-test-qs01"
    dj = next(f for f in res.findings if f.extra["package"] == "django")
    assert dj.extra["severity_source"] == "unknown" and "placeholder" in dj.description
    assert res.metadata["ecosystems"] == ["PyPI", "npm"] and res.metadata["packages"] == 3
    assert any("requirements are not pinned" in w for w in res.warnings)


def test_lockfile_supersedes_package_json(tmp_path, monkeypatch):
    install_mock_osv(monkeypatch)
    res = run(project_dir(tmp_path, {"package.json": json.dumps({"dependencies": {"qs": "6.11.0"}})}))
    assert not any("package.json" in w for w in res.warnings)
    assert res.metadata["manifests"] == 3 and len([f for f in res.findings if f.extra["package"] == "qs"]) == 1


def test_no_vulnerabilities_gives_complete_clean_result(tmp_path, monkeypatch):
    install_mock_osv(monkeypatch, vulnerable={})
    res = run(project_dir(tmp_path))
    assert res.complete and res.findings == []


def test_offline_is_incomplete_and_not_clean(tmp_path, monkeypatch):
    res = run(project_dir(tmp_path), offline=True, cache=False)
    assert res.findings == [] and res.complete is False
    assert "NOT checked" in " ".join(res.warnings) and res.metadata["osv"] == "unavailable"


def test_osv_outage_is_incomplete_not_clean(tmp_path, monkeypatch):
    install_mock_osv(monkeypatch, fail=True)
    res = run(project_dir(tmp_path), cache=False)
    assert res.complete is False and res.findings == []


def test_no_manifests_is_a_clean_complete_scan(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    res = run(tmp_path)
    assert res.complete and res.findings == [] and res.metadata["manifests"] == 0


# ---- through the API and the worker: lifecycle and safety --------------------------------------
def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)
    return buf.getvalue()


def api_scan(client, project, repo):
    r = client.post(f"/api/projects/{project['id']}/scans",
                    json={"scanners": ["dependencies"], "repository_id": repo["id"]})
    assert r.status_code == 202, r.text
    process_one("w")
    return client.get(f"/api/scans/{r.json()['id']}").json()


@pytest.fixture
def project_repo(client):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "r"}).json()
    return p, repo


def upload(client, repo, files):
    r = client.post(f"/api/repositories/{repo['id']}/upload",
                    files={"file": ("a.zip", make_zip(files), "application/zip")})
    assert r.status_code == 201


def test_api_flow_findings_and_fix_by_upgrading(client, project_repo, monkeypatch):
    install_mock_osv(monkeypatch)
    project, repo = project_repo
    upload(client, repo, {"package-lock.json": json.dumps(LOCK)})
    done = api_scan(client, project, repo)
    assert done["status"] == "completed"
    items = client.get("/api/findings", params={"project_id": project["id"]}).json()["items"]
    assert [i["detection_source"] for i in items] == ["Dependency Scanner"]
    detail = client.get(f"/api/findings/{items[0]['id']}").json()
    assert detail["extra"]["dependency_path"] == ["express", "qs"]

    fixed_lock = json.loads(json.dumps(LOCK))
    fixed_lock["packages"]["node_modules/qs"]["version"] = "6.11.2"
    fixed_lock["packages"]["node_modules/express"]["dependencies"]["qs"] = "6.11.2"
    upload(client, repo, {"package-lock.json": json.dumps(fixed_lock)})
    after = api_scan(client, project, repo)
    assert after["summary"]["scanners"]["dependencies"]["ingest"]["resolved"] == 1


def test_osv_outage_never_resolves_existing_findings(client, project_repo, monkeypatch):
    project, repo = project_repo
    upload(client, repo, {"package-lock.json": json.dumps(LOCK)})
    install_mock_osv(monkeypatch)
    api_scan(client, project, repo)
    install_mock_osv(monkeypatch, fail=True)
    import shutil

    from netguard.config import get_settings

    shutil.rmtree(get_settings().cache_dir, ignore_errors=True)  # force live lookups
    outage = api_scan(client, project, repo)
    assert outage["summary"]["scanners"]["dependencies"]["complete"] is False
    still_open = client.get("/api/findings", params={"project_id": project["id"], "status": "open"})
    assert still_open.json()["total"] == 1  # not silently marked fixed
