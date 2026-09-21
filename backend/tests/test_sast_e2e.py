"""End-to-end SAST: real scanner, real fixtures, through the API and the job queue."""

import io
import zipfile
from pathlib import Path

from netguard.worker import process_one

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app"

EXPECTED_RULES = {
    "py.sql-injection", "py.command-injection", "py.unsafe-deserialization", "py.path-traversal",
    "py.ssrf", "py.tls-verification-disabled", "py.open-redirect", "py.weak-hash",
    "py.insecure-random", "py.debug-enabled",
    "js.sql-injection", "js.reflected-xss", "js.command-injection", "js.eval", "js.open-redirect",
    "js.weak-hash", "js.tls-verification-disabled",
    "java.sql-injection", "java.unsafe-deserialization", "java.weak-hash",
    "php.reflected-xss", "php.file-inclusion", "php.sql-injection", "php.command-injection",
    "php.weak-hash",
    "go.sql-injection", "go.command-injection", "go.weak-hash", "go.tls-verification-disabled",
}


def zip_tree(root: Path, overrides: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(root).as_posix()
                data = (overrides or {}).get(rel)
                zf.writestr(rel, data if data is not None else path.read_bytes())
    return buf.getvalue()


def setup(client):
    client.register()
    p = client.post("/api/projects", json={"name": "Vulnerable App"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "app"}).json()
    return p, repo


def upload(client, repo, data):
    r = client.post(
        f"/api/repositories/{repo['id']}/upload", files={"file": ("a.zip", data, "application/zip")}
    )
    assert r.status_code == 201, r.text


def scan(client, project, repo):
    r = client.post(
        f"/api/projects/{project['id']}/scans",
        json={"scanners": ["sast"], "repository_id": repo["id"]},
    )
    assert r.status_code == 202, r.text
    process_one("w")
    return client.get(f"/api/scans/{r.json()['id']}").json()


def all_findings(client, project, **params):
    return client.get(
        "/api/findings", params={"project_id": project["id"], "limit": 500, **params}
    ).json()["items"]


def test_sast_finds_expected_vulnerabilities_in_fixture_app(client):
    project, repo = setup(client)
    upload(client, repo, zip_tree(FIXTURE))
    done = scan(client, project, repo)
    assert done["status"] == "completed", done
    assert done["progress"]["sast"]["state"] == "completed"

    found = {f["rule_id"] for f in all_findings(client, project)}
    missing = EXPECTED_RULES - found
    assert not missing, f"scanner missed: {sorted(missing)}"

    by_rule = {f["rule_id"]: f for f in all_findings(client, project)}
    sqli = by_rule["py.sql-injection"]
    assert sqli["file_path"] == "py/app.py" and sqli["line"] == 21
    assert sqli["cwe"] == "CWE-89" and sqli["severity"] == "high" and sqli["confidence"] == "high"
    assert sqli["detection_source"] == "SAST" and sqli["language"] == "python"

    detail = client.get(f"/api/findings/{sqli['id']}").json()
    assert "21:" in detail["code_context"] and "SELECT" in detail["code_context"]
    assert detail["remediation"] and detail["impact"] and detail["references"]


def test_findings_can_be_filtered_by_language_and_type(client):
    project, repo = setup(client)
    upload(client, repo, zip_tree(FIXTURE))
    scan(client, project, repo)
    py = all_findings(client, project, language="python")
    assert py and all(f["language"] == "python" for f in py)
    inj = all_findings(client, project, category="SQL Injection")
    assert {f["language"] for f in inj} >= {"python", "javascript", "java", "php", "go"}
    assert all_findings(client, project, file="server.js") and all(
        "server.js" in f["file_path"] for f in all_findings(client, project, file="server.js")
    )


def test_rescan_is_idempotent_and_fix_resolves_finding(client):
    project, repo = setup(client)
    upload(client, repo, zip_tree(FIXTURE))
    first = scan(client, project, repo)
    n = first["summary"]["scanners"]["sast"]["findings"]
    second = scan(client, project, repo)
    assert second["summary"]["scanners"]["sast"]["ingest"]["new"] == 0  # deduplicated
    assert len(all_findings(client, project)) == n

    fixed_app = (FIXTURE / "py/app.py").read_text().replace(
        "cur.execute(\"SELECT * FROM users WHERE id = '\" + uid + \"'\")",
        "cur.execute('SELECT * FROM users WHERE id = ?', (uid,))",
    )
    upload(client, repo, zip_tree(FIXTURE, {"py/app.py": fixed_app}))
    third = scan(client, project, repo)
    assert third["summary"]["scanners"]["sast"]["ingest"]["resolved"] == 1
    fixed = all_findings(client, project, status="fixed")
    assert [f["rule_id"] for f in fixed] == ["py.sql-injection"]


def test_scan_reports_progress_and_metadata(client):
    project, repo = setup(client)
    upload(client, repo, zip_tree(FIXTURE))
    done = scan(client, project, repo)
    meta = done["summary"]["scanners"]["sast"]["metadata"]
    assert meta["files_analyzed"] == 5 and meta["rules"] >= 100
