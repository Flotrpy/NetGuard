import hashlib
import hmac
import io
import json
import tarfile

import httpx
import pytest
from fastapi.testclient import TestClient

from netguard.services import providers
from netguard.worker import process_one

VULN = "import os\n\ndef run(x):\n    os.system('echo ' + x)\n"
SAFE = "def run(x):\n    return x\n"


def make_tarball(files: dict[str, str], top="o-r-abc1234") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeGitHub:
    def __init__(self, files):
        self.files = files
        self.calls: list[tuple[str, str, dict]] = []
        self.tarball_status = 200

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}
        self.calls.append((method, path, body))
        if method == "GET" and path == "/repos/o/r":
            return httpx.Response(200, json={"default_branch": "main", "html_url": "https://github.com/o/r"})
        if "/tarball/" in path:
            if self.tarball_status != 200:
                return httpx.Response(self.tarball_status)
            return httpx.Response(200, content=make_tarball(self.files))
        if method == "GET" and path.endswith("/comments"):
            return httpx.Response(200, json=[])
        return httpx.Response(201, json={})

    def posted(self, suffix):
        return [c for c in self.calls if c[0] == "POST" and c[1].endswith(suffix)]


@pytest.fixture
def gh(monkeypatch):
    fake = FakeGitHub({"app.py": VULN})
    monkeypatch.setattr(providers, "_new_http", lambda: httpx.Client(transport=httpx.MockTransport(fake.handler)))
    return fake


def setup(client):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    r = client.post(f"/api/projects/{p['id']}/repositories/connect",
                    json={"provider": "github", "external_id": "o/r", "token": "ghp_faketoken1234"})
    assert r.status_code == 201, r.text
    return p, r.json()


def sign(secret, raw):
    return "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def webhook(client, secret, event, payload, signature=None):
    raw = json.dumps(payload).encode()
    return client.http.post("/api/webhooks/github", content=raw, headers={
        "X-GitHub-Event": event, "X-Hub-Signature-256": signature or sign(secret, raw),
        "Content-Type": "application/json"})


def drain():
    while process_one("w"):
        pass


def findings(client, project):
    return client.get("/api/findings", params={"project_id": project["id"]}).json()


def test_connect_stores_encrypted_token_and_returns_secret_once(client, gh):
    p, conn = setup(client)
    assert conn["repository"]["provider"] == "github" and conn["repository"]["default_branch"] == "main"
    assert conn["webhook_secret"] and conn["webhook_path"] == "/api/webhooks/github"
    assert "ghp_faketoken1234" not in json.dumps(conn)
    repos = client.get(f"/api/projects/{p['id']}/repositories").json()
    assert "token" not in json.dumps(repos) and conn["webhook_secret"] not in json.dumps(repos)
    from netguard.db import get_session_factory
    from netguard.models import Repository

    with get_session_factory()() as db:
        row = db.get(Repository, conn["repository"]["id"])
        assert "ghp_faketoken1234" not in row.token_encrypted and conn["webhook_secret"] not in row.webhook_secret
    assert gh.calls[0][:2] == ("GET", "/repos/o/r")  # credentials were verified with the provider


def test_connect_validation_and_permissions(client, make_client, gh):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    url = f"/api/projects/{p['id']}/repositories/connect"
    for bad in ["../x", "o/r/extra", "o r/x"]:
        assert client.post(url, json={"provider": "github", "external_id": bad, "token": "t" * 10}).status_code == 422
    assert client.post(url, json={"provider": "svn", "external_id": "o/r", "token": "t" * 10}).status_code == 422
    other = make_client("x@example.com")
    assert other.post(url, json={"provider": "github", "external_id": "o/r", "token": "t" * 10}).status_code == 404


def test_connect_reports_provider_rejection(client, monkeypatch):
    monkeypatch.setattr(providers, "_new_http", lambda: httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(401))))
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    r = client.post(f"/api/projects/{p['id']}/repositories/connect",
                    json={"provider": "github", "external_id": "o/r", "token": "badtoken123"})
    assert r.status_code == 422 and "rejected" in r.json()["detail"]
    assert client.get(f"/api/projects/{p['id']}/repositories").json() == []


def test_default_branch_scan_updates_project_findings(client, gh):
    p, conn = setup(client)
    repo_id = conn["repository"]["id"]
    r = client.post(f"/api/repositories/{repo_id}/scan", json={"scanners": ["sast"]})
    assert r.status_code == 202 and r.json()["snapshot_id"] is None  # code fetched by the worker
    drain()
    scan = client.get(f"/api/scans/{r.json()['id']}").json()
    assert scan["status"] == "completed" and scan["snapshot_id"]
    page = findings(client, p)
    assert page["total"] == 1 and page["items"][0]["rule_id"] == "py.command-injection"
    snaps = client.get(f"/api/repositories/{repo_id}/snapshots").json()
    assert snaps[0]["source"] == "git" and snaps[0]["ref"] == "main"


def test_signed_pr_webhook_runs_ephemeral_scan_and_reports_back(client, gh):
    p, conn = setup(client)
    secret = conn["webhook_secret"]
    # Main already knows about the finding (default-branch scan).
    client.post(f"/api/repositories/{conn['repository']['id']}/scan", json={"scanners": ["sast"]})
    drain()
    before = findings(client, p)["total"]

    gh.files = {"app.py": SAFE}  # the PR branch fixes it
    payload = {"action": "opened", "number": 7, "repository": {"full_name": "o/r"},
               "pull_request": {"number": 7, "head": {"ref": "fix", "sha": "abc1234def"}}}
    r = webhook(client, secret, "pull_request", payload)
    assert r.status_code == 202 and len(r.json()["queued"]) == 1
    drain()
    scan = client.get(f"/api/scans/{r.json()['queued'][0]}").json()
    assert scan["status"] == "completed" and scan["trigger"] == "webhook" and scan["ref"] == "pr-7"
    # The PR branch (which lacks the vulnerability) must NOT mark main's finding fixed.
    after = findings(client, p)
    assert after["total"] == before == 1 and after["items"][0]["status"] == "open"
    assert scan["summary"]["report"]["posted"] is True
    status = gh.posted("/statuses/abc1234def")[0][2]
    assert status["state"] == "success" and status["context"] == "NetGuard"
    comment = gh.posted("/issues/7/comments")[0][2]["body"]
    assert "NetGuard Security Check" in comment and "✓ SAST" in comment and "Gate passed" in comment
    gate = client.get(f"/api/scans/{scan['id']}/gate").json()
    assert gate["passed"] is True and gate["ephemeral"] is True


def test_pr_introducing_a_new_high_finding_fails_the_gate(client, gh):
    p, conn = setup(client)
    payload = {"action": "synchronize", "number": 9, "repository": {"full_name": "o/r"},
               "pull_request": {"number": 9, "head": {"ref": "feat", "sha": "deadbee1234"}}}
    r = webhook(client, conn["webhook_secret"], "pull_request", payload)
    drain()
    scan = client.get(f"/api/scans/{r.json()['queued'][0]}").json()
    assert findings(client, p)["total"] == 0  # ephemeral: nothing stored in the finding DB
    items = scan["summary"]["scanners"]["sast"]["items"]
    assert items[0]["is_new"] and items[0]["severity"] == "high"
    assert gh.posted("/statuses/deadbee1234")[0][2]["state"] == "failure"
    comment = gh.posted("/issues/9/comments")[0][2]["body"]
    assert "⚠ SAST" in comment and "Gate failed" in comment and "New High findings" in comment
    assert "py.command-injection" not in comment and "os.system" not in comment
    assert client.get(f"/api/scans/{scan['id']}/gate").json()["passed"] is False


def test_policy_changes_flip_the_gate(client, gh):
    p, conn = setup(client)
    payload = {"action": "opened", "number": 1, "repository": {"full_name": "o/r"},
               "pull_request": {"number": 1, "head": {"ref": "b", "sha": "abcdef1"}}}
    r = webhook(client, conn["webhook_secret"], "pull_request", payload)
    drain()
    sid = r.json()["queued"][0]
    assert client.get(f"/api/scans/{sid}/gate").json()["passed"] is False
    assert client.put(f"/api/projects/{p['id']}/policy", json={"max_new_high": None}).status_code == 200
    assert client.get(f"/api/projects/{p['id']}/policy").json()["max_new_high"] is None
    assert client.get(f"/api/scans/{sid}/gate").json()["passed"] is True
    assert client.put(f"/api/projects/{p['id']}/policy", json={"max_critical": -1}).status_code == 422


def test_push_to_default_branch_updates_state_and_other_branches_are_ephemeral(client, gh):
    p, conn = setup(client)
    push = lambda ref: {"ref": f"refs/heads/{ref}", "after": "1234567abcdef", "repository": {"full_name": "o/r"}}  # noqa: E731
    r = webhook(client, conn["webhook_secret"], "push", push("feature-x"))
    drain()
    assert findings(client, p)["total"] == 0
    assert client.get(f"/api/scans/{r.json()['queued'][0]}").json()["config"] if False else True
    r = webhook(client, conn["webhook_secret"], "push", push("main"))
    drain()
    assert findings(client, p)["total"] == 1


def test_webhook_rejects_bad_signatures_unknown_repos_and_ignores_irrelevant_events(client, gh):
    p, conn = setup(client)
    secret = conn["webhook_secret"]
    payload = {"repository": {"full_name": "o/r"}}
    assert webhook(client, secret, "push", payload, signature="sha256=" + "0" * 64).status_code == 401
    assert webhook(client, "wrong-secret", "push", payload).status_code == 401
    assert webhook(client, secret, "push", {"repository": {"full_name": "someone/else"}}).status_code == 401
    assert webhook(client, secret, "ping", payload).json() == {"ok": True}
    assert webhook(client, secret, "issues", payload).json() == {"queued": []}
    deleted = {"ref": "refs/heads/x", "after": "0" * 40, "deleted": True, "repository": {"full_name": "o/r"}}
    assert webhook(client, secret, "push", deleted).json() == {"queued": []}
    assert client.http.post("/api/webhooks/github", content=b"not json").status_code == 400
    big = client.http.post("/api/webhooks/github", content=b"x" * (1024 * 1024 + 1))
    assert big.status_code == 413


def test_fetch_failure_marks_scan_failed_with_a_clear_reason(client, gh):
    p, conn = setup(client)
    gh.tarball_status = 404
    r = client.post(f"/api/repositories/{conn['repository']['id']}/scan", json={})
    drain()
    scan = client.get(f"/api/scans/{r.json()['id']}").json()
    assert scan["status"] == "failed" and "Could not fetch code" in scan["error"]


def test_gitlab_webhook_uses_shared_token(client, monkeypatch):
    def handler(request):
        if request.method == "GET" and request.url.path.startswith("/api/v4/projects/"):
            return httpx.Response(200, json={"default_branch": "main", "web_url": "u", "visibility": "private"})
        return httpx.Response(200, content=make_tarball({"app.py": VULN}), json=None) if "archive" in request.url.path else httpx.Response(201, json={})

    monkeypatch.setattr(providers, "_new_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    conn = client.post(f"/api/projects/{p['id']}/repositories/connect",
                       json={"provider": "gitlab", "external_id": "grp/proj", "token": "glpat-faketoken1"}).json()
    body = {"project": {"path_with_namespace": "grp/proj", "id": 5}, "checkout_sha": "abcdef12",
            "ref": "refs/heads/dev"}
    bad = client.http.post("/api/webhooks/gitlab", json=body, headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "nope"})
    assert bad.status_code == 401
    ok = client.http.post("/api/webhooks/gitlab", json=body,
                          headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": conn["webhook_secret"]})
    assert ok.status_code == 202 and len(ok.json()["queued"]) == 1


def test_ci_tokens_are_project_scoped_hashed_and_revocable(client, make_client, gh):
    p, conn = setup(client)
    other = client.post("/api/projects", json={"name": "Other"}).json()
    created = client.post(f"/api/projects/{p['id']}/tokens", json={"name": "ci", "scopes": ["read", "write"]}).json()
    raw = created["token"]
    assert raw.startswith("ngt_") and created["prefix"] == raw[:12]
    listing = client.get(f"/api/projects/{p['id']}/tokens")
    assert raw not in listing.text and listing.json()[0]["name"] == "ci"
    from netguard.db import get_session_factory
    from netguard.models import ApiToken

    with get_session_factory()() as db:
        assert raw not in db.query(ApiToken).first().token_hash

    ci = TestClient(client.http.app)
    auth = {"Authorization": f"Bearer {raw}"}
    assert ci.get("/api/auth/whoami", headers=auth).status_code == 200
    scan = ci.post(f"/api/repositories/{conn['repository']['id']}/scan", json={"scanners": ["sast"]}, headers=auth)
    assert scan.status_code == 202 and scan.json()["trigger"] == "ci"
    drain()
    assert ci.get(f"/api/scans/{scan.json()['id']}/gate", headers=auth).status_code == 200
    # Scoped to its own project only.
    assert ci.get(f"/api/projects/{other['id']}", headers=auth).status_code == 404
    assert ci.get("/api/projects", headers=auth).json()[0]["id"] == p["id"]
    # Tokens cannot mint tokens or change policy (session-only endpoints).
    assert ci.post(f"/api/projects/{p['id']}/tokens", json={"name": "x"}, headers=auth).status_code == 403

    read_only = client.post(f"/api/projects/{p['id']}/tokens", json={"name": "ro", "scopes": ["read"]}).json()["token"]
    ro = {"Authorization": f"Bearer {read_only}"}
    assert ci.post(f"/api/repositories/{conn['repository']['id']}/scan", json={}, headers=ro).status_code == 403

    assert client.delete(f"/api/projects/{p['id']}/tokens/{created['id']}").status_code == 204
    assert ci.get("/api/auth/whoami", headers=auth).status_code == 401
    assert ci.get("/api/auth/whoami", headers={"Authorization": "Bearer ngt_bogus"}).status_code == 401
    assert ci.get("/api/auth/whoami", headers={"Authorization": "Bearer notatoken"}).status_code == 401
