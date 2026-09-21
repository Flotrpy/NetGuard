"""Finding -> proposed patch -> review -> apply -> rescan -> verify, end to end."""

import io
import json
import zipfile

import pytest

from netguard.config import get_settings
from netguard.services.ai import llm
from netguard.worker import process_one

APP = '''import hashlib
import os


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def home():
    return os.getcwd()
'''


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)
    return buf.getvalue()


class Env:
    def __init__(self, client, files):
        client.register()
        self.client = client
        self.project = client.post("/api/projects", json={"name": "P"}).json()
        self.repo = client.post(f"/api/projects/{self.project['id']}/repositories", json={"name": "r"}).json()
        self.upload(files)

    def upload(self, files):
        r = self.client.post(f"/api/repositories/{self.repo['id']}/upload",
                             files={"file": ("a.zip", make_zip(files), "application/zip")})
        assert r.status_code == 201, r.text

    def scan(self, scanners=("sast",)):
        r = self.client.post(f"/api/projects/{self.project['id']}/scans",
                             json={"scanners": list(scanners), "repository_id": self.repo["id"]})
        assert r.status_code == 202, r.text
        while process_one("w"):
            pass
        return self.client.get(f"/api/scans/{r.json()['id']}").json()

    def findings(self, **params):
        return self.client.get("/api/findings", params={"project_id": self.project["id"], **params}).json()["items"]

    def finding(self, rule):
        return next(f for f in self.findings() if f["rule_id"] == rule)

    def detail(self, fid):
        return self.client.get(f"/api/findings/{fid}").json()


def run_verification(env, finding_id, patch_id=None):
    r = env.client.post(f"/api/findings/{finding_id}/validate", json={"patch_id": patch_id} if patch_id else {})
    assert r.status_code == 202, r.text
    while process_one("w"):
        pass
    return r.json()


def test_full_lifecycle_rule_fix_is_verified_only_after_rescan(client):
    env = Env(client, {"auth.py": APP})
    env.scan()
    f = env.finding("py.weak-hash")
    assert f["status"] == "open"

    r = client.post(f"/api/findings/{f['id']}/generate-fix", json={})
    assert r.status_code == 201, r.text
    patch = r.json()
    assert patch["generator"] == "rule" and patch["status"] == "proposed"
    assert "-    return hashlib.md5(pw.encode()).hexdigest()" in patch["diff"]
    assert "+    return hashlib.sha256(pw.encode()).hexdigest()" in patch["diff"]
    assert patch["verification"]["preflight"]["rule_still_triggers"] is False
    assert any("64 hex" in c for c in patch["caveats"])

    # Generating a patch changes nothing and does NOT mark anything fixed.
    assert env.detail(f["id"])["status"] == "open" and env.detail(f["id"])["verification"] == "none"
    snaps = client.get(f"/api/repositories/{env.repo['id']}/snapshots").json()
    original = client.get(f"/api/snapshots/{snaps[0]['id']}/file", params={"path": "auth.py"}).json()["content"]
    assert original == APP

    applied = client.post(f"/api/patches/{patch['id']}/apply")
    assert applied.status_code == 200 and applied.json()["status"] == "applied"
    detail = env.detail(f["id"])
    assert detail["status"] == "in_progress" and detail["verification"] == "none"  # still unverified
    snaps_after = client.get(f"/api/repositories/{env.repo['id']}/snapshots").json()
    assert len(snaps_after) == 2
    # The original snapshot is immutable; the new one has the fix.
    assert client.get(f"/api/snapshots/{snaps[0]['id']}/file", params={"path": "auth.py"}).json()["content"] == APP
    new_content = client.get(f"/api/snapshots/{snaps_after[0]['id']}/file", params={"path": "auth.py"}).json()["content"]
    assert "sha256" in new_content and "md5" not in new_content

    run_verification(env, f["id"], patch["id"])
    detail = env.detail(f["id"])
    assert detail["verification"] == "verified_fixed" and detail["status"] == "fixed"
    kinds = [e["kind"] for e in detail["events"]]
    assert kinds[:1] == ["detected"]
    for expected in ("patch_generated", "patch_applied", "verification_requested", "verified"):
        assert expected in kinds
    verified = next(e for e in detail["events"] if e["kind"] == "verified")
    assert all(c["passed"] for c in verified["data"]["checks"])
    stored = client.get(f"/api/patches/{patch['id']}").json()["verification"]
    assert stored["state"] == "verified_fixed"


def test_patch_that_does_not_remove_the_finding_is_reported_still_detected(client, monkeypatch):
    env = Env(client, {"auth.py": APP})
    env.scan()
    f = env.finding("py.weak-hash")
    patch = client.post(f"/api/findings/{f['id']}/generate-fix", json={}).json()
    applied = client.post(f"/api/patches/{patch['id']}/apply").json()
    assert applied["status"] == "applied"
    # Simulate a bad/ineffective change: the applied snapshot still contains the vulnerable code.
    from netguard.db import get_session_factory
    from netguard.models import Patch, Snapshot
    from netguard.services.snapshots import snapshot_root

    with get_session_factory()() as db:
        p = db.get(Patch, patch["id"])
        snap = db.get(Snapshot, p.applied_snapshot_id)
        (snapshot_root(snap) / "auth.py").write_text(APP)  # revert on disk behind the scenes
    run_verification(env, f["id"], patch["id"])
    detail = env.detail(f["id"])
    # Work is still in progress: a failed fix must never leave the finding looking resolved.
    assert detail["verification"] == "still_detected" and detail["status"] == "in_progress"
    verified = next(e for e in detail["events"] if e["kind"] == "verified")
    assert not verified["data"]["checks"][0]["passed"]


def test_unable_to_verify_when_scanner_result_is_incomplete(client, monkeypatch):
    env = Env(client, {"requirements.txt": "Django==3.2.0\n"})
    from tests.test_deps_scanner import ADVISORIES, install_mock_osv

    install_mock_osv(monkeypatch)
    env.scan(("dependencies",))
    f = env.findings()[0]
    patch = client.post(f"/api/findings/{f['id']}/generate-fix", json={}).json()
    assert patch["generator"] == "rule" and "Django==3.2.5" in patch["diff"]
    client.post(f"/api/patches/{patch['id']}/apply")
    install_mock_osv(monkeypatch, fail=True)  # vulnerability database unreachable during verification
    import shutil

    shutil.rmtree(get_settings().cache_dir, ignore_errors=True)
    run_verification(env, f["id"], patch["id"])
    detail = env.detail(f["id"])
    assert detail["verification"] == "unable_to_verify" and detail["status"] == "in_progress"
    assert ADVISORIES  # advisories are synthetic test data
    # Once the database is reachable again the same patch verifies properly.
    install_mock_osv(monkeypatch, vulnerable={})
    run_verification(env, f["id"], patch["id"])
    assert env.detail(f["id"])["verification"] == "verified_fixed"


def test_ai_generated_patch_uses_exact_replacements_and_labels_itself(client, monkeypatch):
    src = "import subprocess\n\n\ndef run(host):\n    subprocess.call('ping ' + host, shell=True)\n"
    env = Env(client, {"run.py": src})
    env.scan()
    f = env.finding("py.command-injection")
    assert client.post(f"/api/findings/{f['id']}/generate-fix", json={}).status_code == 422  # no key

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    get_settings.cache_clear()
    reply = {"explanation": "Pass an argument list and drop shell=True.",
             "replacements": [{"old": "subprocess.call('ping ' + host, shell=True)",
                               "new": "subprocess.call(['ping', host])"}],
             "caveats": ["Behaviour changes if host contained shell syntax."]}
    monkeypatch.setattr(llm, "complete", lambda *a, **k: llm.LlmResult(json.dumps(reply), "claude-opus-5"))
    r = client.post(f"/api/findings/{f['id']}/generate-fix", json={})
    assert r.status_code == 201, r.text
    patch = r.json()
    assert patch["generator"] == "ai" and "subprocess.call(['ping', host])" in patch["diff"]
    assert any("written by AI" in c for c in patch["caveats"])
    assert patch["verification"]["preflight"]["rule_still_triggers"] is False
    client.post(f"/api/patches/{patch['id']}/apply")
    run_verification(env, f["id"], patch["id"])
    assert env.detail(f["id"])["verification"] == "verified_fixed"


@pytest.mark.parametrize("reply,msg", [
    ({"explanation": "x", "replacements": [{"old": "does not exist", "new": "y"}]}, "exactly once"),
    ({"explanation": "cannot", "replacements": []}, "could not produce"),
    ({"explanation": "x", "replacements": [{"old": "def run(host):", "new": "def run(host)"}]}, "syntax"),
    ({"explanation": "x", "replacements": [{"old": "import subprocess", "new": "import subprocess"}]}, "changes nothing"),
])
def test_bad_ai_patches_are_rejected_and_nothing_is_stored(client, monkeypatch, reply, msg):
    src = "import subprocess\n\n\ndef run(host):\n    subprocess.call('ping ' + host, shell=True)\n"
    env = Env(client, {"run.py": src})
    env.scan()
    f = env.finding("py.command-injection")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    get_settings.cache_clear()
    monkeypatch.setattr(llm, "complete", lambda *a, **k: llm.LlmResult(json.dumps(reply), "m"))
    r = client.post(f"/api/findings/{f['id']}/generate-fix", json={})
    assert r.status_code == 422 and msg in r.json()["detail"], r.text
    assert client.get(f"/api/findings/{f['id']}/patches").json() == []


def test_oversized_ai_change_is_refused(client, monkeypatch):
    src = "import subprocess\n" + "\n".join(f"x{i} = {i}" for i in range(150)) + "\nsubprocess.call('a' + b, shell=True)\n"
    env = Env(client, {"big.py": src})
    env.scan()
    f = env.finding("py.command-injection")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    get_settings.cache_clear()
    body = "\n".join(f"x{i} = {i}" for i in range(150))
    reply = {"explanation": "rewrite", "replacements": [{"old": body, "new": body.replace("=", "==")}]}
    monkeypatch.setattr(llm, "complete", lambda *a, **k: llm.LlmResult(json.dumps(reply), "m"))
    r = client.post(f"/api/findings/{f['id']}/generate-fix", json={})
    assert r.status_code == 422 and "too large" in r.json()["detail"]


def test_apply_conflicts_and_state_rules(client):
    env = Env(client, {"auth.py": APP})
    env.scan()
    f = env.finding("py.weak-hash")
    patch = client.post(f"/api/findings/{f['id']}/generate-fix", json={}).json()
    env.upload({"auth.py": APP + "\n# edited elsewhere\n"})  # repository moved on
    r = client.post(f"/api/patches/{patch['id']}/apply")
    assert r.status_code == 409 and "newer snapshot" in r.json()["detail"]
    rej = client.post(f"/api/patches/{patch['id']}/reject").json()
    assert rej["status"] == "rejected"
    assert client.post(f"/api/patches/{patch['id']}/apply").status_code == 409
    assert client.post(f"/api/findings/{f['id']}/validate", json={"patch_id": patch["id"]}).status_code == 409


def test_permissions_viewers_cannot_generate_or_apply_and_strangers_see_nothing(client, make_client):
    env = Env(client, {"auth.py": APP})
    env.scan()
    f = env.finding("py.weak-hash")
    patch = client.post(f"/api/findings/{f['id']}/generate-fix", json={}).json()
    viewer, stranger = make_client("v@example.com"), make_client("s@example.com")
    client.post(f"/api/projects/{env.project['id']}/members", json={"email": "v@example.com", "role": "viewer"})
    assert viewer.get(f"/api/findings/{f['id']}/patches").status_code == 200
    assert viewer.post(f"/api/findings/{f['id']}/generate-fix", json={}).status_code == 403
    assert viewer.post(f"/api/patches/{patch['id']}/apply").status_code == 403
    assert viewer.post(f"/api/findings/{f['id']}/validate", json={}).status_code == 403
    assert stranger.get(f"/api/patches/{patch['id']}").status_code == 404
    assert stranger.post(f"/api/patches/{patch['id']}/apply").status_code == 404
