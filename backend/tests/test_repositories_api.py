import io
import zipfile


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def setup_repo(client, name="web"):
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    r = client.post(f"/api/projects/{p['id']}/repositories", json={"name": name})
    assert r.status_code == 201, r.text
    return p, r.json()


def upload(client, repo_id, data, filename="code.zip"):
    return client.post(
        f"/api/repositories/{repo_id}/upload", files={"file": (filename, data, "application/zip")}
    )


def test_upload_creates_snapshot_and_lists_files(client):
    _, repo = setup_repo(client)
    r = upload(client, repo["id"], make_zip({"app/main.py": "print(1)\n", "README.md": "hi"}))
    assert r.status_code == 201, r.text
    snap = r.json()
    assert snap["file_count"] == 2
    files = client.get(f"/api/snapshots/{snap['id']}/files").json()
    assert {f["path"] for f in files} == {"app/main.py", "README.md"}
    assert next(f for f in files if f["path"] == "app/main.py")["language"] == "python"
    content = client.get(f"/api/snapshots/{snap['id']}/file", params={"path": "app/main.py"})
    assert content.json()["content"] == "print(1)\n"
    repos = client.get(f"/api/projects/{repo['project_id']}/repositories").json()
    assert repos[0]["latest_snapshot_id"] == snap["id"]


def test_malicious_archive_is_rejected_with_422(client):
    _, repo = setup_repo(client)
    r = upload(client, repo["id"], make_zip({"../../evil.py": "x"}))
    assert r.status_code == 422


def test_non_archive_upload_rejected(client):
    _, repo = setup_repo(client)
    assert upload(client, repo["id"], b"just text").status_code == 422


def test_upload_size_limit(client, monkeypatch):
    import os

    from netguard.config import get_settings

    _, repo = setup_repo(client)
    monkeypatch.setenv("NETGUARD_MAX_UPLOAD_MB", "1")
    get_settings.cache_clear()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("blob.bin", os.urandom(2 * 1024 * 1024))
    assert upload(client, repo["id"], buf.getvalue()).status_code == 413


def test_file_read_rejects_traversal(client):
    _, repo = setup_repo(client)
    snap = upload(client, repo["id"], make_zip({"a.py": "1"})).json()
    for evil in ["../../../etc/passwd", "..\\..\\secret", "/etc/passwd"]:
        r = client.get(f"/api/snapshots/{snap['id']}/file", params={"path": evil})
        assert r.status_code in (400, 404)


def test_other_users_cannot_access_repository_or_snapshot(client, make_client):
    _, repo = setup_repo(client)
    snap = upload(client, repo["id"], make_zip({"a.py": "1"})).json()
    other = make_client("intruder@example.com")
    assert other.get(f"/api/snapshots/{snap['id']}/files").status_code == 404
    assert other.get(f"/api/repositories/{repo['id']}/snapshots").status_code == 404
    assert upload(other, repo["id"], make_zip({"a.py": "1"})).status_code == 404


def test_delete_repository_removes_snapshot_files(client):
    from netguard.config import get_settings

    _, repo = setup_repo(client)
    snap = upload(client, repo["id"], make_zip({"a.py": "1"})).json()
    root = get_settings().snapshots_dir
    assert any(root.rglob("a.py"))
    assert client.delete(f"/api/repositories/{repo['id']}").status_code == 204
    assert not any(root.rglob("a.py"))
    assert client.get(f"/api/snapshots/{snap['id']}/files").status_code == 404
