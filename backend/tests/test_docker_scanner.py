import io
import json
import tarfile
import textwrap
from pathlib import Path

import httpx
import pytest

from netguard.config import get_settings
from netguard.scanners.base import ScanContext
from netguard.scanners.dependencies import osv as osv_module
from netguard.scanners.docker import image as img
from netguard.scanners.docker.config import is_eol, parse_dockerfile, scan_compose, scan_dockerfile
from netguard.scanners.registry import get_scanner
from netguard.worker import process_one


def df(src):
    return sorted({f.rule_id for f in scan_dockerfile("Dockerfile", textwrap.dedent(src))})


GOOD = """\
FROM python:3.12-slim@sha256:%s
RUN pip install --no-cache-dir -r requirements.txt
USER app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
""" % ("a" * 64)


def test_hardened_dockerfile_is_clean():
    assert df(GOOD) == []


@pytest.mark.parametrize("src,rule", [
    ("FROM node\nUSER app\nHEALTHCHECK CMD true\n", "docker.mutable-base-image"),
    ("FROM node:latest\nUSER app\nHEALTHCHECK CMD true\n", "docker.mutable-base-image"),
    ("FROM ubuntu:18.04\nUSER app\nHEALTHCHECK CMD true\n", "docker.eol-base-image"),
    ("FROM python:3.7-slim\nUSER app\nHEALTHCHECK CMD true\n", "docker.eol-base-image"),
    ("FROM alpine:3.12\nUSER app\nHEALTHCHECK CMD true\n", "docker.eol-base-image"),
    ("FROM app:1\nHEALTHCHECK CMD true\n", "docker.root-user"),
    ("FROM app:1\nUSER root\nHEALTHCHECK CMD true\n", "docker.root-user"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nADD https://x.io/a.tgz /a\n", "docker.add-remote-url"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nRUN curl -sSL https://x.io/i.sh | sh\n", "docker.curl-pipe-shell"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nENV DB_PASSWORD=hunter2hunter2\n", "docker.secret-in-env"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nARG API_TOKEN abcd1234\n", "docker.secret-in-env"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nEXPOSE 80 22\n", "docker.exposed-ssh"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nRUN chmod -R 777 /app\n", "docker.chmod-777"),
    ("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nRUN sudo apt-get update\n", "docker.sudo"),
    ("FROM app:1\nUSER app\n", "docker.no-healthcheck"),
])
def test_dockerfile_rules(src, rule):
    assert rule in df(src)


def test_dockerfile_negatives_and_multistage():
    multi = "FROM golang:1.22 AS build\nRUN go build\nFROM build AS final\nUSER app\nHEALTHCHECK CMD true\n"
    assert df(multi) == []  # 'FROM build' references a stage; earlier stage user irrelevant
    assert "docker.root-user" in df("FROM a:1 AS b\nUSER app\nFROM c:1\nHEALTHCHECK CMD true\n")  # last stage counts
    assert df("FROM scratch\nUSER 1000\nHEALTHCHECK CMD true\n") == []
    assert df("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nENV PASSWORD=$PW\nENV API_TOKEN=\n") == []
    assert df("FROM app:1\nUSER app\nHEALTHCHECK CMD true\nEXPOSE 2222\n") == []
    assert df("FROM ${BASE}\nUSER app\nHEALTHCHECK CMD true\n") == []


def test_dockerfile_line_numbers_and_continuations():
    src = "FROM app:1\nUSER app\nHEALTHCHECK CMD true\nRUN apt-get update && \\\n    curl https://x | sh\n"
    (f,) = [f for f in scan_dockerfile("Dockerfile", src) if f.rule_id == "docker.curl-pipe-shell"]
    assert f.line == 4 and f.language == "dockerfile" and f.file_path == "Dockerfile"
    assert [i.op for i in parse_dockerfile("# c\nFROM a\n\nRUN x")] == ["FROM", "RUN"]


def test_eol_table_only_flags_known_releases():
    assert is_eol("ubuntu:18.04") and is_eol("debian:buster-slim") and is_eol("node:14-alpine")
    assert not is_eol("ubuntu:24.04") and not is_eol("python:3.12") and not is_eol("nginx:1.25")
    assert not is_eol("myrepo/ubuntu") and not is_eol("reg.io:5000/node")


COMPOSE = """\
services:
  db:
    image: postgres:latest
    privileged: true
    network_mode: host
    cap_add: [SYS_ADMIN]
    security_opt: ["seccomp:unconfined"]
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: supersecretpw
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  web:
    image: nginx:1.25
    user: "1000"
    ports: ["127.0.0.1:5432:5432", "8080:80"]
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
"""


def test_compose_rules_and_safe_service():
    fs = scan_compose("docker-compose.yml", COMPOSE)
    by = {f.rule_id for f in fs}
    assert {"compose.privileged", "compose.host-namespace", "compose.dangerous-capabilities",
            "compose.security-opt-unconfined", "compose.docker-socket", "compose.exposed-database-port",
            "compose.secret-in-environment", "docker.mutable-base-image"} <= by
    assert all(f.extra["resource"] == "service/db" for f in fs)  # nothing reported for `web`
    assert next(f for f in fs if f.rule_id == "compose.privileged").line == 4
    assert scan_compose("x.yml", "version: 1\nname: x\n") == []


# ---- container images ------------------------------------------------------------------------------
DPKG = """\
Package: libssl3
Status: install ok installed
Source: openssl
Version: 3.0.11-1~deb12u1

Package: bash
Status: install ok installed
Version: 5.2.15-2

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0
"""
OS_DEBIAN = 'ID=debian\nVERSION_ID="12"\n'


def build_image(path: Path, *, layers: list[dict[str, str]], config=None, tags=("myapp:latest",)) -> Path:
    def layer_tar(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, content in files.items():
                data = content.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    cfg = {"config": {"User": "", "ExposedPorts": {}, "Env": [], "Healthcheck": None}}
    if config:
        cfg["config"].update(config)
    with tarfile.open(path, "w") as tf:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        names = []
        for i, files in enumerate(layers):
            add(f"l{i}/layer.tar", layer_tar(files))
            names.append(f"l{i}/layer.tar")
        add("cfg.json", json.dumps(cfg).encode())
        add("manifest.json", json.dumps([{"Config": "cfg.json", "RepoTags": list(tags), "Layers": names}]).encode())
    return path


def test_image_parsing_dpkg_layers_override_and_os(tmp_path):
    p = build_image(tmp_path / "i.tar", layers=[
        {"etc/os-release": 'ID=debian\nVERSION_ID="11"\n', "var/lib/dpkg/status": "Package: old\nStatus: install ok installed\nVersion: 1\n"},
        {"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": DPKG}])
    info = img.analyze_image(p)
    assert (info.os_id, info.os_version, info.package_manager, info.layers) == ("debian", "12", "dpkg", 2)
    assert {(x.name, x.version) for x in info.packages} == {("openssl", "3.0.11-1~deb12u1"), ("bash", "5.2.15-2")}
    assert img.osv_ecosystem(info) == "Debian:12" and info.repo_tags == ["myapp:latest"]


def test_apk_parsing_and_alpine_ecosystem(tmp_path):
    apk = "P:musl\nV:1.2.4-r2\no:musl\n\nP:busybox-extras\nV:1.36.1-r5\no:busybox\n"
    p = build_image(tmp_path / "a.tar", layers=[{"etc/os-release": 'ID=alpine\nVERSION_ID=3.19.1\n', "lib/apk/db/installed": apk}])
    info = img.analyze_image(p)
    assert {(x.name, x.version) for x in info.packages} == {("musl", "1.2.4-r2"), ("busybox", "1.36.1-r5")}
    assert img.osv_ecosystem(info) == "Alpine:v3.19"


def test_invalid_images_raise(tmp_path):
    junk = tmp_path / "x.tar"
    junk.write_bytes(b"not a tar")
    with pytest.raises(img.ImageError):
        img.analyze_image(junk)
    plain = tmp_path / "plain.tar"
    with tarfile.open(plain, "w") as tf:
        info = tarfile.TarInfo("readme")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(img.ImageError, match="manifest.json"):
        img.analyze_image(plain)


ADVISORY = {
    "id": "DSA-test-0001", "aliases": ["CVE-2099-1111"], "summary": "Test advisory for openssl",
    "database_specific": {"severity": "HIGH"},
    "affected": [{"package": {"ecosystem": "Debian:12", "name": "openssl"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.11-1~deb12u2"}]}]}],
}
REAL_OSV = osv_module.OsvClient


def mock_osv(monkeypatch, vulnerable=True, fail=False):
    def handler(request):
        if fail:
            return httpx.Response(503)
        if request.url.path == "/v1/querybatch":
            qs = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "DSA-test-0001"}]}
                if vulnerable and q["package"] == {"name": "openssl", "ecosystem": "Debian:12"}
                and q["version"].endswith("deb12u1") else {}
                for q in qs]})
        return httpx.Response(200, json=ADVISORY)

    def factory(base_url, **kw):
        kw.update(client=httpx.Client(transport=httpx.MockTransport(handler)), offline=False)
        return REAL_OSV(base_url, **kw)

    monkeypatch.setattr(osv_module, "OsvClient", factory)


def scan_image(tmp_path, path, name="", cache=False):
    uploads = tmp_path
    ctx = ScanContext(config={"image_path": path.name, "image_name": name},
                      runtime={"uploads_dir": str(uploads), "osv_offline": False, "cache_dir": ""})
    return get_scanner("docker").scan(ctx)


def test_image_scan_reports_config_and_vulnerable_packages(tmp_path, monkeypatch):
    mock_osv(monkeypatch)
    p = build_image(tmp_path / "img.tar", layers=[{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": DPKG}],
                    config={"ExposedPorts": {"22/tcp": {}}, "Env": ["DB_PASSWORD=hunter2hunter2", "PATH=/bin"]})
    res = scan_image(tmp_path, p)
    by = {f.rule_id: f for f in res.findings}
    assert {"image.root-user", "image.exposed-ssh", "image.secret-in-env", "image.no-healthcheck",
            "image.vulnerable-package"} <= set(by)
    vuln = by["image.vulnerable-package"]
    assert vuln.severity.value == "high" and "openssl 3.0.11-1~deb12u1" in vuln.title and "CVE-2099-1111" in vuln.title
    assert vuln.extra["fixed_versions"] == ["3.0.11-1~deb12u2"] and vuln.extra["image"] == "myapp:latest"
    assert "Update openssl to 3.0.11-1~deb12u2" in vuln.remediation
    assert vuln.asset.type == "container_image" and vuln.asset.identifier == "myapp:latest"
    assert "hunter2" not in json.dumps([f.description for f in res.findings])
    counts = res.metadata["severity_counts"]
    # high: baked-in secret + vulnerable openssl; medium: root user + SSH; info: no healthcheck
    assert counts == {"critical": 0, "high": 2, "medium": 2, "low": 0, "info": 1}
    assert res.complete and res.metadata["packages"] == 2 and res.metadata["os"] == "debian 12"


def test_hardened_clean_image(tmp_path, monkeypatch):
    mock_osv(monkeypatch, vulnerable=False)
    p = build_image(tmp_path / "img.tar", layers=[{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": DPKG}],
                    config={"User": "1000", "Healthcheck": {"Test": ["CMD", "true"]}})
    res = scan_image(tmp_path, p, name="clean:1")
    assert res.findings == [] and res.complete and res.metadata["image"] == "clean:1"


def test_unsupported_os_and_osv_outage_are_incomplete_never_clean(tmp_path, monkeypatch):
    ubuntu = build_image(tmp_path / "u.tar", layers=[{"etc/os-release": 'ID=ubuntu\nVERSION_ID="22.04"\n', "var/lib/dpkg/status": DPKG}],
                         config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    res = scan_image(tmp_path, ubuntu)
    assert res.complete is False and "NOT checked" in res.warnings[0] and res.findings == []
    mock_osv(monkeypatch, fail=True)
    deb = build_image(tmp_path / "d.tar", layers=[{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": DPKG}],
                      config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    res = scan_image(tmp_path, deb)
    assert res.complete is False and "NOT checked" in " ".join(res.warnings)


def test_eol_os_and_scratch_images(tmp_path, monkeypatch):
    mock_osv(monkeypatch, vulnerable=False)
    old = build_image(tmp_path / "o.tar", layers=[{"etc/os-release": 'ID=debian\nVERSION_ID="10"\n', "var/lib/dpkg/status": DPKG}],
                      config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    assert [f.rule_id for f in scan_image(tmp_path, old).findings] == ["image.eol-os"]
    scratch = build_image(tmp_path / "s.tar", layers=[{"app": "bin"}], config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    res = scan_image(tmp_path, scratch)
    assert res.findings == [] and "No OS package database" in res.warnings[0]


def test_image_path_cannot_escape_uploads_dir(tmp_path):
    ctx = ScanContext(config={"image_path": "../../etc/passwd"}, runtime={"uploads_dir": str(tmp_path)})
    with pytest.raises(img.ImageError):
        get_scanner("docker").scan(ctx)


def test_source_scan_finds_dockerfile_and_compose_in_repo(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc/Dockerfile").write_text("FROM node\n")
    (tmp_path / "docker-compose.yml").write_text(COMPOSE)
    (tmp_path / "notes.txt").write_text("FROM node")
    res = get_scanner("docker").scan(ScanContext(root=tmp_path))
    files = {f.file_path for f in res.findings}
    assert files == {"svc/Dockerfile", "docker-compose.yml"} and res.metadata["files_analyzed"] == 2


# ---- API: upload an image, get findings, cleanup, rescan resolves -----------------------------------
def upload(client, project, path, name="myapp:latest"):
    with open(path, "rb") as fh:
        r = client.post(f"/api/projects/{project['id']}/container-scans",
                        files={"file": ("image.tar", fh.read(), "application/x-tar")}, data={"image_name": name})
    assert r.status_code == 202, r.text
    process_one("w")
    return client.get(f"/api/scans/{r.json()['id']}").json()


def test_container_scan_api_flow_deduplicates_resolves_and_cleans_up(client, tmp_path, monkeypatch):
    mock_osv(monkeypatch)
    client.register()
    project = client.post("/api/projects", json={"name": "P"}).json()
    layers = [{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": DPKG}]
    img1 = build_image(tmp_path / "v1.tar", layers=layers, config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    done = upload(client, project, img1)
    assert done["status"] == "completed" and done["kind"] == "container"
    items = client.get("/api/findings", params={"project_id": project["id"]}).json()["items"]
    assert [i["rule_id"] for i in items] == ["image.vulnerable-package"]
    assert items[0]["detection_source"] == "Docker Scanner" and items[0]["asset"] == "myapp:latest"
    assert not list((get_settings().uploads_dir / "images").glob("*.tar"))  # tarball removed after the scan

    again = upload(client, project, img1)
    assert again["summary"]["scanners"]["docker"]["ingest"]["new"] == 0
    # A different (clean) image's scan must not resolve myapp's findings...
    other_layers = [{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": "Package: bash\nStatus: install ok installed\nVersion: 5.2\n"}]
    other = build_image(tmp_path / "o.tar", layers=other_layers, tags=("other:1",), config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    upload(client, project, other, name="other:1")
    assert client.get("/api/findings", params={"project_id": project["id"], "status": "open"}).json()["total"] == 1
    # ...but rescanning myapp after rebuilding it with the patched package does.
    patched = DPKG.replace("deb12u1", "deb12u2")
    img2 = build_image(tmp_path / "v2.tar", layers=[{"etc/os-release": OS_DEBIAN, "var/lib/dpkg/status": patched}],
                       config={"User": "1", "Healthcheck": {"Test": ["CMD", "x"]}})
    fixed = upload(client, project, img2)
    assert fixed["summary"]["scanners"]["docker"]["ingest"]["resolved"] == 1


def test_container_scan_api_validation(client, make_client, tmp_path, monkeypatch):
    client.register()
    project = client.post("/api/projects", json={"name": "P"}).json()
    bad = client.post(f"/api/projects/{project['id']}/container-scans",
                      files={"file": ("x.tar", b"garbage", "application/x-tar")})
    assert bad.status_code == 202
    process_one("w")
    scan = client.get(f"/api/scans/{bad.json()['id']}").json()
    assert scan["status"] == "failed" and "not a valid image" in scan["error"].lower()
    monkeypatch.setenv("NETGUARD_MAX_IMAGE_MB", "1")
    get_settings.cache_clear()
    big = client.post(f"/api/projects/{project['id']}/container-scans",
                      files={"file": ("x.tar", b"\0" * (2 * 1024 * 1024), "application/x-tar")})
    assert big.status_code == 413
    other = make_client("o@example.com")
    assert other.post(f"/api/projects/{project['id']}/container-scans", files={"file": ("x.tar", b"x")}).status_code == 404
