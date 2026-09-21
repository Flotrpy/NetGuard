import io
import json
import zipfile

from netguard.scanners.dependencies.models import MAVEN, NPM, NUGET, PYPI, Package
from netguard.services import sbom
from netguard.services.sbom import cyclonedx, dedupe, purl, spdx

PKGS = [
    Package(NPM, "express", "4.18.2", "package-lock.json", direct=True, path=["express"]),
    Package(NPM, "qs", "6.11.0", "package-lock.json", direct=False, path=["express", "qs"]),
    Package(NPM, "@babel/core", "7.20.0", "package-lock.json", direct=True, dev=True, path=["@babel/core"]),
    Package(PYPI, "django", "3.2.0", "requirements.txt", direct=True, path=["django"]),
    Package(MAVEN, "org.yaml:snakeyaml", "1.30", "pom.xml", direct=True, path=["org.yaml:snakeyaml"]),
    Package(NUGET, "Newtonsoft.Json", "13.0.1", "a.csproj", direct=True, path=["Newtonsoft.Json"]),
    Package(NPM, "qs", "6.11.0", "other/package-lock.json", direct=True, path=["qs"]),  # duplicate coordinate
]


def test_purl_formats_per_ecosystem():
    p = {(x.ecosystem, x.name): purl(x) for x in PKGS}
    assert p[(NPM, "express")] == "pkg:npm/express@4.18.2"
    assert p[(NPM, "@babel/core")] == "pkg:npm/%40babel/core@7.20.0"
    assert p[(PYPI, "django")] == "pkg:pypi/django@3.2.0"
    assert p[(MAVEN, "org.yaml:snakeyaml")] == "pkg:maven/org.yaml/snakeyaml@1.30"
    assert p[(NUGET, "Newtonsoft.Json")] == "pkg:nuget/Newtonsoft.Json@13.0.1"


def test_dedupe_keeps_one_component_per_coordinate_preferring_direct():
    comps = dedupe(PKGS)
    assert len(comps) == 6
    qs = next(c for c in comps if c.name == "qs")
    assert qs.direct  # the direct occurrence wins


def test_cyclonedx_structure_and_dependency_graph():
    bom = cyclonedx(PKGS[:6], project_name="Shop/web")
    assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.5")
    assert bom["serialNumber"].startswith("urn:uuid:") and bom["metadata"]["tools"]["components"][0]["name"] == "NetGuard"
    refs = {c["bom-ref"]: c for c in bom["components"]}
    assert len(refs) == 6 and refs["pkg:npm/%40babel/core@7.20.0"]["scope"] == "optional"
    assert refs["pkg:npm/express@4.18.2"]["scope"] == "required" and refs["pkg:npm/qs@6.11.0"]["purl"] == "pkg:npm/qs@6.11.0"
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert "pkg:npm/express@4.18.2" in deps["app:Shop/web"] and "pkg:npm/qs@6.11.0" not in deps["app:Shop/web"]
    assert deps["pkg:npm/express@4.18.2"] == ["pkg:npm/qs@6.11.0"]
    assert "vulnerabilities" not in bom


def test_cyclonedx_vulnerability_associations_from_findings():
    class F:
        severity, description, remediation, file_path = "high", "d", "Upgrade qs to 6.11.1.", "package-lock.json"
        extra = {"package": "qs", "version": "6.11.0", "ecosystem": NPM, "vulnerability": "GHSA-test-1", "cve": "CVE-2099-1"}

    vulns = sbom.vulnerabilities_from_findings([F(), F()])
    assert len(vulns) == 1 and vulns[0]["id"] == "GHSA-test-1"
    assert vulns[0]["source"]["url"] == "https://osv.dev/vulnerability/GHSA-test-1"
    assert vulns[0]["affects"][0]["ref"] == "pkg:npm/qs@6.11.0" and vulns[0]["ratings"][0]["severity"] == "high"
    assert vulns[0]["references"][0]["id"] == "CVE-2099-1"
    bom = cyclonedx(PKGS[:2], project_name="p", vulnerabilities=vulns)
    assert bom["vulnerabilities"][0]["affects"][0]["ref"] in {c["bom-ref"] for c in bom["components"]}


def test_spdx_structure_relationships_and_ids():
    doc = spdx(PKGS[:6], project_name="Shop/web")
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0" and doc["SPDXID"] == "SPDXRef-DOCUMENT"
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) == 7  # root + 6
    assert doc["relationships"][0] == {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                       "relatedSpdxElement": "SPDXRef-RootApplication"}
    express = next(p for p in doc["packages"] if p["name"] == "express")
    qs = next(p for p in doc["packages"] if p["name"] == "qs")
    assert {"spdxElementId": express["SPDXID"], "relationshipType": "DEPENDS_ON", "relatedSpdxElement": qs["SPDXID"]} in doc["relationships"]
    assert express["externalRefs"][0]["referenceLocator"] == "pkg:npm/express@4.18.2"
    assert all(r["spdxElementId"] in ids + ["SPDXRef-DOCUMENT"] for r in doc["relationships"])
    assert doc["creationInfo"]["created"].endswith("Z") and doc["documentNamespace"].startswith("https://")


# ---- API ----------------------------------------------------------------------------------------
LOCK = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"express": "^4"}},
    "node_modules/express": {"version": "4.18.2", "dependencies": {"qs": "6.11.0"}},
    "node_modules/qs": {"version": "6.11.0"}}}


def project_repo(client, files):
    client.register()
    p = client.post("/api/projects", json={"name": "Shop"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "web"}).json()
    if files is not None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for n, c in files.items():
                zf.writestr(n, c)
        client.post(f"/api/repositories/{repo['id']}/upload", files={"file": ("a.zip", buf.getvalue(), "application/zip")})
    return p, repo


def test_sbom_download_both_formats(client):
    _, repo = project_repo(client, {"package-lock.json": json.dumps(LOCK), "requirements.txt": "Django==3.2.0\n"})
    r = client.get(f"/api/repositories/{repo['id']}/sbom")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and r.headers["content-disposition"].endswith('.cdx.json"')
    bom = r.json()
    assert bom["bomFormat"] == "CycloneDX" and {c["name"] for c in bom["components"]} == {"express", "qs", "django"}
    assert bom["metadata"]["component"]["name"] == "Shop/web"
    s = client.get(f"/api/repositories/{repo['id']}/sbom", params={"format": "spdx"})
    assert s.status_code == 200 and s.json()["spdxVersion"] == "SPDX-2.3" and s.headers["content-disposition"].endswith('.spdx.json"')
    assert client.get(f"/api/repositories/{repo['id']}/sbom", params={"format": "xml"}).status_code == 422


def test_sbom_includes_vulnerabilities_from_existing_findings(client):
    from netguard.db import get_session_factory
    from netguard.models import Finding, Scan

    p, repo = project_repo(client, {"package-lock.json": json.dumps(LOCK)})
    with get_session_factory()() as db:
        scan = Scan(project_id=p["id"], scanners=["dependencies"])
        db.add(scan)
        db.flush()
        db.add(Finding(project_id=p["id"], repository_id=repo["id"], scan_id=scan.id, scanner="dependencies",
                       rule_id="dep.osv", fingerprint="f1", title="t", severity="high", confidence="high",
                       description="qs is vulnerable", remediation="Upgrade qs.", file_path="package-lock.json",
                       extra={"package": "qs", "version": "6.11.0", "ecosystem": "npm", "vulnerability": "GHSA-test-1"}))
        db.commit()
    bom = client.get(f"/api/repositories/{repo['id']}/sbom").json()
    assert bom["vulnerabilities"][0]["id"] == "GHSA-test-1"
    assert bom["vulnerabilities"][0]["affects"][0]["ref"] == "pkg:npm/qs@6.11.0"


def test_sbom_errors_and_access_control(client, make_client):
    _, empty = project_repo(client, None)
    assert client.get(f"/api/repositories/{empty['id']}/sbom").status_code == 409
    p = client.post("/api/projects", json={"name": "P2"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "r"}).json()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("main.py", "print(1)")
    client.post(f"/api/repositories/{repo['id']}/upload", files={"file": ("a.zip", buf.getvalue(), "application/zip")})
    assert client.get(f"/api/repositories/{repo['id']}/sbom").status_code == 422
    other = make_client("o@example.com")
    assert other.get(f"/api/repositories/{repo['id']}/sbom").status_code == 404
