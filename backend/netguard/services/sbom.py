"""Software Bill of Materials: CycloneDX 1.5 and SPDX 2.3 (JSON).

Components come from the same manifest/lockfile parsers as the dependency scanner (exact versions
only; nothing is guessed). CycloneDX includes vulnerability associations taken from the project's
existing dependency findings (which originate from OSV.dev). SPDX 2.3 has no vulnerability model,
so none is emitted there.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import quote
from uuid import uuid4

from netguard import __version__
from netguard.scanners.dependencies.models import MAVEN, NPM, NUGET, PYPI, Package

_PURL_TYPE = {NPM: "npm", PYPI: "pypi", MAVEN: "maven", NUGET: "nuget"}


def purl(p: Package) -> str:
    kind = _PURL_TYPE.get(p.ecosystem, "generic")
    name = p.name
    if p.ecosystem == NPM and name.startswith("@"):
        scope, _, rest = name.partition("/")
        ns_name = f"{quote(scope, safe='')}/{quote(rest, safe='')}"
    elif p.ecosystem == MAVEN and ":" in name:
        group, _, artifact = name.partition(":")
        ns_name = f"{quote(group, safe='.-_')}/{quote(artifact, safe='')}"
    else:
        ns_name = quote(name, safe="")
    return f"pkg:{kind}/{ns_name}@{quote(p.version, safe='')}"


def _key(p: Package) -> tuple[str, str, str]:
    return (p.ecosystem, p.name, p.version)


def dedupe(packages: list[Package]) -> list[Package]:
    """One component per (ecosystem, name, version); a direct occurrence wins."""
    best: dict[tuple[str, str, str], Package] = {}
    for p in packages:
        cur = best.get(_key(p))
        if cur is None or (p.direct and not cur.direct):
            best[_key(p)] = p
    return sorted(best.values(), key=lambda p: (p.ecosystem, p.name.lower(), p.version))


def _edges(components: list[Package]) -> dict[str, set[str]]:
    """Dependency edges derived from each component's chain (a > b > c gives a->b, b->c)."""
    by_name: dict[tuple[str, str], list[Package]] = {}
    for p in components:
        by_name.setdefault((p.ecosystem, p.name), []).append(p)
    edges: dict[str, set[str]] = {}
    for p in components:
        chain = p.path or [p.name]
        for parent_name, child_name in zip(chain, chain[1:], strict=False):
            parents = by_name.get((p.ecosystem, parent_name), [])
            child = p if child_name == p.name else None
            if child is None or not parents:
                continue
            same_manifest = [x for x in parents if x.manifest == p.manifest] or parents
            edges.setdefault(purl(same_manifest[0]), set()).add(purl(child))
    return edges


def cyclonedx(
    components: list[Package],
    *,
    project_name: str,
    vulnerabilities: list[dict] | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(UTC)
    comps = dedupe(components)
    root_ref = f"app:{project_name}"
    direct = [purl(p) for p in comps if p.direct]
    edges = _edges(comps)
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now.isoformat(),
            "tools": {"components": [{"type": "application", "name": "NetGuard",
                                      "version": __version__}]},
            "component": {"type": "application", "name": project_name, "bom-ref": root_ref},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": purl(p),
                "name": p.name,
                "version": p.version,
                "purl": purl(p),
                "scope": "optional" if p.dev else "required",
                "properties": [
                    {"name": "netguard:ecosystem", "value": p.ecosystem},
                    {"name": "netguard:manifest", "value": p.manifest},
                ],
            }
            for p in comps
        ],
        "dependencies": [{"ref": root_ref, "dependsOn": sorted(set(direct))}]
        + [{"ref": ref, "dependsOn": sorted(deps)} for ref, deps in sorted(edges.items())],
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def vulnerabilities_from_findings(findings: list) -> list[dict]:
    """CycloneDX vulnerability records from stored dependency findings (OSV-sourced)."""
    grouped: dict[str, dict] = {}
    for f in findings:
        x = f.extra or {}
        vid = x.get("vulnerability")
        if not vid or not x.get("package"):
            continue
        p = Package(x.get("ecosystem", ""), x["package"], x.get("version", ""), f.file_path)
        rec = grouped.setdefault(vid, {
            "id": vid,
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
            "ratings": [{"source": {"name": "OSV"}, "severity": f.severity,
                         "method": "other"}],
            "description": (f.description or "")[:500],
            "recommendation": f.remediation,
            "affects": [],
        })
        rec["affects"].append({"ref": purl(p)})
        if x.get("cve"):
            rec.setdefault("references", []).append(
                {"id": x["cve"], "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{x['cve']}"}})
    return list(grouped.values())


def spdx(components: list[Package], *, project_name: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    comps = dedupe(components)
    root = "SPDXRef-RootApplication"
    packages = [{
        "SPDXID": root, "name": project_name, "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    ids: dict[str, str] = {}
    for i, p in enumerate(comps, 1):
        spdx_id = f"SPDXRef-Package-{i}"
        ids[purl(p)] = spdx_id
        packages.append({
            "SPDXID": spdx_id, "name": p.name, "versionInfo": p.version,
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": purl(p)}],
        })
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": root}]
    for p in comps:
        if p.direct:
            rels.append({"spdxElementId": root, "relationshipType": "DEPENDS_ON",
                         "relatedSpdxElement": ids[purl(p)]})
    for parent, children in sorted(_edges(comps).items()):
        for child in sorted(children):
            if parent in ids and child in ids:
                rels.append({"spdxElementId": ids[parent], "relationshipType": "DEPENDS_ON",
                             "relatedSpdxElement": ids[child]})
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project_name}-sbom",
        "documentNamespace": f"https://netguard.invalid/spdx/{uuid4()}",
        "creationInfo": {"created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": [f"Tool: NetGuard-{__version__}"]},
        "packages": packages, "relationships": rels,
    }
