"""NuGet ecosystem: packages.config, *.csproj, Directory.Packages.props, packages.lock.json."""

from __future__ import annotations

import json
import re

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from netguard.scanners.dependencies.models import (
    NUGET,
    Package,
    ParseResult,
    find_line,
    shortest_paths,
)

_EXACT = re.compile(r"^\[?(\d+(?:\.\d+){0,3}(?:-[\w.]+)?)\]?$")


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _version(spec: str) -> str | None:
    """Accept exact versions ('1.2.3' or '[1.2.3]'); ranges are not resolvable statically."""
    m = _EXACT.match(spec.strip())
    return m.group(1) if m else None


def parse_packages_config(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, DefusedXmlException) as exc:
        result.warnings.append(f"{manifest}: could not parse XML ({type(exc).__name__})")
        return result
    for el in root.iter():
        if _strip_ns(el.tag) == "package" and el.get("id") and el.get("version"):
            result.packages.append(
                Package(NUGET, el.get("id"), el.get("version"), manifest, direct=True,
                        dev=el.get("developmentDependency") == "true", path=[el.get("id")],
                        line=find_line(text, f'id="{el.get("id")}"'))
            )
    return result


def parse_project_file(text: str, manifest: str) -> ParseResult:
    """*.csproj / *.fsproj / *.vbproj / Directory.Packages.props."""
    result = ParseResult()
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, DefusedXmlException) as exc:
        result.warnings.append(f"{manifest}: could not parse XML ({type(exc).__name__})")
        return result
    props: dict[str, str] = {}
    for el in root.iter():
        if _strip_ns(el.tag) == "PropertyGroup":
            for p in el:
                props[_strip_ns(p.tag)] = (p.text or "").strip()
    skipped = 0
    for el in root.iter():
        tag = _strip_ns(el.tag)
        if tag not in ("PackageReference", "PackageVersion"):
            continue
        name = el.get("Include") or el.get("Update")
        version = el.get("Version") or el.get("VersionOverride")
        if version is None:
            for child in el:
                if _strip_ns(child.tag) == "Version":
                    version = (child.text or "").strip()
        if not name:
            continue
        if version and version.startswith("$(") and version.endswith(")"):
            version = props.get(version[2:-1], "")
        exact = _version(version) if version else None
        if not exact:
            skipped += 1
            continue
        result.packages.append(
            Package(NUGET, name, exact, manifest, direct=True,
                    dev=any(_strip_ns(c.tag) == "PrivateAssets" and (c.text or "") == "all"
                            for c in el),
                    path=[name], line=find_line(text, f'"{name}"'))
        )
    if skipped:
        result.warnings.append(
            f"{manifest}: {skipped} package references have floating/ranged or central-managed "
            "versions and were skipped; use packages.lock.json for exact checks"
        )
    return result


def parse_packages_lock(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid JSON ({exc.msg})")
        return result
    seen: dict[str, Package] = {}
    for framework in (data.get("dependencies") or {}).values():
        roots = [n for n, m in framework.items() if m.get("type") == "Direct"]
        edges = {n: list(m.get("dependencies") or {}) for n, m in framework.items()}
        paths = shortest_paths(roots, edges)
        for name, meta in framework.items():
            version = meta.get("resolved")
            if not version or meta.get("type") == "Project":
                continue
            key = f"{name}@{version}"
            if key in seen:
                continue
            chain = paths.get(name, [name])
            seen[key] = Package(NUGET, name, version, manifest, direct=meta.get("type") == "Direct",
                                path=chain, line=find_line(text, f'"{name}"'))
    result.packages.extend(seen.values())
    return result
