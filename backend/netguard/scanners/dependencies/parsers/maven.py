"""Maven / Gradle ecosystem: pom.xml, build.gradle(.kts), gradle.lockfile."""

from __future__ import annotations

import re

from defusedxml import ElementTree as ET  # safe against entity expansion / XXE (untrusted input)
from defusedxml.common import DefusedXmlException

from netguard.scanners.dependencies.models import MAVEN, Package, ParseResult, find_line

_PROP = re.compile(r"\$\{([^}]+)\}")


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(el, name: str):
    return [c for c in el if _strip_ns(c.tag) == name]


def _text(el, name: str) -> str:
    for c in _children(el, name):
        return (c.text or "").strip()
    return ""


def parse_pom(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, DefusedXmlException) as exc:
        result.warnings.append(f"{manifest}: could not parse XML ({type(exc).__name__})")
        return result

    props: dict[str, str] = {}
    for props_el in _children(root, "properties"):
        for p in props_el:
            props[_strip_ns(p.tag)] = (p.text or "").strip()
    parent = next(iter(_children(root, "parent")), None)
    project_version = _text(root, "version") or (
        _text(parent, "version") if parent is not None else ""
    )
    props.setdefault("project.version", project_version)
    props.setdefault("version", project_version)
    props.setdefault("project.groupId", _text(root, "groupId") or
                     (_text(parent, "groupId") if parent is not None else ""))

    def resolve(value: str) -> str:
        for _ in range(5):
            new = _PROP.sub(lambda m: props.get(m.group(1), m.group(0)), value)
            if new == value:
                break
            value = new
        return value

    managed: dict[str, str] = {}
    for dm in _children(root, "dependencyManagement"):
        for deps in _children(dm, "dependencies"):
            for d in _children(deps, "dependency"):
                key = f"{resolve(_text(d, 'groupId'))}:{_text(d, 'artifactId')}"
                managed[key] = resolve(_text(d, "version"))

    unresolved = 0
    for deps in _children(root, "dependencies"):
        for d in _children(deps, "dependency"):
            group = resolve(_text(d, "groupId"))
            artifact = resolve(_text(d, "artifactId"))
            version = resolve(_text(d, "version")) or managed.get(f"{group}:{artifact}", "")
            if not (group and artifact) or not version or "${" in version or "[" in version \
                    or "(" in version:
                unresolved += 1
                continue
            result.packages.append(
                Package(MAVEN, f"{group}:{artifact}", version, manifest, direct=True,
                        dev=_text(d, "scope") == "test", path=[f"{group}:{artifact}"],
                        line=find_line(text, f"<artifactId>{artifact}</artifactId>"))
            )
    if unresolved:
        result.warnings.append(
            f"{manifest}: {unresolved} dependencies have no resolvable fixed version "
            "(inherited/BOM-managed, ranges or unresolved properties) and were skipped"
        )
    return result


_GRADLE_CONFIGS = (
    r"(?:implementation|api|compile|compileOnly|runtimeOnly|runtime|annotationProcessor|"
    r"testImplementation|testCompile|testRuntimeOnly|kapt|classpath)"
)
_GRADLE_STR = re.compile(
    rf"\b(?P<cfg>{_GRADLE_CONFIGS})\s*\(?\s*['\"](?P<g>[\w.\-]+):(?P<a>[\w.\-]+):(?P<v>[^'\":$@\s]+)"
    rf"(?::[\w.\-]+)?(?:@\w+)?['\"]"
)
_GRADLE_MAP = re.compile(
    rf"\b(?P<cfg>{_GRADLE_CONFIGS})\s*\(?\s*group\s*[:=]\s*['\"](?P<g>[^'\"]+)['\"]\s*,\s*"
    r"name\s*[:=]\s*['\"](?P<a>[^'\"]+)['\"]\s*,\s*version\s*[:=]\s*['\"](?P<v>[^'\"$]+)['\"]"
)


def parse_gradle_build(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    seen: set[tuple[str, str]] = set()
    dynamic = 0
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("//"):
            continue
        m = _GRADLE_STR.search(line) or _GRADLE_MAP.search(line)
        if not m:
            if re.search(rf"\b{_GRADLE_CONFIGS}\b[^\n]*['\"][\w.\-]+:[\w.\-]+:\S*\$", line):
                dynamic += 1
            continue
        name, version = f"{m['g']}:{m['a']}", m["v"]
        if (name, version) in seen or "+" in version or version.startswith("["):
            continue
        seen.add((name, version))
        result.packages.append(
            Package(MAVEN, name, version, manifest, direct=True,
                    dev=m["cfg"].startswith("test"), path=[name], line=n)
        )
    if dynamic:
        result.warnings.append(
            f"{manifest}: {dynamic} dependencies use variables/dynamic versions; use "
            "gradle.lockfile (dependency locking) for exact checks"
        )
    return result


def parse_gradle_lockfile(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord, _, configs = line.partition("=")
        parts = coord.split(":")
        if len(parts) != 3:
            continue
        g, a, v = parts
        result.packages.append(
            Package(
                MAVEN, f"{g}:{a}", v, manifest, direct=False,
                dev=all(c.startswith("test") for c in configs.split(",") if c),
                path=[f"{g}:{a}"], line=n,
            )
        )
    return result
