"""PyPI ecosystem: requirements.txt, Pipfile.lock, poetry.lock, uv.lock, pyproject.toml."""

from __future__ import annotations

import json
import re
import tomllib

from netguard.scanners.dependencies.models import (
    PYPI,
    Package,
    ParseResult,
    find_line,
    shortest_paths,
)

_REQ = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>(?:[<>=!~]=?=?|===)[^;#\s]*"
    r"(?:\s*,\s*[<>=!~]=?[^;#\s]*)*)?"
)
_PIN = re.compile(r"^={2,3}\s*([A-Za-z0-9_.!+\-]+)$")


def normalize_name(name: str) -> str:
    """PEP 503 normalisation, which is the form OSV uses for PyPI package names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _package(name: str, version: str, manifest: str, **kw) -> Package:
    return Package(PYPI, normalize_name(name), version, manifest, **kw)


def parse_requirements(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    unpinned = 0
    logical: list[tuple[int, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append((start, (buf + line).strip()))
        buf = ""
    for n, line in logical:
        if not line or line.startswith(("#", "-", "http:", "https:", "git+")):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        pin = _PIN.match((m.group("spec") or "").strip())
        if pin:
            result.packages.append(
                _package(m.group("name"), pin.group(1), manifest, direct=True,
                         path=[normalize_name(m.group("name"))], line=n)
            )
        else:
            unpinned += 1
    if unpinned:
        result.warnings.append(
            f"{manifest}: {unpinned} requirements are not pinned with '==' and were skipped; "
            "pin exact versions (or use a lockfile) so they can be checked"
        )
    return result


def parse_pipfile_lock(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid JSON ({exc.msg})")
        return result
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            version = str(meta.get("version", "")).lstrip("=")
            if version:
                result.packages.append(
                    _package(name, version, manifest, direct=False, dev=dev,
                             path=[normalize_name(name)], line=find_line(text, f'"{name}"'))
                )
    return result


def _parse_toml_lock(text: str, manifest: str) -> tuple[list[dict], ParseResult]:
    result = ParseResult()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid TOML ({exc})")
        return [], result
    return data.get("package", []), result


def _dep_names(deps) -> list[str]:
    if isinstance(deps, dict):
        return [normalize_name(n) for n in deps]
    return [normalize_name(d["name"]) for d in deps or [] if isinstance(d, dict) and "name" in d]


def _graph_packages(pkgs: list[dict], manifest: str, text: str, result: ParseResult,
                    root_names: set[str] | None = None) -> None:
    edges: dict[str, list[str]] = {}
    versions: dict[str, str] = {}
    for p in pkgs:
        name = normalize_name(p["name"])
        versions[name] = p.get("version", "")
        edges[name] = _dep_names(p.get("dependencies"))
    if root_names is None:  # poetry: top-level = nothing else depends on it
        depended = {c for children in edges.values() for c in children}
        root_names = {n for n in edges if n not in depended}
    paths = shortest_paths(sorted(root_names), edges)
    for name, version in versions.items():
        if not version or name in (root_names & {"__root__"}):
            continue
        chain = paths.get(name, [name])
        result.packages.append(
            _package(name, version, manifest, direct=len(chain) <= 1, path=chain,
                     line=find_line(text, f'name = "{name}"'))
        )


def parse_poetry_lock(text: str, manifest: str) -> ParseResult:
    pkgs, result = _parse_toml_lock(text, manifest)
    _graph_packages(pkgs, manifest, text, result)
    return result


def parse_uv_lock(text: str, manifest: str) -> ParseResult:
    pkgs, result = _parse_toml_lock(text, manifest)
    project = [
        p for p in pkgs
        if isinstance(p.get("source"), dict) and ({"virtual", "editable"} & set(p["source"]))
    ]
    roots = {d for p in project for d in _dep_names(p.get("dependencies"))}
    own = {normalize_name(p["name"]) for p in project}
    _graph_packages([p for p in pkgs if normalize_name(p["name"]) not in own], manifest, text,
                    result, roots or None)
    return result


def parse_pyproject(text: str, manifest: str) -> ParseResult:
    """PEP 621 ``[project] dependencies`` — only exact pins can be checked."""
    result = ParseResult()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid TOML ({exc})")
        return result
    project = data.get("project", {})
    reqs = list(project.get("dependencies", []))
    for group in (project.get("optional-dependencies") or {}).values():
        reqs.extend(group)
    unpinned = 0
    for req in reqs:
        m = _REQ.match(req.strip())
        pin = _PIN.match((m.group("spec") or "").strip()) if m else None
        if m and pin:
            result.packages.append(
                _package(m.group("name"), pin.group(1), manifest, direct=True,
                         path=[normalize_name(m.group("name"))],
                         line=find_line(text, m.group("name")))
            )
        else:
            unpinned += 1
    if unpinned:
        result.warnings.append(
            f"{manifest}: {unpinned} dependencies use version ranges; use a lockfile "
            "(poetry.lock / uv.lock / pinned requirements) for exact checks"
        )
    return result
