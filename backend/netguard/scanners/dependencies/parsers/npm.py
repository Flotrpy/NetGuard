"""npm ecosystem: package-lock.json (v1-v3), yarn.lock (v1) and pinned package.json."""

from __future__ import annotations

import json
import re

from netguard.scanners.dependencies.models import (
    NPM,
    Package,
    ParseResult,
    find_line,
    shortest_paths,
)

_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.\-+]+)?$")


def _name_from_key(key: str) -> str:
    """'node_modules/a/node_modules/@s/b' -> '@s/b'."""
    return key.rsplit("node_modules/", 1)[-1]


def _resolve(packages: dict[str, dict], from_key: str, dep: str) -> str | None:
    """Node's resolution: look in from_key/node_modules, then walk up to the root."""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx >= 0 else ""


def parse_package_lock(text: str, manifest: str) -> ParseResult:
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid JSON ({exc.msg})")
        return result

    if "packages" in data:  # lockfileVersion 2 / 3
        pkgs: dict[str, dict] = data["packages"]
        root = pkgs.get("", {})
        root_deps = {
            **root.get("dependencies", {}),
            **root.get("devDependencies", {}),
            **root.get("optionalDependencies", {}),
        }
        dev_roots = set(root.get("devDependencies", {}))
        edges: dict[str, list[str]] = {}
        for key, meta in pkgs.items():
            if not key:
                continue
            deps = {
                **meta.get("dependencies", {}),
                **meta.get("optionalDependencies", {}),
            }
            edges[key] = [r for d in deps if (r := _resolve(pkgs, key, d))]
        roots = [r for d in root_deps if (r := _resolve(pkgs, "", d))]
        paths = shortest_paths(roots, edges)
        for key, meta in pkgs.items():
            if not key or "version" not in meta or meta.get("link"):
                continue
            name = meta.get("name") or _name_from_key(key)
            chain = [_name_from_key(k) for k in paths.get(key, [key])]
            is_direct = len(chain) <= 1 and key in roots
            result.packages.append(
                Package(
                    ecosystem=NPM,
                    name=name,
                    version=meta["version"],
                    manifest=manifest,
                    direct=is_direct,
                    dev=bool(meta.get("dev")) or (is_direct and name in dev_roots),
                    path=chain,
                    line=find_line(text, f'"{key}"'),
                )
            )
    elif "dependencies" in data:  # lockfileVersion 1: nested tree
        def walk(deps: dict, chain: list[str]) -> None:
            for name, meta in deps.items():
                new_chain = [*chain, name]
                if "version" in meta:
                    result.packages.append(
                        Package(
                            ecosystem=NPM,
                            name=name,
                            version=meta["version"],
                            manifest=manifest,
                            direct=not chain,
                            dev=bool(meta.get("dev")),
                            path=new_chain,
                            line=find_line(text, f'"{name}"'),
                        )
                    )
                walk(meta.get("dependencies", {}), new_chain)

        walk(data["dependencies"], [])
    else:
        result.warnings.append(f"{manifest}: no packages found (unsupported lockfile format?)")
    return result



def parse_yarn_lock(text: str, manifest: str) -> ParseResult:
    """yarn.lock v1. Yarn Berry (v2+) lockfiles are YAML; those are reported as unsupported."""
    result = ParseResult()
    if "__metadata:" in text:
        result.warnings.append(f"{manifest}: Yarn Berry lockfiles are not supported yet")
        return result
    current: str | None = None
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            first = line.rstrip().rstrip(":").split(", ")[0].strip('"')
            current = first.rsplit("@", 1)[0] if "@" in first[1:] else None
            continue
        stripped = line.strip()
        if current and stripped.startswith("version "):
            version = stripped.split(None, 1)[1].strip().strip('"')
            result.packages.append(
                Package(
                    ecosystem=NPM,
                    name=current,
                    version=version,
                    manifest=manifest,
                    direct=False,  # yarn.lock does not record which entries are direct
                    path=[current],
                    line=n,
                )
            )
            current = None
    return result


def parse_package_json(text: str, manifest: str) -> ParseResult:
    """Only exactly pinned versions can be checked without a lockfile."""
    result = ParseResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.warnings.append(f"{manifest}: invalid JSON ({exc.msg})")
        return result
    unpinned = 0
    for section, is_dev in (("dependencies", False), ("devDependencies", True),
                            ("optionalDependencies", False)):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and _EXACT.match(spec):
                result.packages.append(
                    Package(NPM, name, spec, manifest, direct=True, dev=is_dev, path=[name],
                            line=find_line(text, f'"{name}"'))
                )
            else:
                unpinned += 1
    if unpinned:
        result.warnings.append(
            f"{manifest}: {unpinned} dependencies use version ranges; add a lockfile "
            "(package-lock.json / yarn.lock) so exact versions can be checked"
        )
    return result
