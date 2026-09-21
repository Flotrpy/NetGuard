"""Container image analysis from a ``docker save`` tarball.

The tarball is untrusted input. Nothing is extracted to disk: we open the archive in memory, read
only a handful of small files (manifest, image config, OS release and package databases) and
never follow links. Package databases are read per layer in order so later layers override
earlier ones, matching how the image filesystem is built.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_META_BYTES = 8 * 1024 * 1024
MAX_DB_BYTES = 64 * 1024 * 1024
_TARGETS = {
    "var/lib/dpkg/status": "dpkg",
    "lib/apk/db/installed": "apk",
    "etc/os-release": "os-release",
    "usr/lib/os-release": "os-release-usr",
}


class ImageError(ValueError):
    pass


@dataclass
class OsPackage:
    name: str  # source package name (what advisories are filed against)
    version: str
    binary: str = ""


@dataclass
class ImageInfo:
    repo_tags: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    os_id: str = ""
    os_version: str = ""
    packages: list[OsPackage] = field(default_factory=list)
    package_manager: str = ""
    layers: int = 0


def _read_member(tf: tarfile.TarFile, name: str, limit: int) -> bytes | None:
    try:
        member = tf.getmember(name)
    except KeyError:
        return None
    if not member.isfile() or member.size > limit:
        return None
    fh = tf.extractfile(member)
    return fh.read() if fh else None


def parse_dpkg(text: str) -> list[OsPackage]:
    packages = []
    for block in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line[:1] not in (" ", "\t") and ":" in line:
                k, _, v = line.partition(":")
                fields[k.strip()] = v.strip()
        if not fields.get("Package") or "installed" not in fields.get("Status", "installed"):
            continue
        if fields.get("Status") and not fields["Status"].endswith("installed"):
            continue
        source = fields.get("Source", fields["Package"]).split(" ")[0]
        packages.append(OsPackage(source, fields.get("Version", ""), fields["Package"]))
    return packages


def parse_apk(text: str) -> list[OsPackage]:
    packages = []
    for block in re.split(r"\n\s*\n", text):
        fields = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        if fields.get("P") and fields.get("V"):
            packages.append(OsPackage(fields.get("o", fields["P"]), fields["V"], fields["P"]))
    return packages


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k and v:
            out[k.strip()] = v.strip().strip("\"'")
    return out


def analyze_image(path: Path) -> ImageInfo:
    info = ImageInfo()
    try:
        outer = tarfile.open(path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ImageError("Not a valid image tarball (expected `docker save` output)") from exc
    with outer:
        raw = _read_member(outer, "manifest.json", MAX_META_BYTES)
        if raw is None:
            raise ImageError("manifest.json not found: this is not a `docker save` tarball")
        try:
            manifest = json.loads(raw)[0]
            info.repo_tags = list(manifest.get("RepoTags") or [])
            layers = list(manifest["Layers"])
            config_raw = _read_member(outer, manifest["Config"], MAX_META_BYTES)
            info.config = json.loads(config_raw or b"{}")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ImageError("Malformed image manifest") from exc
        info.layers = len(layers)

        found: dict[str, bytes] = {}
        for layer in layers:
            member = None
            try:
                member = outer.getmember(layer)
            except KeyError:
                continue
            fh = outer.extractfile(member) if member.isfile() else None
            if fh is None:
                continue
            try:
                inner = tarfile.open(fileobj=io.BufferedReader(fh), mode="r|*")  # streaming
            except tarfile.TarError:
                continue
            with inner:
                try:
                    for m in inner:
                        key = m.name.lstrip("./")
                        kind = _TARGETS.get(key)
                        if kind and m.isfile() and m.size <= MAX_DB_BYTES:
                            data = inner.extractfile(m)
                            if data:
                                found[kind] = data.read()
                        elif key.startswith("var/lib/dpkg/status.d/") and m.isfile() and \
                                m.size <= MAX_META_BYTES:  # distroless images
                            data = inner.extractfile(m)
                            if data:
                                found["dpkg"] = found.get("dpkg", b"") + b"\n\n" + data.read()
                except tarfile.TarError:
                    continue

    osr = parse_os_release((found.get("os-release") or found.get("os-release-usr") or b"").decode(
        "utf-8", "replace"))
    info.os_id, info.os_version = osr.get("ID", ""), osr.get("VERSION_ID", "")
    if "dpkg" in found:
        info.package_manager = "dpkg"
        info.packages = parse_dpkg(found["dpkg"].decode("utf-8", "replace"))
    elif "apk" in found:
        info.package_manager = "apk"
        info.packages = parse_apk(found["apk"].decode("utf-8", "replace"))
    return info


def osv_ecosystem(info: ImageInfo) -> str | None:
    """OSV ecosystem for the image's OS, only where coverage is reliable (Debian, Alpine)."""
    if info.os_id == "debian" and info.os_version:
        return f"Debian:{info.os_version.split('.')[0]}"
    if info.os_id == "alpine" and info.os_version:
        major_minor = ".".join(info.os_version.split(".")[:2])
        return f"Alpine:v{major_minor}"
    return None
