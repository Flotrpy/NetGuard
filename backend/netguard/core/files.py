"""Safe file walking and reading for scanners."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from netguard.core.archive import SKIP_DIRS

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".sh": "shell",
    ".bash": "shell",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".gradle": "gradle",
    ".properties": "properties",
    ".env": "dotenv",
    ".ini": "ini",
    ".cfg": "ini",
    ".toml": "toml",
    ".conf": "conf",
}
LANGUAGE_BY_NAME = {"dockerfile": "dockerfile", "pipfile": "toml", "gemfile": "ruby"}


def detect_language(path: str | Path) -> str:
    p = Path(path)
    name = p.name.lower()
    if name in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[name]
    if name.startswith("dockerfile"):
        return "dockerfile"
    if name.startswith(".env"):
        return "dotenv"
    return LANGUAGE_BY_EXT.get(p.suffix.lower(), "")


@dataclass(frozen=True)
class SourceFile:
    rel_path: str  # POSIX-style, relative to the scan root
    abs_path: Path
    size: int
    language: str


def iter_files(
    root: Path,
    *,
    max_bytes: int = 1024 * 1024,
    only_paths: set[str] | None = None,
) -> Iterator[SourceFile]:
    """Yield regular files under ``root`` (never following symlinks), skipping huge files."""
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            abs_path = Path(dirpath) / fname
            try:
                if abs_path.is_symlink() or not abs_path.is_file():
                    continue
                size = abs_path.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                continue
            rel = abs_path.relative_to(root).as_posix()
            if only_paths is not None and rel not in only_paths:
                continue
            yield SourceFile(rel, abs_path, size, detect_language(fname))


def read_text(path: Path, max_bytes: int = 1024 * 1024) -> str | None:
    """Read a file as text. Returns ``None`` for binary or unreadable files."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def confined_path(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root`` or raise ValueError if it escapes (traversal/symlink)."""
    root = root.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Path escapes the snapshot directory")
    return target


def context_lines(lines: list[str], line_no: int, radius: int = 2) -> str:
    """Return numbered context around a 1-based ``line_no``."""
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
