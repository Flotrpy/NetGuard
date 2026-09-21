"""Safe extraction of untrusted repository archives (.zip, .tar, .tar.gz, .tgz).

Uploaded archives are attacker-controlled input. Extraction is done entry-by-entry with our own
path checks and streaming size accounting; we never call ``extractall`` and never create
symlinks, hardlinks or device nodes.
"""

from __future__ import annotations

import io
import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Directories that are never useful for security analysis and can be huge.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}


class ArchiveError(ValueError):
    """The archive is malformed, unsafe or exceeds configured limits."""


@dataclass
class ExtractionResult:
    file_count: int
    total_bytes: int


def _safe_relative(name: str) -> PurePosixPath | None:
    """Return a normalised relative path, ``None`` to skip, or raise on traversal."""
    name = name.replace("\\", "/")
    if "\x00" in name:
        raise ArchiveError("Archive contains an invalid file name")
    path = PurePosixPath(name)
    if path.is_absolute() or (path.parts and ":" in path.parts[0]):
        raise ArchiveError(f"Archive contains an absolute path: {name!r}")
    if ".." in path.parts:
        raise ArchiveError(f"Archive contains a path traversal entry: {name!r}")
    parts = [p for p in path.parts if p not in ("", ".")]
    if not parts:
        return None
    if any(p in SKIP_DIRS for p in parts[:-1]) or parts[0] in SKIP_DIRS:
        return None
    return PurePosixPath(*parts)


class _Budget:
    def __init__(self, max_files: int, max_bytes: int) -> None:
        self.max_files, self.max_bytes = max_files, max_bytes
        self.files = 0
        self.bytes = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise ArchiveError(f"Archive has too many files (limit {self.max_files})")

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.max_bytes:
            raise ArchiveError("Archive expands beyond the allowed size (possible archive bomb)")


def _write_stream(src, dest: Path, budget: _Budget) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as out:
        while chunk := src.read(64 * 1024):
            budget.add_bytes(len(chunk))
            out.write(chunk)


def _confined(dest_root: Path, rel: PurePosixPath) -> Path:
    target = (dest_root / Path(*rel.parts)).resolve()
    if dest_root.resolve() not in target.parents:
        raise ArchiveError(f"Archive entry escapes the extraction directory: {rel}")
    return target


def _extract_zip(fileobj, dest: Path, budget: _Budget) -> None:
    try:
        zf = zipfile.ZipFile(fileobj)
    except zipfile.BadZipFile as exc:
        raise ArchiveError("Not a valid zip archive") from exc
    with zf:
        for info in zf.infolist():
            mode = (info.external_attr >> 16) & 0xFFFF
            is_symlink = (mode & 0o170000) == 0o120000
            rel = _safe_relative(info.filename)
            if rel is None or info.is_dir():
                continue
            if is_symlink:
                continue  # never materialise symlinks
            if info.flag_bits & 0x1:
                raise ArchiveError("Encrypted archives are not supported")
            budget.add_file()
            with zf.open(info) as src:
                _write_stream(src, _confined(dest, rel), budget)


def _extract_tar(fileobj, dest: Path, budget: _Budget) -> None:
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r:*")
    except tarfile.TarError as exc:
        raise ArchiveError("Not a valid tar archive") from exc
    with tf:
        for member in tf:
            rel = _safe_relative(member.name)
            if rel is None or member.isdir():
                continue
            if not member.isfile():
                continue  # skip symlinks, hardlinks, devices, fifos
            budget.add_file()
            src = tf.extractfile(member)
            if src is None:
                continue
            _write_stream(src, _confined(dest, rel), budget)


def extract_archive(
    source: Path,
    dest: Path,
    *,
    max_files: int = 20000,
    max_bytes: int = 500 * 1024 * 1024,
) -> ExtractionResult:
    """Extract ``source`` into ``dest`` (created). On any failure ``dest`` is removed."""
    dest.mkdir(parents=True, exist_ok=True)
    budget = _Budget(max_files, max_bytes)
    try:
        with open(source, "rb") as fh:
            head = fh.read(4)
            fh.seek(0)
            data = io.BufferedReader(fh)  # type: ignore[arg-type]
            if head[:2] == b"PK":
                _extract_zip(fh, dest, budget)
            elif head[:2] == b"\x1f\x8b" or _looks_like_tar(source):
                _extract_tar(data, dest, budget)
            else:
                raise ArchiveError("Unsupported archive type (use .zip, .tar, .tar.gz or .tgz)")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    if budget.files == 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise ArchiveError("Archive contains no files")
    return ExtractionResult(file_count=budget.files, total_bytes=budget.bytes)


def _looks_like_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def strip_single_root(dest: Path) -> None:
    """Flatten ``repo-main/`` style archives (GitHub downloads) so paths are repo-relative."""
    entries = [p for p in dest.iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        root = entries[0]
        for child in list(root.iterdir()):
            shutil.move(str(child), str(dest / child.name))
        root.rmdir()
