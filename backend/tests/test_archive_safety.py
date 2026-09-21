"""Security tests: hostile archives must never write outside the destination or explode disk."""

import io
import tarfile
import zipfile

import pytest

from netguard.core.archive import ArchiveError, extract_archive, strip_single_root


def _zip(tmp_path, entries, name="a.zip"):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        for n, data in entries.items():
            zf.writestr(n, data)
    return p


def _tar(tmp_path, build, name="a.tar.gz"):
    p = tmp_path / name
    with tarfile.open(p, "w:gz") as tf:
        build(tf)
    return p


def _add_bytes(tf, name, data, **attrs):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    for k, v in attrs.items():
        setattr(info, k, v)
    tf.addfile(info, io.BytesIO(data))


def test_extracts_normal_zip(tmp_path):
    src = _zip(tmp_path, {"app/main.py": "print(1)", "README.md": "hi"})
    res = extract_archive(src, tmp_path / "out")
    assert res.file_count == 2
    assert (tmp_path / "out/app/main.py").read_text() == "print(1)"


@pytest.mark.parametrize("evil", ["../evil.txt", "a/../../evil.txt", "/etc/passwd", "C:/evil.txt", "..\\evil.txt"])
def test_zip_slip_rejected(tmp_path, evil):
    src = _zip(tmp_path, {evil: "x"})
    with pytest.raises(ArchiveError):
        extract_archive(src, tmp_path / "out")
    assert not (tmp_path / "out").exists()  # cleaned up
    assert not (tmp_path / "evil.txt").exists()


def test_tar_traversal_rejected(tmp_path):
    src = _tar(tmp_path, lambda tf: _add_bytes(tf, "../../evil.txt", b"x"))
    with pytest.raises(ArchiveError):
        extract_archive(src, tmp_path / "out")


def test_tar_symlinks_and_devices_are_skipped_not_created(tmp_path):
    def build(tf):
        _add_bytes(tf, "ok.txt", b"ok")
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
        dev = tarfile.TarInfo("dev")
        dev.type = tarfile.CHRTYPE
        tf.addfile(dev)

    res = extract_archive(_tar(tmp_path, build), tmp_path / "out")
    assert res.file_count == 1
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["ok.txt"]


def test_zip_symlink_entries_are_skipped(tmp_path):
    p = tmp_path / "s.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("ok.txt", "ok")
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        zf.writestr(info, "/etc/passwd")
    res = extract_archive(p, tmp_path / "out")
    assert res.file_count == 1 and not (tmp_path / "out/link").exists()


def test_archive_bomb_size_limit(tmp_path):
    src = _zip(tmp_path, {"big.txt": "A" * 5_000_000})
    with pytest.raises(ArchiveError, match="bomb|size"):
        extract_archive(src, tmp_path / "out", max_bytes=1_000_000)
    assert not (tmp_path / "out").exists()


def test_file_count_limit(tmp_path):
    src = _zip(tmp_path, {f"f{i}.txt": "x" for i in range(20)})
    with pytest.raises(ArchiveError, match="too many"):
        extract_archive(src, tmp_path / "out", max_files=10)


def test_rejects_non_archives_and_empty(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an archive at all")
    with pytest.raises(ArchiveError):
        extract_archive(junk, tmp_path / "out")
    with pytest.raises(ArchiveError):
        extract_archive(_zip(tmp_path, {}, "empty.zip"), tmp_path / "out2")


def test_skips_vcs_and_dependency_dirs(tmp_path):
    src = _zip(tmp_path, {".git/config": "x", "node_modules/a/index.js": "x", "src/a.js": "ok"})
    res = extract_archive(src, tmp_path / "out")
    assert res.file_count == 1


def test_strip_single_root(tmp_path):
    src = _zip(tmp_path, {"repo-main/a.py": "1", "repo-main/lib/b.py": "2"})
    extract_archive(src, tmp_path / "out")
    strip_single_root(tmp_path / "out")
    assert (tmp_path / "out/a.py").exists() and (tmp_path / "out/lib/b.py").exists()
