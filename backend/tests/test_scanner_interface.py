import pytest

from netguard.enums import Confidence, Severity
from netguard.scanners.base import (
    AssetRef,
    RawFinding,
    ScanCancelled,
    ScanContext,
    fingerprint,
)
from netguard.scanners.registry import all_scanners, get_scanner, scanner_infos


def _finding(**kw):
    base = dict(rule_id="r1", title="t", severity=Severity.HIGH, confidence=Confidence.HIGH)
    base.update(kw)
    return RawFinding(**base)


def test_fingerprint_ignores_line_numbers_and_whitespace():
    a = _finding(file_path="a.py", line=10, code_context="x =  eval(user)")
    b = _finding(file_path="a.py", line=99, code_context="x = eval(user)")
    assert a.fingerprint_material("sast") == b.fingerprint_material("sast")


def test_fingerprint_differs_by_file_rule_scanner_and_asset():
    def material(scanner="sast", **kw):
        return _finding(**kw).fingerprint_material(scanner)

    base = material(file_path="a.py", code_context="x")
    assert base != material("secrets", file_path="a.py", code_context="x")
    assert base != material(file_path="b.py", code_context="x")
    assert base != material(rule_id="r2", file_path="a.py", code_context="x")
    host = material("network", asset=AssetRef("host", "10.0.0.1"), key="22/tcp")
    other = material("network", asset=AssetRef("host", "10.0.0.2"), key="22/tcp")
    assert host != other


def test_occurrence_index_disambiguates_identical_findings():
    m = _finding(file_path="a.py", code_context="x").fingerprint_material("sast")
    assert fingerprint(m, 0) != fingerprint(m, 1)
    assert fingerprint(m, 0) == fingerprint(m, 0)


def test_registry_lists_all_modules_and_unimplemented_are_marked_planned():
    infos = {i.name: i for i in scanner_infos()}
    assert set(infos) == {
        "sast", "dependencies", "secrets", "docker", "iac", "api", "network", "packets"
    }
    # Nothing is implemented yet in this checkpoint: everything must be honestly unavailable.
    for scanner in all_scanners():
        if not scanner.info().available:
            result = scanner.scan(ScanContext())
            assert result.findings == []
            assert "not available" in result.warnings[0]
    assert get_scanner("sast").info().supported_inputs


def test_unknown_scanner_raises():
    with pytest.raises(KeyError):
        get_scanner("nope")


def test_cancellation_hook():
    ctx = ScanContext(is_cancelled=lambda: True)
    with pytest.raises(ScanCancelled):
        ctx.check_cancelled()
