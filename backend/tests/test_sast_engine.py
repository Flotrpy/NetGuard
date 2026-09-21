from netguard.scanners.base import ScanContext
from netguard.scanners.registry import get_scanner
from netguard.scanners.sast.catalog import all_rules
from netguard.scanners.sast.engine import is_comment, scan_text_with_rules, suppressed


def scan_dir(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return get_scanner("sast").scan(ScanContext(root=tmp_path))


def test_sast_scanner_is_registered_and_available():
    info = get_scanner("sast").info()
    assert info.available and "source" in info.supported_inputs


def test_rule_ids_are_unique_and_metadata_complete():
    for rule in all_rules():
        assert rule.cwe.startswith("CWE-"), rule.id
        assert rule.remediation and rule.impact and rule.description, rule.id


def test_findings_carry_full_metadata(tmp_path):
    result = scan_dir(tmp_path, {"app.js": "const x = 1;\nconst r = eval(userInput);\n"})
    assert len(result.findings) == 1
    f = result.findings[0]
    assert (f.rule_id, f.file_path, f.line, f.language) == ("js.eval", "app.js", 2, "javascript")
    assert f.cwe == "CWE-95" and f.severity.value == "high" and f.remediation
    assert "2: const r = eval(userInput);" in f.code_context
    assert result.metadata["files_analyzed"] == 1


def test_comments_and_safe_literals_are_not_flagged(tmp_path):
    result = scan_dir(
        tmp_path,
        {"a.js": "// eval(userInput)\n/* eval(x) */\n * eval(y)\nconst z = eval('1+1');\n"},
    )
    assert result.findings == []


def test_inline_suppression(tmp_path):
    src = "eval(a); // netguard:ignore js.eval\neval(b); // netguard:ignore other.rule\neval(c); // netguard:ignore\n"
    result = scan_dir(tmp_path, {"a.js": src})
    assert [f.line for f in result.findings] == [2]


def test_only_analyses_source_languages_and_skips_vendored_dirs(tmp_path):
    result = scan_dir(
        tmp_path,
        {"notes.txt": "eval(x)", "node_modules/lib/i.js": "eval(x)", "src/ok.js": "let a = 1"},
    )
    assert result.findings == [] and result.metadata["files_analyzed"] == 1


def test_helpers():
    assert is_comment("python", "# hi") and not is_comment("python", "x = 1  # hi")
    assert suppressed("x  # netguard:ignore a.b, c.d", "c.d")
    assert not suppressed("x", "a")


def test_scan_text_rule_language_filter():
    findings = scan_text_with_rules(all_rules(), "a.py", "python", "eval(x)")
    assert all(f.language == "python" for f in findings)


def test_binary_and_large_files_skipped(tmp_path):
    (tmp_path / "big.js").write_text("eval(x)\n" * 200_000)  # > default 1 MB limit
    result = get_scanner("sast").scan(ScanContext(root=tmp_path, max_file_bytes=1024))
    assert result.findings == [] and result.metadata["files_analyzed"] == 0
