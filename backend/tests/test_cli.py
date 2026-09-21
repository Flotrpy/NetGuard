import json
import random
import string

import pytest

from netguard.cli import main

RNG = random.Random(9)


def vulnerable_tree(tmp_path, secret=False):
    (tmp_path / "app.py").write_text(
        "import hashlib, os\n\ndef f(x):\n    os.system('echo ' + x)\n    return hashlib.md5(x).hexdigest()\n"
    )
    if secret:
        token = "ghp_" + "".join(RNG.choice(string.ascii_letters + string.digits) for _ in range(36))
        (tmp_path / "cfg.py").write_text(f"TOKEN = '{token}'\n")
    return tmp_path


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_default_policy_passes_with_only_high_and_medium_findings(tmp_path, capsys):
    root = vulnerable_tree(tmp_path)
    code, out, _ = run(capsys, "scan", str(root), "--scanners", "sast", "--baseline", str(baseline(root, capsys)))
    assert code == 0 and "RESULT: PASSED" in out


def baseline(root, capsys):
    path = root.parent / "baseline.json"
    assert main(["baseline", str(root), "--scanners", "sast", "-o", str(path)]) == 0
    capsys.readouterr()
    return path


def test_new_high_findings_fail_without_a_baseline(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(vulnerable_tree(tmp_path)), "--scanners", "sast")
    assert code == 1 and "RESULT: FAILED" in out and "New High findings" in out
    assert "py.command-injection" in out


def test_secrets_fail_the_build(tmp_path, capsys):
    root = vulnerable_tree(tmp_path, secret=True)
    (root / "app.py").unlink()
    code, out, _ = run(capsys, "scan", str(root), "--scanners", "secrets")
    assert code == 1 and "Secrets detected: 1" in out
    token = (root / "cfg.py").read_text().split("'")[1]
    assert token not in out and token[:12] not in out  # secret values are never printed


def test_baseline_makes_existing_findings_old_but_new_ones_still_fail(tmp_path, capsys):
    root = vulnerable_tree(tmp_path)
    b = baseline(root, capsys)
    assert run(capsys, "scan", str(root), "--scanners", "sast", "--baseline", str(b))[0] == 0
    (root / "new.py").write_text("import os\ndef g(y):\n    os.system('ls ' + y)\n")
    code, out, _ = run(capsys, "scan", str(root), "--scanners", "sast", "--baseline", str(b))
    assert code == 1 and "New High findings: 1" in out


def test_custom_policy_file_and_validation(tmp_path, capsys):
    root = vulnerable_tree(tmp_path)
    lenient = tmp_path / "p.json"
    lenient.write_text(json.dumps({"max_new_high": None, "max_critical": None}))
    assert run(capsys, "scan", str(root), "--scanners", "sast", "--policy", str(lenient))[0] == 0
    strict = tmp_path / "s.json"
    strict.write_text(json.dumps({"fail_on_severity": "medium", "max_new_high": None}))
    assert run(capsys, "scan", str(root), "--scanners", "sast", "--policy", str(strict))[0] == 1
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"max_critical": -5}))
    with pytest.raises(SystemExit, match="invalid policy"):
        main(["scan", str(root), "--policy", str(bad)])


def test_sarif_output_is_valid_and_contains_locations(tmp_path, capsys):
    root = vulnerable_tree(tmp_path)
    out_file = tmp_path / "out.sarif"
    code, _, err = run(capsys, "scan", str(root), "--scanners", "sast", "--format", "sarif", "-o", str(out_file))
    sarif = json.loads(out_file.read_text())
    assert code == 1 and sarif["version"] == "2.1.0"
    run0 = sarif["runs"][0]
    assert run0["tool"]["driver"]["name"] == "NetGuard"
    rule_ids = {r["id"] for r in run0["tool"]["driver"]["rules"]}
    assert {"py.command-injection", "py.weak-hash"} <= rule_ids
    res = next(r for r in run0["results"] if r["ruleId"] == "py.command-injection")
    assert res["level"] == "error" and res["locations"][0]["physicalLocation"]["region"]["startLine"] == 4
    assert res["partialFingerprints"]["netguard/v1"]
    assert "RESULT: FAILED" in err  # human summary still printed to stderr


def test_json_format_and_errors(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(vulnerable_tree(tmp_path)), "--scanners", "sast", "--format", "json")
    data = json.loads(out)
    assert code == 1 and data["result"]["passed"] is False and data["findings"][0]["fingerprint"]
    assert run(capsys, "scan", str(tmp_path / "missing"))[0] == 2
    assert run(capsys, "scan", str(tmp_path), "--scanners", "nope")[0] == 2


def test_offline_dependency_scan_is_flagged_incomplete_and_strict_mode_fails(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("Django==3.2.0\n")
    code, out, _ = run(capsys, "scan", str(tmp_path), "--scanners", "dependencies", "--offline")
    assert code == 0 and "NOT checked" in out
    code, _, err = run(capsys, "scan", str(tmp_path), "--scanners", "dependencies", "--offline", "--strict")
    assert code == 3 and "incomplete" in err


def test_unavailable_scanners_are_reported_not_faked(tmp_path, capsys):
    code, out, _ = run(capsys, "scan", str(tmp_path), "--scanners", "network", "--strict")
    assert "skipped" in out and code == 3
