"""NetGuard command line: run the security gate locally or in any CI system.

    netguard-cli scan .                                  # sast + secrets + dependencies
    netguard-cli scan . --policy policy.json --format sarif -o netguard.sarif
    netguard-cli scan . --baseline baseline.json         # only NEW findings count as new
    netguard-cli baseline . -o baseline.json             # record current findings as accepted

Exit codes: 0 passed, 1 policy failed, 2 usage/runtime error, 3 incomplete scan (--strict).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from netguard import __version__
from netguard.scanners.base import RawFinding, ScanContext, fingerprint
from netguard.scanners.registry import get_scanner
from netguard.services.policy import Policy, PolicyFinding, evaluate
from netguard.services.sarif import to_sarif

DEFAULT_SCANNERS = ("sast", "secrets", "dependencies")
CLI_SALT = "netguard-cli-fingerprint-salt"  # secrets are HMAC'd with this for baseline matching
_ORDER = ["critical", "high", "medium", "low", "info"]


def run_scanners(
    root: Path, scanners: list[str], *, offline: bool, cache_dir: Path | None
) -> tuple[list[tuple[str, RawFinding, str]], list[str], bool]:
    """Returns ([(scanner, finding, fingerprint)], warnings, complete)."""
    out: list[tuple[str, RawFinding, str]] = []
    warnings: list[str] = []
    complete = True
    runtime = {
        "fingerprint_salt": CLI_SALT,
        "osv_offline": offline,
        "osv_api_url": os.environ.get("NETGUARD_OSV_API_URL", "https://api.osv.dev"),
        "cache_dir": str(cache_dir) if cache_dir else "",
    }
    for name in scanners:
        scanner = get_scanner(name)
        available, note = scanner.availability()
        if not available or "source" not in scanner.supported_inputs:
            warnings.append(f"{name}: skipped ({note or 'not a source scanner'})")
            complete = False
            continue
        result = scanner.scan(ScanContext(root=root, runtime=runtime))
        warnings.extend(f"{name}: {w}" for w in result.warnings)
        complete = complete and result.complete
        seen: Counter[str] = Counter()
        for f in result.findings:
            material = f.fingerprint_material(name)
            out.append((name, f, fingerprint(material, seen[material])))
            seen[material] += 1
    return out, warnings, complete


def load_policy(path: str | None) -> Policy:
    if not path:
        return Policy()
    try:
        return Policy.model_validate_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise SystemExit(f"error: invalid policy file {path}: {exc}") from exc


def load_baseline(path: str | None) -> set[str] | None:
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return set(data["fingerprints"])
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(f"error: invalid baseline file {path}: {exc}") from exc


def format_text(findings, result, warnings) -> str:
    lines = ["NetGuard security gate", "=" * 22]
    ordered = sorted(findings, key=lambda t: _ORDER.index(t[1].severity.value))
    for scanner, f, _ in ordered:
        loc = f"{f.file_path}:{f.line}" if f.file_path and f.line else f.file_path
        lines.append(f"[{f.severity.value.upper():8}] {f.title}  ({scanner}: {f.rule_id})  {loc}")
    if not findings:
        lines.append("No findings.")
    lines.append("")
    lines.append("Counts: " + ", ".join(f"{k}={result.counts[k]}" for k in _ORDER))
    if result.new_counts and any(result.new_counts.values()):
        lines.append("New:    " + ", ".join(f"{k}={result.new_counts[k]}" for k in _ORDER))
    for w in warnings:
        lines.append(f"warning: {w}")
    lines.append("")
    if result.passed:
        lines.append("RESULT: PASSED")
    else:
        lines.append("RESULT: FAILED")
        lines.extend(f"  - {v.message}" for v in result.violations)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netguard-cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"netguard {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "baseline"):
        p = sub.add_parser(name)
        p.add_argument("path", help="directory to scan")
        p.add_argument("--scanners", default=",".join(DEFAULT_SCANNERS))
        p.add_argument("--offline", action="store_true", help="do not query OSV.dev")
        p.add_argument("--cache-dir", default=None)
        p.add_argument("-o", "--output", default=None)
        if name == "scan":
            p.add_argument("--policy", default=None, help="policy JSON file")
            p.add_argument("--baseline", default=None, help="baseline JSON of known findings")
            p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
            p.add_argument("--strict", action="store_true",
                           help="exit 3 if any scanner could not fully run (e.g. OSV unreachable)")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    try:
        findings, warnings, complete = run_scanners(
            root, scanners, offline=args.offline,
            cache_dir=Path(args.cache_dir) if args.cache_dir else None,
        )
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 2

    if args.cmd == "baseline":
        payload = json.dumps({"version": 1, "fingerprints": sorted(fp for _, _, fp in findings)},
                             indent=2)
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
        else:
            print(payload)
        print(f"baseline of {len(findings)} findings recorded", file=sys.stderr)
        return 0

    policy = load_policy(args.policy)
    baseline = load_baseline(args.baseline)
    pf = [
        PolicyFinding(severity=f.severity.value, scanner=scanner, confidence=f.confidence.value,
                      is_new=(baseline is None or fp not in baseline), title=f.title)
        for scanner, f, fp in findings
    ]
    result = evaluate(pf, policy)

    if args.format == "sarif":
        body = json.dumps(to_sarif(findings), indent=2)
    elif args.format == "json":
        body = json.dumps({"result": result.as_dict(), "warnings": warnings, "complete": complete,
                           "findings": [{"scanner": s, "rule_id": f.rule_id, "title": f.title,
                                         "severity": f.severity.value, "file": f.file_path,
                                         "line": f.line, "fingerprint": fp}
                                        for s, f, fp in findings]}, indent=2)
    else:
        body = format_text(findings, result, warnings)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
        if args.format != "text":
            print(format_text(findings, result, warnings), file=sys.stderr)
    else:
        print(body)
    if not result.passed:
        return 1
    if args.strict and not complete:
        print("error: scan incomplete (--strict)", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
