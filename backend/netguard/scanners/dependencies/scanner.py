"""Dependency scanner: parse manifests/lockfiles, then look packages up in OSV.dev."""

from __future__ import annotations

from pathlib import Path

from netguard.core.files import iter_files, read_text
from netguard.enums import Confidence
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import AssetRef, RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.dependencies import osv
from netguard.scanners.dependencies.models import Package, ParseResult
from netguard.scanners.dependencies.parsers import maven, npm, nuget, pypi

MAX_MANIFEST_BYTES = 25 * 1024 * 1024  # lockfiles are often several MB

# file name (lower-case) -> parser. Lockfiles come first so they win over loose manifests.
_BY_NAME = {
    "package-lock.json": npm.parse_package_lock,
    "npm-shrinkwrap.json": npm.parse_package_lock,
    "yarn.lock": npm.parse_yarn_lock,
    "package.json": npm.parse_package_json,
    "pipfile.lock": pypi.parse_pipfile_lock,
    "poetry.lock": pypi.parse_poetry_lock,
    "uv.lock": pypi.parse_uv_lock,
    "pyproject.toml": pypi.parse_pyproject,
    "pom.xml": maven.parse_pom,
    "gradle.lockfile": maven.parse_gradle_lockfile,
    "build.gradle": maven.parse_gradle_build,
    "build.gradle.kts": maven.parse_gradle_build,
    "packages.config": nuget.parse_packages_config,
    "packages.lock.json": nuget.parse_packages_lock,
    "directory.packages.props": nuget.parse_project_file,
}
_SUFFIXES = {".csproj": nuget.parse_project_file, ".fsproj": nuget.parse_project_file,
             ".vbproj": nuget.parse_project_file}
# Loose manifests are ignored when a lockfile with exact versions sits in the same directory.
_SUPERSEDED_BY_LOCK = {
    "package.json": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"},
    "pyproject.toml": {"poetry.lock", "uv.lock"},
    "build.gradle": {"gradle.lockfile"},
    "build.gradle.kts": {"gradle.lockfile"},
}

_SEV_REMEDIATION = "Upgrade {name} to {fixed} or later (fixes the affected range for {version})."


def _parser_for(path: Path):
    name = path.name.lower()
    if name in _BY_NAME:
        return _BY_NAME[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return pypi.parse_requirements
    return _SUFFIXES.get(path.suffix.lower())


def inventory(root: Path, on_file=None) -> tuple[list[Package], list[str], int]:
    """Parse every manifest/lockfile under ``root`` (lockfiles supersede loose manifests).

    Returns (packages, warnings, manifest_count). No network access: this is the shared source
    for both the vulnerability scan and SBOM generation.
    """
    warnings: list[str] = []
    packages: list[Package] = []
    files = [
        f
        for f in iter_files(root, max_bytes=MAX_MANIFEST_BYTES, only_paths=None)
        if _parser_for(f.abs_path) is not None
    ]
    present = {(Path(f.rel_path).parent.as_posix(), f.abs_path.name.lower()) for f in files}
    for i, f in enumerate(files):
        if on_file:
            on_file(i, len(files), f.rel_path)
        directory, name = Path(f.rel_path).parent.as_posix(), f.abs_path.name.lower()
        if any((directory, lock) in present for lock in _SUPERSEDED_BY_LOCK.get(name, ())):
            continue
        text = read_text(f.abs_path, MAX_MANIFEST_BYTES)
        if text is None:
            continue
        result: ParseResult = _parser_for(f.abs_path)(text, f.rel_path)  # type: ignore[misc]
        packages.extend(result.packages)
        warnings.extend(result.warnings)
    return packages, warnings, len(files)


class DependencyScanner(Scanner):
    name = ScannerName.DEPENDENCIES
    display_name = "Dependency Scanner"
    version = "1.0.0"
    description = (
        "Finds known-vulnerable packages (npm, PyPI, Maven/Gradle, NuGet) by matching exact "
        "versions from manifests and lockfiles against OSV.dev advisories."
    )
    supported_inputs = ("source",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        assert ctx.root is not None
        rt = ctx.runtime
        def on_file(i: int, n: int, path: str) -> None:
            ctx.check_cancelled()
            ctx.progress(20 * i / max(1, n), path)

        packages, warnings, manifest_count = inventory(ctx.root, on_file=on_file)
        files = range(manifest_count)  # only its length is used below
        coords = sorted({p.coordinate for p in packages})
        metadata = {
            "manifests": len(files),
            "packages": len(packages),
            "unique_packages": len(coords),
            "ecosystems": sorted({p.ecosystem for p in packages}),
        }
        if not coords:
            ctx.progress(100, "no dependencies found")
            return ScanResult(metadata=metadata, warnings=warnings)

        client = osv.OsvClient(
            rt.get("osv_api_url", "https://api.osv.dev"),
            timeout=float(rt.get("osv_timeout", 20.0)),
            cache_dir=Path(rt["cache_dir"]) if rt.get("cache_dir") else None,
            offline=bool(rt.get("osv_offline", False)),
        )
        try:
            ctx.progress(25, "querying OSV.dev")
            hits = client.query(coords)
            vuln_ids = sorted({v for ids in hits.values() for v in ids})
            records: dict[str, dict] = {}
            for i, vid in enumerate(vuln_ids):
                ctx.check_cancelled()
                ctx.progress(25 + 70 * i / max(1, len(vuln_ids)), f"advisory {vid}")
                records[vid] = client.get_vuln(vid)
        except osv.OsvUnavailable as exc:
            # Never claim "no vulnerabilities" when we could not ask.
            warnings.append(
                f"Vulnerability data unavailable: {exc}. {len(coords)} packages were inventoried "
                "but NOT checked."
            )
            metadata["osv"] = "unavailable"
            return ScanResult(metadata=metadata, warnings=warnings, complete=False)

        findings = _build_findings(packages, hits, records)
        metadata["osv"] = client.stats
        metadata["vulnerabilities"] = len(vuln_ids)
        ctx.progress(100, "done")
        return ScanResult(findings=findings, metadata=metadata, warnings=warnings)


def _build_findings(
    packages: list[Package], hits: dict[tuple[str, str, str], list[str]], records: dict[str, dict]
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for pkg in packages:
        for vid in hits.get(pkg.coordinate, []):
            v = osv.to_vuln(records[vid], pkg.ecosystem, pkg.name, pkg.version)
            cve = v.cve
            label = f"{vid} / {cve}" if cve else vid
            fixed = v.fixed_versions[0] if v.fixed_versions else ""
            remediation = (
                _SEV_REMEDIATION.format(name=pkg.name, fixed=fixed, version=pkg.version)
                if fixed
                else f"No fixed version is listed for {pkg.name} {pkg.version}. Check the "
                "advisory for mitigations or consider an alternative package."
            )
            confidence = Confidence.HIGH
            findings.append(
                RawFinding(
                    rule_id="dep.osv",
                    title=f"Vulnerable dependency: {pkg.name} {pkg.version} ({label})",
                    category="Vulnerable Dependency",
                    severity=v.severity,
                    confidence=confidence,
                    cwe=v.cwes[0] if v.cwes else "",
                    description=(
                        f"{v.summary or 'Known vulnerability'}. Advisory {label} from OSV.dev "
                        f"affects {pkg.ecosystem} package {pkg.name} {pkg.version}."
                        + (
                            ""
                            if v.severity_source != "unknown"
                            else " The advisory has no severity rating; Medium is a placeholder."
                        )
                    ),
                    impact="Attackers may exploit the known weakness in this package version "
                    "if the vulnerable code path is reachable in your application.",
                    remediation=remediation,
                    file_path=pkg.manifest,
                    line=pkg.line,
                    language="",
                    code_context="",
                    references=[f"https://osv.dev/vulnerability/{vid}", *v.references][:6],
                    exploitability="medium",
                    asset=AssetRef("package", f"{pkg.ecosystem}:{pkg.name}@{pkg.version}",
                                   f"{pkg.name} {pkg.version}"),
                    extra={
                        "package": pkg.name,
                        "version": pkg.version,
                        "ecosystem": pkg.ecosystem,
                        "vulnerability": vid,
                        "aliases": v.aliases,
                        "cve": cve,
                        "fixed_versions": v.fixed_versions,
                        "dependency_path": pkg.path or [pkg.name],
                        "direct": pkg.direct,
                        "dev": pkg.dev,
                        "severity_source": v.severity_source,
                        "cvss_score": v.cvss_score,
                        "source": "OSV.dev",
                    },
                    key=f"{pkg.ecosystem}:{pkg.name}@{pkg.version}:{vid}",
                )
            )
    return findings
