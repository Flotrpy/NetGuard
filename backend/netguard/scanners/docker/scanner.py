"""Docker / container scanner: Dockerfiles, compose files and container images."""

from __future__ import annotations

from pathlib import Path

from netguard.core.files import iter_files, read_text
from netguard.enums import Confidence, Severity
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import AssetRef, RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.dependencies import osv
from netguard.scanners.docker import image as img
from netguard.scanners.docker.config import _SECRET_NAME, is_eol, scan_compose, scan_dockerfile
from netguard.scanners.iac.meta import RULES
from netguard.scanners.sast.engine import make_finding

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _cfg_finding(rule_id: str, image: str, note: str = "") -> RawFinding:
    rule = RULES[rule_id]
    f = make_finding(rule, rel_path=image, language="", lines=[], line_no=0,
                     description_suffix=note)
    f.file_path, f.line, f.code_context = "", 0, ""
    f.asset = AssetRef("container_image", image, image)
    f.key = f"{image}:{rule_id}:{note}"
    f.extra.update({"image": image})
    return f


def _config_findings(image: str, info: img.ImageInfo) -> list[RawFinding]:
    cfg = info.config.get("config") or info.config.get("Config") or {}
    out = []
    user = str(cfg.get("User") or "").split(":")[0]
    if user in ("", "root", "0"):
        out.append(_cfg_finding("image.root-user", image))
    if any(p.split("/")[0] == "22" for p in (cfg.get("ExposedPorts") or {})):
        out.append(_cfg_finding("image.exposed-ssh", image))
    for entry in cfg.get("Env") or []:
        k, _, v = entry.partition("=")
        if _SECRET_NAME.search(k) and v and not v.startswith("$") and len(v) >= 4:
            out.append(_cfg_finding("image.secret-in-env", image, f"Variable {k}."))
    hc = cfg.get("Healthcheck")
    if not hc or hc.get("Test") in (None, ["NONE"]):
        out.append(_cfg_finding("image.no-healthcheck", image))
    if info.os_id and info.os_version and is_eol(f"{info.os_id}:{info.os_version}"):
        out.append(_cfg_finding("image.eol-os", image, f"{info.os_id} {info.os_version}."))
    return out


class DockerScanner(Scanner):
    name = ScannerName.DOCKER
    display_name = "Docker Scanner"
    version = "1.0.0"
    description = (
        "Checks Dockerfiles and docker-compose files for risky configuration (root user, mutable or "
        "end-of-life base images, secrets in ENV, privileged containers) and analyses uploaded "
        "`docker save` images for vulnerable OS packages using OSV.dev."
    )
    supported_inputs = ("source", "container_image")

    def scan(self, ctx: ScanContext) -> ScanResult:
        if ctx.config.get("image_path"):
            return self._scan_image(ctx)
        return self._scan_source(ctx)

    # ---- Dockerfile / compose in a repository ------------------------------------------------
    def _scan_source(self, ctx: ScanContext) -> ScanResult:
        assert ctx.root is not None
        findings: list[RawFinding] = []
        seen = 0
        for f in iter_files(ctx.root, max_bytes=ctx.max_file_bytes, only_paths=ctx.only_paths):
            name = f.abs_path.name.lower()
            is_docker = name.startswith("dockerfile") or name.endswith(".dockerfile")
            is_compose = name.startswith(("docker-compose", "compose")) and name.endswith(
                (".yml", ".yaml"))
            if not (is_docker or is_compose):
                continue
            ctx.check_cancelled()
            text = read_text(f.abs_path, ctx.max_file_bytes)
            if text is None:
                continue
            seen += 1
            findings.extend(scan_dockerfile(f.rel_path, text) if is_docker
                            else scan_compose(f.rel_path, text))
        return ScanResult(findings=findings, metadata={"mode": "source", "files_analyzed": seen})

    # ---- container image ------------------------------------------------------------------
    def _scan_image(self, ctx: ScanContext) -> ScanResult:
        rt = ctx.runtime
        base = Path(rt["uploads_dir"]).resolve()
        path = (base / str(ctx.config["image_path"])).resolve()
        if base not in path.parents or not path.is_file():
            raise img.ImageError("Image file not found")
        name = str(ctx.config.get("image_name") or path.stem)[:200]
        ctx.progress(5, "reading image")
        info = img.analyze_image(path)
        name = ctx.config.get("image_name") or (info.repo_tags[0] if info.repo_tags else name)
        findings = _config_findings(name, info)
        warnings: list[str] = []
        complete = True
        meta: dict = {"mode": "image", "image": name, "layers": info.layers, "os": f"{info.os_id} {info.os_version}".strip(),
                      "packages": len(info.packages), "package_manager": info.package_manager}
        ecosystem = img.osv_ecosystem(info)
        if not info.packages:
            warnings.append("No OS package database found (scratch/distroless image?); OS "
                            "packages were not checked.")
        elif ecosystem is None:
            complete = False
            warnings.append(
                f"Vulnerability data for OS '{info.os_id} {info.os_version}' is not supported; "
                f"{len(info.packages)} packages were inventoried but NOT checked."
            )
        else:
            client = osv.OsvClient(
                rt.get("osv_api_url", "https://api.osv.dev"), timeout=float(rt.get("osv_timeout", 20.0)),
                cache_dir=Path(rt["cache_dir"]) if rt.get("cache_dir") else None,
                offline=bool(rt.get("osv_offline", False)))
            coords = sorted({(ecosystem, p.name, p.version) for p in info.packages})
            try:
                ctx.progress(30, f"querying advisories for {len(coords)} packages")
                hits = client.query(coords)
                records = {vid: client.get_vuln(vid) for ids in hits.values() for vid in ids}
            except osv.OsvUnavailable as exc:
                complete = False
                warnings.append(f"Vulnerability data unavailable: {exc}. Packages were NOT checked.")
                hits, records = {}, {}
            base_eco = ecosystem.split(":")[0]
            for pkg in {(p.name, p.version): p for p in info.packages}.values():
                for vid in hits.get((ecosystem, pkg.name, pkg.version), []):
                    v = osv.to_vuln(records[vid], base_eco, pkg.name, pkg.version)
                    findings.append(_vuln_finding(name, pkg, v))
        counts = {s: 0 for s in _SEV_ORDER}
        for f in findings:
            counts[f.severity.value] += 1
        meta["severity_counts"] = counts
        ctx.progress(100, "done")
        return ScanResult(findings=findings, metadata=meta, warnings=warnings, complete=complete)


def _vuln_finding(image: str, pkg: img.OsPackage, v: osv.Vuln) -> RawFinding:
    fixed = v.fixed_versions[0] if v.fixed_versions else ""
    f = _cfg_finding("image.vulnerable-package", image)
    f.title = f"Vulnerable package in {image}: {pkg.name} {pkg.version} ({v.cve or v.id})"
    f.severity = v.severity
    f.confidence = Confidence.HIGH
    f.cwe = v.cwes[0] if v.cwes else ""
    f.description = (f"{v.summary or 'Known vulnerability'}. Advisory {v.id} from OSV.dev affects "
                     f"{pkg.name} {pkg.version} installed in the image."
                     + ("" if v.severity_source != "unknown"
                        else " The advisory has no severity rating; Medium is a placeholder."))
    f.remediation = (f"Update {pkg.name} to {fixed} or later, or rebuild the image on a base image "
                     "that already includes the fix." if fixed else
                     "No fixed version is listed. Check the advisory for mitigations.")
    f.references = [f"https://osv.dev/vulnerability/{v.id}", *v.references][:6]
    f.key = f"{image}:{pkg.name}@{pkg.version}:{v.id}"
    f.extra.update({"package": pkg.name, "version": pkg.version, "vulnerability": v.id,
                    "cve": v.cve, "fixed_versions": v.fixed_versions, "binary": pkg.binary,
                    "severity_source": v.severity_source, "source": "OSV.dev"})
    _ = Severity
    return f
