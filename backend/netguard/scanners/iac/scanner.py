"""IaC scanner: Terraform, Kubernetes and CloudFormation."""

from __future__ import annotations

from netguard.core.files import iter_files, read_text
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.iac.cloudformation import scan_cloudformation
from netguard.scanners.iac.kubernetes import scan_kubernetes
from netguard.scanners.iac.meta import RULES
from netguard.scanners.iac.terraform import scan_terraform

_YAML = (".yaml", ".yml")
_JSON = (".json", ".template")


class IacScanner(Scanner):
    name = ScannerName.IAC
    display_name = "IaC Scanner"
    version = "1.0.0"
    description = (
        "Finds security misconfigurations in Terraform (AWS/GCP/Azure), Kubernetes manifests and "
        "CloudFormation templates: public storage, open networks, missing encryption, excessive "
        "privileges."
    )
    supported_inputs = ("source",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        assert ctx.root is not None
        files = [
            f for f in iter_files(ctx.root, max_bytes=ctx.max_file_bytes, only_paths=ctx.only_paths)
            if f.rel_path.endswith((".tf", *_YAML, *_JSON))
        ]
        findings: list[RawFinding] = []
        analysed = {"terraform": 0, "kubernetes": 0, "cloudformation": 0}
        for i, f in enumerate(files):
            ctx.check_cancelled()
            ctx.progress(100 * i / max(1, len(files)), f.rel_path)
            text = read_text(f.abs_path, ctx.max_file_bytes)
            if text is None:
                continue
            if f.rel_path.endswith(".tf"):
                analysed["terraform"] += 1
                findings.extend(scan_terraform(f.rel_path, text))
                continue
            k8s = scan_kubernetes(f.rel_path, text) if f.rel_path.endswith(_YAML) else []
            cfn = scan_cloudformation(f.rel_path, text)
            analysed["kubernetes"] += bool(k8s)
            analysed["cloudformation"] += bool(cfn)
            findings.extend(k8s)
            findings.extend(cfn)
        ctx.progress(100, "done")
        return ScanResult(findings=findings,
                          metadata={"files_considered": len(files), "rules": len(RULES),
                                    "files_with_findings": analysed})
