"""Terraform security checks (AWS, GCP and Azure resources)."""

from __future__ import annotations

import re

from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac import hcl
from netguard.scanners.iac.meta import RULES
from netguard.scanners.sast.engine import make_finding, suppressed

SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}
_OPEN_V4, _OPEN_V6 = "0.0.0.0/0", "::/0"


def _truthy(v: str | None) -> bool:
    return v is not None and hcl.unquote(v).strip().lower() == "true"


def _falsy(v: str | None) -> bool:
    return v is not None and hcl.unquote(v).strip().lower() == "false"


def _is_open(v: str | None) -> bool:
    return v is not None and (_OPEN_V4 in v or _OPEN_V6 in v or hcl.unquote(v).strip() == "*")


def _int(v: str | None) -> int | None:
    try:
        return int(hcl.unquote(v).strip()) if v is not None else None
    except ValueError:
        return None


def _exposes_sensitive(from_port: int | None, to_port: int | None, protocol: str) -> bool:
    if protocol in ("-1", "all"):
        return True
    if from_port is None or to_port is None:
        return False
    if from_port <= 0 and to_port >= 65535:
        return True
    return any(from_port <= p <= to_port for p in SENSITIVE_PORTS)


def _ports_in_text(v: str | None) -> set[int]:
    """Ports/ranges from a string like "22", "1024-2000" or ["22","3389"]."""
    ports: set[int] = set()
    for a, b in re.findall(r"(\d{1,5})(?:\s*-\s*(\d{1,5}))?", v or ""):
        lo, hi = int(a), int(b or a)
        ports.update(p for p in SENSITIVE_PORTS if lo <= p <= hi)
    return ports


def _policy_wildcard(text: str) -> bool:
    for stmt in re.findall(r"\{[^{}]*\}", text, re.DOTALL):
        if re.search(r"""["']?Effect["']?\s*[:=]\s*["']?Deny""", stmt):
            continue
        action = re.search(r"""["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']""", stmt)
        resource = re.search(r"""["']?Resource["']?\s*[:=]\s*\[?\s*["']\*["']""", stmt)
        if action and resource:
            return True
    return False


class _Scanner:
    def __init__(self, rel_path: str, text: str) -> None:
        self.path, self.lines = rel_path, text.splitlines()
        self.findings: list[RawFinding] = []

    def emit(self, rule_id: str, line: int, block: hcl.Block, note: str = "") -> None:
        src = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if suppressed(src, rule_id):
            return
        f = make_finding(RULES[rule_id], rel_path=self.path, language="terraform",
                         lines=self.lines, line_no=line, description_suffix=note)
        f.asset = AssetRef("iac", f"{self.path}:{block.type}.{block.name}",
                           f"{block.type}.{block.name}")
        f.key = f"{block.type}.{block.name}:{rule_id}:{note}"
        f.extra["resource"] = f"{block.type}.{block.name}"
        self.findings.append(f)

    # ---- dispatch -----------------------------------------------------------------------------
    def block(self, b: hcl.Block) -> None:
        if b.kind == "data" and b.type == "aws_iam_policy_document":
            self.iam_document(b)
        if b.kind != "resource":
            return
        handler = getattr(self, f"r_{b.type}", None)
        if handler:
            handler(b)

    # ---- AWS ----------------------------------------------------------------------------------
    def r_aws_s3_bucket(self, b: hcl.Block) -> None:
        acl = b.attrs.get("acl")
        if acl and hcl.unquote(acl.value) in ("public-read", "public-read-write", "authenticated-read"):
            self.emit("tf.s3-public-acl", acl.line, b, f"ACL is {hcl.unquote(acl.value)}.")

    def r_aws_s3_bucket_acl(self, b: hcl.Block) -> None:
        acl = b.attrs.get("acl")
        if acl and hcl.unquote(acl.value) in ("public-read", "public-read-write", "authenticated-read"):
            self.emit("tf.s3-public-acl", acl.line, b, f"ACL is {hcl.unquote(acl.value)}.")

    def r_aws_s3_bucket_public_access_block(self, b: hcl.Block) -> None:
        for key in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                    "restrict_public_buckets"):
            if _falsy(b.get(key)):
                self.emit("tf.s3-public-access-block-disabled", b.attrs[key].line, b, f"{key} = false.")

    def _sg_check(self, b: hcl.Block, holder: hcl.Block, line_from: hcl.Block | None = None) -> None:
        cidrs = " ".join(filter(None, [holder.get("cidr_blocks"), holder.get("ipv6_cidr_blocks"),
                                       holder.get("cidr_ipv4"), holder.get("cidr_ipv6")]))
        if not _is_open(cidrs):
            return
        proto = hcl.unquote(holder.get("protocol") or holder.get("ip_protocol") or "tcp")
        lo, hi = _int(holder.get("from_port")), _int(holder.get("to_port"))
        if _exposes_sensitive(lo, hi, proto):
            anchor = holder.attrs.get("cidr_blocks") or holder.attrs.get("cidr_ipv4") or \
                holder.attrs.get("ipv6_cidr_blocks")
            where = f"ports {lo}-{hi}" if lo is not None else "all ports"
            self.emit("tf.sg-open-ingress", anchor.line if anchor else holder.line, b,
                      f"Open to the internet on {where}.")

    def r_aws_security_group(self, b: hcl.Block) -> None:
        for ing in b.blocks("ingress"):
            self._sg_check(b, ing)

    def r_aws_security_group_rule(self, b: hcl.Block) -> None:
        if hcl.unquote(b.get("type")) == "ingress":
            self._sg_check(b, b)

    def r_aws_vpc_security_group_ingress_rule(self, b: hcl.Block) -> None:
        self._sg_check(b, b)

    def r_aws_db_instance(self, b: hcl.Block) -> None:
        if _truthy(b.get("publicly_accessible")):
            self.emit("tf.rds-public", b.attrs["publicly_accessible"].line, b)
        enc = b.get("storage_encrypted")
        if enc is None or _falsy(enc):
            self.emit("tf.rds-unencrypted", b.attrs["storage_encrypted"].line if enc else b.line, b,
                      "storage_encrypted is false." if enc else "storage_encrypted is not set.")

    def r_aws_ebs_volume(self, b: hcl.Block) -> None:
        enc = b.get("encrypted")
        if enc is None or _falsy(enc):
            self.emit("tf.ebs-unencrypted", b.attrs["encrypted"].line if enc else b.line, b)

    def _iam_policy_attr(self, b: hcl.Block) -> None:
        pol = b.attrs.get("policy")
        if pol and _policy_wildcard(pol.value):
            self.emit("tf.iam-wildcard", pol.line, b)

    r_aws_iam_policy = r_aws_iam_role_policy = r_aws_iam_user_policy = _iam_policy_attr
    r_aws_iam_group_policy = _iam_policy_attr

    def iam_document(self, b: hcl.Block) -> None:
        for st in b.blocks("statement"):
            effect = hcl.unquote(st.get("effect") or "Allow")
            if effect == "Allow" and re.search(r'\[\s*"\*"\s*\]|^"\*"$', st.get("actions") or "") \
                    and re.search(r'\[\s*"\*"\s*\]|^"\*"$', st.get("resources") or ""):
                self.emit("tf.iam-wildcard", (st.attrs.get("actions") or st.attrs.get("resources")).line, b)

    def _lb_listener(self, b: hcl.Block) -> None:
        proto = hcl.unquote(b.get("protocol") or "")
        if proto == "HTTP" and "redirect" not in " ".join(
            c.get("type") or "" for c in b.blocks("default_action")
        ) and not any(c.blocks("redirect") for c in b.blocks("default_action")):
            self.emit("tf.lb-http-listener", b.attrs["protocol"].line, b)

    r_aws_lb_listener = r_aws_alb_listener = _lb_listener

    def _imds(self, b: hcl.Block) -> None:
        for md in b.blocks("metadata_options"):
            if hcl.unquote(md.get("http_tokens") or "") == "optional":
                self.emit("tf.imdsv1-enabled", md.attrs["http_tokens"].line, b)

    r_aws_instance = r_aws_launch_template = r_aws_launch_configuration = _imds

    # ---- GCP ----------------------------------------------------------------------------------
    def _gcs_members(self, b: hcl.Block) -> None:
        for key in ("member", "members"):
            v = b.get(key)
            if v and re.search(r"allUsers|allAuthenticatedUsers", v):
                self.emit("tf.gcs-public", b.attrs[key].line, b)

    r_google_storage_bucket_iam_member = r_google_storage_bucket_iam_binding = _gcs_members

    def r_google_compute_firewall(self, b: hcl.Block) -> None:
        if not _is_open(b.get("source_ranges")) or b.get("direction") and \
                hcl.unquote(b.get("direction")) == "EGRESS":
            return
        for allow in b.blocks("allow"):
            proto = hcl.unquote(allow.get("protocol") or "")
            ports = allow.get("ports")
            if proto == "all" or (proto in ("tcp", "udp") and (ports is None or _ports_in_text(ports))):
                self.emit("tf.gcp-firewall-open", b.attrs["source_ranges"].line, b)
                return

    # ---- Azure --------------------------------------------------------------------------------
    def r_azurerm_storage_account(self, b: hcl.Block) -> None:
        for key in ("allow_blob_public_access", "allow_nested_items_to_be_public"):
            if _truthy(b.get(key)):
                self.emit("tf.azure-storage-public", b.attrs[key].line, b)
        if _falsy(b.get("enable_https_traffic_only")):
            self.emit("tf.azure-storage-insecure-transport", b.attrs["enable_https_traffic_only"].line,
                      b, "HTTPS-only is disabled.")
        tls = hcl.unquote(b.get("min_tls_version") or "")
        if tls in ("TLS1_0", "TLS1_1"):
            self.emit("tf.azure-storage-insecure-transport", b.attrs["min_tls_version"].line, b,
                      f"Minimum TLS version is {tls}.")

    def r_azurerm_network_security_rule(self, b: hcl.Block) -> None:
        if hcl.unquote(b.get("direction") or "") != "Inbound" or \
                hcl.unquote(b.get("access") or "") != "Allow":
            return
        if not _is_open(b.get("source_address_prefix")):
            return
        port = b.get("destination_port_range") or b.get("destination_port_ranges") or ""
        if hcl.unquote(port) == "*" or _ports_in_text(port):
            anchor = b.attrs.get("source_address_prefix")
            self.emit("tf.azure-nsg-open", anchor.line if anchor else b.line, b)


def scan_terraform(rel_path: str, text: str) -> list[RawFinding]:
    s = _Scanner(rel_path, text)
    for block in hcl.parse(text):
        s.block(block)
    return s.findings
