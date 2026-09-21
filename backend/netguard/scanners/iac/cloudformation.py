"""AWS CloudFormation template checks (YAML and JSON)."""

from __future__ import annotations

import json
from typing import Any

import yaml

from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac import yamlutil as yu
from netguard.scanners.iac.meta import RULES
from netguard.scanners.iac.terraform import SENSITIVE_PORTS
from netguard.scanners.sast.engine import make_finding, suppressed


def looks_like_cloudformation(text: str) -> bool:
    return "AWSTemplateFormatVersion" in text or ("Resources" in text and "AWS::" in text)


def _open(v: Any) -> bool:
    return v in ("0.0.0.0/0", "::/0")


def _num(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _truthy(v: Any) -> bool:
    return v is True or str(v).lower() == "true"


def scan_cloudformation(rel_path: str, text: str) -> list[RawFinding]:
    if not looks_like_cloudformation(text):
        return []
    lines = text.splitlines()
    findings: list[RawFinding] = []
    try:
        docs = [(json.loads(text), None)] if text.lstrip().startswith("{") else list(yu.load_documents(text))
    except (yaml.YAMLError, ValueError):
        return []

    def line_of(node, key: str, logical: str) -> int:
        if node is not None:
            return yu.key_line(node, key)
        for i, ln in enumerate(lines, 1):  # JSON: best-effort textual search
            if f'"{key}"' in ln:
                return i
        for i, ln in enumerate(lines, 1):
            if f'"{logical}"' in ln:
                return i
        return 1

    def emit(rule_id: str, logical: str, rtype: str, line: int, note: str = "") -> None:
        src = lines[line - 1] if 0 < line <= len(lines) else ""
        if suppressed(src, rule_id):
            return
        f = make_finding(RULES[rule_id], rel_path=rel_path, language="yaml", lines=lines,
                         line_no=line, description_suffix=note)
        f.asset = AssetRef("iac", f"{rel_path}:{logical}", f"{rtype} {logical}")
        f.key = f"{logical}:{rule_id}:{note}"
        f.extra["resource"] = logical
        findings.append(f)

    for doc, node in docs:
        resources = doc.get("Resources") if isinstance(doc, dict) else None
        if not isinstance(resources, dict):
            continue
        for logical, res in resources.items():
            if not isinstance(res, dict):
                continue
            rtype = res.get("Type", "")
            props = res.get("Properties") or {}
            rnode = yu.walk(node, "Resources", logical) if node else None
            pnode = yu.walk(rnode, "Properties") if rnode else None
            if rtype == "AWS::S3::Bucket" and props.get("AccessControl") in ("PublicRead", "PublicReadWrite"):
                emit("cfn.s3-public-acl", logical, rtype, line_of(pnode, "AccessControl", logical),
                     f"AccessControl is {props['AccessControl']}.")
            elif rtype in ("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress"):
                rules = props.get("SecurityGroupIngress") if rtype.endswith("Group") else [props]
                for idx, rule in enumerate(rules or []):
                    if not isinstance(rule, dict):
                        continue
                    rule_node = (
                        yu.walk(pnode, "SecurityGroupIngress", idx)
                        if rtype.endswith("Group") else pnode
                    )
                    if not (_open(rule.get("CidrIp")) or _open(rule.get("CidrIpv6"))):
                        continue
                    lo, hi = _num(rule.get("FromPort")), _num(rule.get("ToPort"))
                    proto = str(rule.get("IpProtocol", ""))
                    every = proto == "-1" or (lo is not None and hi is not None and lo <= 0 and hi >= 65535)
                    if every or (lo is not None and hi is not None and any(lo <= p <= hi for p in SENSITIVE_PORTS)):
                        emit("cfn.sg-open-ingress", logical, rtype, line_of(rule_node, "CidrIp", logical),
                             f"Open to the internet on {'all ports' if every else f'ports {lo}-{hi}'}.")
            elif rtype == "AWS::RDS::DBInstance":
                if _truthy(props.get("PubliclyAccessible")):
                    emit("cfn.rds-public", logical, rtype, line_of(pnode, "PubliclyAccessible", logical))
                if not _truthy(props.get("StorageEncrypted")):
                    emit("cfn.unencrypted-storage", logical, rtype, line_of(pnode, "StorageEncrypted", logical),
                         "StorageEncrypted is not true.")
            elif rtype == "AWS::EC2::Volume" and not _truthy(props.get("Encrypted")):
                emit("cfn.unencrypted-storage", logical, rtype, line_of(pnode, "Encrypted", logical),
                     "Encrypted is not true.")
    return findings
