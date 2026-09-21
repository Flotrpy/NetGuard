"""Dockerfile and docker-compose configuration checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac import yamlutil as yu
from netguard.scanners.iac.meta import RULES
from netguard.scanners.sast.engine import make_finding, suppressed

_SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
_DB_PORTS = {3306, 5432, 1433, 27017, 6379, 9200, 5984, 11211, 1521}

# Release lines that vendors have ended support for (facts, not predictions). Anything newer or
# unknown is NOT flagged.
EOL_TAGS: dict[str, tuple[str, ...]] = {
    "ubuntu": ("12.04", "14.04", "16.04", "18.04", "trusty", "xenial", "bionic"),
    "debian": ("jessie", "stretch", "buster", "7", "8", "9", "10", "wheezy"),
    "centos": ("5", "6", "7", "8"),
    "alpine": tuple(f"3.{n}" for n in range(0, 15)),
    "python": ("2", "2.7", "3.5", "3.6", "3.7"),
    "node": ("6", "8", "10", "12", "14", "16"),
}


def is_eol(image: str) -> bool:
    """True when ``image`` is a known release line whose vendor support has ended."""
    last = image.split("@")[0].rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    name, tag = last.rsplit(":", 1)
    versions = EOL_TAGS.get(name.lower())
    if not versions:
        return False
    head = re.split(r"[-_]", tag.lower())[0]
    return any(head == v or head.startswith(v + ".") for v in versions)


def _assignments(args: str) -> list[tuple[str, str]]:
    """ENV/ARG forms: ``KEY=value KEY2="v 2"`` and the legacy ``KEY value``."""
    if re.match(r"^[A-Za-z_]\w*=", args):
        return re.findall(r"""([A-Za-z_]\w*)=("[^"]*"|'[^']*'|\S*)""", args)
    parts = args.split(None, 1)
    return [(parts[0], parts[1])] if len(parts) == 2 else []


@dataclass
class Instruction:
    op: str
    args: str
    line: int


def parse_dockerfile(text: str) -> list[Instruction]:
    out: list[Instruction] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        full = (buf + line).strip()
        buf = ""
        op, _, args = full.partition(" ")
        out.append(Instruction(op.upper(), args.strip(), start))
    return out


def _mutable(image: str) -> bool:
    if image.lower() == "scratch" or "$" in image or "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


class _Emitter:
    def __init__(self, path: str, text: str, language: str, resource: str = "") -> None:
        self.path, self.lines, self.language = path, text.splitlines(), language
        self.resource = resource
        self.findings: list[RawFinding] = []

    def emit(self, rule_id: str, line: int, note: str = "", resource: str = "") -> None:
        src = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if suppressed(src, rule_id):
            return
        f = make_finding(RULES[rule_id], rel_path=self.path, language=self.language,
                         lines=self.lines, line_no=line, description_suffix=note)
        res = resource or self.resource or self.path
        f.asset = AssetRef("iac", f"{self.path}:{res}", res)
        f.key = f"{res}:{rule_id}:{note}"
        f.extra["resource"] = res
        self.findings.append(f)


def scan_dockerfile(rel_path: str, text: str) -> list[RawFinding]:
    e = _Emitter(rel_path, text, "dockerfile", rel_path)
    stages: list[str] = []
    final_user: tuple[str, int] | None = None
    has_healthcheck, last_from_line = False, 0
    for ins in parse_dockerfile(text):
        op, args = ins.op, ins.args
        if op == "FROM":
            m = re.match(r"(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", args)
            if not m:
                continue
            image = m.group(1)
            last_from_line = ins.line
            final_user, has_healthcheck = None, False  # per-stage state; only the last counts
            if image not in stages:  # FROM <previous stage> is not an external image
                if _mutable(image):
                    e.emit("docker.mutable-base-image", ins.line, f"Image '{image}'.")
                if is_eol(image):
                    e.emit("docker.eol-base-image", ins.line, f"Image '{image}'.")
            if m.group(2):
                stages.append(m.group(2))
        elif op == "USER":
            final_user = (args.split()[0].split(":")[0], ins.line)
        elif op == "HEALTHCHECK" and not args.upper().startswith("NONE"):
            has_healthcheck = True
        elif op == "ADD" and re.match(r"(?:--\S+\s+)*https?://", args):
            e.emit("docker.add-remote-url", ins.line)
        elif op == "RUN":
            if re.search(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", args):
                e.emit("docker.curl-pipe-shell", ins.line)
            if re.search(r"\bchmod\s+(?:-R\s+)?0?777\b", args):
                e.emit("docker.chmod-777", ins.line)
            if re.search(r"(?:^|[;&|]\s*|\s)sudo\s", args):
                e.emit("docker.sudo", ins.line)
        elif op in ("ENV", "ARG"):
            for name, value in _assignments(args):
                v = value.strip("\"'")
                if _SECRET_NAME.search(name) and v and not v.startswith("$") and len(v) >= 4:
                    e.emit("docker.secret-in-env", ins.line, f"Variable {name}.")
        elif op == "EXPOSE" and re.search(r"(?:^|\s)22(?:/tcp)?(?:\s|$)", args):
            e.emit("docker.exposed-ssh", ins.line)
    if last_from_line:
        if final_user is None or final_user[0].lower() in ("root", "0"):
            e.emit("docker.root-user", final_user[1] if final_user else last_from_line,
                   "No USER instruction." if final_user is None else "USER is root.")
        if not has_healthcheck:
            e.emit("docker.no-healthcheck", last_from_line)
    return e.findings


def _env_pairs(env: Any) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    pairs = []
    for item in env or []:
        k, _, v = str(item).partition("=")
        pairs.append((k, v))
    return pairs


def looks_like_compose(text: str) -> bool:
    return re.search(r"^services:\s*$", text, re.M) is not None


def scan_compose(rel_path: str, text: str) -> list[RawFinding]:
    if not looks_like_compose(text):
        return []
    e = _Emitter(rel_path, text, "yaml")
    try:
        docs = list(yu.load_documents(text))
    except yaml.YAMLError:
        return []
    for doc, node in docs:
        services = doc.get("services") if isinstance(doc, dict) else None
        if not isinstance(services, dict):
            continue
        for name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            sn = yu.walk(node, "services", name)
            res = f"service/{name}"
            if svc.get("privileged") is True:
                e.emit("compose.privileged", yu.key_line(sn, "privileged"), resource=res)
            for key in ("network_mode", "pid", "ipc"):
                if svc.get(key) == "host":
                    e.emit("compose.host-namespace", yu.key_line(sn, key), f"{key}: host.", res)
            caps = {str(c).upper() for c in svc.get("cap_add") or []}
            if caps & _DANGEROUS_CAPS:
                e.emit("compose.dangerous-capabilities", yu.key_line(sn, "cap_add"),
                       f"Adds {', '.join(sorted(caps & _DANGEROUS_CAPS))}.", res)
            if any("unconfined" in str(o) for o in svc.get("security_opt") or []):
                e.emit("compose.security-opt-unconfined", yu.key_line(sn, "security_opt"), resource=res)
            for i, vol in enumerate(svc.get("volumes") or []):
                src = str(vol.get("source") if isinstance(vol, dict) else str(vol).split(":")[0])
                if src in ("/", "/var/run/docker.sock", "/run/docker.sock"):
                    e.emit("compose.docker-socket", yu.node_line(yu.walk(sn, "volumes", i)),
                           f"Mounts {src}.", res)
            for i, port in enumerate(svc.get("ports") or []):
                text_port = str(port)
                parts = text_port.split(":")
                published_all = len(parts) < 3 or parts[0] in ("0.0.0.0", "")
                container_port = re.sub(r"\D.*$", "", parts[-1].split("/")[0]) or "0"
                target = int(container_port) if container_port.isdigit() else 0
                if published_all and len(parts) >= 2 and target in _DB_PORTS:
                    e.emit("compose.exposed-database-port", yu.node_line(yu.walk(sn, "ports", i)),
                           f"Port {target}.", res)
            for k, v in _env_pairs(svc.get("environment")):
                if _SECRET_NAME.search(k) and v and not v.startswith("$") and len(v) >= 4:
                    e.emit("compose.secret-in-environment", yu.key_line(sn, "environment"),
                           f"Variable {k}.", res)
            image = str(svc.get("image", ""))
            if image and _mutable(image):
                e.emit("docker.mutable-base-image", yu.key_line(sn, "image"), f"Image '{image}'.", res)
            if image and is_eol(image):
                e.emit("docker.eol-base-image", yu.key_line(sn, "image"), f"Image '{image}'.", res)
            if str(svc.get("user", "")).split(":")[0] in ("root", "0"):
                e.emit("docker.root-user", yu.key_line(sn, "user"), "user: root.", res)
    return e.findings
