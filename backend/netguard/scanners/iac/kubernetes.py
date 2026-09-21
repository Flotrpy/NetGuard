"""Kubernetes manifest security checks."""

from __future__ import annotations

from typing import Any

import yaml

from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac import yamlutil as yu
from netguard.scanners.iac.meta import RULES
from netguard.scanners.sast.engine import make_finding, suppressed

_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController"}
_DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}
_SENSITIVE_HOSTPATHS = ("/var/run/docker.sock", "/run/containerd", "/etc", "/proc", "/sys", "/root")


def looks_like_kubernetes(text: str) -> bool:
    return "apiVersion:" in text and "kind:" in text and "{{" not in text  # skip Helm templates


def _pod_spec_path(kind: str) -> tuple[str, ...] | None:
    if kind == "Pod":
        return ("spec",)
    if kind in _WORKLOADS:
        return ("spec", "template", "spec")
    if kind == "CronJob":
        return ("spec", "jobTemplate", "spec", "template", "spec")
    return None


def _image_is_mutable(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


class _K8s:
    def __init__(self, rel_path: str, text: str) -> None:
        self.path, self.lines = rel_path, text.splitlines()
        self.findings: list[RawFinding] = []

    def emit(self, rule_id: str, line: int, kind: str, name: str, note: str = "") -> None:
        src = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if suppressed(src, rule_id):
            return
        f = make_finding(RULES[rule_id], rel_path=self.path, language="yaml", lines=self.lines,
                         line_no=line, description_suffix=note)
        f.asset = AssetRef("iac", f"{self.path}:{kind}/{name}", f"{kind}/{name}")
        f.key = f"{kind}/{name}:{rule_id}:{note}"
        f.extra["resource"] = f"{kind}/{name}"
        self.findings.append(f)

    def document(self, doc: dict[str, Any], node: yu.Node) -> None:
        kind = doc.get("kind", "")
        name = (doc.get("metadata") or {}).get("name", "unnamed")
        path = _pod_spec_path(kind)
        if path:
            spec: Any = doc
            for p in path:
                spec = (spec or {}).get(p) if isinstance(spec, dict) else None
            if isinstance(spec, dict):
                self.pod(spec, yu.walk(node, *path), kind, str(name))
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            ref = doc.get("roleRef") or {}
            if ref.get("name") == "cluster-admin":
                self.emit("k8s.cluster-admin-binding", yu.key_line(yu.walk(node, "roleRef"), "name"),
                          kind, str(name))
        elif kind in ("ClusterRole", "Role"):
            for i, rule in enumerate(doc.get("rules") or []):
                if "*" in (rule.get("verbs") or []) and "*" in (rule.get("resources") or []):
                    self.emit("k8s.rbac-wildcard", yu.node_line(yu.walk(node, "rules", i)), kind,
                              str(name))
        elif kind == "Service" and (doc.get("spec") or {}).get("type") in ("LoadBalancer", "NodePort"):
            self.emit("k8s.service-exposed", yu.key_line(yu.walk(node, "spec"), "type"), kind,
                      str(name), f"Type is {(doc['spec'])['type']}.")
        elif kind == "Ingress" and not (doc.get("spec") or {}).get("tls"):
            self.emit("k8s.ingress-no-tls", yu.key_line(node, "spec"), kind, str(name))

    def pod(self, spec: dict[str, Any], node: yu.Node | None, kind: str, name: str) -> None:
        pod_sc = spec.get("securityContext") or {}
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(flag) is True:
                self.emit("k8s.host-namespace", yu.key_line(node, flag), kind, name, f"{flag}: true.")
        for i, vol in enumerate(spec.get("volumes") or []):
            hp = (vol or {}).get("hostPath")
            if hp:
                path = str(hp.get("path", ""))
                risky = path == "/" or path.startswith(_SENSITIVE_HOSTPATHS)
                note = f"hostPath {path}" + (" (sensitive host path)." if risky else ".")
                self.emit("k8s.hostpath-volume", yu.node_line(yu.walk(node, "volumes", i)), kind,
                          name, note)
        for group in ("containers", "initContainers"):
            for i, c in enumerate(spec.get(group) or []):
                self.container(c or {}, yu.walk(node, group, i), pod_sc, kind, name)

    def container(self, c: dict[str, Any], node: yu.Node | None, pod_sc: dict[str, Any], kind: str,
                  name: str) -> None:
        cname = c.get("name", "container")
        sc = c.get("securityContext") or {}
        sc_node = yu.walk(node, "securityContext")
        line_sc = yu.node_line(sc_node) if sc_node else yu.node_line(node)
        if sc.get("privileged") is True:
            self.emit("k8s.privileged-container", yu.key_line(sc_node, "privileged"), kind, name,
                      f"Container '{cname}'.")
        elif sc.get("allowPrivilegeEscalation") is not False:
            explicit = sc.get("allowPrivilegeEscalation") is True
            self.emit("k8s.privilege-escalation",
                      yu.key_line(sc_node, "allowPrivilegeEscalation") if explicit else line_sc,
                      kind, name, f"Container '{cname}'.")
        user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        if user == 0 or (non_root is not True and not (isinstance(user, int) and user > 0)):
            self.emit("k8s.run-as-root", line_sc, kind, name, f"Container '{cname}'.")
        if sc.get("readOnlyRootFilesystem") is not True:
            self.emit("k8s.writable-root-fs", line_sc, kind, name, f"Container '{cname}'.")
        added = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
        if added & _DANGEROUS_CAPS:
            self.emit("k8s.dangerous-capabilities",
                      yu.key_line(yu.walk(sc_node, "capabilities"), "add"), kind, name,
                      f"Container '{cname}' adds {', '.join(sorted(added & _DANGEROUS_CAPS))}.")
        image = str(c.get("image", ""))
        if image and _image_is_mutable(image):
            self.emit("k8s.mutable-image-tag", yu.key_line(node, "image"), kind, name,
                      f"Image '{image}'.")
        if not ((c.get("resources") or {}).get("limits")):
            self.emit("k8s.no-resource-limits", yu.node_line(node), kind, name,
                      f"Container '{cname}'.")


def scan_kubernetes(rel_path: str, text: str) -> list[RawFinding]:
    if not looks_like_kubernetes(text):
        return []
    s = _K8s(rel_path, text)
    try:
        for doc, node in yu.load_documents(text):
            if isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc:
                s.document(doc, node)
    except yaml.YAMLError:
        return []
    return s.findings
