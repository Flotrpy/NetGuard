"""Network scan persistence, inventory queries, export and topology."""

from __future__ import annotations

import csv
import io
import ipaddress
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from netguard.db import utcnow
from netguard.enums import ACTIVE_STATUSES
from netguard.models import Finding, NetworkHost, NetworkService, Scan
from netguard.scanners.base import AssetRef
from netguard.services.findings import get_or_create_asset
from netguard.services.risk import severity_counts


def persist_hosts(db: Session, scan: Scan, hosts: list[dict[str, Any]]) -> None:
    """Store the hosts/services a network scan observed (idempotent per scan)."""
    for old in db.scalars(select(NetworkHost).where(NetworkHost.scan_id == scan.id)):
        db.delete(old)
    db.flush()
    for h in hosts:
        asset = get_or_create_asset(
            db, scan.project_id,
            AssetRef("host", h["ip"], h.get("hostname") or h["ip"],
                     {"os_guess": h.get("os_guess", ""), "device_type": h.get("device_type", "")}),
        )
        scanned = utcnow()
        row = NetworkHost(
            project_id=scan.project_id, scan_id=scan.id, asset_id=asset.id, ip=h["ip"],
            hostname=h.get("hostname", ""), os_guess=h.get("os_guess", ""),
            device_type=h.get("device_type", ""), status=h.get("status", "up"),
            latency_ms=float(h.get("latency_ms", 0.0)), scanned_at=scanned,
        )
        db.add(row)
        db.flush()
        for s in h.get("services", []):
            db.add(NetworkService(
                host_id=row.id, port=s["port"], protocol=s.get("protocol", "tcp"),
                state=s.get("state", "open"), service=s.get("service", ""),
                version=s.get("version", "")[:300], banner=s.get("banner", "")[:500],
                scanned_at=scanned,
            ))


def host_dict(host: NetworkHost, findings: list[Finding] | None = None) -> dict[str, Any]:
    return {
        "id": host.id, "ip": host.ip, "hostname": host.hostname, "os_guess": host.os_guess,
        "device_type": host.device_type, "status": host.status, "latency_ms": host.latency_ms,
        "scanned_at": host.scanned_at,
        "services": [
            {"port": s.port, "protocol": s.protocol, "state": s.state, "service": s.service,
             "version": s.version, "banner": s.banner}
            for s in sorted(host.services, key=lambda s: s.port)
        ],
        "findings": severity_counts([f.severity for f in findings or []]),
    }


def _active_findings_by_ip(db: Session, project_id: str) -> dict[str, list[Finding]]:
    rows = db.scalars(select(Finding).where(
        Finding.project_id == project_id, Finding.scanner == "network",
        Finding.status.in_([s.value for s in ACTIVE_STATUSES])))
    out: dict[str, list[Finding]] = {}
    for f in rows:
        out.setdefault((f.extra or {}).get("ip", ""), []).append(f)
    return out


def latest_inventory(db: Session, project_id: str) -> list[dict[str, Any]]:
    """Most recent observation of each IP across all of the project's network scans."""
    rows = db.scalars(select(NetworkHost).where(NetworkHost.project_id == project_id)
                      .order_by(NetworkHost.scanned_at.desc()))
    latest: dict[str, NetworkHost] = {}
    for h in rows:
        latest.setdefault(h.ip, h)
    by_ip = _active_findings_by_ip(db, project_id)
    hosts = sorted(latest.values(), key=lambda h: _ip_key(h.ip))
    return [host_dict(h, by_ip.get(h.ip)) for h in hosts]


def _ip_key(ip: str) -> tuple:
    a = ipaddress.ip_address(ip)
    return (a.version, int(a))


def scan_hosts(db: Session, scan_id: str) -> list[dict[str, Any]]:
    scan = db.get(Scan, scan_id)
    rows = db.scalars(select(NetworkHost).where(NetworkHost.scan_id == scan_id)).all()
    by_ip = _active_findings_by_ip(db, scan.project_id) if scan else {}
    return [host_dict(h, by_ip.get(h.ip)) for h in sorted(rows, key=lambda h: _ip_key(h.ip))]


def export_csv(hosts: list[dict[str, Any]]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["ip", "hostname", "status", "device_type", "os_guess", "port", "protocol", "state",
                "service", "version", "scanned_at"])
    for h in hosts:
        base = [h["ip"], h["hostname"], h["status"], h["device_type"], h["os_guess"]]
        stamp = h["scanned_at"].isoformat() if isinstance(h["scanned_at"], datetime) else h["scanned_at"]
        if not h["services"]:
            w.writerow([*base, "", "", "", "", "", stamp])
        for s in h["services"]:
            w.writerow([*[_csv_safe(x) for x in base], s["port"], s["protocol"], s["state"],
                        _csv_safe(s["service"]), _csv_safe(s["version"]), stamp])
    return out.getvalue()


def _csv_safe(value: Any) -> Any:
    """Banners are attacker-controlled: neutralise spreadsheet formula injection."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def topology(db: Session, project_id: str) -> dict[str, Any]:
    """Logical map grouped by /24 (or /64) subnet. Physical links are NOT discovered."""
    hosts = latest_inventory(db, project_id)
    nodes: list[dict[str, Any]] = [{"id": "scanner", "type": "scanner", "label": "NetGuard scanner"}]
    edges: list[dict[str, str]] = []
    subnets: dict[str, str] = {}
    public_seen = False
    for h in hosts:
        ip = ipaddress.ip_address(h["ip"])
        net = ipaddress.ip_network(f"{ip}/{24 if ip.version == 4 else 64}", strict=False)
        sid = f"subnet:{net}"
        if str(net) not in subnets:
            subnets[str(net)] = sid
            nodes.append({"id": sid, "type": "subnet", "label": str(net)})
            edges.append({"from": "scanner", "to": sid})
        if not (ip.is_private or ip.is_loopback):
            public_seen = True
        nodes.append({
            "id": f"host:{h['id']}", "type": "host", "host_id": h["id"], "label": h["hostname"] or h["ip"],
            "ip": h["ip"], "device_type": h["device_type"] or "Unknown", "os_guess": h["os_guess"],
            "ports": [s["port"] for s in h["services"]], "findings": h["findings"],
            "worst": next((s for s in ("critical", "high", "medium", "low", "info")
                           if h["findings"].get(s)), None),
        })
        edges.append({"from": sid, "to": f"host:{h['id']}"})
    if public_seen:
        nodes.insert(0, {"id": "internet", "type": "internet", "label": "Internet"})
        edges.insert(0, {"from": "internet", "to": "scanner"})
    return {"nodes": nodes, "edges": edges,
            "note": "Logical view grouped by subnet. Physical topology (routers, switches) is not "
                    "discovered by connect scans."}
