"""Network scanner: authorized discovery, port/service inventory and security audit."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from netguard.core.targets import TargetError, check_address, parse_ports
from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.network import engine
from netguard.scanners.network.audit import RULES, audit_host
from netguard.scanners.network.identify import (
    DISCOVERY_PORTS,
    PORT_SERVICES,
    TOP_PORTS,
    guess_device,
)

SCAN_TYPES = {
    "quick_discovery": "Find which hosts respond (no port listing)",
    "port_scan": "TCP connect scan of common ports",
    "service_detection": "Port scan plus banner and TLS detection",
    "inventory": "Service detection plus hostnames and device/OS guesses",
    "security_audit": "Inventory plus security findings (exposure and configuration)",
}
CONCURRENCY = 200


class NetworkScanner(Scanner):
    name = ScannerName.NETWORK
    display_name = "Network Scanner"
    version = "1.0.0"
    description = (
        "Authorized network discovery, port and service inventory and security audit using TCP "
        "connections only. Never exploits, authenticates to or brute-forces services."
    )
    supported_inputs = ("network_target",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        return asyncio.run(self._scan(ctx))

    async def _scan(self, ctx: ScanContext) -> ScanResult:
        cfg, rt = ctx.config, ctx.runtime
        scan_type = cfg.get("scan_type", "port_scan")
        if scan_type not in SCAN_TYPES:
            raise ValueError(f"Unknown scan type: {scan_type}")
        allow_public = bool(rt.get("allow_public_targets", False))
        max_hosts = int(rt.get("max_scan_hosts", 1024))
        targets: list[str] = list(cfg.get("targets", []))
        if not targets or len(targets) > max_hosts:
            raise ValueError("No targets, or too many targets for one scan")
        try:  # defence in depth: never trust that the API already validated
            import ipaddress

            for t in targets:
                check_address(ipaddress.ip_address(t), allow_public=allow_public)
            ports = parse_ports(cfg.get("ports"), max_ports=int(rt.get("max_scan_ports", 1024)),
                                default=TOP_PORTS)
        except (TargetError, ValueError) as exc:
            raise ValueError(f"Target not permitted: {exc}") from exc
        timeout = min(max(float(cfg.get("timeout", 1.0)), 0.2), 5.0)
        hostname_hint = cfg.get("hostname", "")
        sem = asyncio.Semaphore(CONCURRENCY)
        hosts: list[dict[str, Any]] = []
        started = datetime.now(UTC)

        # 1. host discovery
        ctx.progress(2, "discovering hosts")
        live: list[tuple[str, float]] = []
        dsem = asyncio.Semaphore(CONCURRENCY // max(1, len(DISCOVERY_PORTS)) + 1)

        async def disc(ip: str) -> None:
            async with dsem:
                up, latency = await engine.discover(ip, DISCOVERY_PORTS, timeout)
            if up:
                live.append((ip, latency))

        await asyncio.gather(*(disc(ip) for ip in targets))
        live.sort(key=lambda t: tuple(int(x) for x in t[0].split(".")) if "." in t[0] else (0,))
        ctx.progress(30, f"{len(live)} of {len(targets)} hosts responded")

        # 2. per-host port scan / enrichment
        for i, (ip, latency) in enumerate(live):
            ctx.check_cancelled()
            host: dict[str, Any] = {"ip": ip, "hostname": hostname_hint if len(targets) == 1 else "",
                                    "status": "up", "latency_ms": round(latency, 1),
                                    "os_guess": "", "device_type": "", "services": [],
                                    "scanned_at": datetime.now(UTC).isoformat()}
            if scan_type != "quick_discovery":
                results = await engine.scan_ports(ip, ports, timeout, sem)
                if scan_type in ("service_detection", "inventory", "security_audit"):
                    await engine.enrich(ip, results, timeout, sem)
                idents = {}
                for r in results:
                    ident = r.identity
                    idents[r.port] = ident
                    host["services"].append({
                        "port": r.port, "protocol": "tcp", "state": "open",
                        "service": ident.service if ident else PORT_SERVICES.get(r.port, "unknown"),
                        "version": ident.version if ident else "",
                        "detection": ident.detection if ident else "port",
                        "banner": r.banner[:300], "tls": r.tls,
                    })
                if scan_type in ("inventory", "security_audit"):
                    if not host["hostname"]:
                        host["hostname"] = await engine.reverse_dns(ip)
                    device, os_guess = guess_device({r.port for r in results}, {
                        p: v for p, v in idents.items() if v})
                    host["device_type"], host["os_guess"] = device, os_guess
            hosts.append(host)
            ctx.progress(30 + 65 * (i + 1) / max(1, len(live)), f"scanned {ip}")

        findings: list[RawFinding] = []
        if scan_type == "security_audit":
            for h in hosts:
                findings.extend(audit_host(h))
        ctx.progress(100, "done")
        finished = datetime.now(UTC)
        return ScanResult(
            findings=findings,
            # Only a full audit can vouch for the absence of findings; discovery/port scans must
            # never cause earlier audit findings to be auto-resolved.
            complete=scan_type == "security_audit",
            metadata={
                "responsive_ips": [h["ip"] for h in hosts],
                "scan_type": scan_type, "hosts": hosts, "targets_scanned": len(targets),
                "hosts_up": len(hosts), "scanned_ips": targets, "ports_per_host": len(ports)
                if scan_type != "quick_discovery" else 0,
                "open_services": sum(len(h["services"]) for h in hosts),
                "duration_seconds": round((finished - started).total_seconds(), 2),
                "rules": len(RULES),
            },
            warnings=(["Hosts that did not answer any probe are reported as down; a firewall that "
                       "drops packets is indistinguishable from an absent host."]
                      if len(hosts) < len(targets) else []),
        )
