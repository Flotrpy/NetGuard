"""Security-audit findings derived from what the network scan observed.

These are *exposure and configuration* observations, not proof of vulnerability: the scanner
never authenticates, never sends exploit payloads and never brute-forces. Each finding says what
was observed and what to verify.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from netguard.enums import Confidence as C
from netguard.enums import Severity as S
from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac.meta import R
from netguard.scanners.network.identify import DB_SERVICES

NET = "Network Exposure"
RULES = {r.id: r for r in [
    R("net.telnet-open", "Telnet service exposed", NET, S.HIGH, C.HIGH, "CWE-319",
      "A Telnet service accepted a connection. Telnet sends credentials and data in cleartext.",
      "Anyone on the network path can capture credentials and take over sessions.",
      "Disable Telnet and use SSH; if the device only supports Telnet, isolate it on a management VLAN.",
      expl="high"),
    R("net.ftp-open", "FTP service exposed", NET, S.MEDIUM, C.HIGH, "CWE-319",
      "An FTP service accepted a connection. Plain FTP transmits credentials in cleartext.",
      "Credentials and files can be intercepted on the network.",
      "Use SFTP/FTPS, or disable the service if it is not needed."),
    R("net.smb-exposed", "SMB file sharing reachable", NET, S.MEDIUM, C.HIGH, "CWE-668",
      "SMB (port 445) is reachable from the scanning host.",
      "SMB is a frequent target for lateral movement and wormable vulnerabilities.",
      "Restrict SMB to required hosts with firewall rules, disable SMBv1 and keep systems patched."),
    R("net.rdp-exposed", "Remote Desktop reachable", NET, S.MEDIUM, C.HIGH, "CWE-668",
      "RDP (port 3389) is reachable from the scanning host.",
      "Exposed RDP is a common entry point for credential attacks and ransomware.",
      "Restrict RDP behind a VPN/gateway, require NLA and MFA, and limit source addresses."),
    R("net.vnc-exposed", "VNC remote access reachable", NET, S.HIGH, C.HIGH, "CWE-668",
      "A VNC service accepted a connection.",
      "VNC often has weak or no authentication and unencrypted traffic.",
      "Tunnel VNC through SSH/VPN, require strong authentication, or disable it.", expl="high"),
    R("net.database-exposed", "Database service reachable over the network", NET, S.HIGH, C.MEDIUM,
      "CWE-668",
      "A database or data-store port accepted a connection. NetGuard did not attempt to "
      "authenticate, so whether authentication is enforced is unknown.",
      "Databases are meant to be reachable only from application servers; many default "
      "installs (Redis, Memcached, MongoDB, Elasticsearch) have no authentication.",
      "Bind to private interfaces, restrict with firewall rules and verify authentication is "
      "required.", expl="high"),
    R("net.docker-api-exposed", "Docker API reachable", NET, S.CRITICAL, C.MEDIUM, "CWE-668",
      "The Docker remote API port (2375) accepted a connection.",
      "An unauthenticated Docker API grants root on the host.",
      "Disable the TCP socket or protect it with mutual TLS and firewall rules.", expl="high"),
    R("net.rpc-nfs-exposed", "RPC/NFS services reachable", NET, S.MEDIUM, C.MEDIUM, "CWE-668",
      "rpcbind or NFS accepted a connection.",
      "These services can leak system details and expose file shares.",
      "Restrict to trusted hosts or disable them."),
    R("net.http-cleartext", "Web service without HTTPS", NET, S.LOW, C.MEDIUM, "CWE-319",
      "HTTP is served and no HTTPS port was found open on this host.",
      "Traffic to this service is unencrypted.", "Serve over HTTPS and redirect HTTP to it."),
    R("net.tls-legacy-protocol", "Legacy TLS protocol negotiated", NET, S.MEDIUM, C.HIGH, "CWE-327",
      "The service negotiated a TLS version older than 1.2.",
      "Old protocol versions have known weaknesses.",
      "Require TLS 1.2 or newer and disable SSLv3/TLS 1.0/1.1."),
    R("net.tls-cert-expired", "TLS certificate expired", NET, S.MEDIUM, C.HIGH, "CWE-298",
      "The presented certificate is past its validity period.",
      "Clients will warn or fail, and users may learn to ignore certificate warnings.",
      "Renew the certificate and automate renewal."),
    R("net.tls-cert-expiring", "TLS certificate expiring soon", NET, S.LOW, C.HIGH, "CWE-298",
      "The certificate expires within 30 days.", "An unexpected expiry will cause an outage.",
      "Renew it now and automate renewal."),
    R("net.tls-self-signed", "Self-signed TLS certificate", NET, S.LOW, C.MEDIUM, "CWE-295",
      "The certificate's subject and issuer are identical.",
      "Clients cannot verify the server's identity, enabling man-in-the-middle attacks.",
      "Use a certificate from a trusted (or your internal) CA."),
    R("net.version-disclosed", "Service discloses its version", NET, S.INFO, C.HIGH, "CWE-200",
      "The service banner reveals a specific product and version.",
      "Attackers can look up known vulnerabilities for that exact version.",
      "Where possible hide version details, and verify the version against vendor advisories."),
]}
_BY_SERVICE = {"telnet": "net.telnet-open", "ftp": "net.ftp-open", "smb": "net.smb-exposed",
               "rdp": "net.rdp-exposed", "vnc": "net.vnc-exposed", "docker-api": "net.docker-api-exposed",
               "rpcbind": "net.rpc-nfs-exposed", "nfs": "net.rpc-nfs-exposed"}
_LEGACY_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _exposure(ip: str) -> str:
    return "internal" if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback \
        else "internet"


def audit_host(host: dict[str, Any]) -> list[RawFinding]:
    from netguard.scanners.sast.rules import cwe_url

    ip, name = host["ip"], host.get("hostname") or host["ip"]
    asset = AssetRef("host", ip, name, {"os_guess": host.get("os_guess", ""),
                                        "device_type": host.get("device_type", "")})
    services = host["services"]
    out: list[RawFinding] = []

    def emit(rule_id: str, svc: dict[str, Any], note: str = "") -> None:
        rule = RULES[rule_id]
        out.append(RawFinding(
            rule_id=rule_id, title=f"{rule.title}: {name}:{svc['port']}/{svc['protocol']}",
            category=rule.category, severity=rule.severity, confidence=rule.confidence,
            cwe=rule.cwe, description=f"{rule.description} {note}".strip(), impact=rule.impact,
            remediation=rule.remediation, references=[cwe_url(rule.cwe)],
            exploitability=rule.exploitability, exposure=_exposure(ip), asset=asset,
            extra={"ip": ip, "port": svc["port"], "protocol": svc["protocol"],
                   "service": svc["service"], "version": svc.get("version", ""),
                   "banner": svc.get("banner", "")[:200]},
            key=f"{ip}:{svc['port']}/{svc['protocol']}:{rule_id}",
        ))

    open_ports = {s["port"] for s in services}
    for svc in services:
        rule = _BY_SERVICE.get(svc["service"])
        if rule:
            emit(rule, svc)
        elif svc["service"] in DB_SERVICES:
            emit("net.database-exposed", svc, f"Service: {svc['service']}.")
        if svc["service"] in ("http", "http-alt") and not open_ports & {443, 8443} \
                and svc["port"] in (80, 8080, 8000, 3000):
            emit("net.http-cleartext", svc)
        tls = svc.get("tls") or {}
        if tls.get("version") in _LEGACY_TLS:
            emit("net.tls-legacy-protocol", svc, f"Negotiated {tls['version']}.")
        if tls.get("expired"):
            emit("net.tls-cert-expired", svc, f"Expired {tls.get('not_after', '')}.")
        elif tls.get("days_left") is not None and 0 <= tls["days_left"] <= 30:
            emit("net.tls-cert-expiring", svc, f"{tls['days_left']} days left.")
        if tls.get("self_signed"):
            emit("net.tls-self-signed", svc)
        if svc.get("version") and svc.get("detection") == "banner":
            emit("net.version-disclosed", svc, f"Observed: {svc['version']}.")
    return out
