"""Service identification from ports and passively observed banners.

Only information the service volunteers (or returns to a benign ``HEAD /``) is used. Versions are
reported only when they appear in a banner; a service identified purely by its well-known port
is labelled ``detection = "port"`` so the UI can show it is an assumption, not a fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-api",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 5000: "http-alt", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9100: "jetdirect",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}
HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 8888, 9000, 9090, 5601, 9200}
# The 100 or so ports that carry most real-world services.
TOP_PORTS = sorted(set(PORT_SERVICES) | {
    20, 69, 79, 88, 102, 113, 119, 123, 137, 161, 179, 264, 514, 515, 548, 554, 587, 873, 990,
    1080, 1194, 1723, 1883, 2082, 2083, 2181, 3128, 4444, 4567, 5060, 5222, 5353, 5985, 5986,
    6000, 6443, 7001, 7443, 8008, 8081, 8181, 8880, 9001, 9042, 9092, 9418, 10000, 10250,
    15672, 27018, 50000,
})
DISCOVERY_PORTS = [443, 80, 22, 445, 3389, 135, 8080, 21, 25, 53, 3306, 5432]
DB_SERVICES = {"mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "memcached",
               "elasticsearch", "amqp"}


@dataclass
class Identity:
    service: str
    version: str = ""
    detection: str = "port"  # "banner" (observed) or "port" (assumed from the port number)
    os_hint: str = ""


def sanitize(text: str, limit: int = 200) -> str:
    """Banners are attacker-controlled: keep printable ASCII only and cap the length."""
    return "".join(c if 32 <= ord(c) < 127 else " " for c in text).strip()[:limit]


_SSH = re.compile(r"^SSH-\d\.\d+-(\S+)(?:\s+(.*))?")
_HTTP_SERVER = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_OS_WORDS = ("Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "Alpine", "FreeBSD", "Win32",
             "Win64", "Windows")


def _os_hint(text: str) -> str:
    for w in _OS_WORDS:
        if w.lower() in text.lower():
            return "Windows" if w.startswith("Win") else w
    return ""


def identify(port: int, banner: str, *, tls: bool = False) -> Identity:
    banner = banner or ""
    m = _SSH.match(banner)
    if m:
        product = m.group(1).replace("_", " ")
        return Identity("ssh", product, "banner", _os_hint(m.group(2) or ""))
    if banner.startswith("HTTP/"):
        server = _HTTP_SERVER.search(banner)
        product = server.group(1).strip() if server else ""
        return Identity("https" if tls else "http", product.replace("/", " ", 1), "banner",
                        _os_hint(product))
    if re.match(r"^220[ -].*\bFTP", banner, re.I) or (port == 21 and banner.startswith("220")):
        v = re.search(r"(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server)\s*([\d.]+)?", banner, re.I)
        return Identity("ftp", " ".join(filter(None, v.groups())) if v else "", "banner")
    if banner.startswith("220") and ("SMTP" in banner.upper() or port in (25, 465, 587)):
        v = re.search(r"(Postfix|Exim|Sendmail|Microsoft ESMTP)\s*([\d.]+)?", banner, re.I)
        return Identity("smtp", " ".join(filter(None, v.groups())) if v else "", "banner")
    if banner.startswith("+OK") and port in (110, 995):
        return Identity("pop3", "", "banner")
    if banner.startswith("* OK") and port in (143, 993):
        return Identity("imap", "", "banner")
    if port == 3306 or "mysql" in banner.lower() or "mariadb" in banner.lower():
        v = re.search(r"(\d+\.\d+\.\d+(?:[-\w.]*)?)", banner)
        if v and port == 3306:
            return Identity("mysql", v.group(1), "banner")
    if banner.startswith("RFB "):
        return Identity("vnc", banner.strip()[:12], "banner")
    if banner.startswith("-ERR") and port == 6379 or banner.startswith("-DENIED"):
        return Identity("redis", "", "banner")
    return Identity(PORT_SERVICES.get(port, "unknown"), "", "port")


def guess_device(open_ports: set[int], services: dict[int, Identity]) -> tuple[str, str]:
    """(device_type, os_guess): heuristics, always presented to users as guesses."""
    os_hint = next((i.os_hint for i in services.values() if i.os_hint), "")
    if {3389, 445} & open_ports or {135, 139} <= open_ports:
        return "Windows host", os_hint or "Windows"
    if 9100 in open_ports or 631 in open_ports:
        return "Printer", os_hint
    if any(i.service in DB_SERVICES for i in services.values()):
        return "Database server", os_hint
    if 22 in open_ports and os_hint in ("Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "Alpine"):
        return "Linux server", os_hint
    if open_ports & (HTTP_PORTS | {443, 8443}):
        return "Web server", os_hint
    if 22 in open_ports:
        return "SSH host", os_hint
    return ("Unknown" if not open_ports else "Network host"), os_hint
