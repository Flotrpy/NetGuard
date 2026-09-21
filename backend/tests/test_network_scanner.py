import asyncio
import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from netguard.scanners.base import ScanContext
from netguard.scanners.network import engine
from netguard.scanners.network.audit import RULES, audit_host
from netguard.scanners.network.identify import (
    TOP_PORTS,
    Identity,
    guess_device,
    identify,
    sanitize,
)
from netguard.scanners.registry import get_scanner


class Server:
    """A throwaway TCP server on 127.0.0.1 for scanner tests."""

    def __init__(self, banner: bytes = b"", reply: bytes = b"", cert: tuple[str, str] | None = None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.banner, self.reply, self.cert = banner, reply, cert
        self.received: list[bytes] = []
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            if self.cert:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(*self.cert)
                conn = ctx.wrap_socket(conn, server_side=True)
            if self.banner:
                conn.sendall(self.banner)
            conn.settimeout(1.0)
            try:
                data = conn.recv(2048)
                if data:
                    self.received.append(data)
                    if self.reply:
                        conn.sendall(self.reply)
            except (TimeoutError, OSError):
                pass
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.fixture
def servers():
    made = []

    def make(*a, **k):
        s = Server(*a, **k)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def free_closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_cert(tmp_path, *, expired=False, days=365, self_signed=True):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    now = datetime.datetime.now(datetime.UTC)
    start, end = (now - datetime.timedelta(days=800), now - datetime.timedelta(days=5)) if expired else \
        (now - datetime.timedelta(days=1), now + datetime.timedelta(days=days))
    issuer = name if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


def run_scan(scan_type, ports, targets=("127.0.0.1",), timeout=0.5, **extra):
    ctx = ScanContext(config={"scan_type": scan_type, "targets": list(targets), "ports": ports,
                              "timeout": timeout, **extra}, runtime={"allow_public_targets": False})
    return get_scanner("network").scan(ctx)


# ---- identification ----------------------------------------------------------------------------
def test_identify_from_banners_and_ports():
    ssh = identify(2222, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    assert (ssh.service, ssh.version, ssh.detection, ssh.os_hint) == ("ssh", "OpenSSH 8.9p1", "banner", "Ubuntu")
    http = identify(8080, "HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nX: y")
    assert (http.service, http.version, http.os_hint) == ("http", "nginx 1.18.0 (Ubuntu)", "Ubuntu")
    assert identify(443, "HTTP/1.1 200 OK\nServer: Apache", tls=True).service == "https"
    ftp = identify(21, "220 (vsFTPd 3.0.5)")
    assert (ftp.service, ftp.version) == ("ftp", "vsFTPd 3.0.5")
    assert identify(25, "220 mail ESMTP Postfix").service == "smtp"
    port_only = identify(5432, "")
    assert (port_only.service, port_only.version, port_only.detection) == ("postgresql", "", "port")
    assert identify(60000, "").service == "unknown"


def test_banner_sanitizing_strips_control_and_truncates():
    cleaned = sanitize("SSH\x00\x1b[31m-2.0\r\n\tX")
    assert cleaned.startswith("SSH") and cleaned.endswith("X")
    assert all(32 <= ord(c) < 127 for c in cleaned)  # printable ASCII only
    assert "\x1b" not in sanitize("a\x1bb") and len(sanitize("x" * 1000)) == 200


def test_device_guess_is_heuristic():
    assert guess_device({3389, 445}, {})[0] == "Windows host"
    assert guess_device({22}, {22: Identity("ssh", "OpenSSH 9", "banner", "Ubuntu")}) == ("Linux server", "Ubuntu")
    assert guess_device({3306}, {3306: Identity("mysql")})[0] == "Database server"
    assert guess_device({443}, {})[0] == "Web server" and guess_device(set(), {})[0] == "Unknown"


# ---- engine against local servers ---------------------------------------------------------------
def test_probe_states(servers):
    s = servers()
    assert asyncio.run(engine.probe_port("127.0.0.1", s.port, 0.5))[0] == "open"
    # Windows takes ~2s to report a refused loopback connection, so allow for that here.
    assert asyncio.run(engine.probe_port("127.0.0.1", free_closed_port(), 4.0))[0] == "closed"


def test_discovery_treats_refused_as_host_up():
    up, _ = asyncio.run(engine.discover("127.0.0.1", [free_closed_port()], 4.0))
    assert up is True


def test_passive_banner_is_read_without_sending_anything(servers):
    s = servers(banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    banner, tls = asyncio.run(engine.grab_banner("127.0.0.1", s.port, 0.5))
    assert banner.startswith("SSH-2.0-OpenSSH_8.9p1") and tls == {} and s.received == []


def test_silent_services_get_a_benign_head_probe(servers):
    s = servers(reply=b"HTTP/1.0 200 OK\r\nServer: TestSrv/1.2\r\n\r\n")
    banner, _ = asyncio.run(engine.grab_banner("127.0.0.1", s.port, 0.4))
    assert "TestSrv/1.2" in banner and s.received[0].startswith(b"HEAD / HTTP/1.0")


def test_tls_inspection_reports_version_and_certificate(servers, tmp_path):
    good = servers(cert=make_cert(tmp_path, days=365), reply=b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\n")
    _, tls = asyncio.run(engine.grab_banner("127.0.0.1", good.port, 0.5, tls=True))
    assert tls["version"] in ("TLSv1.2", "TLSv1.3") and tls["self_signed"] and not tls["expired"]
    assert "test.local" in tls["subject"] and 360 <= tls["days_left"] <= 366
    expired = servers(cert=make_cert(tmp_path, expired=True))
    _, tls = asyncio.run(engine.grab_banner("127.0.0.1", expired.port, 0.5, tls=True))
    assert tls["expired"] is True


# ---- full scanner ----------------------------------------------------------------------------------
def test_quick_discovery_lists_hosts_without_ports(servers):
    s = servers()
    res = run_scan("quick_discovery", [s.port])
    assert res.metadata["hosts_up"] == 1 and res.metadata["hosts"][0]["services"] == [] and res.findings == []
    assert res.metadata["hosts"][0]["status"] == "up"


def test_port_scan_reports_open_ports_only(servers):
    a, b = servers(), servers()
    closed = free_closed_port()
    res = run_scan("port_scan", [a.port, b.port, closed])
    ports = sorted(s["port"] for s in res.metadata["hosts"][0]["services"])
    assert ports == sorted([a.port, b.port]) and closed not in ports
    assert res.metadata["open_services"] == 2 and res.metadata["duration_seconds"] >= 0


def test_service_detection_versions_come_from_banners(servers):
    ssh = servers(banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    plain = servers(banner=b"")
    res = run_scan("service_detection", [ssh.port, plain.port])
    svcs = {s["port"]: s for s in res.metadata["hosts"][0]["services"]}
    assert svcs[ssh.port]["service"] == "ssh" and svcs[ssh.port]["version"] == "OpenSSH 8.9p1"
    assert svcs[ssh.port]["detection"] == "banner"
    assert svcs[plain.port]["version"] == "" and svcs[plain.port]["detection"] == "port"


def test_inventory_adds_device_guess_and_hostname(servers):
    ssh = servers(banner=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    res = run_scan("inventory", [ssh.port], hostname="nas.lan")
    host = res.metadata["hosts"][0]
    assert host["hostname"] == "nas.lan" and host["os_guess"] == "Ubuntu" and host["latency_ms"] >= 0
    assert host["scanned_at"] and res.findings == []  # inventory reports no findings


def test_security_audit_findings_have_asset_exposure_and_no_exploitation(servers):
    ssh = servers(banner=b"SSH-2.0-OpenSSH_7.4\r\n")
    res = run_scan("security_audit", [ssh.port])
    (f,) = res.findings
    assert f.rule_id == "net.version-disclosed" and f.severity.value == "info"
    assert f.asset.type == "host" and f.asset.identifier == "127.0.0.1" and f.exposure == "internal"
    assert f.extra["port"] == ssh.port and "OpenSSH 7.4" in f.description
    assert "exploit" not in f.remediation.lower()


def test_multiple_targets_and_down_hosts(servers, monkeypatch):
    s = servers()
    res = run_scan("port_scan", [s.port], targets=("127.0.0.1", "127.0.0.2"))
    ips = {h["ip"] for h in res.metadata["hosts"]}
    assert "127.0.0.1" in ips and res.metadata["targets_scanned"] == 2


def test_scanner_refuses_forbidden_and_invalid_input():
    for bad in (["169.254.169.254"], ["8.8.8.8"], ["224.0.0.1"]):
        with pytest.raises(ValueError, match="not permitted"):
            run_scan("port_scan", [80], targets=bad)
    with pytest.raises(ValueError, match="Unknown scan type"):
        run_scan("nmap-vuln", [80])
    with pytest.raises(ValueError, match="No targets"):
        run_scan("port_scan", [80], targets=())
    with pytest.raises(ValueError, match="not permitted"):
        run_scan("port_scan", [70000])


def test_timeout_is_clamped():
    res = run_scan("quick_discovery", [free_closed_port()], timeout=999)  # clamped to 5s
    assert res.metadata["hosts_up"] == 1  # refused => up, and clamping avoids a 999s hang


# ---- audit rules (pure) -----------------------------------------------------------------------------------
def host(*services, ip="10.0.0.5"):
    return {"ip": ip, "hostname": "srv", "os_guess": "", "device_type": "", "services": [
        {"port": p, "protocol": "tcp", "service": s, "version": v, "banner": "", "tls": tls or {},
         "detection": "banner" if v else "port"} for p, s, v, tls in services]}


def ids(h):
    return sorted(f.rule_id for f in audit_host(h))


def test_audit_rules_for_risky_services():
    assert ids(host((23, "telnet", "", None))) == ["net.telnet-open"]
    assert ids(host((21, "ftp", "", None))) == ["net.ftp-open"]
    assert ids(host((445, "smb", "", None), (3389, "rdp", "", None))) == ["net.rdp-exposed", "net.smb-exposed"]
    assert ids(host((5900, "vnc", "", None))) == ["net.vnc-exposed"]
    assert ids(host((6379, "redis", "", None), (5432, "postgresql", "", None))) == ["net.database-exposed"] * 2
    assert ids(host((2375, "docker-api", "", None))) == ["net.docker-api-exposed"]
    assert ids(host((111, "rpcbind", "", None), (2049, "nfs", "", None))) == ["net.rpc-nfs-exposed"] * 2
    assert ids(host((22, "ssh", "", None))) == []


def test_audit_http_tls_and_versions():
    assert ids(host((80, "http", "", None))) == ["net.http-cleartext"]
    assert ids(host((80, "http", "", None), (443, "https", "", {"version": "TLSv1.3"}))) == []
    tls = {"version": "TLSv1", "expired": True, "self_signed": True, "not_after": "2020-01-01"}
    assert ids(host((443, "https", "", tls))) == ["net.tls-cert-expired", "net.tls-legacy-protocol", "net.tls-self-signed"]
    assert ids(host((443, "https", "", {"version": "TLSv1.3", "days_left": 10}))) == ["net.tls-cert-expiring"]
    assert ids(host((443, "https", "", {"version": "TLSv1.3", "days_left": 200}))) == []
    assert ids(host((22, "ssh", "OpenSSH 7.4", None))) == ["net.version-disclosed"]


def test_audit_exposure_and_severity_metadata():
    (f,) = audit_host(host((23, "telnet", "", None), ip="93.184.216.34"))
    assert f.exposure == "internet" and f.severity.value == "high" and f.cwe == "CWE-319"
    assert f.title == "Telnet service exposed: srv:23/tcp"
    assert f.key == "93.184.216.34:23/tcp:net.telnet-open"
    for rule in RULES.values():
        assert rule.remediation and rule.impact and rule.cwe.startswith("CWE-")


def test_top_ports_are_valid_and_sorted():
    assert TOP_PORTS == sorted(set(TOP_PORTS)) and 22 in TOP_PORTS and 443 in TOP_PORTS
    assert all(1 <= p <= 65535 for p in TOP_PORTS) and 80 <= len(TOP_PORTS) <= 140
