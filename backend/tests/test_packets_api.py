import struct

import pytest

from netguard.config import get_settings
from netguard.scanners.packets.analyze import Analyzer
from netguard.scanners.packets.dissect import dissect
from netguard.scanners.packets.pcap import RawPacket, read_packets
from netguard.worker import process_one
from tests import pcapgen as g

STATEMENT = "I am authorized to analyze this capture from my own lab network."
CLIENT, SERVER, DNS_SRV = "192.168.1.10", "93.184.216.34", "192.168.1.1"


def T(payload, sport, dport, flags=0x18, src=CLIENT, dst=SERVER, **kw):
    return g.eth(g.ipv4(g.tcp(sport, dport, flags, payload, **kw), src=src, dst=dst))


def U(payload, sport, dport, src=CLIENT, dst=DNS_SRV):
    return g.eth(g.ipv4(g.udp(sport, dport, payload), src=src, dst=dst, proto=17))


def sample_capture() -> bytes:
    frames = [
        U(g.dns_query("shop.example.com"), 5000, 53),
        U(g.dns_response("shop.example.com", SERVER), 53, 5000, src=DNS_SRV, dst=CLIENT),
        T(b"", 40000, 80, flags=0x02),
        T(b"", 80, 40000, flags=0x12, src=SERVER, dst=CLIENT),
        T(g.http_request("shop.example.com", "/login", "POST", {"Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
                         b"user=a&password=hunter2"), 40000, 80),
        T(g.http_response(), 80, 40000, src=SERVER, dst=CLIENT),
        T(g.tls_client_hello("secure.example.com", supported=[0x0304]), 40001, 443, flags=0x18),
        T(g.tls_server_hello(0x0303, supported=0x0304), 443, 40001, src=SERVER, dst=CLIENT),
        T(g.tls_app_data(), 40001, 443),
        T(b"USER alice\r\n", 40002, 21), T(b"PASS supersecret\r\n", 40002, 21),
        g.eth(g.arp(1, "00:11:22:33:44:55", CLIENT, "00:00:00:00:00:00", DNS_SRV), etype=0x0806),
        g.eth(g.ipv4(g.icmp_echo(), src=CLIENT, dst=SERVER, proto=1)),
    ]
    return g.pcap_bytes([(1700000000 + i * 0.1, f) for i, f in enumerate(frames)])


@pytest.fixture
def project(client):
    client.register()
    return client.post("/api/projects", json={"name": "Lab"}).json()


def upload(client, project, data, name="lab.pcap", authorized=True, statement=STATEMENT):
    return client.post("/api/packet-analysis", data={"project_id": project["id"], "authorized": str(authorized).lower(),
                                                     "authorization_statement": statement},
                       files={"file": (name, data, "application/octet-stream")})


def analyze(client, project, data=None):
    r = upload(client, project, data or sample_capture())
    assert r.status_code == 202, r.text
    while process_one("w"):
        pass
    return client.get(f"/api/packet-captures/{r.json()['id']}").json()


# ---- analysis unit tests -------------------------------------------------------------------------
def analysis_of(frames):
    a = Analyzer()
    for i, f in enumerate(frames, 1):
        p = RawPacket(i, 1000.0 + i * 0.01, len(f), f, 1)
        a.add(p, dissect(p))
    return a


def rule_ids(a):
    return sorted(f.rule_id for f in a.findings())


def test_summary_statistics_hierarchy_conversations_endpoints():
    a = analysis_of([U(g.dns_query("a.example"), 5000, 53), T(g.http_request(), 40000, 80), T(b"", 80, 40000, src=SERVER, dst=CLIENT)])
    s = a.summary()
    assert s["packets"] == 3 and s["bytes"] == sum(p["bytes"] for p in s["protocols"])
    protos = {p["protocol"]: p["packets"] for p in s["protocols"]}
    assert protos == {"DNS": 1, "HTTP": 1, "TCP": 1}
    paths = {h["path"]: h["packets"] for h in s["hierarchy"]}
    assert paths["eth"] == 3 and paths["eth>ipv4>udp>dns"] == 1 and paths["eth>ipv4>tcp>http"] == 1
    tcp_conv = next(c for c in s["conversations"] if c["protocol"] == "tcp")
    assert tcp_conv["packets"] == 2 and {tcp_conv["a_to_b_packets"], tcp_conv["b_to_a_packets"]} == {1}
    ends = {e["address"]: e for e in s["endpoints"]}
    assert ends[CLIENT]["tx_packets"] == 2 and ends[CLIENT]["rx_packets"] == 1
    assert sum(s["timeline"]["counts"]) == 3 and sum(x["packets"] for x in s["size_distribution"]) == 3


def test_cleartext_credential_observations_never_contain_the_secret():
    a = analysis_of([T(g.http_request("h.test", "/l", "POST", {"Authorization": "Basic c2VjcmV0"}, b"password=hunter2"), 4000, 80),
                     T(b"PASS topsecret\r\n", 4001, 21), T(b"\xff\xfd\x18", 4002, 23)])
    fs = a.findings()
    assert {f.rule_id for f in fs} == {"pk.cleartext-credentials", "pk.http-cleartext", "pk.telnet-traffic"}
    blob = repr([(f.title, f.description, f.extra) for f in fs])
    assert "c2VjcmV0" not in blob and "hunter2" not in blob and "topsecret" not in blob
    cred = [f for f in fs if f.rule_id == "pk.cleartext-credentials"]
    assert {f.extra["kind"] for f in cred} == {"HTTP Basic authentication", "HTTP form password field", "FTP password"}
    assert all(f.severity.value == "high" and f.asset.identifier == CLIENT and f.exposure == "internal" for f in cred)


def test_tls_legacy_arp_conflict_and_malformed():
    a = analysis_of([
        T(g.tls_server_hello(0x0301), 443, 4000, src=SERVER, dst=CLIENT),
        T(g.tls_client_hello("x.example", record_version=0x0301, hello_version=0x0301), 4001, 443),
        g.eth(g.arp(2, "aa:aa:aa:aa:aa:aa", "10.0.0.1", "ff:ff:ff:ff:ff:ff", "10.0.0.9"), etype=0x0806),
        g.eth(g.arp(2, "bb:bb:bb:bb:bb:bb", "10.0.0.1", "ff:ff:ff:ff:ff:ff", "10.0.0.9"), etype=0x0806),
        b"\x00" * 8,
    ])
    ids = rule_ids(a)
    assert ids.count("pk.tls-legacy") == 2 and "pk.arp-conflict" in ids and "pk.malformed-packets" in ids
    arp = next(f for f in a.findings() if f.rule_id == "pk.arp-conflict")
    assert arp.confidence.value == "medium" and "aa:aa:aa:aa:aa:aa" in arp.description and "failover" in arp.description


def test_port_scan_and_sweep_detection_thresholds():
    scan = [T(b"", 50000, p, flags=0x02, src="10.9.9.9", dst=CLIENT) for p in range(1000, 1030)]
    assert rule_ids(analysis_of(scan)) == ["pk.port-scan"]
    few = [T(b"", 50000, p, flags=0x02, src="10.9.9.9", dst=CLIENT) for p in range(1000, 1010)]
    assert rule_ids(analysis_of(few)) == []
    answered = scan + [T(b"", p, 50000, flags=0x12, src=CLIENT, dst="10.9.9.9") for p in range(1000, 1030)]
    assert rule_ids(analysis_of(answered)) == []  # every probe completed: not a stealth scan
    sweep = [T(b"", 50000, 445, flags=0x02, src="10.9.9.9", dst=f"10.1.0.{i}") for i in range(1, 30)]
    (f,) = analysis_of(sweep).findings()
    assert f.rule_id == "pk.port-scan" and "29 hosts" in f.title


def test_dns_heuristics_are_low_confidence():
    long_name = ".".join(["a" * 55, "example", "com"])
    a = analysis_of([U(g.dns_query(long_name), 5000, 53)] +
                    [U(g.dns_response(f"x{i}.example", "0.0.0.0", tid=i, rcode=3), 53, 5000, src=DNS_SRV, dst=CLIENT) for i in range(25)])
    fs = {f.rule_id: f for f in a.findings()}
    assert set(fs) == {"pk.dns-long-name", "pk.dns-nxdomain-burst"}
    assert all(f.confidence.value == "low" and f.severity.value == "low" for f in fs.values())


def test_analyzer_caps_are_respected():
    frames = [T(b"", 1000 + i, 80, src=f"10.{i // 250}.{i % 250}.1") for i in range(50)]
    s = analysis_of(frames).summary()
    assert len(s["endpoints"]) <= 200 and s["packets"] == 50


# ---- API ------------------------------------------------------------------------------------------
def test_capabilities_are_honest_about_live_capture(client, project):
    c = client.get("/api/packet-analysis/capabilities").json()
    assert c["import"]["available"] and "pcapng" in c["import"]["formats"]
    assert c["live_capture"]["available"] is False and "tcpdump" in c["live_capture"]["reason"]
    assert "authorized" in c["authorization_text"] and "never stored" in c["authorization_text"]


def test_authorization_is_required_and_validated(client, project):
    assert upload(client, project, sample_capture(), authorized=False).status_code == 422
    assert upload(client, project, sample_capture(), statement="short").status_code == 422
    assert upload(client, project, b"definitely not a capture at all").status_code == 422
    assert upload(client, project, b"").status_code == 422


def test_upload_size_limit(client, project, monkeypatch):
    monkeypatch.setenv("NETGUARD_MAX_PCAP_MB", "1")
    get_settings.cache_clear()
    big = g.pcap_bytes([]) + b"\x00" * (2 * 1024 * 1024)
    assert upload(client, project, big).status_code == 413


def test_full_analysis_flow_stats_findings_and_privacy(client, project):
    cap = analyze(client, project)
    assert cap["scan_status"] == "completed" and cap["packet_count"] == 13
    s = cap["summary"]
    assert s["packets"] == 13 and s["format"] == "pcap" and s["duration"] == pytest.approx(1.2, abs=0.01)
    assert {"DNS", "HTTP", "TLS", "ARP", "ICMP", "FTP"} <= {p["protocol"] for p in s["protocols"]}
    findings = client.get("/api/findings", params={"project_id": project["id"]}).json()["items"]
    rules = {f["rule_id"] for f in findings}
    assert {"pk.cleartext-credentials", "pk.http-cleartext"} <= rules
    assert all(f["detection_source"] == "Packet Analyzer" for f in findings)
    everything = client.get("/api/findings", params={"project_id": project["id"]}).text + str(cap)
    for secret in ("hunter2", "supersecret", "dXNlcjpwYXNzd29yZA=="):
        assert secret not in everything
    # Packet-capture findings must never auto-resolve just because a later capture lacks them.
    clean = analyze(client, project, g.pcap_bytes([(1.0, T(g.tls_app_data(), 4000, 443))]))
    assert clean["packet_count"] == 1
    assert client.get("/api/findings", params={"project_id": project["id"], "status": "open"}).json()["total"] == len(findings)


def test_packet_list_filters_search_and_paging(client, project):
    cap = analyze(client, project)
    url = f"/api/packet-captures/{cap['id']}/packets"
    all_ = client.get(url).json()
    assert all_["total"] == 13 and all_["items"][0]["n"] == 1 and all_["items"][0]["time"] == 0.0
    first = all_["items"][0]
    assert set(first) == {"n", "time", "source", "destination", "sport", "dport", "protocol", "length", "info"}

    def total(**p):
        return client.get(url, params=p).json()["total"]

    assert total(protocol="dns") == 2 and total(protocol="http") == 2 and total(protocol="tls") == 3
    assert total(protocol="arp") == 1 and total(protocol="icmp") == 1 and total(protocol="udp") == 2
    assert total(protocol="tcp") == 9 and total(protocol="dns,arp") == 3
    assert total(ip=SERVER) == 10 and total(ip="203.0.113.99") == 0
    assert total(ip=DNS_SRV) == 3  # DNS query + response + the ARP request that targets it and total(port=443) == 3 and total(port=21) == 2
    assert total(q="secure.example.com") == 1 and total(q="POST /login") == 1 and total(q="nomatch") == 0
    assert total(min_size=100) < total() and total(max_size=10) == 0
    page = client.get(url, params={"offset": 5, "limit": 3}).json()
    assert [p["n"] for p in page["items"]] == [6, 7, 8] and page["total"] == 13
    assert client.get(url, params={"limit": 501}).status_code == 422


def test_packet_detail_layers_and_hex_with_redaction(client, project):
    cap = analyze(client, project)
    url = f"/api/packet-captures/{cap['id']}/packets"
    http = client.get(url, params={"protocol": "http"}).json()["items"][0]
    d = client.get(f"{url}/{http['n']}").json()
    names = [layer["name"] for layer in d["layers"]]
    assert names == [f"Frame {http['n']}", "Ethernet II", "Internet Protocol Version 4",
                     "Transmission Control Protocol", "Hypertext Transfer Protocol"]
    fields = dict(map(tuple, d["layers"][-1]["fields"]))
    assert fields["Start line"] == "POST /login HTTP/1.1" and fields["Authorization"] == "Basic [redacted]"
    assert d["hex"][0].startswith("0000  ") and d["source"] == CLIENT and d["info"] == "POST /login HTTP/1.1"
    tls = client.get(f"{url}/{client.get(url, params={'protocol': 'tls'}).json()['items'][0]['n']}").json()
    assert dict(map(tuple, tls["layers"][-1]["fields"]))["SNI"] == "secure.example.com"
    assert client.get(f"{url}/999").status_code == 404 and client.get(f"{url}/0").status_code == 404


def test_export_filtered_pcap_roundtrips(client, project, tmp_path):
    cap = analyze(client, project)
    r = client.get(f"/api/packet-captures/{cap['id']}/export", params={"protocol": "dns"})
    assert r.status_code == 200 and r.content[:4] == b"\xd4\xc3\xb2\xa1"
    out = tmp_path / "e.pcap"
    out.write_bytes(r.content)
    pkts = list(read_packets(out))
    assert len(pkts) == 2 and all(dissect(p).protocol == "DNS" for p in pkts)
    assert client.get(f"/api/packet-captures/{cap['id']}/export", params={"q": "nomatch"}).status_code == 404


def test_pcapng_upload_and_detail(client, project):
    frames = [(1700000000 + i, T(g.http_request(), 4000 + i, 80)) for i in range(3)]
    cap = analyze(client, project, g.pcapng_bytes(frames))
    assert cap["packet_count"] == 3 and cap["summary"]["format"] == "pcapng"
    d = client.get(f"/api/packet-captures/{cap['id']}/packets/2").json()
    assert d["info"] == "GET / HTTP/1.1" and d["layers"][-1]["name"] == "Hypertext Transfer Protocol"
    assert client.get(f"/api/packet-captures/{cap['id']}/export").status_code == 200


def test_corrupt_capture_fails_cleanly(client, project):
    evil = g.pcap_bytes([]) + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
    r = upload(client, project, evil)
    assert r.status_code == 202
    process_one("w")
    scan = client.get(f"/api/scans/{r.json()['scan_id']}").json()
    assert scan["status"] == "failed" and "oversized" in scan["error"]


def test_delete_removes_files_and_access_is_controlled(client, make_client, project):
    cap = analyze(client, project)
    uploads = get_settings().uploads_dir / "captures"
    assert len(list(uploads.glob("*"))) == 2  # capture + index
    other = make_client("o@example.com")
    assert other.get(f"/api/packet-captures/{cap['id']}").status_code == 404
    assert other.get(f"/api/packet-captures/{cap['id']}/packets").status_code == 404
    assert other.delete(f"/api/packet-captures/{cap['id']}").status_code == 404
    client.post(f"/api/projects/{project['id']}/members", json={"email": "o@example.com", "role": "viewer"})
    assert other.get(f"/api/packet-captures/{cap['id']}/packets").status_code == 200
    assert other.delete(f"/api/packet-captures/{cap['id']}").status_code == 403
    assert upload(other, project, sample_capture()).status_code == 403
    assert client.delete(f"/api/packet-captures/{cap['id']}").status_code == 204
    assert list(uploads.glob("*")) == []
    assert client.get(f"/api/packet-captures/{cap['id']}").status_code == 404
    assert client.get(f"/api/projects/{project['id']}/packet-captures").json() == []


def test_capture_list_and_audit_log(client, project):
    from netguard.db import get_session_factory
    from netguard.models import AuditLog

    cap = analyze(client, project)
    listing = client.get(f"/api/projects/{project['id']}/packet-captures").json()
    assert [c["id"] for c in listing] == [cap["id"]] and listing[0]["summary"] == {}  # list stays light
    assert listing[0]["filename"] == "lab.pcap" and listing[0]["sha256"] == cap["sha256"]
    with get_session_factory()() as db:
        entry = db.query(AuditLog).filter(AuditLog.action == "packets.import").one()
        assert entry.details["authorized"] is True and entry.target_id == cap["id"]
