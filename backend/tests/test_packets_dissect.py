import struct

import pytest

from netguard.scanners.packets import dissect as dz
from netguard.scanners.packets import pcap
from netguard.scanners.packets.pcap import PcapError, RawPacket, read_packets
from tests import pcapgen as g


def d(frame, linktype=1):
    return dz.dissect(RawPacket(1, 1.0, len(frame), frame, linktype))


def tcp_frame(payload=b"", sport=51000, dport=80, flags=0x18, **kw):
    return g.eth(g.ipv4(g.tcp(sport, dport, flags, payload), **kw))


# ---- readers -----------------------------------------------------------------------------------
FRAMES = [(1700000000.25, tcp_frame()), (1700000001.5, g.eth(g.ipv4(g.udp(5000, 53, g.dns_query("a.example")), proto=17)))]


@pytest.mark.parametrize("kwargs", [{}, {"big_endian": True}, {"nano": True}])
def test_pcap_variants_roundtrip(tmp_path, kwargs):
    p = tmp_path / "a.pcap"
    p.write_bytes(g.pcap_bytes(FRAMES, **kwargs))
    pkts = list(read_packets(p))
    assert [x.index for x in pkts] == [1, 2] and pkts[0].data == FRAMES[0][1]
    assert abs(pkts[0].timestamp - 1700000000.25) < 1e-3 and abs(pkts[1].timestamp - 1700000001.5) < 1e-3
    assert pkts[0].offset == 24 and pkts[0].linktype == 1


def test_pcapng_roundtrip_with_resolution(tmp_path):
    p = tmp_path / "a.pcapng"
    p.write_bytes(g.pcapng_bytes(FRAMES, tsresol=9))
    pkts = list(read_packets(p))
    assert len(pkts) == 2 and pkts[1].data == FRAMES[1][1]
    assert abs(pkts[1].timestamp - 1700000001.5) < 1e-6


def test_truncated_tail_is_tolerated_and_garbage_rejected(tmp_path):
    raw = g.pcap_bytes(FRAMES)
    p = tmp_path / "t.pcap"
    p.write_bytes(raw[:-10])
    assert len(list(read_packets(p))) == 1  # second packet cut off: first is still returned
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture")
    with pytest.raises(PcapError):
        list(read_packets(bad))
    tiny = tmp_path / "tiny.pcap"
    tiny.write_bytes(g.pcap_bytes([])[:10])
    with pytest.raises(PcapError):
        list(read_packets(tiny))


def test_oversized_record_and_unsupported_linktype_and_packet_cap(tmp_path):
    hdr = g.pcap_bytes([])
    evil = tmp_path / "evil.pcap"
    evil.write_bytes(hdr + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF))
    with pytest.raises(PcapError, match="oversized"):
        list(read_packets(evil))
    odd = tmp_path / "odd.pcap"
    odd.write_bytes(g.pcap_bytes([], linktype=228))
    with pytest.raises(PcapError, match="link type"):
        list(read_packets(odd))
    many = tmp_path / "many.pcap"
    many.write_bytes(g.pcap_bytes([(1.0, tcp_frame())] * 50))
    assert len(list(read_packets(many, max_packets=10))) == 10


def test_write_and_read_at(tmp_path):
    src = tmp_path / "s.pcap"
    src.write_bytes(g.pcap_bytes(FRAMES))
    pkts = list(read_packets(src))
    out = tmp_path / "o.pcap"
    pcap.write_pcap(out, [pkts[1]])
    again = list(read_packets(out))
    assert len(again) == 1 and again[0].data == pkts[1].data
    assert pcap.read_at(src, pkts[1].offset, "pcap").data == pkts[1].data
    ng = tmp_path / "s.pcapng"
    ng.write_bytes(g.pcapng_bytes(FRAMES))
    ng_pkts = list(read_packets(ng))
    assert pcap.read_at(ng, ng_pkts[1].offset, "pcapng").data == ng_pkts[1].data


# ---- dissectors -------------------------------------------------------------------------------
def test_ethernet_ipv4_tcp_syn_summary():
    r = d(tcp_frame(flags=0x02, sport=40000, dport=443, src="192.168.1.5", dst="93.184.216.34"))
    assert (r.protocol, r.src, r.dst, r.sport, r.dport) == ("TCP", "192.168.1.5", "93.184.216.34", 40000, 443)
    assert "[SYN]" in r.info and "40000 → 443" in r.info and r.chain == ["eth", "ipv4", "tcp"]
    assert [l.name for l in r.layers] == ["Ethernet II", "Internet Protocol Version 4", "Transmission Control Protocol"]
    tcp_layer = r.layers[-1]
    assert ("Flags", "0x002 (SYN)") in tcp_layer.fields


def test_udp_dns_query_and_response_with_compression():
    q = d(g.eth(g.ipv4(g.udp(5353 + 1, 53, g.dns_query("www.example.com", 28)), proto=17)))
    assert q.protocol == "DNS" and q.info == "Standard query 0x1234 AAAA www.example.com"
    assert q.meta["dns_qnames"] == ["www.example.com"] and q.chain[-2:] == ["udp", "dns"]
    r = d(g.eth(g.ipv4(g.udp(53, 5000, g.dns_response("www.example.com", "93.184.216.34")), proto=17)))
    assert "response" in r.info and "A 93.184.216.34" in r.info and r.meta["dns_response"]
    nx = d(g.eth(g.ipv4(g.udp(53, 5000, g.dns_response("nope.example", "0.0.0.0", rcode=3)), proto=17)))
    assert "(rcode 3)" in nx.info


def test_dns_pointer_loop_and_garbage_do_not_hang_or_crash():
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    r = d(g.eth(g.ipv4(g.udp(5000, 53, loop), proto=17)))
    assert r.protocol == "Malformed" or r.protocol == "UDP"  # loop guarded either way


def test_http_request_and_response_and_credentials_are_never_captured():
    req = d(tcp_frame(g.http_request("shop.test", "/login", "POST", {"Authorization": "Basic dXNlcjpzZWNyZXQ="},
                                     b"user=a&password=hunter2")))
    assert req.protocol == "HTTP" and req.info == "POST /login HTTP/1.1"
    assert req.meta["http_host"] == "shop.test" and req.meta["http_auth_scheme"] == "Basic"
    assert req.meta["http_password_field"] is True
    text = repr(req)
    assert "dXNlcjpzZWNyZXQ=" not in text and "hunter2" not in text  # secrets never retained
    resp = d(tcp_frame(g.http_response("404 Not Found"), sport=80, dport=51000))
    assert resp.info == "HTTP/1.1 404 Not Found" and resp.meta["http_status"] == 404


def test_tls_client_hello_sni_and_versions():
    ch = d(tcp_frame(g.tls_client_hello("secure.example.org", supported=[0x0304, 0x0303]), dport=443))
    assert ch.protocol == "TLS" and ch.meta["tls_sni"] == "secure.example.org" and ch.meta["tls_version"] == "TLSv1.3"
    assert ch.info == "Client Hello (SNI=secure.example.org), TLSv1.3"
    old = d(tcp_frame(g.tls_client_hello("old.example", record_version=0x0301, hello_version=0x0301), dport=443))
    assert old.meta["tls_version"] == "TLSv1.0"
    sh = d(tcp_frame(g.tls_server_hello(0x0303, supported=0x0304), sport=443, dport=51000))
    assert sh.info.startswith("Server Hello") and sh.meta["tls_version"] == "TLSv1.3"
    assert d(tcp_frame(g.tls_app_data(), dport=443)).info == "Application Data"


def test_arp_request_and_reply():
    req = d(g.eth(g.arp(1, "00:11:22:33:44:55", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.9"), etype=0x0806))
    assert req.protocol == "ARP" and req.info == "Who has 10.0.0.9? Tell 10.0.0.1"
    rep = d(g.eth(g.arp(2, "aa:bb:cc:dd:ee:ff", "10.0.0.9", "00:11:22:33:44:55", "10.0.0.1"), etype=0x0806))
    assert rep.info == "10.0.0.9 is at aa:bb:cc:dd:ee:ff" and rep.meta["arp_sender_ip"] == "10.0.0.9"


def test_icmp_ipv6_and_vlan_and_fragments():
    ping = d(g.eth(g.ipv4(g.icmp_echo(), proto=1)))
    assert ping.protocol == "ICMP" and "Echo request" in ping.info
    v6 = d(g.eth(g.ipv6(g.tcp(1234, 80, 0x02)), etype=0x86DD))
    assert v6.protocol == "TCP" and v6.src == "fd00::1" and v6.chain[1] == "ipv6"
    vlan = g.eth(b"\x00\x0a\x08\x00" + g.ipv4(g.udp(1, 2), proto=17), etype=0x8100)
    assert d(vlan).protocol == "UDP"
    frag = bytearray(g.ipv4(g.udp(1, 2), proto=17))
    frag[6:8] = struct.pack("!H", 0x00B9)
    assert "Fragmented" in d(g.eth(bytes(frag))).info


def test_cleartext_protocols_flag_but_never_keep_passwords():
    ftp_user = d(tcp_frame(b"USER alice\r\n", dport=21))
    ftp_pass = d(tcp_frame(b"PASS supersecret\r\n", dport=21))
    assert ftp_user.protocol == "FTP" and ftp_user.meta["ftp_user_sent"]
    assert ftp_pass.info == "PASS ********" and ftp_pass.meta["ftp_password_sent"]
    assert "supersecret" not in repr(ftp_pass)
    tel = d(tcp_frame(b"\xff\xfd\x18login:", dport=23))
    assert tel.protocol == "Telnet" and tel.meta["cleartext_protocol"] == "telnet"


def test_other_link_types():
    ip = g.ipv4(g.tcp(1, 2, 0x02))
    assert d(ip, linktype=101).protocol == "TCP"  # raw IP
    assert d(struct.pack("<I", 2) + ip, linktype=0).protocol == "TCP"  # loopback
    sll = b"\x00\x00\x00\x01\x00\x06" + b"\x00" * 8 + struct.pack("!H", 0x0800) + ip
    assert d(sll, linktype=113).protocol == "TCP"


@pytest.mark.parametrize("junk", [b"", b"\x00" * 5, b"\xff" * 60, bytes(range(256)), b"\x45" * 40])
def test_dissector_never_raises_on_garbage(junk):
    for lt in (1, 0, 101, 113):
        r = dz.dissect(RawPacket(1, 0.0, len(junk), junk, lt))
        assert r.protocol  # always returns *something*


def test_random_fuzz_is_safe():
    import random

    rng = random.Random(7)
    base = tcp_frame(g.http_request())
    for _ in range(300):
        buf = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        dz.dissect(RawPacket(1, 0.0, len(buf), bytes(buf[:rng.randint(1, len(buf))]), 1))


def test_hexdump_and_protocol_filters():
    lines = dz.hexdump(b"ABC\x00\xff" + b"x" * 20)
    assert lines[0].startswith("0000  41 42 43 00 ff") and lines[0].endswith("ABC..xxxxxxxxxxx")
    assert len(lines) == 2
    chain = ["eth", "ipv4", "tcp", "tls"]
    assert dz.matches_protocol(chain, "TCP") and dz.matches_protocol(chain, "https")
    assert not dz.matches_protocol(chain, "udp") and not dz.matches_protocol(chain, "bogus")
