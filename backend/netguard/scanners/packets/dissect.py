"""Protocol dissectors: Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS, HTTP, TLS, FTP, Telnet.

Design rules: never raise on malformed data (return a partial/“Malformed” result), never
follow unbounded loops (DNS compression pointers are capped), never keep payload bytes beyond
what is needed for headers, and never store credentials: secrets seen in cleartext protocols are
recorded only as *presence flags* in ``meta``.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

from netguard.scanners.packets.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_NULL,
    RawPacket,
)

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ",
                b"CONNECT ", b"TRACE ")
FTP_VERBS = (b"USER ", b"PASS ", b"RETR ", b"STOR ", b"LIST", b"CWD ", b"QUIT", b"PASV", b"PORT ",
             b"SYST", b"TYPE ", b"AUTH ")
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 65: "HTTPS", 255: "ANY"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 8: "Echo request",
              11: "Time exceeded", 5: "Redirect"}
ICMP6_TYPES = {1: "Destination unreachable", 3: "Time exceeded", 128: "Echo request",
               129: "Echo reply", 133: "Router solicitation", 134: "Router advertisement",
               135: "Neighbor solicitation", 136: "Neighbor advertisement"}
TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2",
                0x0304: "TLSv1.3"}
TLS_HANDSHAKE = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
                 11: "Certificate", 12: "Server Key Exchange", 14: "Server Hello Done",
                 16: "Client Key Exchange", 20: "Finished"}
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"),
             (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


@dataclass
class Layer:
    name: str
    fields: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Decoded:
    protocol: str = "Unknown"
    src: str = ""
    dst: str = ""
    sport: int | None = None
    dport: int | None = None
    info: str = ""
    length: int = 0
    chain: list[str] = field(default_factory=list)  # e.g. ["eth", "ipv4", "tcp", "http"]
    layers: list[Layer] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _tcp_flags(flags: int) -> str:
    return ", ".join(n for bit, n in TCP_FLAGS if flags & bit) or "none"


# ---- link layer ------------------------------------------------------------------------------
def dissect(pkt: RawPacket) -> Decoded:
    d = Decoded(length=pkt.orig_len)
    try:
        _link(pkt, d)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        d.protocol = "Malformed"
        d.info = d.info or "Malformed or truncated packet"
        d.meta["malformed"] = True
    return d


def _link(pkt: RawPacket, d: Decoded) -> None:
    data, lt = pkt.data, pkt.linktype
    if lt == LINKTYPE_ETHERNET:
        if len(data) < 14:
            raise ValueError("short ethernet")
        d.chain.append("eth")
        dst, src, etype = data[:6], data[6:12], struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        d.src, d.dst = mac(src), mac(dst)
        d.protocol, d.info = "Ethernet", f"Ethertype 0x{etype:04x}"
        d.layers.append(Layer("Ethernet II", [("Destination", d.dst), ("Source", d.src),
                                              ("Type", f"0x{etype:04x}")]))
        _network(etype, data[off:], d)
    elif lt == LINKTYPE_LINUX_SLL:
        etype = struct.unpack("!H", data[14:16])[0]
        d.chain.append("sll")
        _network(etype, data[16:], d)
    elif lt == LINKTYPE_NULL or lt == 108:
        family = struct.unpack("<I", data[:4])[0]
        _network(0x0800 if family == 2 else 0x86DD, data[4:], d)
    else:  # raw IP
        _network(0x0800 if data[:1] and data[0] >> 4 == 4 else 0x86DD, data, d)


def _network(etype: int, data: bytes, d: Decoded) -> None:
    if etype == 0x0806:
        _arp(data, d)
    elif etype == 0x0800:
        _ipv4(data, d)
    elif etype == 0x86DD:
        _ipv6(data, d)


def _arp(data: bytes, d: Decoded) -> None:
    hw, proto, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
    sha, spa = data[8:8 + hlen], data[8 + hlen:8 + hlen + plen]
    tha, tpa = data[8 + hlen + plen:8 + 2 * hlen + plen], data[8 + 2 * hlen + plen:8 + 2 * hlen + 2 * plen]
    smac, sip, tip = mac(sha), str(ipaddress.ip_address(spa)), str(ipaddress.ip_address(tpa))
    d.chain.append("arp")
    d.protocol, d.src, d.dst = "ARP", smac, "ff:ff:ff:ff:ff:ff" if op == 1 else mac(tha)
    d.info = f"Who has {tip}? Tell {sip}" if op == 1 else f"{sip} is at {smac}"
    d.meta.update(arp_op=op, arp_sender_mac=smac, arp_sender_ip=sip, arp_target_ip=tip)
    d.layers.append(Layer("Address Resolution Protocol", [
        ("Opcode", "request (1)" if op == 1 else "reply (2)" if op == 2 else str(op)),
        ("Sender MAC", smac), ("Sender IP", sip), ("Target MAC", mac(tha)), ("Target IP", tip)]))


def _ipv4(data: bytes, d: Decoded) -> None:
    vihl, tos, tlen, ident, frag, ttl, proto = struct.unpack("!BBHHHBB", data[:10])
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20 or len(data) < ihl:
        raise ValueError("bad ipv4")
    src, dst = str(ipaddress.IPv4Address(data[12:16])), str(ipaddress.IPv4Address(data[16:20]))
    d.chain.append("ipv4")
    d.src, d.dst, d.protocol = src, dst, "IPv4"
    d.layers.append(Layer("Internet Protocol Version 4", [
        ("Source", src), ("Destination", dst), ("TTL", str(ttl)), ("Protocol", str(proto)),
        ("Total length", str(tlen)), ("Identification", f"0x{ident:04x}"),
        ("Flags/Fragment", f"0x{frag:04x}")]))
    end = min(len(data), tlen) if tlen >= ihl else len(data)
    if frag & 0x1FFF:
        d.info = f"Fragmented IP protocol (proto={proto}, offset={(frag & 0x1FFF) * 8})"
        return
    _transport(proto, data[ihl:end], d)


def _ipv6(data: bytes, d: Decoded) -> None:
    if len(data) < 40 or data[0] >> 4 != 6:
        raise ValueError("bad ipv6")
    plen, nxt, hop = struct.unpack("!HBB", data[4:8])
    src, dst = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
    d.chain.append("ipv6")
    d.src, d.dst, d.protocol = src, dst, "IPv6"
    d.layers.append(Layer("Internet Protocol Version 6", [
        ("Source", src), ("Destination", dst), ("Hop limit", str(hop)), ("Next header", str(nxt))]))
    off = 40
    for _ in range(8):  # skip extension headers (hop-by-hop, routing, destination options)
        if nxt in (0, 43, 60) and len(data) >= off + 8:
            nxt, ext_len = data[off], data[off + 1]
            off += 8 + ext_len * 8
        else:
            break
    _transport(nxt, data[off:40 + plen if plen else len(data)], d)


def _transport(proto: int, data: bytes, d: Decoded) -> None:
    if proto == 1:
        _icmp(data, d, v6=False)
    elif proto == 58:
        _icmp(data, d, v6=True)
    elif proto == 6:
        _tcp(data, d)
    elif proto == 17:
        _udp(data, d)
    else:
        d.info = f"IP protocol {proto}"


def _icmp(data: bytes, d: Decoded, v6: bool) -> None:
    t, code = data[0], data[1]
    names = ICMP6_TYPES if v6 else ICMP_TYPES
    d.chain.append("icmpv6" if v6 else "icmp")
    d.protocol = "ICMPv6" if v6 else "ICMP"
    d.info = f"{names.get(t, f'Type {t}')} (type={t}, code={code})"
    d.layers.append(Layer("ICMPv6" if v6 else "Internet Control Message Protocol",
                          [("Type", f"{names.get(t, t)} ({t})"), ("Code", str(code))]))


def _tcp(data: bytes, d: Decoded) -> None:
    sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", data[:16])
    hlen = (off_flags >> 12) * 4
    if hlen < 20 or len(data) < hlen:
        raise ValueError("bad tcp")
    flags = off_flags & 0xFF
    payload = data[hlen:]
    d.chain.append("tcp")
    d.sport, d.dport, d.protocol = sport, dport, "TCP"
    d.meta.update(tcp_flags=flags, seq=seq, ack=ack, payload_len=len(payload))
    d.info = (f"{sport} → {dport} [{_tcp_flags(flags)}] Seq={seq} Ack={ack} Win={win} "
              f"Len={len(payload)}")
    d.layers.append(Layer("Transmission Control Protocol", [
        ("Source port", str(sport)), ("Destination port", str(dport)), ("Sequence", str(seq)),
        ("Acknowledgment", str(ack)), ("Flags", f"0x{flags:03x} ({_tcp_flags(flags)})"),
        ("Window", str(win)), ("Header length", f"{hlen} bytes"), ("Payload", f"{len(payload)} bytes")]))
    if payload:
        _tcp_payload(sport, dport, payload, d)


def _udp(data: bytes, d: Decoded) -> None:
    sport, dport, length = struct.unpack("!HHH", data[:6])
    payload = data[8:]
    d.chain.append("udp")
    d.sport, d.dport, d.protocol = sport, dport, "UDP"
    d.info = f"{sport} → {dport} Len={max(length - 8, 0)}"
    d.layers.append(Layer("User Datagram Protocol", [
        ("Source port", str(sport)), ("Destination port", str(dport)), ("Length", str(length))]))
    d.meta["payload_len"] = len(payload)
    if 53 in (sport, dport) or 5353 in (sport, dport):
        _dns(payload, d)
    elif {sport, dport} & {67, 68}:
        d.chain.append("dhcp")
        d.protocol, d.info = "DHCP", "DHCP message"
    elif 123 in (sport, dport):
        d.chain.append("ntp")
        d.protocol, d.info = "NTP", "NTP message"
    elif 1900 in (sport, dport):
        d.chain.append("ssdp")
        d.protocol, d.info = "SSDP", payload.split(b"\r\n", 1)[0].decode("ascii", "replace")[:80]
    elif 443 in (sport, dport) and payload and payload[0] & 0x80:
        d.chain.append("quic")
        d.protocol, d.info = "QUIC", "QUIC long-header packet"


# ---- application layer -----------------------------------------------------------------------
def _dns_name(data: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(data):
            raise ValueError("dns name overrun")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            hops += 1
            if hops > 16:  # compression-pointer loop guard
                raise ValueError("dns pointer loop")
            continue
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def _dns(data: bytes, d: Decoded) -> None:
    tid, flags, qd, an = struct.unpack("!HHHH", data[:8])
    is_response, rcode = bool(flags & 0x8000), flags & 0x0F
    off, questions, answers = 12, [], []
    for _ in range(min(qd, 10)):
        name, off = _dns_name(data, off)
        qtype = struct.unpack("!H", data[off:off + 2])[0]
        off += 4
        questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
    if is_response:
        for _ in range(min(an, 20)):
            _, off = _dns_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            rdata = data[off + 10:off + 10 + rdlen]
            if rtype == 1 and rdlen == 4:
                answers.append(f"A {ipaddress.IPv4Address(rdata)}")
            elif rtype == 28 and rdlen == 16:
                answers.append(f"AAAA {ipaddress.IPv6Address(rdata)}")
            elif rtype in (2, 5, 12):
                answers.append(f"{DNS_TYPES.get(rtype)} {_dns_name(data, off + 10)[0]}")
            else:
                answers.append(DNS_TYPES.get(rtype, str(rtype)))
            off += 10 + rdlen
    d.chain.append("dns")
    d.protocol = "DNS"
    qtext = ", ".join(f"{t} {n}" for n, t in questions)
    d.info = (f"Standard query response 0x{tid:04x} {qtext}" + (f" {'; '.join(answers)}" if answers else "")
              + (f" (rcode {rcode})" if rcode else "")) if is_response else \
        f"Standard query 0x{tid:04x} {qtext}"
    d.meta.update(dns_qnames=[n for n, _ in questions], dns_response=is_response, dns_rcode=rcode)
    d.layers.append(Layer("Domain Name System", [
        ("Transaction ID", f"0x{tid:04x}"), ("Type", "response" if is_response else "query"),
        ("Response code", str(rcode)), ("Questions", qtext or "-"), ("Answers", "; ".join(answers) or "-")]))


def _tcp_payload(sport: int, dport: int, payload: bytes, d: Decoded) -> None:
    ports = {sport, dport}
    if payload[:4] == b"HTTP" or payload.startswith(HTTP_METHODS):
        _http(payload, d)
    elif payload[0] in (0x14, 0x15, 0x16, 0x17) and len(payload) >= 5 and payload[1] == 3:
        _tls(payload, d)
    elif 21 in ports and payload.startswith(FTP_VERBS + (b"220", b"230", b"331", b"530", b"227")):
        _ftp(payload, d)
    elif 23 in ports:
        d.chain.append("telnet")
        d.protocol, d.info = "Telnet", f"Telnet data ({len(payload)} bytes)"
        d.meta["cleartext_protocol"] = "telnet"


def _http(payload: bytes, d: Decoded) -> None:
    head = payload.split(b"\r\n\r\n", 1)[0][:8192].decode("latin-1")
    lines = head.split("\r\n")
    first = lines[0][:200]
    headers = {}
    for line in lines[1:40]:
        k, _, v = line.partition(":")
        if v:
            headers[k.strip().lower()] = v.strip()
    d.chain.append("http")
    d.protocol, d.info = "HTTP", first
    is_req = not first.startswith("HTTP/")
    d.meta.update(http_request=is_req, http_host=headers.get("host", "")[:200])
    if is_req:
        parts = first.split(" ")
        d.meta["http_method"] = parts[0]
        d.meta["http_uri"] = parts[1][:300] if len(parts) > 1 else ""
        auth = headers.get("authorization", "")
        if auth:  # record the scheme only, never the credential
            d.meta["http_auth_scheme"] = auth.split(" ", 1)[0][:20]
        body = payload.split(b"\r\n\r\n", 1)[1][:2000] if b"\r\n\r\n" in payload else b""
        if b"password=" in body.lower() or b"passwd=" in body.lower() or b'"password"' in body.lower():
            d.meta["http_password_field"] = True
    else:
        parts = first.split(" ", 2)
        d.meta["http_status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    d.layers.append(Layer("Hypertext Transfer Protocol", [
        ("Start line", first), ("Host", headers.get("host", "-")),
        ("User-Agent", headers.get("user-agent", "-")[:120]),
        ("Content-Type", headers.get("content-type", "-")),
        ("Authorization", f"{d.meta.get('http_auth_scheme')} [redacted]" if d.meta.get("http_auth_scheme") else "-")]))


def _tls(payload: bytes, d: Decoded) -> None:
    ctype, ver, rlen = payload[0], struct.unpack("!H", payload[1:3])[0], struct.unpack("!H", payload[3:5])[0]
    record = payload[5:5 + rlen]
    d.chain.append("tls")
    version = TLS_VERSIONS.get(ver, f"0x{ver:04x}")
    d.protocol = "TLS"
    fields = [("Record version", version), ("Record length", str(rlen))]
    if ctype == 22 and record:
        htype = record[0]
        name = TLS_HANDSHAKE.get(htype, f"Handshake {htype}")
        d.info = name
        d.meta["tls_handshake"] = htype
        if htype in (1, 2) and len(record) > 38:
            chosen = struct.unpack("!H", record[4:6])[0]
            sni, alpn, supported = _tls_extensions(record, client=(htype == 1))
            negotiated = TLS_VERSIONS.get(supported or chosen, version)
            d.meta.update(tls_version=negotiated, tls_sni=sni)
            fields += [("Handshake", name), ("Version", negotiated)] + ([("SNI", sni)] if sni else [])
            d.info = f"{name}" + (f" (SNI={sni})" if sni else "") + f", {negotiated}"
    elif ctype == 23:
        d.info = "Application Data"
    elif ctype == 21:
        d.info = "Encrypted Alert" if rlen > 2 else "Alert"
    else:
        d.info = "Change Cipher Spec"
    d.layers.append(Layer("Transport Layer Security", fields))


def _tls_extensions(hs: bytes, client: bool) -> tuple[str, str, int | None]:
    off = 38  # type(1)+len(3)+version(2)+random(32)
    sid = hs[off]
    off += 1 + sid
    if client:
        off += 2 + struct.unpack("!H", hs[off:off + 2])[0]
        off += 1 + hs[off]
    else:
        off += 3  # cipher suite (2) + compression (1)
    if off + 2 > len(hs):
        return "", "", None
    ext_end = min(len(hs), off + 2 + struct.unpack("!H", hs[off:off + 2])[0])
    off += 2
    sni, alpn, supported = "", "", None
    while off + 4 <= ext_end:
        etype, elen = struct.unpack("!HH", hs[off:off + 4])
        body = hs[off + 4:off + 4 + elen]
        if etype == 0 and len(body) > 5:  # server_name
            nlen = struct.unpack("!H", body[3:5])[0]
            sni = body[5:5 + nlen].decode("ascii", "replace")[:255]
        elif etype == 43 and body:  # supported_versions
            if client:
                versions = [struct.unpack("!H", body[i:i + 2])[0] for i in range(1, len(body) - 1, 2)]
                supported = max((v for v in versions if v in TLS_VERSIONS), default=None)
            else:
                supported = struct.unpack("!H", body[:2])[0]
        elif etype == 16 and len(body) > 3:
            alpn = body[3:3 + body[2]].decode("ascii", "replace")
        off += 4 + elen
    return sni, alpn, supported


def _ftp(payload: bytes, d: Decoded) -> None:
    line = payload.split(b"\r\n", 1)[0].decode("ascii", "replace")[:100]
    verb = line.split(" ", 1)[0].upper()
    d.chain.append("ftp")
    d.protocol = "FTP"
    d.meta["cleartext_protocol"] = "ftp"
    if verb == "PASS":
        d.meta["ftp_password_sent"] = True
        line = "PASS ********"  # never keep the password
    elif verb == "USER":
        d.meta["ftp_user_sent"] = True
    d.info = line


def hexdump(data: bytes, width: int = 16, limit: int = 1024) -> list[str]:
    lines = []
    for i in range(0, min(len(data), limit), width):
        chunk = data[i:i + width]
        hexes = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexes}  {text}")
    return lines


FILTER_CHAIN = {"tcp": "tcp", "udp": "udp", "dns": "dns", "http": "http", "tls": "tls",
                "https": "tls", "ssl": "tls", "arp": "arp", "icmp": "icmp", "icmpv6": "icmpv6",
                "ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6", "ftp": "ftp", "telnet": "telnet",
                "dhcp": "dhcp", "quic": "quic", "ntp": "ntp", "ssdp": "ssdp"}


def matches_protocol(chain: list[str], name: str) -> bool:
    key = FILTER_CHAIN.get(name.lower())
    return key is not None and key in chain
