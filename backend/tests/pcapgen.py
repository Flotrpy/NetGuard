"""Build synthetic packets and capture files for tests (no real traffic involved)."""

from __future__ import annotations

import ipaddress
import struct


def macb(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def eth(payload: bytes, src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb", etype=0x0800) -> bytes:
    return macb(dst) + macb(src) + struct.pack("!H", etype) + payload


def ipv4(payload: bytes, src="10.0.0.1", dst="10.0.0.2", proto=6, ttl=64) -> bytes:
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, ttl, proto, 0,
                       ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed) + payload


def ipv6(payload: bytes, src="fd00::1", dst="fd00::2", nxt=6) -> bytes:
    return (struct.pack("!IHBB", 0x60000000, len(payload), nxt, 64)
            + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload)


def tcp(sport, dport, flags=0x18, payload=b"", seq=1000, ack=2000, win=8192) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, win, 0, 0) + payload


def udp(sport, dport, payload=b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(reply=False) -> bytes:
    return struct.pack("!BBHHH", 0 if reply else 8, 0, 0, 1, 1) + b"abcd"


def arp(op, smac, sip, tmac, tip) -> bytes:
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + macb(smac) + ipaddress.IPv4Address(sip).packed
            + macb(tmac) + ipaddress.IPv4Address(tip).packed)


def _name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(name: str, qtype=1, tid=0x1234) -> bytes:
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _name(name) + struct.pack("!HH", qtype, 1)


def dns_response(name: str, ip: str, tid=0x1234, rcode=0) -> bytes:
    answers = 0 if rcode else 1
    head = struct.pack("!HHHHHH", tid, 0x8180 | rcode, 1, answers, 0, 0)
    body = _name(name) + struct.pack("!HH", 1, 1)
    if answers:  # answer uses a compression pointer back to the question name (offset 12)
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(ip).packed
    return head + body


def http_request(host="example.com", path="/", method="GET", headers=None, body=b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "User-Agent: test/1.0"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status="200 OK", server="nginx/1.18.0") -> bytes:
    return f"HTTP/1.1 {status}\r\nServer: {server}\r\nContent-Type: text/html\r\n\r\n<html>".encode()


def tls_client_hello(sni="example.com", record_version=0x0301, hello_version=0x0303, supported=None) -> bytes:
    host = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(host) + 5, len(host) + 3, 0, len(host)) + host
    exts = sni_ext
    if supported:
        body = bytes([len(supported) * 2]) + b"".join(struct.pack("!H", v) for v in supported)
        exts += struct.pack("!HH", 43, len(body)) + body
    ciphers = struct.pack("!HH", 2, 0x1301)
    hello = (struct.pack("!H", hello_version) + b"\x11" * 32 + b"\x00" + ciphers + b"\x01\x00"
             + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16" + struct.pack("!HH", record_version, len(hs)) + hs


def tls_server_hello(version=0x0303, supported=None) -> bytes:
    exts = b""
    if supported:
        exts = struct.pack("!HHH", 43, 2, supported)
    hello = (struct.pack("!H", version) + b"\x22" * 32 + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
             + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + len(hello).to_bytes(3, "big") + hello
    return b"\x16" + struct.pack("!HH", 0x0303, len(hs)) + hs


def tls_app_data(n=32) -> bytes:
    return b"\x17" + struct.pack("!HH", 0x0303, n) + b"\x00" * n


def pcap_bytes(frames: list[tuple[float, bytes]], linktype=1, big_endian=False, nano=False) -> bytes:
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(f"{e}IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for ts, frame in frames:
        sec = int(ts)
        frac = int(round((ts - sec) * (1_000_000_000 if nano else 1_000_000)))
        out += struct.pack(f"{e}IIII", sec, frac, len(frame), len(frame)) + frame
    return out


def pcapng_bytes(frames: list[tuple[float, bytes]], linktype=1, tsresol=6) -> bytes:
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack("<HHB3x", 9, 1, tsresol) + struct.pack("<HH", 0, 0)
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535) + opt)
    out = shb + idb
    scale = 10 ** tsresol
    for ts, frame in frames:
        ticks = int(round(ts * scale))
        out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out
