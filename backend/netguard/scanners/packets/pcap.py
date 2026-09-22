"""Readers and writer for classic pcap and pcapng capture files.

Captures are untrusted binary input: every length field is bounds-checked, packet counts and sizes
are capped, and malformed data raises :class:`PcapError` (or ends iteration cleanly for a
truncated tail) instead of crashing.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_PACKET_BYTES = 262144
LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL = 0, 1, 101, 113
SUPPORTED_LINKTYPES = {LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, 12, 108}

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


class PcapError(ValueError):
    pass


@dataclass
class RawPacket:
    index: int  # 1-based, in file order
    timestamp: float
    orig_len: int
    data: bytes
    linktype: int
    offset: int = 0  # file offset of the record (for on-demand re-reads)


def detect_format(head: bytes) -> str:
    if head[:4] in _PCAP_MAGICS:
        return "pcap"
    if head[:4] == _PCAPNG_SHB:
        return "pcapng"
    raise PcapError("Not a pcap or pcapng file")


def read_packets(path: Path, max_packets: int = 200_000) -> Iterator[RawPacket]:
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        fmt = detect_format(head)
        yield from (_read_pcap(fh, max_packets) if fmt == "pcap" else _read_pcapng(fh, max_packets))


def _read_pcap(fh, max_packets: int) -> Iterator[RawPacket]:
    header = fh.read(24)
    if len(header) < 24:
        raise PcapError("Truncated pcap header")
    endian, resolution = _PCAP_MAGICS[header[:4]]
    _, _, _, _, snaplen, linktype = struct.unpack(f"{endian}HHiIII", header[4:24])
    if linktype not in SUPPORTED_LINKTYPES:
        raise PcapError(f"Unsupported link type {linktype}")
    index = 0
    while index < max_packets:
        offset = fh.tell()
        rec = fh.read(16)
        if len(rec) < 16:
            return
        sec, frac, caplen, orig = struct.unpack(f"{endian}IIII", rec)
        if caplen > MAX_PACKET_BYTES:
            raise PcapError("Corrupt capture: oversized packet record")
        data = fh.read(caplen)
        if len(data) < caplen:
            return  # truncated final packet
        index += 1
        yield RawPacket(index, sec + frac * resolution, orig, data, linktype, offset)


def _read_pcapng(fh, max_packets: int) -> Iterator[RawPacket]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    index = 0
    while index < max_packets:
        offset = fh.tell()
        head = fh.read(8)
        if len(head) < 8:
            return
        btype_raw = head[:4]
        if btype_raw == _PCAPNG_SHB:
            magic = fh.read(4)
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("Bad pcapng byte-order magic")
            (blen,) = struct.unpack(f"{endian}I", head[4:8])
            if blen < 28 or blen > 1 << 20:
                raise PcapError("Corrupt pcapng section header")
            fh.read(blen - 12)
            interfaces = []
            continue
        btype, blen = struct.unpack(f"{endian}II", head)
        if blen < 12 or blen > MAX_PACKET_BYTES + 1024:
            raise PcapError("Corrupt pcapng block length")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(f"{endian}H", body[:2])[0]
            tick = 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(f"{endian}HH", opts[:4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    r = opts[4]
                    tick = 2.0 ** -(r & 0x7F) if r & 0x80 else 10.0 ** -r
                opts = opts[4 + ((olen + 3) & ~3):]
            interfaces.append((linktype, tick))
        elif btype == 6 and len(body) >= 20:  # Enhanced Packet Block
            iface, hi, lo, caplen, orig = struct.unpack(f"{endian}IIIII", body[:20])
            if iface >= len(interfaces) or caplen > len(body) - 20:
                continue
            linktype, tick = interfaces[iface]
            if linktype not in SUPPORTED_LINKTYPES:
                continue
            index += 1
            yield RawPacket(index, ((hi << 32) | lo) * tick, orig, body[20:20 + caplen], linktype,
                            offset)
        elif btype == 3 and interfaces and len(body) >= 4:  # Simple Packet Block
            (orig,) = struct.unpack(f"{endian}I", body[:4])
            linktype, _ = interfaces[0]
            index += 1
            yield RawPacket(index, 0.0, orig, body[4:4 + min(orig, len(body) - 4)], linktype, offset)


def read_at(path: Path, offset: int, fmt: str) -> RawPacket | None:
    """Re-read a single packet record by file offset (used for detail views and export)."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        endian, resolution = _PCAP_MAGICS.get(head[:4], ("<", 1e-6))
        if fmt == "pcap":
            linktype = struct.unpack(f"{endian}I", head[20:24])[0]
            fh.seek(offset)
            rec = fh.read(16)
            if len(rec) < 16:
                return None
            sec, frac, caplen, orig = struct.unpack(f"{endian}IIII", rec)
            if caplen > MAX_PACKET_BYTES:
                return None
            data = fh.read(caplen)
            return RawPacket(0, sec + frac * resolution, orig, data, linktype, offset)
    # pcapng: offsets are per-block; find the packet by scanning (rare path)
    for pkt in read_packets(path, 1_000_000):
        if pkt.offset == offset:
            return pkt
    return None


def write_pcap(path: Path, packets: list[RawPacket], linktype: int = LINKTYPE_ETHERNET) -> None:
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for p in packets:
            sec = int(p.timestamp)
            usec = int((p.timestamp - sec) * 1_000_000)
            out.write(struct.pack("<IIII", sec, usec, len(p.data), p.orig_len))
            out.write(p.data)
