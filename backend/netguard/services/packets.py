"""Packet capture storage, search, detail and export (API side).

Untrusted capture parsing happens in the sandboxed scanner. This module only reads the index the
scanner wrote and re-dissects *single packets* on demand (bounded, exception-safe).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from netguard.config import get_settings
from netguard.models import PacketCapture, Scan
from netguard.scanners.packets import pcap
from netguard.scanners.packets.dissect import dissect, hexdump, matches_protocol


def capture_path(capture: PacketCapture) -> Path:
    return get_settings().uploads_dir / capture.stored_path


def index_path(capture: PacketCapture) -> Path:
    return get_settings().uploads_dir / f"{capture.stored_path}.index.jsonl"


def persist_capture(db: Session, scan: Scan, metadata: dict[str, Any]) -> None:
    capture = db.get(PacketCapture, (scan.config or {}).get("capture_id", ""))
    if capture is None:
        return
    capture.packet_count = int(metadata.get("packet_count", 0))
    capture.summary = {**(metadata.get("summary") or {}), "format": metadata.get("format"),
                       "truncated": metadata.get("truncated", False)}


@lru_cache(maxsize=6)
def _load(path: str, mtime_ns: int) -> tuple[dict[str, Any], ...]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            rows.append(json.loads(line))
    return tuple(rows)


def load_index(capture: PacketCapture) -> tuple[dict[str, Any], ...]:
    p = index_path(capture)
    if not p.is_file():
        return ()
    return _load(str(p), p.stat().st_mtime_ns)


def _match(row: dict[str, Any], protocols: list[str], q: str, ip: str, port: int | None,
           min_size: int | None, max_size: int | None) -> bool:
    if protocols and not any(matches_protocol(row["chain"], p) for p in protocols):
        return False
    if ip and ip not in (row["src"], row["dst"]) and ip not in row.get("ips", ()):
        return False
    if port is not None and port not in (row["sport"], row["dport"]):
        return False
    if min_size is not None and row["len"] < min_size:
        return False
    if max_size is not None and row["len"] > max_size:
        return False
    if q:
        hay = f"{row['src']} {row['dst']} {row['proto']} {row['info']}".lower()
        return q.lower() in hay
    return True


def query(capture: PacketCapture, *, protocol: str = "", q: str = "", ip: str = "",
          port: int | None = None, min_size: int | None = None, max_size: int | None = None,
          offset: int = 0, limit: int = 100) -> tuple[int, list[dict[str, Any]]]:
    protocols = [p.strip() for p in protocol.split(",") if p.strip()]
    rows = [r for r in load_index(capture) if _match(r, protocols, q, ip, port, min_size, max_size)]
    page = rows[offset:offset + limit]
    return len(rows), [_public(r) for r in page]


def _public(r: dict[str, Any]) -> dict[str, Any]:
    return {"n": r["n"], "time": r["t"], "source": r["src"], "destination": r["dst"],
            "sport": r["sport"], "dport": r["dport"], "protocol": r["proto"], "length": r["len"],
            "info": r["info"]}


def packet_detail(capture: PacketCapture, n: int) -> dict[str, Any] | None:
    rows = load_index(capture)
    if not 1 <= n <= len(rows):
        return None
    row = rows[n - 1]
    fmt = (capture.summary or {}).get("format", "pcap")
    raw = pcap.read_at(capture_path(capture), row["off"], fmt)
    if raw is None:
        return None
    raw.index = n
    d = dissect(raw)
    frame = {"name": f"Frame {n}", "fields": [
        ("Arrival time (epoch)", f"{raw.timestamp:.6f}"), ("Frame length", f"{raw.orig_len} bytes"),
        ("Captured length", f"{len(raw.data)} bytes"), ("Protocols", " > ".join(d.chain) or "-")]}
    return {**_public(row), "layers": [frame] + [{"name": la.name, "fields": la.fields} for la in d.layers],
            "hex": hexdump(raw.data, limit=2048), "truncated_hex": len(raw.data) > 2048}


def export_filtered(capture: PacketCapture, out: Path, **filters: Any) -> int:
    """Write the packets matching ``filters`` to a new classic pcap. Returns the packet count."""
    protocols = [p.strip() for p in filters.get("protocol", "").split(",") if p.strip()]
    fmt = (capture.summary or {}).get("format", "pcap")
    src = capture_path(capture)
    selected = []
    for row in load_index(capture):
        if _match(row, protocols, filters.get("q", ""), filters.get("ip", ""), filters.get("port"),
                  filters.get("min_size"), filters.get("max_size")):
            pkt = pcap.read_at(src, row["off"], fmt) if fmt == "pcap" else None
            if pkt is not None:
                selected.append(pkt)
    if fmt != "pcap":  # pcapng: gather in a single pass
        wanted = {r["off"] for r in load_index(capture) if _match(
            r, protocols, filters.get("q", ""), filters.get("ip", ""), filters.get("port"),
            filters.get("min_size"), filters.get("max_size"))}
        selected = [p for p in pcap.read_packets(src, 1_000_000) if p.offset in wanted]
    linktype = selected[0].linktype if selected else pcap.LINKTYPE_ETHERNET
    pcap.write_pcap(out, selected, linktype)
    return len(selected)


def delete_capture_files(capture: PacketCapture) -> None:
    capture_path(capture).unlink(missing_ok=True)
    index_path(capture).unlink(missing_ok=True)
    _load.cache_clear()
