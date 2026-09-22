"""Packet analyzer scanner: parses an uploaded capture (in the sandbox) and writes an index."""

from __future__ import annotations

import json
from pathlib import Path

from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import ScanContext, Scanner, ScanResult
from netguard.scanners.packets.analyze import RULES, Analyzer
from netguard.scanners.packets.dissect import dissect
from netguard.scanners.packets.pcap import PcapError, detect_format, read_packets

DEFAULT_MAX_PACKETS = 100_000


class PacketScanner(Scanner):
    name = ScannerName.PACKETS
    display_name = "Packet Analyzer"
    version = "1.0.0"
    description = (
        "Passive analysis of uploaded pcap/pcapng captures: protocol hierarchy, conversations, "
        "endpoints and security observations (cleartext credentials, legacy TLS, ARP conflicts, "
        "scan-like behaviour). Live capture is not available in this deployment."
    )
    supported_inputs = ("pcap",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        rt = ctx.runtime
        base = Path(rt["uploads_dir"]).resolve()
        rel = str(ctx.config["pcap_path"])
        path = (base / rel).resolve()
        if base not in path.parents or not path.is_file():
            raise PcapError("Capture file not found")
        max_packets = int(rt.get("max_pcap_packets", DEFAULT_MAX_PACKETS))
        with open(path, "rb") as fh:
            fmt = detect_format(fh.read(4))
        size = path.stat().st_size
        analyzer = Analyzer()
        index_rel = f"{rel}.index.jsonl"
        truncated = False
        with open(base / index_rel, "w", encoding="utf-8") as idx:
            first_ts = None
            for pkt in read_packets(path, max_packets + 1):
                ctx.check_cancelled()
                if analyzer.packets >= max_packets:
                    truncated = True
                    break
                d = dissect(pkt)
                analyzer.add(pkt, d)
                first_ts = pkt.timestamp if first_ts is None else first_ts
                idx.write(json.dumps({
                    "n": pkt.index, "t": round(pkt.timestamp - first_ts, 6), "ts": pkt.timestamp,
                    "src": d.src, "dst": d.dst, "sport": d.sport, "dport": d.dport,
                    "proto": d.protocol, "len": pkt.orig_len, "info": d.info[:300],
                    "chain": d.chain, "off": pkt.offset, "lt": pkt.linktype,
                    # ARP rows show MACs in the address columns; keep the IPs searchable too
                    "ips": [d.meta["arp_sender_ip"], d.meta["arp_target_ip"]]
                    if "arp_sender_ip" in d.meta else [],
                }, separators=(",", ":")) + "\n")
                if analyzer.packets % 2000 == 0:
                    ctx.progress(min(95, 100 * analyzer.packets / max_packets), f"{analyzer.packets} packets")
        summary = analyzer.summary()
        findings = analyzer.findings()
        warnings = []
        if truncated:
            warnings.append(f"Capture truncated to the first {max_packets} packets for analysis.")
        if analyzer.packets == 0:
            warnings.append("The capture contains no packets.")
        ctx.progress(100, "done")
        return ScanResult(
            findings=findings,
            warnings=warnings,
            # A capture is a point-in-time observation: it can never prove an issue is gone, so it
            # must not auto-resolve findings from other captures.
            complete=False,
            metadata={"format": fmt, "file_bytes": size, "packet_count": analyzer.packets,
                      "index": index_rel, "truncated": truncated, "summary": summary,
                      "rules": len(RULES)},
        )
