"""Traffic statistics and passive security observations for a capture."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from netguard.enums import Confidence as C
from netguard.enums import Severity as S
from netguard.scanners.base import AssetRef, RawFinding
from netguard.scanners.iac.meta import R
from netguard.scanners.packets.dissect import Decoded
from netguard.scanners.packets.pcap import RawPacket

MAX_CONVERSATIONS = 5000
MAX_ENDPOINTS = 5000
TIMELINE_BUCKETS = 120
SIZE_BUCKETS = [(0, 63), (64, 127), (128, 255), (256, 511), (512, 1023), (1024, 1499), (1500, 10**9)]
SCAN_PORT_THRESHOLD = 20
NXDOMAIN_THRESHOLD = 20
DNS_LABEL_LIMIT, DNS_NAME_LIMIT = 50, 100
LEGACY_TLS = {"SSLv3", "TLSv1.0", "TLSv1.1"}

CAT = "Network Traffic"
RULES = {r.id: r for r in [
    R("pk.cleartext-credentials", "Credentials sent in cleartext", CAT, S.HIGH, C.HIGH, "CWE-319",
      "Authentication material (HTTP Basic, an HTTP form password field or an FTP PASS command) "
      "was observed unencrypted. The values are not stored by NetGuard.",
      "Anyone on the network path can capture and reuse these credentials.",
      "Use HTTPS/SFTP/FTPS everywhere credentials are sent and rotate credentials that were "
      "exposed on this network.", expl="high"),
    R("pk.telnet-traffic", "Telnet session observed", CAT, S.MEDIUM, C.HIGH, "CWE-319",
      "Telnet traffic was seen. Telnet is unencrypted, including logins.",
      "Sessions and credentials can be read or hijacked on the wire.",
      "Replace Telnet with SSH."),
    R("pk.http-cleartext", "Unencrypted HTTP traffic observed", CAT, S.LOW, C.HIGH, "CWE-319",
      "HTTP requests were sent without TLS.",
      "Content, cookies and tokens travel in cleartext and can be modified in transit.",
      "Serve and use HTTPS; redirect HTTP to HTTPS and enable HSTS."),
    R("pk.tls-legacy", "Legacy TLS/SSL version in use", CAT, S.MEDIUM, C.HIGH, "CWE-327",
      "A TLS handshake negotiated (or a client offered only) SSLv3, TLS 1.0 or TLS 1.1.",
      "These protocol versions have known weaknesses.",
      "Require TLS 1.2 or newer on servers and clients."),
    R("pk.arp-conflict", "Possible ARP spoofing (IP claimed by multiple MACs)", CAT, S.MEDIUM,
      C.MEDIUM, "CWE-923",
      "The same IP address was announced by more than one MAC address in ARP replies. This can "
      "indicate ARP spoofing, but also failover, VRRP/HSRP or DHCP address changes.",
      "An attacker able to spoof ARP can intercept traffic (man-in-the-middle).",
      "Verify the MAC addresses belong to legitimate devices; consider dynamic ARP inspection."),
    R("pk.port-scan", "Possible port scan or sweep", CAT, S.MEDIUM, C.MEDIUM, "CWE-200",
      "A host sent SYN packets without completing handshakes to many ports (or many hosts). This "
      "is consistent with scanning but can also be a legitimate security tool.",
      "Reconnaissance often precedes an attack.",
      "Confirm whether the source is an authorized scanner; otherwise investigate the host."),
    R("pk.dns-long-name", "Unusually long DNS names", CAT, S.LOW, C.LOW, "CWE-200",
      "DNS queries with very long names or labels were seen. This is a weak indicator of DNS "
      "tunnelling or data exfiltration but also occurs in some legitimate services.",
      "DNS tunnelling can bypass network controls.",
      "Inspect the destinations and consider DNS filtering/monitoring."),
    R("pk.dns-nxdomain-burst", "Many failed DNS lookups", CAT, S.LOW, C.LOW, "CWE-200",
      "A client received many NXDOMAIN responses, which can indicate misconfiguration or "
      "algorithmically generated domains.",
      "May indicate malware or a broken application.", "Investigate the client's software."),
    R("pk.malformed-packets", "Malformed packets in capture", CAT, S.INFO, C.HIGH, "CWE-20",
      "Some packets could not be fully decoded.",
      "May indicate truncated capture, unsupported protocols or crafted traffic.",
      "Check the capture snaplen or inspect the raw packets."),
]}


def _ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _endpoint(addr: str, port: int | None) -> str:
    return f"[{addr}]:{port}" if port is not None and ":" in addr else \
        f"{addr}:{port}" if port is not None else addr


class Analyzer:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.first = self.last = None
        self.malformed = 0
        self.proto: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        self.hierarchy: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        self.convs: dict[tuple, dict[str, Any]] = {}
        self.endpoints: dict[str, dict[str, int]] = {}
        self.times: list[float] = []
        self.sizes = [0] * len(SIZE_BUCKETS)
        # observation state
        self.cleartext: dict[tuple[str, str, str], int] = defaultdict(int)
        self.http_hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
        self.http_reqs: dict[tuple[str, str], int] = defaultdict(int)
        self.telnet: dict[tuple[str, str], int] = defaultdict(int)
        self.tls_legacy: dict[tuple[str, str, str], str] = {}
        self.arp: dict[str, set[str]] = defaultdict(set)
        self.syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
        self.syn_hosts: dict[tuple[str, int], set[str]] = defaultdict(set)
        self.synack: set[tuple[str, str, int]] = set()
        self.dns_long: dict[str, set[str]] = defaultdict(set)
        self.nxdomain: dict[str, int] = defaultdict(int)

    # ---- ingestion ----------------------------------------------------------------------------
    def add(self, pkt: RawPacket, d: Decoded) -> None:
        size = pkt.orig_len
        self.packets += 1
        self.bytes += size
        ts = pkt.timestamp
        self.first = ts if self.first is None else min(self.first, ts)
        self.last = ts if self.last is None else max(self.last, ts)
        self.times.append(ts)
        for i, (lo, hi) in enumerate(SIZE_BUCKETS):
            if lo <= size <= hi:
                self.sizes[i] += 1
                break
        if d.meta.get("malformed"):
            self.malformed += 1
        self.proto[d.protocol][0] += 1
        self.proto[d.protocol][1] += size
        for i in range(1, len(d.chain) + 1):
            key = ">".join(d.chain[:i])
            self.hierarchy[key][0] += 1
            self.hierarchy[key][1] += size
        self._conversation(d, size, ts)
        self._observe(d)

    def _conversation(self, d: Decoded, size: int, ts: float) -> None:
        if not d.src or not d.dst:
            return
        for addr, tx in ((d.src, True), (d.dst, False)):
            ep = self.endpoints.get(addr)
            if ep is None:
                if len(self.endpoints) >= MAX_ENDPOINTS:
                    continue
                ep = self.endpoints[addr] = {"tx_packets": 0, "rx_packets": 0, "tx_bytes": 0, "rx_bytes": 0}
            ep["tx_packets" if tx else "rx_packets"] += 1
            ep["tx_bytes" if tx else "rx_bytes"] += size
        transport = "tcp" if "tcp" in d.chain else "udp" if "udp" in d.chain else d.protocol.lower()
        a, b = _endpoint(d.src, d.sport), _endpoint(d.dst, d.dport)
        key = (transport, *sorted((a, b)))
        conv = self.convs.get(key)
        if conv is None:
            if len(self.convs) >= MAX_CONVERSATIONS:
                return
            conv = self.convs[key] = {"protocol": transport, "a": key[1], "b": key[2], "packets": 0,
                                      "bytes": 0, "a_to_b_packets": 0, "b_to_a_packets": 0,
                                      "start": ts, "end": ts, "top": d.protocol}
        conv["packets"] += 1
        conv["bytes"] += size
        conv["a_to_b_packets" if a == conv["a"] else "b_to_a_packets"] += 1
        conv["end"] = max(conv["end"], ts)
        if d.protocol not in ("TCP", "UDP", "IPv4", "IPv6", "Ethernet"):
            conv["top"] = d.protocol

    def _observe(self, d: Decoded) -> None:
        m = d.meta
        if m.get("http_request"):
            self.http_reqs[(d.src, d.dst)] += 1
            if m.get("http_host"):
                self.http_hosts[(d.src, d.dst)].add(m["http_host"])
            if m.get("http_auth_scheme", "").lower() == "basic":
                self.cleartext[(d.src, d.dst, "HTTP Basic authentication")] += 1
            if m.get("http_password_field"):
                self.cleartext[(d.src, d.dst, "HTTP form password field")] += 1
        if m.get("ftp_password_sent"):
            self.cleartext[(d.src, d.dst, "FTP password")] += 1
        if m.get("cleartext_protocol") == "telnet":
            self.telnet[(d.src, d.dst)] += 1
        ver, hs = m.get("tls_version"), m.get("tls_handshake")
        if ver in LEGACY_TLS and hs in (1, 2):
            kind = "negotiated by server" if hs == 2 else "only offered by client"
            self.tls_legacy[(d.src, d.dst, ver)] = kind
        if m.get("arp_op") == 2:
            self.arp[m["arp_sender_ip"]].add(m["arp_sender_mac"])
        flags = m.get("tcp_flags")
        if flags is not None and d.dport is not None:
            if flags & 0x12 == 0x02:  # SYN without ACK
                self.syn_ports[(d.src, d.dst)].add(d.dport)
                self.syn_hosts[(d.src, d.dport)].add(d.dst)
            elif flags & 0x12 == 0x12:  # SYN-ACK: the probed port answered
                self.synack.add((d.dst, d.src, d.sport))
        for name in m.get("dns_qnames", []) if not m.get("dns_response") else []:
            if len(name) > DNS_NAME_LIMIT or any(len(x) > DNS_LABEL_LIMIT for x in name.split(".")):
                self.dns_long[d.src].add(name[:60] + "…")
        if m.get("dns_response") and m.get("dns_rcode") == 3:
            self.nxdomain[d.dst] += 1

    # ---- output -------------------------------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        duration = (self.last - self.first) if self.first is not None else 0.0
        bucket = max(duration / TIMELINE_BUCKETS, 1e-6) if duration > 0 else 1.0
        timeline: dict[int, int] = defaultdict(int)
        for t in self.times:
            timeline[min(int((t - (self.first or 0)) / bucket), TIMELINE_BUCKETS - 1)] += 1
        convs = sorted(self.convs.values(), key=lambda c: -c["bytes"])[:200]
        for c in convs:
            c["duration"] = round(c["end"] - c["start"], 6)
            c["start"] = round(c["start"] - (self.first or 0), 6)
            del c["end"]
        endpoints = sorted(({"address": a, **v} for a, v in self.endpoints.items()),
                           key=lambda e: -(e["tx_bytes"] + e["rx_bytes"]))[:200]
        return {
            "packets": self.packets, "bytes": self.bytes, "duration": round(duration, 6),
            "first_timestamp": self.first, "malformed": self.malformed,
            "avg_packet_size": round(self.bytes / self.packets, 1) if self.packets else 0,
            "protocols": sorted(({"protocol": p, "packets": v[0], "bytes": v[1]}
                                 for p, v in self.proto.items()), key=lambda x: -x["packets"]),
            "hierarchy": sorted(({"path": k, "packets": v[0], "bytes": v[1]}
                                 for k, v in self.hierarchy.items()), key=lambda x: x["path"]),
            "conversations": convs, "endpoints": endpoints,
            "timeline": {"bucket_seconds": round(bucket, 6),
                         "counts": [timeline.get(i, 0) for i in range(TIMELINE_BUCKETS)]},
            "size_distribution": [{"range": f"{lo}-{hi}" if hi < 10**9 else f"{lo}+", "packets": n}
                                  for (lo, hi), n in zip(SIZE_BUCKETS, self.sizes, strict=True)],
        }

    def findings(self) -> list[RawFinding]:
        out: list[RawFinding] = []

        def emit(rule_id: str, host: str, title_suffix: str, note: str, key: str, extra: dict) -> None:
            rule = RULES[rule_id]
            asset = AssetRef("host", host, host) if _ip(host) else None
            exposure = "unknown"
            if _ip(host):
                a = ipaddress.ip_address(host)
                exposure = "internal" if a.is_private or a.is_loopback else "internet"
            out.append(RawFinding(
                rule_id=rule_id, title=f"{rule.title}: {title_suffix}", category=rule.category,
                severity=rule.severity, confidence=rule.confidence, cwe=rule.cwe,
                description=f"{rule.description} {note}".strip(), impact=rule.impact,
                remediation=rule.remediation, references=[f"https://cwe.mitre.org/data/definitions/{rule.cwe[4:]}.html"],
                exploitability=rule.exploitability, exposure=exposure, asset=asset,
                extra={"ip": host if _ip(host) else "", "source": "packet capture", **extra},
                key=key))

        for (src, dst, kind), n in sorted(self.cleartext.items()):
            emit("pk.cleartext-credentials", src, f"{src} → {dst} ({kind})",
                 f"{n} packet(s).", f"{src}>{dst}:{kind}", {"packets": n, "kind": kind, "destination": dst})
        for (src, dst), n in sorted(self.telnet.items()):
            emit("pk.telnet-traffic", src, f"{src} → {dst}", f"{n} packet(s).", f"{src}>{dst}:telnet",
                 {"packets": n, "destination": dst})
        for (src, dst), n in sorted(self.http_reqs.items()):
            hosts = ", ".join(sorted(self.http_hosts[(src, dst)])[:5])
            emit("pk.http-cleartext", src, f"{src} → {dst}",
                 f"{n} request(s)" + (f" for {hosts}." if hosts else "."), f"{src}>{dst}:http",
                 {"requests": n, "hosts": sorted(self.http_hosts[(src, dst)])[:10], "destination": dst})
        for (src, dst, ver), how in sorted(self.tls_legacy.items()):
            emit("pk.tls-legacy", src if how.startswith("only") else dst, f"{ver} between {src} and {dst}",
                 f"{ver} {how}.", f"{src}>{dst}:{ver}", {"version": ver, "detail": how})
        for ip, macs in sorted(self.arp.items()):
            if len(macs) > 1:
                emit("pk.arp-conflict", ip, f"{ip} claimed by {len(macs)} MAC addresses",
                     f"MACs: {', '.join(sorted(macs))}.", f"arp:{ip}", {"macs": sorted(macs)})
        for (src, dst), ports in sorted(self.syn_ports.items()):
            unanswered = {p for p in ports if (src, dst, p) not in self.synack}
            if len(ports) >= SCAN_PORT_THRESHOLD and len(unanswered) >= SCAN_PORT_THRESHOLD // 2:
                emit("pk.port-scan", src, f"{src} probed {len(ports)} ports on {dst}",
                     f"{len(unanswered)} of them never completed a handshake.", f"scan:{src}>{dst}",
                     {"ports_probed": len(ports), "destination": dst})
        for (src, port), hosts in sorted(self.syn_hosts.items()):
            if len(hosts) >= SCAN_PORT_THRESHOLD:
                emit("pk.port-scan", src, f"{src} probed port {port} on {len(hosts)} hosts",
                     "Consistent with a network sweep.", f"sweep:{src}:{port}",
                     {"hosts_probed": len(hosts), "port": port})
        for src, names in sorted(self.dns_long.items()):
            emit("pk.dns-long-name", src, f"{src} ({len(names)} long name(s))",
                 f"Example: {sorted(names)[0]}", f"dnslong:{src}", {"examples": sorted(names)[:3]})
        for client, n in sorted(self.nxdomain.items()):
            if n >= NXDOMAIN_THRESHOLD:
                emit("pk.dns-nxdomain-burst", client, f"{client} received {n} NXDOMAIN responses",
                     "", f"nx:{client}", {"nxdomain": n})
        if self.malformed:
            rule = RULES["pk.malformed-packets"]
            out.append(RawFinding(
                rule_id="pk.malformed-packets", title=f"{rule.title}: {self.malformed}",
                category=rule.category, severity=rule.severity, confidence=rule.confidence,
                cwe=rule.cwe, description=rule.description, impact=rule.impact,
                remediation=rule.remediation, extra={"count": self.malformed},
                key="malformed"))
        return out
