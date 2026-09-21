"""Scan target authorization policy (network and API scanners).

NetGuard only assesses systems the user is authorized to test. Technical guardrails, enforced
on the server regardless of what the client sends:

* Always blocked: link-local (incl. the 169.254.169.254 cloud-metadata address), multicast,
  unspecified/reserved, and broadcast addresses.
* Private, loopback and unique-local ranges are allowed by default (typical internal audits).
* Public addresses are refused unless the *operator* enabled NETGUARD_ALLOW_PUBLIC_TARGETS.
* Range size and port counts are capped.
* Every address a hostname resolves to must pass the same policy.

These checks are a safety net, not a substitute for authorization: the API additionally requires
an explicit authorization attestation which is stored on the scan and audit-logged.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetError(ValueError):
    """The requested target is not permitted."""


@dataclass(frozen=True)
class ResolvedTarget:
    original: str
    addresses: list[str]  # concrete IPs to scan, deduplicated, in order
    hostname: str = ""  # set when the input was a hostname


def _blocked_reason(ip: IPAddress) -> str | None:
    if ip.is_loopback:  # ::1 sits inside ::/8, which Python also calls "reserved"
        return None
    if ip.is_link_local:
        return "link-local addresses (including cloud metadata endpoints) are never scanned"
    if ip.is_multicast:
        return "multicast addresses are not scannable"
    if ip.is_unspecified or ip.is_reserved:
        return "unspecified/reserved addresses are not scannable"
    if isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255"):
        return "the broadcast address is not scannable"
    return None


def check_address(ip: IPAddress, *, allow_public: bool) -> None:
    reason = _blocked_reason(ip)
    if reason:
        raise TargetError(f"{ip}: {reason}")
    if not (ip.is_private or ip.is_loopback) and not allow_public:
        raise TargetError(
            f"{ip} is a public address. Scanning public addresses is disabled on this "
            "installation (an administrator can enable NETGUARD_ALLOW_PUBLIC_TARGETS)."
        )


def _resolve_host(host: str) -> list[IPAddress]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"Could not resolve hostname '{host}'") from exc
    seen: list[IPAddress] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip not in seen:
            seen.append(ip)
    return seen


def resolve_target(target: str, *, allow_public: bool, max_hosts: int) -> ResolvedTarget:
    """Validate ``target`` (IP, CIDR or hostname) and expand it to concrete addresses."""
    target = target.strip()
    if not target or len(target) > 253 or any(c in target for c in " \t\r\n;|&$`'\"<>"):
        raise TargetError("Invalid target")
    # CIDR range
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise TargetError("Invalid CIDR range") from exc
        if net.num_addresses > max_hosts * 4 and net.num_addresses > 2:
            raise TargetError(f"Range too large ({net.num_addresses} addresses); split it up "
                              f"(max {max_hosts} hosts per scan)")
        hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
        if len(hosts) > max_hosts:
            raise TargetError(f"Range has {len(hosts)} hosts; the limit is {max_hosts} per scan")
        for ip in (hosts[0], hosts[-1]) if hosts else ():
            check_address(ip, allow_public=allow_public)
        # Every address in a range shares the same class for private/public purposes except
        # exotic ranges, so validate them all cheaply.
        for ip in hosts:
            check_address(ip, allow_public=allow_public)
        return ResolvedTarget(target, [str(h) for h in hosts])
    # Single IP
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    if ip is not None:
        check_address(ip, allow_public=allow_public)
        return ResolvedTarget(target, [str(ip)])
    # Hostname: all resolved addresses must be permitted
    if not all(c.isalnum() or c in "-." for c in target):
        raise TargetError("Invalid hostname")
    ips = _resolve_host(target)
    for resolved in ips:
        check_address(resolved, allow_public=allow_public)
    return ResolvedTarget(target, [str(i) for i in ips[:max_hosts]], hostname=target)


def parse_ports(spec: str | list[int] | None, *, max_ports: int, default: list[int]) -> list[int]:
    """Parse "22,80,8000-8010" (or a list) into a sorted, validated, capped port list."""
    if spec in (None, "", []):
        return default[:max_ports]
    ports: set[int] = set()
    parts = spec if isinstance(spec, list) else str(spec).split(",")
    for part in parts:
        part = str(part).strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                if lo > hi:
                    raise ValueError
                ports.update(range(lo, hi + 1))
            else:
                ports.add(int(part))
        except ValueError as exc:
            raise TargetError(f"Invalid port specification '{part}'") from exc
        if len(ports) > max_ports:
            raise TargetError(f"Too many ports (limit {max_ports})")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise TargetError("Ports must be between 1 and 65535")
    return sorted(ports)
