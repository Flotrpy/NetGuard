"""Asyncio TCP connect scanner: discovery, ports, banners and TLS inspection.

Uses ordinary TCP connections (no raw sockets, no privileges, no exploitation). A refused
connection proves a host is up just as an accepted one does; total silence is reported as
"no response" (which may also mean a firewall drops probes).
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509

from netguard.scanners.network.identify import (
    HTTP_PORTS,
    TLS_PORTS,
    Identity,
    identify,
    sanitize,
)

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"


@dataclass
class PortResult:
    port: int
    state: str
    banner: str = ""
    identity: Identity | None = None
    tls: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0


async def probe_port(ip: str, port: int, timeout: float) -> tuple[str, float]:
    start = asyncio.get_running_loop().time()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except ConnectionRefusedError:
        return CLOSED, (asyncio.get_running_loop().time() - start) * 1000
    except (TimeoutError, OSError):
        return FILTERED, 0.0
    latency = (asyncio.get_running_loop().time() - start) * 1000
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return OPEN, latency


async def _read(reader: asyncio.StreamReader, timeout: float, n: int = 512) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout)
    except (TimeoutError, OSError, ConnectionError):
        return b""


async def grab_banner(
    ip: str, port: int, timeout: float, tls: bool | None = None
) -> tuple[str, dict[str, Any]]:
    """Read what the service says on connect; if it stays silent send one benign HEAD request.

    Services that speak first (SSH, FTP, SMTP, MySQL...) are identified purely passively.
    """
    tls_info: dict[str, Any] = {}
    use_tls = port in TLS_PORTS if tls is None else tls
    try:
        ctx = None
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we are *inspecting*, not trusting, the certificate
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=None), timeout * 3
        )
    except (TimeoutError, OSError, ssl.SSLError):
        return "", tls_info
    try:
        if use_tls:
            tls_info = _tls_details(writer)
        web = port in HTTP_PORTS or (use_tls and port in (443, 8443))
        data = b"" if web else await _read(reader, timeout)  # speak-first protocols
        if not data:
            writer.write(b"HEAD / HTTP/1.0\r\nUser-Agent: NetGuard\r\nAccept: */*\r\n\r\n")
            await writer.drain()
            data = await _read(reader, timeout * 2, 2048)
        return sanitize(data.decode("latin-1"), 600) if data else "", tls_info
    except (OSError, ConnectionError, ssl.SSLError):
        return "", tls_info
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _tls_details(writer: asyncio.StreamWriter) -> dict[str, Any]:
    obj = writer.get_extra_info("ssl_object")
    if obj is None:
        return {}
    info: dict[str, Any] = {"version": obj.version(), "cipher": (obj.cipher() or ("",))[0]}
    der = obj.getpeercert(binary_form=True)
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
            not_after = cert.not_valid_after_utc
            info.update({
                "subject": sanitize(cert.subject.rfc4514_string(), 200),
                "issuer": sanitize(cert.issuer.rfc4514_string(), 200),
                "not_after": not_after.isoformat(),
                "expired": not_after < datetime.now(UTC),
                "days_left": (not_after - datetime.now(UTC)).days,
                "self_signed": cert.subject == cert.issuer,
            })
        except ValueError:
            pass
    return info


async def reverse_dns(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2.0)
        return sanitize(name, 200)
    except (TimeoutError, OSError):
        return ""


async def discover(ip: str, ports: list[int], timeout: float) -> tuple[bool, float]:
    """A host is 'up' if any probe is accepted or actively refused."""
    results = await asyncio.gather(*(probe_port(ip, p, timeout) for p in ports))
    live = [lat for state, lat in results if state in (OPEN, CLOSED)]
    return bool(live), (min(live) if live else 0.0)


async def scan_ports(ip: str, ports: list[int], timeout: float, sem: asyncio.Semaphore) -> list[PortResult]:
    async def one(port: int) -> PortResult:
        async with sem:
            state, latency = await probe_port(ip, port, timeout)
        return PortResult(port, state, latency_ms=latency)

    results = await asyncio.gather(*(one(p) for p in ports))
    return [r for r in results if r.state == OPEN]


async def enrich(ip: str, results: list[PortResult], timeout: float, sem: asyncio.Semaphore) -> None:
    async def one(r: PortResult) -> None:
        async with sem:
            banner, tls = await grab_banner(ip, r.port, timeout)
        r.banner, r.tls = banner, tls
        r.identity = identify(r.port, banner, tls=bool(tls))

    await asyncio.gather(*(one(r) for r in results))
