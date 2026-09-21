import ipaddress
import socket

import pytest

from netguard.core import targets
from netguard.core.targets import TargetError, check_address, parse_ports, resolve_target


def resolve(t, public=False, max_hosts=256):
    return resolve_target(t, allow_public=public, max_hosts=max_hosts)


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.5.5", "192.168.1.21", "127.0.0.1", "::1", "fd00::5"])
def test_private_and_loopback_allowed_by_default(ip):
    assert resolve(ip).addresses == [ip]


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_need_operator_opt_in(ip):
    with pytest.raises(TargetError, match="public address"):
        resolve(ip)
    assert resolve(ip, public=True).addresses == [ip]


@pytest.mark.parametrize("ip", ["169.254.169.254", "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "fe80::1", "ff02::1", "240.0.0.1"])
def test_metadata_link_local_multicast_and_reserved_are_always_blocked(ip):
    for public in (False, True):
        with pytest.raises(TargetError):
            resolve(ip, public=public)


def test_cidr_expansion_and_limits():
    r = resolve("192.168.1.0/30")
    assert r.addresses == ["192.168.1.1", "192.168.1.2"]
    assert resolve("192.168.1.7/32").addresses == ["192.168.1.7"]
    assert len(resolve("10.0.0.0/24").addresses) == 254
    with pytest.raises(TargetError, match="too large"):
        resolve("10.0.0.0/8")
    with pytest.raises(TargetError, match="too large|limit"):
        resolve("10.0.0.0/23", max_hosts=100)
    with pytest.raises(TargetError, match="limit"):
        resolve("10.0.0.0/24", max_hosts=100)  # 254 hosts: under the 4x pre-check, over the limit
    with pytest.raises(TargetError, match="public"):
        resolve("8.8.8.0/30")
    with pytest.raises(TargetError, match="Invalid CIDR"):
        resolve("10.0.0.0/33")


def test_range_spanning_blocked_addresses_is_rejected():
    with pytest.raises(TargetError, match="link-local"):
        resolve("169.254.169.0/24")


@pytest.mark.parametrize("bad", ["", "  ", "a b", "10.0.0.1;rm -rf /", "10.0.0.1|x", "$(id)", "x" * 300, "host`whoami`", "a\nb", "http://x"])
def test_malformed_and_injection_shaped_targets_rejected(bad):
    with pytest.raises(TargetError):
        resolve(bad)


def test_hostnames_must_resolve_only_to_permitted_addresses(monkeypatch):
    def fake(host, *a, **k):
        table = {"app.internal": ["10.0.0.5", "10.0.0.6"], "sneaky.example": ["10.0.0.5", "169.254.169.254"],
                 "pub.example": ["93.184.216.34"]}
        if host not in table:
            raise socket.gaierror("nope")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[host]]

    monkeypatch.setattr(targets.socket, "getaddrinfo", fake)
    ok = resolve("app.internal")
    assert ok.addresses == ["10.0.0.5", "10.0.0.6"] and ok.hostname == "app.internal"
    with pytest.raises(TargetError, match="link-local"):  # DNS pointing partly at metadata: refused
        resolve("sneaky.example")
    with pytest.raises(TargetError, match="public"):
        resolve("pub.example")
    with pytest.raises(TargetError, match="Could not resolve"):
        resolve("missing.example")


def test_check_address_direct():
    check_address(ipaddress.ip_address("10.0.0.1"), allow_public=False)
    with pytest.raises(TargetError):
        check_address(ipaddress.ip_address("169.254.169.254"), allow_public=True)


def test_port_parsing():
    default = [22, 80, 443]
    assert parse_ports(None, max_ports=100, default=default) == default
    assert parse_ports("", max_ports=100, default=default) == default
    assert parse_ports("443, 22,8000-8003", max_ports=100, default=default) == [22, 443, 8000, 8001, 8002, 8003]
    assert parse_ports([80, 22], max_ports=100, default=default) == [22, 80]
    for bad in ["0", "70000", "abc", "10-5", "1-"]:
        with pytest.raises(TargetError):
            parse_ports(bad, max_ports=100, default=default)
    with pytest.raises(TargetError, match="Too many"):
        parse_ports("1-500", max_ports=100, default=default)
    assert parse_ports(None, max_ports=2, default=default) == [22, 80]
