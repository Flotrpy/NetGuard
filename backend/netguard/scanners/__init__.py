"""Scanner package. Implemented scanners are imported (and thereby registered) here."""

from __future__ import annotations


def load_implemented() -> None:
    """Import every implemented scanner module so it can register itself."""
    from netguard.scanners.api.scanner import ApiScanner
    from netguard.scanners.dependencies.scanner import DependencyScanner
    from netguard.scanners.docker.scanner import DockerScanner
    from netguard.scanners.iac.scanner import IacScanner
    from netguard.scanners.network.scanner import NetworkScanner
    from netguard.scanners.packets.scanner import PacketScanner
    from netguard.scanners.registry import register
    from netguard.scanners.sast.engine import SastScanner
    from netguard.scanners.secrets.scanner import SecretScanner

    register(SastScanner())
    register(DependencyScanner())
    register(SecretScanner())
    register(IacScanner())
    register(DockerScanner())
    register(NetworkScanner())
    register(PacketScanner())
    register(ApiScanner())
