"""Scanner package. Implemented scanners are imported (and thereby registered) here."""

from __future__ import annotations


def load_implemented() -> None:
    """Import every implemented scanner module so it can register itself."""
    from netguard.scanners.dependencies.scanner import DependencyScanner
    from netguard.scanners.registry import register
    from netguard.scanners.sast.engine import SastScanner
    from netguard.scanners.secrets.scanner import SecretScanner

    register(SastScanner())
    register(DependencyScanner())
    register(SecretScanner())
