"""Scanner package. Implemented scanners are imported (and thereby registered) here."""

from __future__ import annotations


def load_implemented() -> None:
    """Import every implemented scanner module so it can register itself."""
    # Each phase adds its scanner import here.
