"""Scanner registry: the single place scanners are discovered."""

from __future__ import annotations

from netguard.enums import Scanner as ScannerName
from netguard.scanners.base import PlannedScanner, Scanner, ScannerInfo

_REGISTRY: dict[str, Scanner] = {}


def register(scanner: Scanner) -> Scanner:
    _REGISTRY[scanner.name.value] = scanner
    return scanner


def get_scanner(name: str) -> Scanner:
    _load_builtin()
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"Unknown scanner: {name}") from exc


def all_scanners() -> list[Scanner]:
    _load_builtin()
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def scanner_infos() -> list[ScannerInfo]:
    return [s.info() for s in all_scanners()]


class _Planned(PlannedScanner):
    def __init__(self, name: ScannerName, display: str, description: str, inputs: tuple[str, ...]):
        self.name = name  # type: ignore[misc]
        self.display_name = display  # type: ignore[misc]
        self.description = description  # type: ignore[misc]
        self.supported_inputs = inputs  # type: ignore[misc]


_PLANNED = [
    (ScannerName.SAST, "SAST Code Scanner", "Static analysis of source code.", ("source",)),
    (ScannerName.DEPENDENCIES, "Dependency Scanner", "Known-vulnerable packages.", ("source",)),
    (ScannerName.SECRETS, "Secret Scanner", "Exposed credentials.", ("source",)),
    (ScannerName.DOCKER, "Docker Scanner", "Container images/config.", ("source",)),
    (ScannerName.IAC, "IaC Scanner", "Infrastructure-as-code misconfigurations.", ("source",)),
    (ScannerName.API, "API Scanner", "Authorized web API checks.", ("api_target",)),
    (ScannerName.NETWORK, "Network Scanner", "Authorized network inventory.", ("network_target",)),
    (ScannerName.PACKETS, "Packet Analyzer", "Packet capture analysis.", ("pcap",)),
]

_loaded = False


def _load_builtin() -> None:
    """Register planned placeholders first, then let implemented scanners replace them."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    for name, display, desc, inputs in _PLANNED:
        _REGISTRY.setdefault(name.value, _Planned(name, display, desc, inputs))
    # Implemented scanners register themselves on import (see netguard.scanners.__init__).
    from netguard import scanners  # noqa: F401

    scanners.load_implemented()
