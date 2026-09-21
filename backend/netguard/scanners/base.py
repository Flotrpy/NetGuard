"""The common scanner interface.

Every scanner (SAST, dependencies, secrets, ...) implements :class:`Scanner`. A scanner takes a
:class:`ScanContext` and returns a :class:`ScanResult` containing normalized
:class:`RawFinding` objects; persistence, de-duplication and risk scoring happen in the scan
service, not in scanners. This keeps scanners small, testable and easy to add.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from netguard.enums import Confidence, Severity
from netguard.enums import Scanner as ScannerName

ProgressFn = Callable[[float, str], None]


class ScanCancelled(Exception):
    """Raised by a scanner when ``ScanContext.check_cancelled`` reports cancellation."""


@dataclass
class AssetRef:
    """The asset a finding is attached to (host, container image, API, ...)."""

    type: str
    identifier: str
    name: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class RawFinding:
    """A scanner-neutral finding, before it is stored in the unified finding database."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str = ""
    cwe: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    file_path: str = ""
    line: int = 0
    end_line: int = 0
    language: str = ""
    code_context: str = ""
    references: list[str] = field(default_factory=list)
    exploitability: str = "medium"  # high | medium | low
    exposure: str = "unknown"  # internet | internal | local | unknown
    asset: AssetRef | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # Distinguishes findings of the same rule in the same file. Defaults to the flagged snippet
    # so that the fingerprint survives unrelated edits that only shift line numbers.
    key: str = ""

    def fingerprint_material(self, scanner: str) -> str:
        key = self.key or _normalize_snippet(self.code_context) or str(self.line)
        asset = self.asset.identifier if self.asset else ""
        return "|".join([scanner, self.rule_id, self.file_path, asset, key])


def _normalize_snippet(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def fingerprint(material: str, occurrence: int = 0) -> str:
    return hashlib.sha256(f"{material}#{occurrence}".encode()).hexdigest()


@dataclass
class ScanContext:
    """Everything a scanner needs to run. ``root`` is a read-only workspace snapshot."""

    root: Path | None = None
    config: dict[str, Any] = field(default_factory=dict)
    max_file_bytes: int = 1024 * 1024
    progress: ProgressFn = lambda pct, msg="": None  # noqa: E731
    is_cancelled: Callable[[], bool] = lambda: False  # noqa: E731
    # Optional: restrict to these relative paths (incremental scanning of changed files).
    only_paths: set[str] | None = None

    def check_cancelled(self) -> None:
        if self.is_cancelled():
            raise ScanCancelled()


@dataclass
class ScanResult:
    findings: list[RawFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # True when every relevant input was analysed. If False, the absence of a finding must not
    # be read as "fixed" (used by the patch validator and auto-resolution).
    complete: bool = True


@dataclass(frozen=True)
class ScannerInfo:
    name: str
    display_name: str
    version: str
    description: str
    supported_inputs: tuple[str, ...]
    available: bool
    status_note: str


class Scanner(ABC):
    """Base class for all scanners."""

    name: ClassVar[ScannerName]
    display_name: ClassVar[str]
    version: ClassVar[str] = "1.0.0"
    description: ClassVar[str] = ""
    # What the scanner consumes: "source" (repo files), "container_image", "network_target",
    # "api_target", "pcap" ...
    supported_inputs: ClassVar[tuple[str, ...]] = ("source",)

    def availability(self) -> tuple[bool, str]:
        """Whether the scanner can run in this environment, and why not if it cannot."""
        return True, ""

    @abstractmethod
    def scan(self, ctx: ScanContext) -> ScanResult: ...

    def info(self) -> ScannerInfo:
        available, note = self.availability()
        return ScannerInfo(
            name=self.name.value,
            display_name=self.display_name,
            version=self.version,
            description=self.description,
            supported_inputs=tuple(self.supported_inputs),
            available=available,
            status_note=note,
        )


class PlannedScanner(Scanner):
    """Placeholder for a scanner that is designed but not implemented yet.

    It never produces findings: it exists so the UI/API can list the module honestly as
    "planned" instead of fabricating results.
    """

    def availability(self) -> tuple[bool, str]:
        return False, "Planned: not implemented yet"

    def scan(self, ctx: ScanContext) -> ScanResult:
        return ScanResult(
            metadata={"state": "unavailable"}, warnings=[f"{self.display_name} is not available"]
        )
