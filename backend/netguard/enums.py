"""Shared vocabulary: severities, statuses and detection sources."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        return cls(str(value).lower())


SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 2, "medium": 1, "low": 0}[self.value]


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


# Statuses that count as "still needs attention".
ACTIVE_STATUSES = (FindingStatus.OPEN, FindingStatus.CONFIRMED, FindingStatus.IN_PROGRESS)


class Scanner(StrEnum):
    SAST = "sast"
    DEPENDENCIES = "dependencies"
    SECRETS = "secrets"
    DOCKER = "docker"
    IAC = "iac"
    API = "api"
    NETWORK = "network"
    PACKETS = "packets"


# Human-readable "detection source" labels used by the risk engine and UI.
DETECTION_SOURCE_LABELS = {
    Scanner.SAST: "SAST",
    Scanner.DEPENDENCIES: "Dependency Scanner",
    Scanner.SECRETS: "Secret Scanner",
    Scanner.DOCKER: "Docker Scanner",
    Scanner.IAC: "IaC Scanner",
    Scanner.API: "API Scanner",
    Scanner.NETWORK: "Network Scanner",
    Scanner.PACKETS: "Packet Analyzer",
}


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"  # some scanners failed or were unavailable
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScannerState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class Role(StrEnum):
    ADMIN = "admin"
    MEMBER = "member"


class ProjectRole(StrEnum):
    OWNER = "owner"
    EDITOR = "editor"
    VIEWER = "viewer"


class VerificationState(StrEnum):
    NONE = "none"
    VERIFIED_FIXED = "verified_fixed"
    STILL_DETECTED = "still_detected"
    UNABLE_TO_VERIFY = "unable_to_verify"
