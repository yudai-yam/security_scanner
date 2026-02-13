"""Data models for security scan findings and results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    def __ge__(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


@dataclass
class Finding:
    scanner: str
    severity: Severity
    title: str
    description: str
    location: str
    remediation: str
    cwe_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    scanner_name: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    scanned_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "duration_seconds": self.duration_seconds,
            "scanned_at": self.scanned_at.isoformat(),
        }
