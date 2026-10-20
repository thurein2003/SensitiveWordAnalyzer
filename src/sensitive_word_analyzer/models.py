"""Typed result models shared by the scanner and report writers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Finding severity, ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(value.lower())
        except ValueError as exc:
            choices = ", ".join(item.value for item in cls)
            raise ValueError(f"invalid severity {value!r}; choose one of: {choices}") from exc

    @property
    def rank(self) -> int:
        return list(type(self)).index(self)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    category: str
    severity: Severity
    description: str
    match: str
    snippet: str
    source: str
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class FileReport:
    path: str
    size: int
    file_type: str
    hashes: Dict[str, str] = field(default_factory=dict)
    entropy: Optional[float] = None
    findings: List[Finding] = field(default_factory=list)
    indicators: Dict[str, List[str]] = field(default_factory=dict)
    skipped_reason: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["findings"] = [finding.to_dict() for finding in self.findings]
        return result


@dataclass
class ScanReport:
    target: str
    started_at: str
    duration_seconds: float
    files: List[FileReport] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return sum(len(file.findings) for file in self.files)

    @property
    def scanned_count(self) -> int:
        return sum(not file.skipped_reason and not file.error for file in self.files)

    @property
    def skipped_count(self) -> int:
        return sum(bool(file.skipped_reason) for file in self.files)

    @property
    def error_count(self) -> int:
        return sum(bool(file.error) for file in self.files)

    @property
    def highest_severity(self) -> Optional[Severity]:
        severities = [finding.severity for file in self.files for finding in file.findings]
        return max(severities, key=lambda severity: severity.rank, default=None)

    def to_dict(self) -> Dict[str, Any]:
        highest = self.highest_severity
        return {
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "files_discovered": len(self.files),
                "files_scanned": self.scanned_count,
                "files_skipped": self.skipped_count,
                "errors": self.error_count,
                "findings": self.finding_count,
                "highest_severity": highest.value if highest else None,
            },
            "files": [file.to_dict() for file in self.files],
        }
