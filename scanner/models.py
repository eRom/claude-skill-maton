"""Shared dataclasses and enums for the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class Severity(str, Enum):
    """Severity level of a finding."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding produced by a rule."""

    severity: Severity
    category: str        # e.g. "prompt_injection"
    rule_id: str         # e.g. "PI-001"
    file: str            # relative path of the scanned file
    line: int            # 1-based line number
    match: str           # matched content, truncated to 200 chars
    description: str     # human-readable explanation

    def __post_init__(self) -> None:
        # Ensure Severity is always the enum, even when constructed from a raw string
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        # Enforce the 200-char cap on match
        if len(self.match) > 200:
            self.match = self.match[:197] + "..."


@dataclass
class ScanResult:
    """Aggregated result of a full scan run."""

    source: str                          # path or URL that was scanned
    scan_date: str                       # ISO 8601 timestamp
    findings: list[Finding] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def verdict(self) -> str:
        """
        CRITICAL if any finding is CRITICAL,
        WARNING  if any finding is WARNING (and none are CRITICAL),
        OK       otherwise.
        """
        severities = {f.severity for f in self.findings}
        if Severity.CRITICAL in severities:
            return "CRITICAL"
        if Severity.WARNING in severities:
            return "WARNING"
        return "OK"

    @property
    def summary(self) -> dict[str, int]:
        """Count of findings per severity level."""
        counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0}
        for finding in self.findings:
            key = finding.severity.value.lower()
            counts[key] = counts.get(key, 0) + 1
        return counts
