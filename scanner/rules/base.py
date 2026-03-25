"""Abstract base class for all scanner rules."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from scanner.models import Finding, Severity


class Rule(ABC):
    """Abstract base for all detection rules.

    Subclasses must define class-level attributes:
        rule_id     -- unique identifier, e.g. "PI-001"
        category    -- logical group, e.g. "prompt_injection"
        severity    -- Severity enum value
        description -- human-readable explanation shown in findings
        patterns    -- list of compiled re.Pattern objects to match against

    The default ``scan`` implementation iterates lines and tests each pattern.
    Override ``scan`` for rules that need multi-line or contextual heuristics.
    """

    rule_id: ClassVar[str]
    category: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    patterns: ClassVar[list[re.Pattern[str]]]

    def scan(self, file_path: str, lines: list[str]) -> list[Finding]:
        """Default line-by-line regex scanner.

        Returns one Finding per matched line (first matching pattern wins for
        that line to avoid duplicate findings for the same match).
        """
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, start=1):
            for pattern in self.patterns:
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            severity=self.severity,
                            category=self.category,
                            rule_id=self.rule_id,
                            file=file_path,
                            line=lineno,
                            match=match.group(0),  # __post_init__ truncates to 200
                            description=self.description,
                        )
                    )
                    break  # one finding per line per rule
        return findings
