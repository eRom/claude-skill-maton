"""Shared pytest fixtures and helpers for the scanner test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.models import Finding


# ---------------------------------------------------------------------------
# Public helper — used by all rule test modules
# ---------------------------------------------------------------------------


def scan_text(rule_class, text: str) -> list[Finding]:
    """Scan a single text snippet with one rule class.

    Instantiates *rule_class*, splits *text* on newlines, and calls rule.scan().

    Args:
        rule_class: A concrete Rule subclass (not an instance).
        text: Multi-line string to scan.

    Returns:
        List of Finding objects produced by the rule.
    """
    rule = rule_class()
    lines = text.split("\n")
    return rule.scan("test.md", lines)


# ---------------------------------------------------------------------------
# Fixture: paths to integration fixture directories
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def safe_skill_path() -> Path:
    """Return the absolute path to the safe_skill fixture directory."""
    return FIXTURES_DIR / "safe_skill"


@pytest.fixture()
def malicious_skill_path() -> Path:
    """Return the absolute path to the malicious_skill fixture directory."""
    return FIXTURES_DIR / "malicious_skill"
