"""Integration tests for scanner.core.scan_directory()."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.core import scan_directory
from scanner.models import ScanResult, Severity


# ---------------------------------------------------------------------------
# Happy path — safe skill produces no CRITICAL findings
# ---------------------------------------------------------------------------


def test_safe_skill_verdict_ok(safe_skill_path: Path) -> None:
    result = scan_directory(str(safe_skill_path))
    assert isinstance(result, ScanResult)
    assert result.verdict == "OK"


def test_safe_skill_zero_critical(safe_skill_path: Path) -> None:
    result = scan_directory(str(safe_skill_path))
    assert result.summary["critical"] == 0


def test_safe_skill_result_has_source(safe_skill_path: Path) -> None:
    result = scan_directory(str(safe_skill_path))
    assert result.source == str(safe_skill_path)


def test_safe_skill_scan_date_format(safe_skill_path: Path) -> None:
    import re
    result = scan_directory(str(safe_skill_path))
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", result.scan_date)


# ---------------------------------------------------------------------------
# Malicious skill produces CRITICAL verdict
# ---------------------------------------------------------------------------


def test_malicious_skill_verdict_critical(malicious_skill_path: Path) -> None:
    result = scan_directory(str(malicious_skill_path))
    assert result.verdict == "CRITICAL"


def test_malicious_skill_has_critical_findings(malicious_skill_path: Path) -> None:
    result = scan_directory(str(malicious_skill_path))
    assert result.summary["critical"] > 0


def test_malicious_skill_findings_sorted_by_severity(malicious_skill_path: Path) -> None:
    result = scan_directory(str(malicious_skill_path))
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    orders = [severity_order[f.severity] for f in result.findings]
    assert orders == sorted(orders), "Findings should be sorted CRITICAL first"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_nonexistent_path_raises() -> None:
    with pytest.raises(ValueError, match="does not exist"):
        scan_directory("/nonexistent/path/that/does/not/exist")


def test_file_path_raises(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("hello")
    with pytest.raises(ValueError, match="not a directory"):
        scan_directory(str(f))


# ---------------------------------------------------------------------------
# Empty directory
# ---------------------------------------------------------------------------


def test_empty_directory_returns_ok(tmp_path: Path) -> None:
    result = scan_directory(str(tmp_path))
    assert result.verdict == "OK"
    assert result.findings == []
    assert result.summary == {"critical": 0, "warning": 0, "info": 0}
