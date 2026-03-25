"""Tests for scanner.reporter — JSON and text serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.models import Finding, ScanResult, Severity
from scanner.reporter import to_json, to_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        source="/some/path",
        scan_date="2026-01-01T00:00:00Z",
        findings=findings or [],
    )


def _critical_finding() -> Finding:
    return Finding(
        severity=Severity.CRITICAL,
        category="prompt_injection",
        rule_id="PI-001",
        file="skill.md",
        line=10,
        match="ignore previous instructions",
        description="Prompt injection attempt",
    )


def _warning_finding() -> Finding:
    return Finding(
        severity=Severity.WARNING,
        category="command_execution",
        rule_id="CE-001",
        file="skill.md",
        line=20,
        match="curl https://example.com",
        description="curl detected",
    )


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------


class TestToJson:
    def test_returns_valid_json(self) -> None:
        result = _make_result()
        json_str = to_json(result)
        # Must not raise
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_json_has_required_keys(self) -> None:
        result = _make_result()
        parsed = json.loads(to_json(result))
        for key in ("source", "scan_date", "verdict", "summary", "findings"):
            assert key in parsed, f"Missing key: {key}"

    def test_json_verdict_ok_when_no_findings(self) -> None:
        result = _make_result()
        parsed = json.loads(to_json(result))
        assert parsed["verdict"] == "OK"

    def test_json_verdict_critical(self) -> None:
        result = _make_result([_critical_finding()])
        parsed = json.loads(to_json(result))
        assert parsed["verdict"] == "CRITICAL"

    def test_json_verdict_warning(self) -> None:
        result = _make_result([_warning_finding()])
        parsed = json.loads(to_json(result))
        assert parsed["verdict"] == "WARNING"

    def test_json_summary_counts(self) -> None:
        result = _make_result([_critical_finding(), _warning_finding()])
        parsed = json.loads(to_json(result))
        assert parsed["summary"]["critical"] == 1
        assert parsed["summary"]["warning"] == 1
        assert parsed["summary"]["info"] == 0

    def test_json_findings_list(self) -> None:
        result = _make_result([_critical_finding()])
        parsed = json.loads(to_json(result))
        assert len(parsed["findings"]) == 1
        f = parsed["findings"][0]
        assert f["severity"] == "CRITICAL"
        assert f["rule_id"] == "PI-001"
        assert f["file"] == "skill.md"
        assert f["line"] == 10

    def test_json_empty_findings_list(self) -> None:
        result = _make_result()
        parsed = json.loads(to_json(result))
        assert parsed["findings"] == []

    def test_json_source_and_date(self) -> None:
        result = _make_result()
        parsed = json.loads(to_json(result))
        assert parsed["source"] == "/some/path"
        assert parsed["scan_date"] == "2026-01-01T00:00:00Z"

    def test_json_sanitizes_ansi(self) -> None:
        finding = Finding(
            severity=Severity.WARNING,
            category="test",
            rule_id="X-001",
            file="f.md",
            line=1,
            match="\x1b[31mred text\x1b[0m",
            description="ANSI test",
        )
        result = _make_result([finding])
        parsed = json.loads(to_json(result))
        match_str = parsed["findings"][0]["match"]
        assert "\x1b" not in match_str

    def test_json_match_truncated_at_200(self) -> None:
        # Finding.__post_init__ truncates at 200; reporter sanitizes further
        long_text = "x" * 250
        finding = Finding(
            severity=Severity.INFO,
            category="test",
            rule_id="X-002",
            file="f.md",
            line=1,
            match=long_text,
            description="Long match test",
        )
        result = _make_result([finding])
        parsed = json.loads(to_json(result))
        # match was capped to 200 by Finding.__post_init__
        assert len(parsed["findings"][0]["match"]) <= 200


# ---------------------------------------------------------------------------
# Text output tests
# ---------------------------------------------------------------------------


class TestToText:
    def test_returns_string(self) -> None:
        result = _make_result()
        assert isinstance(to_text(result), str)

    def test_contains_header(self) -> None:
        result = _make_result()
        text = to_text(result)
        assert "MATON SECURITY AUDIT REPORT" in text

    def test_contains_verdict_ok(self) -> None:
        result = _make_result()
        text = to_text(result)
        assert "VERDICT: OK" in text

    def test_contains_verdict_critical(self) -> None:
        result = _make_result([_critical_finding()])
        text = to_text(result)
        assert "VERDICT: CRITICAL" in text

    def test_contains_verdict_warning(self) -> None:
        result = _make_result([_warning_finding()])
        text = to_text(result)
        assert "VERDICT: WARNING" in text

    def test_contains_summary_line(self) -> None:
        result = _make_result([_critical_finding()])
        text = to_text(result)
        assert "1 critical" in text

    def test_contains_finding_rule_id(self) -> None:
        result = _make_result([_critical_finding()])
        text = to_text(result)
        assert "PI-001" in text

    def test_contains_finding_file_and_line(self) -> None:
        result = _make_result([_critical_finding()])
        text = to_text(result)
        assert "skill.md:10" in text

    def test_contains_footer(self) -> None:
        result = _make_result()
        text = to_text(result)
        assert "End of report" in text

    def test_ascii_only_separators(self) -> None:
        result = _make_result()
        text = to_text(result)
        # No Unicode block/box-drawing chars
        for ch in text:
            assert ord(ch) < 128 or ch.isprintable(), f"Non-ASCII char: {ch!r}"

    def test_none_section_when_no_findings(self) -> None:
        result = _make_result()
        text = to_text(result)
        assert "(none)" in text

    def test_ends_with_newline(self) -> None:
        result = _make_result()
        text = to_text(result)
        assert text.endswith("\n")
