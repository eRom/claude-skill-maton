"""Serialization helpers: JSON and human-readable text reports."""

from __future__ import annotations

import json
import re

from scanner.models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Safety helpers
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

_MAX_MATCH_DISPLAY = 120  # chars shown in text output (match is already <= 200)


def _sanitize(text: str) -> str:
    """Strip ANSI escape sequences and control characters from a match string."""
    text = _ANSI_RE.sub("", text)
    # Replace non-printable control chars (except regular whitespace)
    text = "".join(
        ch if (ch.isprintable() or ch in ("\t",)) else " " for ch in text
    )
    return text.strip()


def _truncate(text: str, max_len: int = _MAX_MATCH_DISPLAY) -> str:
    text = _sanitize(text)
    if len(text) > max_len:
        return text[:max_len - 3] + "..."
    return text


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------


def to_json(result: ScanResult) -> str:
    """Serialize a ScanResult to a valid JSON string.

    The JSON structure conforms to the documented format:
    {
        "source": "...",
        "scan_date": "...",
        "verdict": "...",
        "summary": {"critical": N, "warning": N, "info": N},
        "findings": [...]
    }
    """
    findings_list = [
        {
            "severity": f.severity.value,
            "category": f.category,
            "file": f.file,
            "line": f.line,
            "match": _sanitize(f.match),
            "rule_id": f.rule_id,
            "description": f.description,
        }
        for f in result.findings
    ]

    payload = {
        "source": result.source,
        "scan_date": result.scan_date,
        "verdict": result.verdict,
        "summary": result.summary,
        "findings": findings_list,
    }

    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Text serialization
# ---------------------------------------------------------------------------

_SEP_HEAVY = "=" * 44
_SEP_LIGHT = "-" * 44

_VERDICT_ASCII = {
    "CRITICAL": (
        "  *** VERDICT: CRITICAL ***\n"
        "  Immediate action required."
    ),
    "WARNING": (
        "  *** VERDICT: WARNING ***\n"
        "  Review findings carefully."
    ),
    "OK": (
        "  *** VERDICT: OK ***\n"
        "  No significant threats detected."
    ),
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.WARNING, Severity.INFO]


def to_text(result: ScanResult) -> str:
    """Serialize a ScanResult to a human-readable ASCII text report."""

    summary = result.summary
    lines: list[str] = []

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------
    lines += [
        _SEP_HEAVY,
        "  MATON SECURITY AUDIT REPORT",
        _SEP_HEAVY,
        "",
        f"Source:    {result.source}",
        f"Date:      {result.scan_date}",
        f"Verdict:   {result.verdict}",
        "",
        _VERDICT_ASCII[result.verdict],
        "",
        _SEP_LIGHT,
        "",
        f"Summary:  {summary['critical']} critical, "
        f"{summary['warning']} warning, "
        f"{summary['info']} info",
        "",
    ]

    # ------------------------------------------------------------------
    # Findings grouped by severity
    # ------------------------------------------------------------------
    findings_by_severity: dict[Severity, list[Finding]] = {
        Severity.CRITICAL: [],
        Severity.WARNING: [],
        Severity.INFO: [],
    }
    for finding in result.findings:
        findings_by_severity[finding.severity].append(finding)

    for severity in _SEVERITY_ORDER:
        group = findings_by_severity[severity]
        count = len(group)

        lines += [
            _SEP_LIGHT,
            f"  {severity.value} ({count})",
            _SEP_LIGHT,
        ]

        if count == 0:
            lines += ["", "  (none)", ""]
            continue

        lines.append("")
        for finding in group:
            lines += [
                f"[{finding.rule_id}] {finding.description}",
                f"  File:  {finding.file}:{finding.line}",
                f'  Match: "{_truncate(finding.match)}"',
                "",
            ]

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------
    lines += [
        _SEP_HEAVY,
        "  End of report.",
        _SEP_HEAVY,
    ]

    return "\n".join(lines) + "\n"
