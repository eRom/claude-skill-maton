"""Core scanner orchestrator — ties loader, rules, and findings together."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from scanner import loader, rules
from scanner.models import Finding, ScanResult, Severity

# Severity ordering for sorting: lower index = higher priority
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
}


def scan_directory(path: str) -> ScanResult:
    """Scan *path* recursively and return a :class:`ScanResult`.

    Args:
        path: Absolute or relative path to the directory to scan.

    Returns:
        A :class:`ScanResult` with all findings sorted by severity (CRITICAL
        first), then by file path, then by line number.

    Raises:
        ValueError: If *path* does not exist or is not a directory.
    """
    # --- Validate path ---
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {path!r}")
    if not os.path.isdir(path):
        raise ValueError(f"Path is not a directory: {path!r}")

    # --- Load files ---
    files = loader.load_files(path)

    # --- Get rules ---
    all_rules = rules.get_all_rules()

    # --- Apply every rule to every file ---
    findings: list[Finding] = []
    for file_path, lines in files:
        for rule in all_rules:
            findings.extend(rule.scan(file_path, lines))

    # --- Sort findings: severity asc (CRITICAL=0 first), then file, then line ---
    findings.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.file, f.line)
    )

    # --- Build and return result ---
    scan_date = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ScanResult(source=path, scan_date=scan_date, findings=findings)
