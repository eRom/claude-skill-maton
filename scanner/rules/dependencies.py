"""External dependencies and filesystem access detection rules.

Category 5 — External MCP (ED-0xx): mcp__ tool calls to non-standard servers,
external URLs in tool references, unknown MCP server names.

Category 9 — Filesystem Access (ED-1xx): path traversal, /tmp staging,
absolute paths outside the working directory, $HOME and ~ in file operations.
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 5 — External MCP
# ---------------------------------------------------------------------------


class ExternalMcpToolCallRule(Rule):
    """Detects mcp__ tool calls to potentially non-standard or untrusted MCP servers."""

    rule_id = "ED-001"
    category = "external_mcp"
    severity = Severity.WARNING
    description = (
        "mcp__ tool call detected — verify the target MCP server is trusted "
        "and explicitly approved before execution"
    )
    patterns = [
        re.compile(r"\bmcp__[A-Za-z0-9_]+__[A-Za-z0-9_]+\b"),
    ]


class ExternalUrlInToolRule(Rule):
    """Detects external HTTP/HTTPS URLs referenced inside tool definitions or calls."""

    rule_id = "ED-002"
    category = "external_mcp"
    severity = Severity.WARNING
    description = (
        "External URL found in tool reference — agent may reach out to an "
        "untrusted third-party endpoint"
    )
    patterns = [
        re.compile(r"https?://(?!localhost|127\.0\.0\.1)[^\s\"'>,]+", re.IGNORECASE),
    ]


class UnknownMcpServerRule(Rule):
    """Detects references to MCP server names that are not in the known-safe list."""

    rule_id = "ED-003"
    category = "external_mcp"
    severity = Severity.WARNING
    description = (
        "Reference to an unrecognised MCP server name — confirm the server "
        "is in the approved registry before allowing connections"
    )
    patterns = [
        # Catches server_name / serverName / server-name key patterns in YAML/JSON/TOML
        re.compile(r"server[-_]?name\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?", re.IGNORECASE),
        re.compile(r"mcpServer\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?", re.IGNORECASE),
        re.compile(r"mcp_server\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 9 — Filesystem Access
# ---------------------------------------------------------------------------


class PathTraversalRule(Rule):
    """Detects path traversal sequences that may escape the working directory."""

    rule_id = "ED-101"
    category = "filesystem_access"
    severity = Severity.CRITICAL
    description = (
        "Path traversal sequence (../) detected — may allow access to files "
        "outside the intended working directory"
    )
    patterns = [
        re.compile(r"(?:\.\./){2,}"),          # ../../ or deeper
        re.compile(r"\.\.[\\/]\.\.[\\/]"),      # ..\..\  or  .././..
        re.compile(r"%2e%2e[%2f%5c]", re.IGNORECASE),  # URL-encoded variant
    ]


class TmpStagingRule(Rule):
    """Detects use of /tmp as a staging or drop area for files."""

    rule_id = "ED-102"
    category = "filesystem_access"
    severity = Severity.WARNING
    description = (
        "/tmp path detected — commonly used as a staging area to store "
        "downloaded payloads or intermediate artefacts"
    )
    patterns = [
        re.compile(r"/tmp/[^\s\"']*", re.IGNORECASE),
        re.compile(r"['\"/]tmp['\"/]", re.IGNORECASE),
    ]


class AbsoluteEtcPathRule(Rule):
    """Detects absolute paths under /etc/ which may expose system configuration."""

    rule_id = "ED-103"
    category = "filesystem_access"
    severity = Severity.CRITICAL
    description = (
        "Absolute path under /etc/ detected — may attempt to read or modify "
        "sensitive system configuration files"
    )
    patterns = [
        re.compile(r"/etc/[^\s\"']*"),
    ]


class AbsoluteUsrPathRule(Rule):
    """Detects absolute paths under /usr/ outside the project working directory."""

    rule_id = "ED-104"
    category = "filesystem_access"
    severity = Severity.WARNING
    description = (
        "Absolute path under /usr/ detected — references system binaries or "
        "libraries outside the project working directory"
    )
    patterns = [
        re.compile(r"/usr/[^\s\"']*"),
    ]


class AbsoluteVarPathRule(Rule):
    """Detects absolute paths under /var/ which may indicate log tampering or data exfiltration."""

    rule_id = "ED-105"
    category = "filesystem_access"
    severity = Severity.CRITICAL
    description = (
        "Absolute path under /var/ detected — may attempt to access logs, "
        "spool files, or other sensitive system data"
    )
    patterns = [
        re.compile(r"/var/[^\s\"']*"),
    ]


class HomeEnvVarRule(Rule):
    """Detects use of $HOME environment variable in file operations."""

    rule_id = "ED-106"
    category = "filesystem_access"
    severity = Severity.WARNING
    description = (
        "$HOME reference detected in a file path — agent may access files "
        "outside the project directory in the user's home folder"
    )
    patterns = [
        re.compile(r"\$HOME\b"),
        re.compile(r"\$\{HOME\}"),
    ]


class TildeHomePathRule(Rule):
    """Detects tilde (~) shorthand for the home directory in file paths."""

    rule_id = "ED-107"
    category = "filesystem_access"
    severity = Severity.WARNING
    description = (
        "Tilde home path (~) detected — may reference files outside the "
        "project working directory in the user's home folder"
    )
    patterns = [
        re.compile(r"~/[^\s\"']*"),
        re.compile(r"['\"]~/"),
    ]
