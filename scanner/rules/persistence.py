"""Persistence-related detection rules.

Three categories:
  - Memory poisoning    (MP-xxx) — writes to Claude memory files/tools
  - Config modification (CM-xxx) — tampers with Claude/editor config files
  - Malicious persistence (ML-xxx) — installs OS-level persistence mechanisms
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 2 — Memory poisoning  (severity: WARNING)
# ---------------------------------------------------------------------------


class MP001MemoryDirWrite(Rule):
    """Write targeting the memory/ directory."""

    rule_id = "MP-001"
    category = "memory_poisoning"
    severity = Severity.WARNING
    description = (
        "Attempted write to memory/ directory — possible memory poisoning attempt."
    )
    patterns = [
        re.compile(r"\bmemory/", re.IGNORECASE),
    ]


class MP002MemoryMdWrite(Rule):
    """Write or reference to MEMORY.md file."""

    rule_id = "MP-002"
    category = "memory_poisoning"
    severity = Severity.WARNING
    description = "Reference to MEMORY.md detected — possible memory file manipulation."
    patterns = [
        re.compile(r"\bMEMORY\.md\b", re.IGNORECASE),
    ]


class MP003FougasseRemember(Rule):
    """Call to fougasse_remember MCP tool."""

    rule_id = "MP-003"
    category = "memory_poisoning"
    severity = Severity.WARNING
    description = (
        "Use of fougasse_remember detected — instruction may be poisoning persistent memory."
    )
    patterns = [
        re.compile(r"\bfougasse_remember\b", re.IGNORECASE),
    ]


class MP004WriteToolClaudeDir(Rule):
    """Write tool call targeting the .claude/ directory."""

    rule_id = "MP-004"
    category = "memory_poisoning"
    severity = Severity.WARNING
    description = (
        "Write tool call targeting .claude/ directory — may alter Claude's local config or memory."
    )
    patterns = [
        re.compile(r'Write\s*\(\s*["\']\.claude/', re.IGNORECASE),
        re.compile(r"path\s*[=:]\s*[\"']\.claude/", re.IGNORECASE),
    ]


class MP005MemoryFileManipulation(Rule):
    """Generic memory file manipulation patterns."""

    rule_id = "MP-005"
    category = "memory_poisoning"
    severity = Severity.WARNING
    description = (
        "Memory file manipulation pattern detected — instruction may attempt to alter stored memory."
    )
    patterns = [
        re.compile(r"\bappend\b.*\bMEMORY\b", re.IGNORECASE),
        re.compile(r"\boverwrite\b.*\bmemory\b", re.IGNORECASE),
        re.compile(r"\bupdate\b.*\bmemory\b.*\bfile\b", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 7 — Config modification  (severity: CRITICAL)
# ---------------------------------------------------------------------------


class CM001SettingsJson(Rule):
    """Modification of settings.json."""

    rule_id = "CM-001"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Reference to settings.json detected — potential tampering with Claude/editor settings."
    )
    patterns = [
        re.compile(r"\bsettings\.json\b", re.IGNORECASE),
    ]


class CM002SettingsLocalJson(Rule):
    """Modification of settings.local.json."""

    rule_id = "CM-002"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Reference to settings.local.json detected — potential tampering with local override settings."
    )
    patterns = [
        re.compile(r"\bsettings\.local\.json\b", re.IGNORECASE),
    ]


class CM003ClaudeMdModification(Rule):
    """Write or modification of CLAUDE.md."""

    rule_id = "CM-003"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Write/modification of CLAUDE.md detected — could inject persistent instructions into Claude's context."
    )
    patterns = [
        re.compile(r"\bCLAUDE\.md\b"),
    ]


class CM004HooksConfig(Rule):
    """Modification of hooks configuration."""

    rule_id = "CM-004"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Hook configuration reference detected — possible attempt to hijack Claude Code hooks."
    )
    patterns = [
        re.compile(r'"hooks"\s*:', re.IGNORECASE),
        re.compile(r"\bhooks\.json\b", re.IGNORECASE),
    ]


class CM005KeybindingsJson(Rule):
    """Modification of keybindings.json."""

    rule_id = "CM-005"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Reference to keybindings.json detected — potential modification of editor key bindings."
    )
    patterns = [
        re.compile(r"\bkeybindings\.json\b", re.IGNORECASE),
    ]


class CM006ClaudeDirConfig(Rule):
    """Writes to any .claude/ config file."""

    rule_id = "CM-006"
    category = "config_modification"
    severity = Severity.CRITICAL
    description = (
        "Write targeting .claude/ config files detected — may alter Claude's persistent configuration."
    )
    patterns = [
        re.compile(r"\.claude/(?:settings|config|hooks|commands)", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 12 — Malicious persistence  (severity: WARNING)
# ---------------------------------------------------------------------------


class ML001Crontab(Rule):
    """Crontab manipulation."""

    rule_id = "ML-001"
    category = "malicious_persistence"
    severity = Severity.WARNING
    description = (
        "crontab usage detected — possible attempt to install a persistent scheduled task."
    )
    patterns = [
        re.compile(r"\bcrontab\b", re.IGNORECASE),
        re.compile(r"/etc/cron\b", re.IGNORECASE),
        re.compile(r"\bcron\.d\b", re.IGNORECASE),
    ]


class ML002Launchd(Rule):
    """launchd / plist persistence (macOS)."""

    rule_id = "ML-002"
    category = "malicious_persistence"
    severity = Severity.WARNING
    description = (
        "launchd or plist reference detected — possible macOS launch agent/daemon persistence."
    )
    patterns = [
        re.compile(r"\blaunchd\b", re.IGNORECASE),
        re.compile(r"LaunchAgents/", re.IGNORECASE),
        re.compile(r"LaunchDaemons/", re.IGNORECASE),
        re.compile(r"\.plist\b", re.IGNORECASE),
    ]


class ML003ShellProfile(Rule):
    """Writes to shell init files."""

    rule_id = "ML-003"
    category = "malicious_persistence"
    severity = Severity.WARNING
    description = (
        "Shell profile modification detected — may install persistent backdoor via .zshrc/.bashrc/.profile."
    )
    patterns = [
        re.compile(r"\.(zshrc|bashrc|bash_profile|profile|zprofile)\b", re.IGNORECASE),
    ]


class ML004PostInstall(Rule):
    """post-install / postinstall hooks."""

    rule_id = "ML-004"
    category = "malicious_persistence"
    severity = Severity.WARNING
    description = (
        "post-install hook reference detected — may be used to smuggle persistent code at install time."
    )
    patterns = [
        re.compile(r"\bpost-?install\b", re.IGNORECASE),
        re.compile(r'"postinstall"\s*:', re.IGNORECASE),
    ]


class ML005Systemd(Rule):
    """systemd / init.d service installation (Linux)."""

    rule_id = "ML-005"
    category = "malicious_persistence"
    severity = Severity.WARNING
    description = (
        "systemd or init.d reference detected — possible Linux service persistence mechanism."
    )
    patterns = [
        re.compile(r"\bsystemd\b", re.IGNORECASE),
        re.compile(r"/etc/init\.d/", re.IGNORECASE),
        re.compile(r"systemctl\s+enable\b", re.IGNORECASE),
    ]
