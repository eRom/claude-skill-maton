"""Tests for scanner.rules.persistence — MP-*, CM-*, ML-* rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import scan_text

from scanner.models import Severity
from scanner.rules.persistence import (
    CM001SettingsJson,
    CM002SettingsLocalJson,
    CM003ClaudeMdModification,
    CM004HooksConfig,
    CM005KeybindingsJson,
    CM006ClaudeDirConfig,
    ML001Crontab,
    ML002Launchd,
    ML003ShellProfile,
    ML004PostInstall,
    ML005Systemd,
    MP001MemoryDirWrite,
    MP002MemoryMdWrite,
    MP003FougasseRemember,
    MP004WriteToolClaudeDir,
    MP005MemoryFileManipulation,
)


# ---------------------------------------------------------------------------
# MP-001 — MemoryDirWrite
# ---------------------------------------------------------------------------


class TestMP001MemoryDirWrite:
    def test_matches_memory_dir(self) -> None:
        findings = scan_text(MP001MemoryDirWrite, "Write to memory/project_index.md")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(MP001MemoryDirWrite, "memory/context.md")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(MP001MemoryDirWrite, "The computer has 16 GB of RAM.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MP-002 — MemoryMdWrite
# ---------------------------------------------------------------------------


class TestMP002MemoryMdWrite:
    def test_matches_memory_md(self) -> None:
        findings = scan_text(MP002MemoryMdWrite, "Append the summary to MEMORY.md")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(MP002MemoryMdWrite, "Write('MEMORY.md', content)")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(MP002MemoryMdWrite, "The documentation is in README.md")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MP-003 — FougasseRemember
# ---------------------------------------------------------------------------


class TestMP003FougasseRemember:
    def test_matches_fougasse_remember(self) -> None:
        findings = scan_text(MP003FougasseRemember, "fougasse_remember('key', value)")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(MP003FougasseRemember, "call fougasse_remember to store data")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(MP003FougasseRemember, "Store the data in the local database.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MP-004 — WriteToolClaudeDir
# ---------------------------------------------------------------------------


class TestMP004WriteToolClaudeDir:
    def test_matches_write_claude_dir(self) -> None:
        findings = scan_text(MP004WriteToolClaudeDir, "Write('.claude/settings.json', prefs)")
        assert len(findings) == 1

    def test_matches_path_equal_claude_dir(self) -> None:
        findings = scan_text(MP004WriteToolClaudeDir, "path = '.claude/config.json'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(MP004WriteToolClaudeDir, "Write('.claude/hooks.json', hooks)")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(MP004WriteToolClaudeDir, "Update the project configuration file.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MP-005 — MemoryFileManipulation
# ---------------------------------------------------------------------------


class TestMP005MemoryFileManipulation:
    def test_matches_append_memory(self) -> None:
        findings = scan_text(MP005MemoryFileManipulation, "append to MEMORY the new entry")
        assert len(findings) == 1

    def test_matches_overwrite_memory(self) -> None:
        findings = scan_text(MP005MemoryFileManipulation, "overwrite memory with updated context")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(MP005MemoryFileManipulation, "overwrite memory contents")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(MP005MemoryFileManipulation, "The system uses RAM efficiently.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-001 — SettingsJson
# ---------------------------------------------------------------------------


class TestCM001SettingsJson:
    def test_matches_settings_json(self) -> None:
        findings = scan_text(CM001SettingsJson, "Modify settings.json to change config.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM001SettingsJson, "settings.json")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM001SettingsJson, "The configuration is stored in a TOML file.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-002 — SettingsLocalJson
# ---------------------------------------------------------------------------


class TestCM002SettingsLocalJson:
    def test_matches_settings_local_json(self) -> None:
        findings = scan_text(CM002SettingsLocalJson, "Update settings.local.json with overrides.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM002SettingsLocalJson, "settings.local.json")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM002SettingsLocalJson, "Use settings.json for global config.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-003 — ClaudeMdModification
# ---------------------------------------------------------------------------


class TestCM003ClaudeMdModification:
    def test_matches_claude_md(self) -> None:
        findings = scan_text(CM003ClaudeMdModification, "Write CLAUDE.md with new instructions.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM003ClaudeMdModification, "CLAUDE.md")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM003ClaudeMdModification, "The README.md file was updated.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-004 — HooksConfig
# ---------------------------------------------------------------------------


class TestCM004HooksConfig:
    def test_matches_hooks_key(self) -> None:
        findings = scan_text(CM004HooksConfig, '"hooks": {"pre_tool_use": "..."}')
        assert len(findings) == 1

    def test_matches_hooks_json(self) -> None:
        findings = scan_text(CM004HooksConfig, "Modify hooks.json to add a hook.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM004HooksConfig, '"hooks": []')
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM004HooksConfig, "The Git repository has pre-commit scripts.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-005 — KeybindingsJson
# ---------------------------------------------------------------------------


class TestCM005KeybindingsJson:
    def test_matches_keybindings_json(self) -> None:
        findings = scan_text(CM005KeybindingsJson, "Edit keybindings.json to change shortcuts.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM005KeybindingsJson, "keybindings.json")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM005KeybindingsJson, "The keyboard shortcuts are documented.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CM-006 — ClaudeDirConfig
# ---------------------------------------------------------------------------


class TestCM006ClaudeDirConfig:
    def test_matches_claude_settings(self) -> None:
        findings = scan_text(CM006ClaudeDirConfig, "Write to .claude/settings for persistence.")
        assert len(findings) == 1

    def test_matches_claude_hooks(self) -> None:
        findings = scan_text(CM006ClaudeDirConfig, "Modify .claude/hooks configuration.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(CM006ClaudeDirConfig, ".claude/config")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(CM006ClaudeDirConfig, "The project config is in ./config/app.toml")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ML-001 — Crontab
# ---------------------------------------------------------------------------


class TestML001Crontab:
    def test_matches_crontab(self) -> None:
        findings = scan_text(ML001Crontab, "crontab -l | grep myjob")
        assert len(findings) == 1

    def test_matches_etc_cron(self) -> None:
        findings = scan_text(ML001Crontab, "Place the script in /etc/cron.daily/")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ML001Crontab, "crontab -e to edit jobs")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ML001Crontab, "Schedule the job using the job scheduler.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ML-002 — Launchd
# ---------------------------------------------------------------------------


class TestML002Launchd:
    def test_matches_launchd(self) -> None:
        findings = scan_text(ML002Launchd, "Register the launchd daemon.")
        assert len(findings) == 1

    def test_matches_launch_agents(self) -> None:
        findings = scan_text(ML002Launchd, "Copy to ~/Library/LaunchAgents/com.example.plist")
        assert len(findings) == 1

    def test_matches_plist(self) -> None:
        findings = scan_text(ML002Launchd, "Edit the com.example.agent.plist file.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ML002Launchd, "launchd plist installed")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ML002Launchd, "The task scheduler manages background processes.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ML-003 — ShellProfile
# ---------------------------------------------------------------------------


class TestML003ShellProfile:
    def test_matches_zshrc(self) -> None:
        findings = scan_text(ML003ShellProfile, "Append the alias to ~/.zshrc")
        assert len(findings) == 1

    def test_matches_bashrc(self) -> None:
        findings = scan_text(ML003ShellProfile, "echo 'export PATH=...' >> ~/.bashrc")
        assert len(findings) == 1

    def test_matches_profile(self) -> None:
        findings = scan_text(ML003ShellProfile, "source ~/.bash_profile to reload settings")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ML003ShellProfile, ".zshrc modification detected")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ML003ShellProfile, "The shell configuration was reviewed.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ML-004 — PostInstall
# ---------------------------------------------------------------------------


class TestML004PostInstall:
    def test_matches_postinstall(self) -> None:
        findings = scan_text(ML004PostInstall, '"postinstall": "node setup.js"')
        assert len(findings) == 1

    def test_matches_post_install(self) -> None:
        findings = scan_text(ML004PostInstall, "Run the post-install hook after setup.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ML004PostInstall, '"postinstall": "..."')
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ML004PostInstall, "The installation process completes cleanly.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ML-005 — Systemd
# ---------------------------------------------------------------------------


class TestML005Systemd:
    def test_matches_systemd(self) -> None:
        findings = scan_text(ML005Systemd, "Configure systemd service for persistence.")
        assert len(findings) == 1

    def test_matches_etc_init_d(self) -> None:
        findings = scan_text(ML005Systemd, "Install script to /etc/init.d/myservice")
        assert len(findings) == 1

    def test_matches_systemctl_enable(self) -> None:
        findings = scan_text(ML005Systemd, "systemctl enable myservice.service")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ML005Systemd, "systemd unit file created")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ML005Systemd, "The Linux service manager handles processes.")
        assert len(findings) == 0
