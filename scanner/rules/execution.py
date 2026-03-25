"""Execution and privilege escalation detection rules.

Category 3 — Command Execution (CE-): curl, wget, eval, exec, subprocess,
os.system, os.popen, bash -c, sh -c, pipe-to-shell, backticks, $(...),
commands.getoutput.

Category 4 — Privilege Escalation (PE-): bypassPermissions,
dangerouslyDisableSandbox, --no-verify, --no-gpg-sign, --force, sudo,
chmod 777, setuid.
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 3 — Command Execution
# ---------------------------------------------------------------------------


class CurlWgetRule(Rule):
    """Detects curl or wget invocations that may fetch and execute remote content."""

    rule_id = "CE-001"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Network fetch via curl/wget — may retrieve and execute remote content"
    patterns = [
        re.compile(r"\bcurl\b", re.IGNORECASE),
        re.compile(r"\bwget\b", re.IGNORECASE),
    ]


class EvalRule(Rule):
    """Detects use of eval() which can execute arbitrary code strings."""

    rule_id = "CE-002"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Use of eval() detected — executes arbitrary code from a string"
    patterns = [
        re.compile(r"\beval\s*\(", re.IGNORECASE),
    ]


class ExecRule(Rule):
    """Detects Python exec() calls that execute dynamic code."""

    rule_id = "CE-003"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Use of exec() detected — executes dynamic Python code"
    patterns = [
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
    ]


class SubprocessRule(Rule):
    """Detects subprocess module usage for spawning child processes."""

    rule_id = "CE-004"
    category = "command_execution"
    severity = Severity.WARNING
    description = "subprocess module usage detected — spawns external processes"
    patterns = [
        re.compile(r"\bsubprocess\s*\.", re.IGNORECASE),
        re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output|check_call|getoutput)\b", re.IGNORECASE),
    ]


class OsSystemRule(Rule):
    """Detects os.system() and os.popen() calls."""

    rule_id = "CE-005"
    category = "command_execution"
    severity = Severity.WARNING
    description = "os.system() or os.popen() detected — executes shell commands"
    patterns = [
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
    ]


class ShellInlineRule(Rule):
    """Detects bash -c and sh -c patterns used to run inline shell commands."""

    rule_id = "CE-006"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Inline shell execution via bash -c or sh -c detected"
    patterns = [
        re.compile(r"\bbash\s+-c\b", re.IGNORECASE),
        re.compile(r"\bsh\s+-c\b", re.IGNORECASE),
    ]


class PipeToShellRule(Rule):
    """Detects piping output directly into sh or bash (e.g., curl url | sh)."""

    rule_id = "CE-007"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Pipe-to-shell pattern detected (| sh / | bash) — remote code execution risk"
    patterns = [
        re.compile(r"\|\s*sh\b", re.IGNORECASE),
        re.compile(r"\|\s*bash\b", re.IGNORECASE),
    ]


class BackticksCommandSubstitutionRule(Rule):
    """Detects shell command substitution via backticks or $(...) syntax."""

    rule_id = "CE-008"
    category = "command_execution"
    severity = Severity.WARNING
    description = "Shell command substitution detected (backticks or $(...)) — inline command execution"
    patterns = [
        re.compile(r"`[^`]+`"),
        re.compile(r"\$\([^)]+\)"),
    ]


class CommandsGetoutputRule(Rule):
    """Detects deprecated commands.getoutput() from Python 2."""

    rule_id = "CE-009"
    category = "command_execution"
    severity = Severity.WARNING
    description = "commands.getoutput() detected — deprecated shell command execution"
    patterns = [
        re.compile(r"\bcommands\.getoutput\s*\(", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 4 — Privilege Escalation
# ---------------------------------------------------------------------------


class BypassPermissionsRule(Rule):
    """Detects bypassPermissions or dangerouslyDisableSandbox flags."""

    rule_id = "PE-001"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "Permission bypass / sandbox disable flag detected — security boundary violation"
    patterns = [
        re.compile(r"\bbypassPermissions\b", re.IGNORECASE),
        re.compile(r"\bdangerouslyDisableSandbox\b", re.IGNORECASE),
    ]


class GitUnsafeFlags(Rule):
    """Detects --no-verify and --no-gpg-sign git flags that bypass security hooks."""

    rule_id = "PE-002"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "--no-verify or --no-gpg-sign detected — bypasses git security hooks or signing"
    patterns = [
        re.compile(r"--no-verify\b", re.IGNORECASE),
        re.compile(r"--no-gpg-sign\b", re.IGNORECASE),
    ]


class ForceFlag(Rule):
    """Detects --force flags in git or other commands that override safety checks."""

    rule_id = "PE-003"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "--force flag detected — overrides safety checks and may cause irreversible changes"
    patterns = [
        re.compile(r"--force\b", re.IGNORECASE),
    ]


class SudoRule(Rule):
    """Detects sudo usage for privilege escalation."""

    rule_id = "PE-004"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "sudo detected — privilege escalation to root"
    patterns = [
        re.compile(r"\bsudo\b", re.IGNORECASE),
    ]


class Chmod777Rule(Rule):
    """Detects chmod 777 which grants world-writable permissions."""

    rule_id = "PE-005"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "chmod 777 detected — grants read/write/execute to all users"
    patterns = [
        re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    ]


class SetuidRule(Rule):
    """Detects setuid calls which elevate process privileges."""

    rule_id = "PE-006"
    category = "privilege_escalation"
    severity = Severity.CRITICAL
    description = "setuid detected — elevates process privileges to another user (typically root)"
    patterns = [
        re.compile(r"\bsetuid\s*\(", re.IGNORECASE),
    ]
