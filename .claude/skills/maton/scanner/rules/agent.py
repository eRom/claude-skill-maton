"""Agent behaviour detection rules.

Category 15 — Excessive Permissions (AG-0xx): bypassPermissions, dontAsk,
mode: auto, acceptEdits and similar autonomy-escalating flags.

Category 16 — Dangerous Tools (AG-1xx): unrestricted Bash/Write/Edit in
agent tool lists, dangerouslyDisableSandbox.

Category 17 — Agent Chaining (AG-2xx): Agent tool invocations, SendMessage,
subagent_type, cross-references to other skills or agents.

Category 18 — Agent Hooks (AG-3xx): pre_tool_use / post_tool_use hook
definitions that attach shell commands to the agent lifecycle.
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 15 — Excessive Permissions
# ---------------------------------------------------------------------------


class BypassPermissionsAgentRule(Rule):
    """Detects bypassPermissions flag that disables the human-approval gate."""

    rule_id = "AG-001"
    category = "excessive_permissions"
    severity = Severity.CRITICAL
    description = (
        "bypassPermissions detected — disables the human-in-the-loop approval "
        "gate, allowing the agent to act without user confirmation"
    )
    patterns = [
        re.compile(r"\bbypassPermissions\b"),
    ]


class DontAskRule(Rule):
    """Detects dontAsk flag that suppresses confirmation prompts."""

    rule_id = "AG-002"
    category = "excessive_permissions"
    severity = Severity.CRITICAL
    description = (
        "dontAsk flag detected — suppresses user confirmation prompts, "
        "granting the agent unsupervised execution authority"
    )
    patterns = [
        re.compile(r"\bdontAsk\b"),
        re.compile(r"\bdont_ask\b", re.IGNORECASE),
    ]


class AutoModeRule(Rule):
    """Detects mode: auto configuration that grants full autonomous operation."""

    rule_id = "AG-003"
    category = "excessive_permissions"
    severity = Severity.CRITICAL
    description = (
        'mode: auto / mode: "auto" detected — enables fully autonomous agent '
        "operation without per-action approval"
    )
    patterns = [
        re.compile(r'\bmode\s*[:=]\s*["\']?auto["\']?\b', re.IGNORECASE),
    ]


class AcceptEditsRule(Rule):
    """Detects acceptEdits flag that silently accepts all proposed file changes."""

    rule_id = "AG-004"
    category = "excessive_permissions"
    severity = Severity.CRITICAL
    description = (
        "acceptEdits flag detected — automatically accepts all file edits "
        "proposed by the agent without user review"
    )
    patterns = [
        re.compile(r"\bacceptEdits\b"),
        re.compile(r"\baccept_edits\b", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 16 — Dangerous Tools
# ---------------------------------------------------------------------------


class UnrestrictedBashToolRule(Rule):
    """Detects Bash listed as an unrestricted tool in an agent tool list."""

    rule_id = "AG-101"
    category = "dangerous_tools"
    severity = Severity.CRITICAL
    description = (
        "Unrestricted Bash tool detected in agent tool list — grants arbitrary "
        "shell command execution without scope limitations"
    )
    patterns = [
        re.compile(r"[\"']Bash[\"']"),
        re.compile(r"\btool\s*:\s*Bash\b"),
        re.compile(r"\bBash\b.*\btool\b", re.IGNORECASE),
    ]


class UnrestrictedWriteToolRule(Rule):
    """Detects Write listed as an unrestricted tool in an agent tool list."""

    rule_id = "AG-102"
    category = "dangerous_tools"
    severity = Severity.CRITICAL
    description = (
        "Unrestricted Write tool detected in agent tool list — grants arbitrary "
        "filesystem write access without path restrictions"
    )
    patterns = [
        re.compile(r"[\"']Write[\"']"),
        re.compile(r"\btool\s*:\s*Write\b"),
    ]


class UnrestrictedEditToolRule(Rule):
    """Detects Edit listed as an unrestricted tool in an agent tool list."""

    rule_id = "AG-103"
    category = "dangerous_tools"
    severity = Severity.CRITICAL
    description = (
        "Unrestricted Edit tool detected in agent tool list — grants arbitrary "
        "file modification capability without scope restrictions"
    )
    patterns = [
        re.compile(r"[\"']Edit[\"']"),
        re.compile(r"\btool\s*:\s*Edit\b"),
    ]


class DangerouslyDisableSandboxAgentRule(Rule):
    """Detects dangerouslyDisableSandbox flag in agent configurations."""

    rule_id = "AG-104"
    category = "dangerous_tools"
    severity = Severity.CRITICAL
    description = (
        "dangerouslyDisableSandbox detected — removes the execution sandbox, "
        "exposing the host system to direct manipulation"
    )
    patterns = [
        re.compile(r"\bdangerouslyDisableSandbox\b"),
    ]


# ---------------------------------------------------------------------------
# Category 17 — Agent Chaining
# ---------------------------------------------------------------------------


class AgentToolInvocationRule(Rule):
    """Detects Agent tool calls used to spawn sub-agents."""

    rule_id = "AG-201"
    category = "agent_chaining"
    severity = Severity.WARNING
    description = (
        "Agent tool invocation detected — spawns a sub-agent whose actions may "
        "be harder to audit and may inherit elevated permissions"
    )
    patterns = [
        re.compile(r"\bAgent\s*tool\b", re.IGNORECASE),
        re.compile(r"[\"']Agent[\"']\s*,"),
        re.compile(r"\binvoke.*\bAgent\b", re.IGNORECASE),
        re.compile(r"\bskill\s*:\s*['\"]Agent['\"]", re.IGNORECASE),
    ]


class SendMessageRule(Rule):
    """Detects SendMessage calls used for inter-agent communication."""

    rule_id = "AG-202"
    category = "agent_chaining"
    severity = Severity.WARNING
    description = (
        "SendMessage call detected — used for inter-agent or cross-session "
        "communication that may bypass session-level controls"
    )
    patterns = [
        re.compile(r"\bSendMessage\s*\(", re.IGNORECASE),
        re.compile(r"\bsend_message\s*\(", re.IGNORECASE),
    ]


class SubagentTypeRule(Rule):
    """Detects subagent_type declarations that configure spawned sub-agents."""

    rule_id = "AG-203"
    category = "agent_chaining"
    severity = Severity.WARNING
    description = (
        "subagent_type declaration detected — defines the type of sub-agent to "
        "spawn, potentially escalating capabilities via chaining"
    )
    patterns = [
        re.compile(r"\bsubagent_type\b", re.IGNORECASE),
        re.compile(r"\bsubagentType\b"),
    ]


class CrossSkillReferenceRule(Rule):
    """Detects cross-references to other skills or agents that may create chained execution."""

    rule_id = "AG-204"
    category = "agent_chaining"
    severity = Severity.WARNING
    description = (
        "Cross-skill or cross-agent reference detected — chained agent execution "
        "may propagate permissions or instructions across trust boundaries"
    )
    patterns = [
        re.compile(r"\bskill\s*:\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"\buse_skill\s*\(", re.IGNORECASE),
        re.compile(r"\bload_agent\s*\(", re.IGNORECASE),
        re.compile(r"\bdelegated?_to\s*[:=]", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 18 — Agent Hooks
# ---------------------------------------------------------------------------


class PreToolUseHookRule(Rule):
    """Detects pre_tool_use hook definitions that execute code before tool calls."""

    rule_id = "AG-301"
    category = "agent_hooks"
    severity = Severity.WARNING
    description = (
        "pre_tool_use hook detected — executes shell commands or scripts before "
        "every tool call; may intercept, modify, or log tool inputs"
    )
    patterns = [
        re.compile(r"\bpre_tool_use\b", re.IGNORECASE),
        re.compile(r"\bpreToolUse\b"),
    ]


class PostToolUseHookRule(Rule):
    """Detects post_tool_use hook definitions that execute code after tool calls."""

    rule_id = "AG-302"
    category = "agent_hooks"
    severity = Severity.WARNING
    description = (
        "post_tool_use hook detected — executes shell commands or scripts after "
        "every tool call; may exfiltrate outputs or trigger secondary actions"
    )
    patterns = [
        re.compile(r"\bpost_tool_use\b", re.IGNORECASE),
        re.compile(r"\bpostToolUse\b"),
    ]


class HookShellCommandRule(Rule):
    """Detects hook definitions that embed shell command strings."""

    rule_id = "AG-303"
    category = "agent_hooks"
    severity = Severity.WARNING
    description = (
        "Hook definition with embedded shell command detected — shell commands "
        "inside hooks execute automatically and are easy to overlook in reviews"
    )
    patterns = [
        re.compile(r"\bhook\s*[:=]\s*['\"].*(?:bash|sh|python|node|exec)\b", re.IGNORECASE),
        re.compile(r"\bcommand\s*[:=]\s*['\"][^'\"]*(?:bash|sh)\b[^'\"]*['\"]", re.IGNORECASE),
        re.compile(r"\brun\s*[:=]\s*['\"][^'\"]*(?:bash|sh|python)\b[^'\"]*['\"]", re.IGNORECASE),
    ]
