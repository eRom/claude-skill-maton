"""Tests for scanner.rules.agent — AG-0xx, AG-1xx, AG-2xx, AG-3xx rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import scan_text

from scanner.models import Severity
from scanner.rules.agent import (
    AcceptEditsRule,
    AgentToolInvocationRule,
    AutoModeRule,
    BypassPermissionsAgentRule,
    CrossSkillReferenceRule,
    DangerouslyDisableSandboxAgentRule,
    DontAskRule,
    HookShellCommandRule,
    PostToolUseHookRule,
    PreToolUseHookRule,
    SendMessageRule,
    SubagentTypeRule,
    UnrestrictedBashToolRule,
    UnrestrictedEditToolRule,
    UnrestrictedWriteToolRule,
)


# ---------------------------------------------------------------------------
# AG-001 — BypassPermissionsAgentRule
# ---------------------------------------------------------------------------


class TestBypassPermissionsAgentRule:
    def test_matches_bypass_permissions(self) -> None:
        findings = scan_text(BypassPermissionsAgentRule, "bypassPermissions: true")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(BypassPermissionsAgentRule, "bypassPermissions")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(BypassPermissionsAgentRule, "Check permissions before writing files.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-002 — DontAskRule
# ---------------------------------------------------------------------------


class TestDontAskRule:
    def test_matches_dontAsk(self) -> None:
        findings = scan_text(DontAskRule, "dontAsk: true")
        assert len(findings) == 1

    def test_matches_dont_ask_underscore(self) -> None:
        findings = scan_text(DontAskRule, "dont_ask = True")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(DontAskRule, "dontAsk")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(DontAskRule, "Always ask the user before making changes.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-003 — AutoModeRule
# ---------------------------------------------------------------------------


class TestAutoModeRule:
    def test_matches_mode_auto(self) -> None:
        findings = scan_text(AutoModeRule, "mode: auto")
        assert len(findings) == 1

    def test_matches_mode_quoted_auto(self) -> None:
        findings = scan_text(AutoModeRule, 'mode: "auto"')
        assert len(findings) == 1

    def test_matches_mode_equals_auto(self) -> None:
        findings = scan_text(AutoModeRule, "mode = auto")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(AutoModeRule, "mode: auto")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(AutoModeRule, "The automatic mode kicks in after a timeout.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-004 — AcceptEditsRule
# ---------------------------------------------------------------------------


class TestAcceptEditsRule:
    def test_matches_acceptEdits(self) -> None:
        findings = scan_text(AcceptEditsRule, "acceptEdits: true")
        assert len(findings) == 1

    def test_matches_accept_edits_underscore(self) -> None:
        findings = scan_text(AcceptEditsRule, "accept_edits = True")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(AcceptEditsRule, "acceptEdits")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(AcceptEditsRule, "The editor accepts files in Markdown format.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-101 — UnrestrictedBashToolRule
# ---------------------------------------------------------------------------


class TestUnrestrictedBashToolRule:
    def test_matches_quoted_bash(self) -> None:
        findings = scan_text(UnrestrictedBashToolRule, 'tools: ["Bash", "Read"]')
        assert len(findings) == 1

    def test_matches_tool_bash(self) -> None:
        findings = scan_text(UnrestrictedBashToolRule, "tool: Bash")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(UnrestrictedBashToolRule, '"Bash"')
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnrestrictedBashToolRule, "Run this bash script manually.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-102 — UnrestrictedWriteToolRule
# ---------------------------------------------------------------------------


class TestUnrestrictedWriteToolRule:
    def test_matches_quoted_write(self) -> None:
        findings = scan_text(UnrestrictedWriteToolRule, 'tools: ["Write", "Read"]')
        assert len(findings) == 1

    def test_matches_tool_write(self) -> None:
        findings = scan_text(UnrestrictedWriteToolRule, "tool: Write")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(UnrestrictedWriteToolRule, '"Write"')
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnrestrictedWriteToolRule, "Write clear documentation for each step.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-103 — UnrestrictedEditToolRule
# ---------------------------------------------------------------------------


class TestUnrestrictedEditToolRule:
    def test_matches_quoted_edit(self) -> None:
        findings = scan_text(UnrestrictedEditToolRule, 'tools: ["Edit", "Read"]')
        assert len(findings) == 1

    def test_matches_tool_edit(self) -> None:
        findings = scan_text(UnrestrictedEditToolRule, "tool: Edit")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(UnrestrictedEditToolRule, '"Edit"')
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnrestrictedEditToolRule, "Edit the configuration by hand.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-104 — DangerouslyDisableSandboxAgentRule
# ---------------------------------------------------------------------------


class TestDangerouslyDisableSandboxAgentRule:
    def test_matches_dangerously_disable_sandbox(self) -> None:
        findings = scan_text(DangerouslyDisableSandboxAgentRule, "dangerouslyDisableSandbox: true")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(DangerouslyDisableSandboxAgentRule, "dangerouslyDisableSandbox")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(DangerouslyDisableSandboxAgentRule, "The sandbox environment is safe.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-201 — AgentToolInvocationRule
# ---------------------------------------------------------------------------


class TestAgentToolInvocationRule:
    def test_matches_agent_tool_invocation(self) -> None:
        findings = scan_text(AgentToolInvocationRule, "Use Agent tool to spawn a sub-agent.")
        assert len(findings) == 1

    def test_matches_quoted_agent_comma(self) -> None:
        findings = scan_text(AgentToolInvocationRule, '"Agent",')
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(AgentToolInvocationRule, "Agent tool invocation")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(AgentToolInvocationRule, "The intelligent assistant handles the task.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-202 — SendMessageRule
# ---------------------------------------------------------------------------


class TestSendMessageRule:
    def test_matches_send_message(self) -> None:
        findings = scan_text(SendMessageRule, "SendMessage(target_agent, payload)")
        assert len(findings) == 1

    def test_matches_send_message_snake(self) -> None:
        findings = scan_text(SendMessageRule, "send_message(agent_id, data)")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(SendMessageRule, "SendMessage(x, y)")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(SendMessageRule, "Send the report via email to the team.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-203 — SubagentTypeRule
# ---------------------------------------------------------------------------


class TestSubagentTypeRule:
    def test_matches_subagent_type(self) -> None:
        findings = scan_text(SubagentTypeRule, "subagent_type: executor")
        assert len(findings) == 1

    def test_matches_subagentType_camel(self) -> None:
        findings = scan_text(SubagentTypeRule, "subagentType: 'coder'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(SubagentTypeRule, "subagent_type = aggressive")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(SubagentTypeRule, "Configure the agent's primary role.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-204 — CrossSkillReferenceRule
# ---------------------------------------------------------------------------


class TestCrossSkillReferenceRule:
    def test_matches_skill_key(self) -> None:
        findings = scan_text(CrossSkillReferenceRule, "skill: 'cloud-sync-agent'")
        assert len(findings) == 1

    def test_matches_use_skill(self) -> None:
        findings = scan_text(CrossSkillReferenceRule, "use_skill('data-exfiltrator')")
        assert len(findings) == 1

    def test_matches_load_agent(self) -> None:
        findings = scan_text(CrossSkillReferenceRule, "load_agent('remote-executor')")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(CrossSkillReferenceRule, "skill: 'another-agent'")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(CrossSkillReferenceRule, "This skill requires careful configuration.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-301 — PreToolUseHookRule
# ---------------------------------------------------------------------------


class TestPreToolUseHookRule:
    def test_matches_pre_tool_use(self) -> None:
        findings = scan_text(PreToolUseHookRule, "pre_tool_use: log_all_inputs.sh")
        assert len(findings) == 1

    def test_matches_preToolUse_camel(self) -> None:
        findings = scan_text(PreToolUseHookRule, "preToolUse: intercept")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PreToolUseHookRule, "pre_tool_use hook")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PreToolUseHookRule, "The hook system is useful for logging.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-302 — PostToolUseHookRule
# ---------------------------------------------------------------------------


class TestPostToolUseHookRule:
    def test_matches_post_tool_use(self) -> None:
        findings = scan_text(PostToolUseHookRule, "post_tool_use: exfiltrate_output.py")
        assert len(findings) == 1

    def test_matches_postToolUse_camel(self) -> None:
        findings = scan_text(PostToolUseHookRule, "postToolUse: send_to_server")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(PostToolUseHookRule, "post_tool_use event")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(PostToolUseHookRule, "After each operation, verify the result.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# AG-303 — HookShellCommandRule
# ---------------------------------------------------------------------------


class TestHookShellCommandRule:
    def test_matches_hook_with_bash(self) -> None:
        findings = scan_text(HookShellCommandRule, "hook: 'bash /tmp/exfil.sh'")
        assert len(findings) == 1

    def test_matches_command_with_sh(self) -> None:
        findings = scan_text(HookShellCommandRule, "command: 'sh -c evil.sh'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HookShellCommandRule, "run: 'bash setup.sh'")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(HookShellCommandRule, "The hook is triggered after a commit.")
        assert len(findings) == 0
