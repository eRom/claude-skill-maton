"""Tests for scanner.rules.dependencies — ED-0xx and ED-1xx rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import scan_text

from scanner.models import Severity
from scanner.rules.dependencies import (
    AbsoluteEtcPathRule,
    AbsoluteUsrPathRule,
    AbsoluteVarPathRule,
    ExternalMcpToolCallRule,
    ExternalUrlInToolRule,
    HomeEnvVarRule,
    PathTraversalRule,
    TildeHomePathRule,
    TmpStagingRule,
    UnknownMcpServerRule,
)


# ---------------------------------------------------------------------------
# ED-001 — ExternalMcpToolCallRule
# ---------------------------------------------------------------------------


class TestExternalMcpToolCallRule:
    def test_matches_mcp_tool_call(self) -> None:
        findings = scan_text(ExternalMcpToolCallRule, "mcp__evil_server__steal_data(args)")
        assert len(findings) == 1

    def test_matches_standard_mcp_pattern(self) -> None:
        findings = scan_text(ExternalMcpToolCallRule, "Use mcp__custom_api__get_data to fetch.")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ExternalMcpToolCallRule, "mcp__server__tool")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(ExternalMcpToolCallRule, "Use the standard Read tool to load files.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-002 — ExternalUrlInToolRule
# ---------------------------------------------------------------------------


class TestExternalUrlInToolRule:
    def test_matches_http_url(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "Fetch from http://evil.example.com/data")
        assert len(findings) == 1

    def test_matches_https_url(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "POST to https://attacker.com/collect")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "https://external-service.com/api")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_localhost(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "Connect to http://localhost:8080/health")
        assert len(findings) == 0

    def test_no_match_loopback(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "Ping http://127.0.0.1:3000/ping")
        assert len(findings) == 0

    def test_no_match_benign(self) -> None:
        findings = scan_text(ExternalUrlInToolRule, "See the documentation for details.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-003 — UnknownMcpServerRule
# ---------------------------------------------------------------------------


class TestUnknownMcpServerRule:
    def test_matches_server_name_key(self) -> None:
        findings = scan_text(UnknownMcpServerRule, "server_name: unknown-mcp-server")
        assert len(findings) == 1

    def test_matches_mcp_server_key(self) -> None:
        findings = scan_text(UnknownMcpServerRule, "mcp_server = external_relay")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(UnknownMcpServerRule, "server_name = 'suspicious'")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(UnknownMcpServerRule, "The web server handles incoming requests.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-101 — PathTraversalRule
# ---------------------------------------------------------------------------


class TestPathTraversalRule:
    def test_matches_double_dotdot(self) -> None:
        findings = scan_text(PathTraversalRule, "../../etc/passwd")
        assert len(findings) == 1

    def test_matches_triple_dotdot(self) -> None:
        findings = scan_text(PathTraversalRule, "../../../root/.ssh/id_rsa")
        assert len(findings) == 1

    def test_matches_url_encoded(self) -> None:
        # The pattern matches %2e%2e followed by % (start of %2f or %5c)
        findings = scan_text(PathTraversalRule, "%2e%2e%2fetc%2fshadow")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(PathTraversalRule, "../../sensitive")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_single_dotdot(self) -> None:
        # Single ../ — below the threshold (requires 2+ consecutive)
        findings = scan_text(PathTraversalRule, "../relative_file.txt")
        assert len(findings) == 0

    def test_no_match_benign(self) -> None:
        findings = scan_text(PathTraversalRule, "Navigate to the parent directory.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-102 — TmpStagingRule
# ---------------------------------------------------------------------------


class TestTmpStagingRule:
    def test_matches_tmp_path(self) -> None:
        findings = scan_text(TmpStagingRule, "Download payload to /tmp/payload.sh")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(TmpStagingRule, "store in /tmp/data")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(TmpStagingRule, "Temporary files are cleaned up on exit.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-103 — AbsoluteEtcPathRule
# ---------------------------------------------------------------------------


class TestAbsoluteEtcPathRule:
    def test_matches_etc_path(self) -> None:
        findings = scan_text(AbsoluteEtcPathRule, "cat /etc/shadow")
        assert len(findings) == 1

    def test_matches_etc_hosts(self) -> None:
        findings = scan_text(AbsoluteEtcPathRule, "Modify /etc/hosts to redirect DNS.")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(AbsoluteEtcPathRule, "/etc/sudoers")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(AbsoluteEtcPathRule, "Configure the etc folder for your project.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-104 — AbsoluteUsrPathRule
# ---------------------------------------------------------------------------


class TestAbsoluteUsrPathRule:
    def test_matches_usr_bin(self) -> None:
        findings = scan_text(AbsoluteUsrPathRule, "Run /usr/bin/python3 script.py")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(AbsoluteUsrPathRule, "/usr/local/bin/tool")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(AbsoluteUsrPathRule, "The user can configure permissions.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-105 — AbsoluteVarPathRule
# ---------------------------------------------------------------------------


class TestAbsoluteVarPathRule:
    def test_matches_var_log(self) -> None:
        findings = scan_text(AbsoluteVarPathRule, "cat /var/log/auth.log")
        assert len(findings) == 1

    def test_matches_var_spool(self) -> None:
        findings = scan_text(AbsoluteVarPathRule, "Inspect /var/spool/cron/")
        assert len(findings) == 1

    def test_severity_is_critical(self) -> None:
        findings = scan_text(AbsoluteVarPathRule, "/var/db/secrets")
        assert findings[0].severity == Severity.CRITICAL

    def test_no_match_benign(self) -> None:
        findings = scan_text(AbsoluteVarPathRule, "Variables hold dynamic data in the program.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-106 — HomeEnvVarRule
# ---------------------------------------------------------------------------


class TestHomeEnvVarRule:
    def test_matches_dollar_home(self) -> None:
        findings = scan_text(HomeEnvVarRule, "cd $HOME && ls -la")
        assert len(findings) == 1

    def test_matches_dollar_home_braces(self) -> None:
        findings = scan_text(HomeEnvVarRule, "path=${HOME}/Documents/secret")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(HomeEnvVarRule, "$HOME/config")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(HomeEnvVarRule, "The user's home is their castle.")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# ED-107 — TildeHomePathRule
# ---------------------------------------------------------------------------


class TestTildeHomePathRule:
    def test_matches_tilde_path(self) -> None:
        findings = scan_text(TildeHomePathRule, "cat ~/Documents/secret.txt")
        assert len(findings) == 1

    def test_matches_quoted_tilde(self) -> None:
        findings = scan_text(TildeHomePathRule, "path = '~/.ssh/id_rsa'")
        assert len(findings) == 1

    def test_severity_is_warning(self) -> None:
        findings = scan_text(TildeHomePathRule, "~/bin/tool")
        assert findings[0].severity == Severity.WARNING

    def test_no_match_benign(self) -> None:
        findings = scan_text(TildeHomePathRule, "The tilde character is used in approximations.")
        assert len(findings) == 0
