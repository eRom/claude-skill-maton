"""Exfiltration detection rules.

Categories covered:
  CL — Context Leaks        (Category 6)  — WARNING
  DE — Data Extraction      (Category 8)  — CRITICAL
  PX — Public Exposure      (Category 10) — WARNING
  ST — Secret Transfer      (Category 11) — CRITICAL
"""

from __future__ import annotations

import re

from scanner.models import Severity
from scanner.rules.base import Rule


# ---------------------------------------------------------------------------
# Category 6 — Context Leaks (CL-*)  severity: WARNING
# ---------------------------------------------------------------------------

class HomeDirectoryLeak(Rule):
    """References to ~/  or $HOME that suggest exposing the user's home path."""

    rule_id = "CL-001"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to home directory path (~/ or $HOME) detected"
    patterns = [
        # Match ~/  or $HOME followed by a path component (not just documentation prose)
        re.compile(r"(?:~/|(?<!\w)\$HOME(?:/|\b))", re.IGNORECASE),
    ]


class DotEnvFileLeak(Rule):
    """References to reading/loading .env files (not just the word 'environment')."""

    rule_id = "CL-002"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to .env file detected — may expose environment secrets"
    patterns = [
        # Matches '.env' as a filename token: .env, .env.local, .env.production, etc.
        # Avoids matching 'environment' or 'env' bare words.
        re.compile(r"(?<!\w)\.env(?:\.[a-z_]+)?(?!\w)", re.IGNORECASE),
    ]


class CredentialsLeak(Rule):
    """References to credential files or variables."""

    rule_id = "CL-003"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to credentials detected"
    patterns = [
        re.compile(r"\bcredentials?\b", re.IGNORECASE),
    ]


class TokenLeak(Rule):
    """References to tokens (auth tokens, API tokens, bearer tokens, etc.)."""

    rule_id = "CL-004"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to token variable or value detected"
    patterns = [
        # Match token as a variable name/assignment context, not generic prose like "token economy"
        re.compile(
            r"(?:token\s*[=:\"']|[\"']token[\"']\s*[=:]|\bapi[_-]?token\b|\bauth[_-]?token\b|\bbearer[_-]?token\b)",
            re.IGNORECASE,
        ),
    ]


class ApiKeyLeak(Rule):
    """References to api_key / API_KEY variables."""

    rule_id = "CL-005"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to API key variable detected"
    patterns = [
        re.compile(r"\bapi[_-]?key\b", re.IGNORECASE),
    ]


class SecretLeak(Rule):
    """References to secret variables or values."""

    rule_id = "CL-006"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to secret variable or value detected"
    patterns = [
        # 'secret' as an assignment target / dict key, not as a common English adjective
        re.compile(
            r"(?:secret\s*[=:\"']|[\"']secret[\"']\s*[=:]|\bsecret[_-]?key\b|\bapp[_-]?secret\b|\bclient[_-]?secret\b)",
            re.IGNORECASE,
        ),
    ]


class PasswordLeak(Rule):
    """References to password variables."""

    rule_id = "CL-007"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to password variable or value detected"
    patterns = [
        re.compile(
            r"(?:password\s*[=:\"']|[\"']password[\"']\s*[=:]|\bpasswd\b|\bpwd\s*=)",
            re.IGNORECASE,
        ),
    ]


class PrivateKeyLeak(Rule):
    """References to private key material or files."""

    rule_id = "CL-008"
    category = "context_leak"
    severity = Severity.WARNING
    description = "Reference to private key detected"
    patterns = [
        re.compile(r"\bprivate[_\s-]?key\b", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 8 — Data Extraction (DE-*)  severity: CRITICAL
# ---------------------------------------------------------------------------

class OsEnvironExtraction(Rule):
    """Python os.environ access — may read sensitive env variables."""

    rule_id = "DE-001"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "os.environ access detected — reads all environment variables"
    patterns = [
        re.compile(r"\bos\.environ\b"),
    ]


class ProcessEnvExtraction(Rule):
    """Node.js process.env access — may read sensitive env variables."""

    rule_id = "DE-002"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "process.env access detected — reads all environment variables"
    patterns = [
        re.compile(r"\bprocess\.env\b"),
    ]


class ShellEnvVarExtraction(Rule):
    """Shell $ENV expansion — may expose sensitive shell variables."""

    rule_id = "DE-003"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "Shell $ENV variable expansion detected"
    patterns = [
        re.compile(r"(?<!\$)\$ENV\b"),
    ]


class EtcPasswdExtraction(Rule):
    """References to /etc/passwd — classic system credential file."""

    rule_id = "DE-004"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "Reference to /etc/passwd detected"
    patterns = [
        re.compile(r"/etc/passwd\b"),
    ]


class KeychainExtraction(Rule):
    """References to macOS Keychain access."""

    rule_id = "DE-005"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "Reference to system keychain detected"
    patterns = [
        re.compile(r"\bkeychain\b", re.IGNORECASE),
    ]


class SshKeyExtraction(Rule):
    """References to SSH key files (id_rsa, id_ed25519, generic 'ssh key')."""

    rule_id = "DE-006"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "Reference to SSH private key file detected"
    patterns = [
        re.compile(r"\bid_rsa\b", re.IGNORECASE),
        re.compile(r"\bid_ed25519\b", re.IGNORECASE),
        re.compile(r"\bssh[_\s-]?key\b", re.IGNORECASE),
    ]


class AwsCredentialsExtraction(Rule):
    """References to AWS credentials files or paths."""

    rule_id = "DE-007"
    category = "data_extraction"
    severity = Severity.CRITICAL
    description = "Reference to AWS credentials file or path detected"
    patterns = [
        re.compile(r"\baws[_\s-]?credentials\b", re.IGNORECASE),
        re.compile(r"\.aws/", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 10 — Public Exposure (PX-*)  severity: WARNING
# ---------------------------------------------------------------------------

class WebhookExposure(Rule):
    """Webhook URLs in prompts — may receive exfiltrated data."""

    rule_id = "PX-001"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "Webhook URL reference detected — potential data exfiltration endpoint"
    patterns = [
        re.compile(r"\bwebhook\b", re.IGNORECASE),
    ]


class PastebinExposure(Rule):
    """References to pastebin-style public paste services."""

    rule_id = "PX-002"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "Public paste service reference detected (pastebin, hastebin, etc.)"
    patterns = [
        re.compile(r"\bpastebin\.com\b", re.IGNORECASE),
        re.compile(r"\bhastebin\b", re.IGNORECASE),
    ]


class GistExposure(Rule):
    """References to GitHub Gist — can be used to exfiltrate data."""

    rule_id = "PX-003"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "GitHub Gist reference detected — potential public data exposure"
    patterns = [
        re.compile(r"\bgist\.github(?:\.com)?\b", re.IGNORECASE),
    ]


class RequestBinExposure(Rule):
    """References to HTTP inspection/bin services (requestbin, hookbin, etc.)."""

    rule_id = "PX-004"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "HTTP inspection service reference detected (requestbin, hookbin)"
    patterns = [
        re.compile(r"\brequestbin\b", re.IGNORECASE),
        re.compile(r"\bhookbin\b", re.IGNORECASE),
    ]


class NgrokExposure(Rule):
    """References to ngrok — used to tunnel internal services to the internet."""

    rule_id = "PX-005"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "ngrok tunnel reference detected — exposes local services publicly"
    patterns = [
        re.compile(r"\bngrok\b", re.IGNORECASE),
    ]


class PostmanExposure(Rule):
    """References to Postman — can be used to relay captured requests externally."""

    rule_id = "PX-006"
    category = "public_exposure"
    severity = Severity.WARNING
    description = "Postman reference detected — may be used to relay sensitive data"
    patterns = [
        re.compile(r"\bpostman\b", re.IGNORECASE),
    ]


# ---------------------------------------------------------------------------
# Category 11 — Secret Transfer (ST-*)  severity: CRITICAL
# ---------------------------------------------------------------------------

class Base64WithSendContext(Rule):
    """base64 encoding combined with data transfer verbs on the same line."""

    rule_id = "ST-001"
    category = "secret_transfer"
    severity = Severity.CRITICAL
    description = "base64 encoding combined with send/upload/post context — possible secret exfiltration"
    patterns = [
        # base64 + send/upload/post/transmit/exfil within the same line
        re.compile(
            r"(?=.*\bbase64\b)(?=.*\b(?:send|upload|post|transmit|exfil(?:trate)?|curl|fetch|request)\b).*",
            re.IGNORECASE,
        ),
    ]


class Base64SensitiveDataEncoding(Rule):
    """base64 encoding of known sensitive variable names."""

    rule_id = "ST-002"
    category = "secret_transfer"
    severity = Severity.CRITICAL
    description = "base64 encoding of sensitive data pattern detected"
    patterns = [
        # base64.encode/b64encode/btoa applied to a sensitive-sounding variable
        re.compile(
            r"\b(?:base64\.encode|b64encode|btoa)\s*\([^)]*"
            r"(?:password|token|secret|key|credential|api_key)[^)]*\)",
            re.IGNORECASE,
        ),
    ]
